'use strict';
// Delivery log storage.
//
// Two drivers behind one interface so the dashboard code never cares which is
// live:
//
//   memory   (default) - a ring buffer in process memory. Correct and complete
//                        when self-hosted (one long-lived process). On Vercel
//                        each serverless instance has its OWN buffer and cold
//                        starts wipe it, so history is partial by nature.
//   supabase           - a `webhook_deliveries` table. Durable and shared across
//                        instances, so it is the only honest option on Vercel.
//                        Unconfigured by default; set SUPABASE_URL + a key.
//
// isDurable() lets the UI tell the operator which of those two worlds they are
// in, rather than silently showing a log with holes in it.

const crypto = require('crypto');
const config = require('./config');

const newId = () => crypto.randomBytes(6).toString('hex');

// ---------------------------------------------------------------------------
// memory driver
// ---------------------------------------------------------------------------
function memoryDriver(size) {
  let rows = [];
  return {
    name: 'memory',
    durable: false,
    async record(entry) {
      rows.unshift(entry);
      if (rows.length > size) rows.length = size;
      return entry;
    },
    async list({ limit = 50, offset = 0, result, q, since } = {}) {
      let out = rows;
      // `at` is an ISO-8601 string, which sorts lexically the same as chronologically.
      if (since) out = out.filter((r) => r.at >= since);
      if (result) out = out.filter((r) => r.result === result);
      if (q) {
        const needle = String(q).toLowerCase();
        out = out.filter((r) =>
          [r.verification_id, r.customer_number, r.reason, r.result, String(r.intuitionStatus)]
            .filter(Boolean)
            .some((v) => String(v).toLowerCase().includes(needle))
        );
      }
      return { rows: out.slice(offset, offset + limit), total: out.length };
    },
    async get(id) {
      return rows.find((r) => r.id === id) || null;
    },
    async all({ since } = {}) {
      return since ? rows.filter((r) => r.at >= since) : rows;
    },
    async clear() {
      const n = rows.length;
      rows = [];
      return n;
    }
  };
}

// ---------------------------------------------------------------------------
// postgres driver
// ---------------------------------------------------------------------------
// Speaks to any Postgres via DATABASE_URL: Supabase, Neon, Vercel Postgres, RDS,
// or the container in docker-compose. This is the durable option — the log
// survives restarts and, crucially, is shared across serverless instances, which
// is what the memory driver cannot do.
function postgresDriver({ url, table, ssl }) {
  // Required so an unquoted identifier can never be injected via LOG_TABLE.
  if (!/^[a-z_][a-z0-9_]*$/i.test(table)) throw new Error(`Unsafe LOG_TABLE name: ${table}`);

  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: url,
    // Serverless: many short-lived instances, so keep one connection each and
    // drop it quickly. Point DATABASE_URL at a pooler (pgbouncer / Neon pooled
    // endpoint) in production or Postgres will run out of connections.
    max: Number(process.env.PG_POOL_MAX || 1),
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 8000,
    // Hosted Postgres presents a cert the container may not have a CA for.
    ssl: ssl ? { rejectUnauthorized: false } : undefined
  });
  // A pool error must not take the process down; the next query reconnects.
  pool.on('error', (e) => console.error(`pg pool error: ${e.message}`));

  // Idempotent migration, run once per process and awaited by every caller, so
  // there is no "remember to run the SQL by hand" step.
  let migrated = null;
  const migrate = () => {
    if (!migrated) {
      migrated = pool.query(`
        CREATE TABLE IF NOT EXISTS ${table} (
          id              text PRIMARY KEY,
          at              timestamptz NOT NULL DEFAULT now(),
          result          text NOT NULL,
          reason          text,
          verified        boolean NOT NULL DEFAULT false,
          verification_id text,
          customer_number text,
          intuition_status integer,
          risk_level      text,
          rules_score     integer,
          duration_ms     integer,
          auth_via        text,
          detail          jsonb NOT NULL DEFAULT '{}'::jsonb
        );
        CREATE INDEX IF NOT EXISTS ${table}_at_idx     ON ${table} (at DESC);
        CREATE INDEX IF NOT EXISTS ${table}_result_idx ON ${table} (result);
        CREATE INDEX IF NOT EXISTS ${table}_vid_idx    ON ${table} (verification_id);
        CREATE INDEX IF NOT EXISTS ${table}_cust_idx   ON ${table} (customer_number);
      `).catch((e) => { migrated = null; throw e; });   // let a later call retry
    }
    return migrated;
  };

  const q = async (sql, params) => { await migrate(); return pool.query(sql, params); };

  // Build the WHERE clause for the dashboard's filter + free-text search + time range.
  function where({ result, q: search, since }) {
    const cond = [];
    const params = [];
    if (since) { params.push(since); cond.push(`at >= $${params.length}`); }
    if (result) { params.push(result); cond.push(`result = $${params.length}`); }
    if (search) {
      params.push(`%${search}%`);
      const p = `$${params.length}`;
      cond.push(`(verification_id ILIKE ${p} OR customer_number ILIKE ${p} OR reason ILIKE ${p} OR result ILIKE ${p})`);
    }
    return { clause: cond.length ? `WHERE ${cond.join(' AND ')}` : '', params };
  }

  return {
    name: 'postgres',
    durable: true,
    async record(entry) {
      const r = toRow(entry);
      await q(
        `INSERT INTO ${table}
           (id, at, result, reason, verified, verification_id, customer_number,
            intuition_status, risk_level, rules_score, duration_ms, auth_via, detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (id) DO NOTHING`,
        [r.id, r.at, r.result, r.reason, r.verified, r.verification_id, r.customer_number,
         r.intuition_status, r.risk_level, r.rules_score, r.duration_ms, r.auth_via,
         JSON.stringify(r.detail)]
      );
      return entry;
    },
    async list({ limit = 50, offset = 0, result, q: search, since } = {}) {
      const { clause, params } = where({ result, q: search, since });
      const rows = await q(
        `SELECT detail FROM ${table} ${clause} ORDER BY at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limit, offset]
      );
      const count = await q(`SELECT count(*)::int AS n FROM ${table} ${clause}`, params);
      return { rows: rows.rows.map((r) => r.detail), total: count.rows[0].n };
    },
    async get(id) {
      const r = await q(`SELECT detail FROM ${table} WHERE id = $1`, [id]);
      return r.rows.length ? r.rows[0].detail : null;
    },
    async all({ since } = {}) {
      // Stats are computed in-process; cap the scan so a big table can't stall
      // the dashboard. Callers surface this as "recent" rather than "all time".
      const { clause, params } = where({ since });
      const r = await q(
        `SELECT detail FROM ${table} ${clause} ORDER BY at DESC LIMIT $${params.length + 1}`,
        [...params, config.store.statsLimit]
      );
      return r.rows.map((x) => x.detail);
    },
    async clear() {
      const r = await q(`DELETE FROM ${table}`);
      return r.rowCount;
    },
    async close() { await pool.end(); }
  };
}

// ---------------------------------------------------------------------------
// supabase driver (PostgREST)
// ---------------------------------------------------------------------------
// Table DDL lives in docs/supabase-schema.sql. We deliberately do not attempt to
// create the table at runtime: DDL needs elevated rights the relay should not
// hold, and a half-created schema is worse than a clear error.
function supabaseDriver({ url, key, table }) {
  const base = `${url.replace(/\/$/, '')}/rest/v1/${table}`;
  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`,
    'Content-Type': 'application/json'
  };

  async function req(path, opts = {}) {
    const res = await fetch(`${base}${path}`, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`supabase ${res.status}: ${body.slice(0, 300)}`);
    }
    return res;
  }

  return {
    name: 'supabase',
    durable: true,
    async record(entry) {
      // Never let a logging failure break the webhook: the caller catches this.
      await req('', { method: 'POST', body: JSON.stringify([toRow(entry)]) });
      return entry;
    },
    async list({ limit = 50, offset = 0, result, q, since } = {}) {
      const p = new URLSearchParams();
      p.set('select', '*');
      p.set('order', 'at.desc');
      p.set('limit', String(limit));
      p.set('offset', String(offset));
      if (since) p.set('at', `gte.${since}`);
      if (result) p.set('result', `eq.${result}`);
      if (q) p.set('or', `(verification_id.ilike.*${q}*,customer_number.ilike.*${q}*,reason.ilike.*${q}*)`);
      const res = await req(`?${p}`, { headers: { Prefer: 'count=exact' } });
      const rows = await res.json();
      const range = res.headers.get('content-range') || '';
      const total = Number(range.split('/')[1]) || rows.length;
      return { rows: rows.map(fromRow), total };
    },
    async get(id) {
      const res = await req(`?id=eq.${encodeURIComponent(id)}&select=*&limit=1`);
      const rows = await res.json();
      return rows.length ? fromRow(rows[0]) : null;
    },
    async all({ since } = {}) {
      const p = new URLSearchParams({ select: '*', order: 'at.desc', limit: '1000' });
      if (since) p.set('at', `gte.${since}`);
      const res = await req(`?${p}`);
      return (await res.json()).map(fromRow);
    },
    async clear() {
      await req('?id=neq.__none__', { method: 'DELETE' });
      return -1; // PostgREST does not return a count without extra round-trips.
    }
  };
}

// ---------------------------------------------------------------------------
// mongodb driver
// ---------------------------------------------------------------------------
// Stores each delivery as one document (_id = delivery id, so a webhook retry
// is a no-op via the duplicate-key guard). Same interface as the other drivers.
function mongoDriver({ url, collection: collName }) {
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(url, { maxPoolSize: Number(process.env.MONGO_POOL_MAX || 5) });
  let coll, ready;
  const init = () => {
    if (!ready) {
      ready = (async () => {
        await client.connect();
        coll = client.db().collection(collName);
        // Idempotent — createIndex is a no-op if the index already exists.
        await Promise.all([
          coll.createIndex({ at: -1 }),
          coll.createIndex({ result: 1 }),
          coll.createIndex({ verification_id: 1 }),
          coll.createIndex({ customer_number: 1 })
        ]);
      })().catch((e) => { ready = null; throw e; });
    }
    return ready;
  };
  const strip = (d) => { if (!d) return d; const { _id, ...rest } = d; return rest; };
  const filter = ({ result, q, since }) => {
    const f = {};
    // `at` is an ISO-8601 string; lexical >= is chronological.
    if (since) f.at = { $gte: since };
    if (result) f.result = result;
    if (q) {
      // Escape regex metacharacters so search input can't alter the query.
      const rx = new RegExp(String(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      f.$or = [{ verification_id: rx }, { customer_number: rx }, { reason: rx }, { result: rx }];
    }
    return f;
  };
  return {
    name: 'mongo',
    durable: true,
    async record(entry) {
      await init();
      try { await coll.insertOne({ _id: entry.id, ...entry }); }
      catch (e) { if (e.code !== 11000) throw e; }   // 11000 = duplicate _id (retry)
      return entry;
    },
    async list(o = {}) {
      await init();
      const { limit = 50, offset = 0 } = o;
      const f = filter(o);
      const [rows, total] = await Promise.all([
        coll.find(f).sort({ at: -1 }).skip(offset).limit(limit).toArray(),
        coll.countDocuments(f)
      ]);
      return { rows: rows.map(strip), total };
    },
    async get(id) { await init(); return strip(await coll.findOne({ _id: id })); },
    async all({ since } = {}) {
      await init();
      const f = since ? { at: { $gte: since } } : {};
      return (await coll.find(f).sort({ at: -1 }).limit(config.store.statsLimit).toArray()).map(strip);
    },
    async clear() { await init(); return (await coll.deleteMany({})).deletedCount; },
    async close() { await client.close(); }
  };
}

// ---------------------------------------------------------------------------
// elasticsearch driver
// ---------------------------------------------------------------------------
// One index, document id = delivery id. Writes force a refresh so the dashboard
// (and tests) can read a delivery back immediately despite ES being near-real-time.
function elasticsearchDriver({ node, apiKey, username, password, index, rejectUnauthorized }) {
  const { Client } = require('@elastic/elasticsearch');
  const auth = apiKey ? { apiKey } : (username ? { username, password } : undefined);
  const client = new Client({ node, auth, tls: { rejectUnauthorized } });
  const body = (r) => (r && r.hits ? r : r && r.body ? r.body : r); // v8 returns body directly; v7 wraps
  let ready;
  const init = () => {
    if (!ready) {
      ready = (async () => {
        const ex = body(await client.indices.exists({ index }));
        if (ex === false || ex?.statusCode === 404) {
          await client.indices.create({
            index,
            mappings: { properties: {
              at: { type: 'date' },
              result: { type: 'keyword' },
              verification_id: { type: 'keyword' },
              customer_number: { type: 'keyword' },
              reason: { type: 'text' },
              riskLevel: { type: 'keyword' }
            } }
          }).catch((e) => { if (e.meta?.statusCode !== 400) throw e; }); // 400 = already exists (race)
        }
      })().catch((e) => { ready = null; throw e; });
    }
    return ready;
  };
  const query = ({ result, q, since }) => {
    const filter = [];
    if (since) filter.push({ range: { at: { gte: since } } });
    if (result) filter.push({ term: { result } });
    const bool = { filter };
    if (q) {
      // q is passed as a structured value, never string-concatenated into a query.
      bool.must = [{ bool: { minimum_should_match: 1, should: [
        { wildcard: { verification_id: { value: `*${q}*`, case_insensitive: true } } },
        { wildcard: { customer_number: { value: `*${q}*`, case_insensitive: true } } },
        { match: { reason: q } }
      ] } }];
    }
    return { bool };
  };
  return {
    name: 'elasticsearch',
    durable: true,
    async record(entry) {
      await init();
      try { await client.index({ index, id: entry.id, document: entry, op_type: 'create', refresh: true }); }
      catch (e) { if (e.meta?.statusCode !== 409) throw e; }  // 409 = doc exists (retry)
      return entry;
    },
    async list(o = {}) {
      await init();
      const { limit = 50, offset = 0 } = o;
      const r = body(await client.search({
        index, from: offset, size: limit, sort: [{ at: 'desc' }], track_total_hits: true, query: query(o)
      }));
      const total = typeof r.hits.total === 'object' ? r.hits.total.value : r.hits.total;
      return { rows: r.hits.hits.map((h) => h._source), total };
    },
    async get(id) {
      await init();
      try { const r = body(await client.get({ index, id })); return r._source || null; }
      catch (e) { if (e.meta?.statusCode === 404) return null; throw e; }
    },
    async all({ since } = {}) {
      await init();
      const r = body(await client.search({
        index, size: config.store.statsLimit, sort: [{ at: 'desc' }],
        query: since ? { bool: { filter: [{ range: { at: { gte: since } } }] } } : { match_all: {} }
      }));
      return r.hits.hits.map((h) => h._source);
    },
    async clear() {
      await init();
      const r = body(await client.deleteByQuery({ index, query: { match_all: {} }, refresh: true }));
      return r.deleted ?? -1;
    },
    async close() { await client.close(); }
  };
}

// The table stores the volatile bits as one jsonb column; everything we filter
// or sort on gets a real column.
const toRow = (e) => ({
  id: e.id,
  at: e.at,
  result: e.result,
  reason: e.reason || null,
  verified: Boolean(e.verified),
  verification_id: e.verification_id || null,
  customer_number: e.customer_number || null,
  intuition_status: e.intuitionStatus ?? null,
  risk_level: e.riskLevel || null,
  rules_score: e.totalRulesScore ?? null,
  duration_ms: e.durationMs ?? null,
  auth_via: e.authVia || null,
  detail: e
});

const fromRow = (r) => (r.detail && typeof r.detail === 'object' ? r.detail : r);

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------
function summarise(rows, opts = {}) {
  const total = rows.length;
  const byResult = {};
  const rulesCount = {};
  const riskCount = {};
  const durations = [];

  for (const r of rows) {
    byResult[r.result] = (byResult[r.result] || 0) + 1;
    if (typeof r.durationMs === 'number') durations.push(r.durationMs);
    if (r.riskLevel) riskCount[r.riskLevel] = (riskCount[r.riskLevel] || 0) + 1;
    for (const rule of r.rulesTriggered || []) {
      const k = String(rule).trim();
      if (k) rulesCount[k] = (rulesCount[k] || 0) + 1;
    }
  }

  durations.sort((a, b) => a - b);
  const pct = (p) => (durations.length ? durations[Math.min(durations.length - 1, Math.floor((p / 100) * durations.length))] : 0);
  const forwarded = byResult.forwarded || 0;

  return {
    total,
    forwarded,
    failed: total - forwarded,
    byResult,
    // Of the requests we actually attempted, how many reached Intuition.
    successRate: total ? Math.round((forwarded / total) * 1000) / 10 : 0,
    avgMs: durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : 0,
    p50Ms: pct(50),
    p95Ms: pct(95),
    maxMs: durations.length ? durations[durations.length - 1] : 0,
    lastAt: rows[0] ? rows[0].at : null,
    topRules: Object.entries(rulesCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count })),
    riskLevels: Object.entries(riskCount).map(([name, count]) => ({ name, count })),
    // The chart follows the selected range: hourly bars for 24h, daily for 7d/30d.
    timeline: buildTimeline(rows, opts.range),
    timelineUnit: timelineSpec(opts.range).unit
  };
}

/** Bucket geometry for the chart, chosen by the selected time range. Anything
 *  other than 7d/30d (incl. 24h and all-time) falls back to 24 hourly buckets. */
function timelineSpec(range) {
  if (range === '7d') return { n: 7, stepMs: 86400000, unit: 'day' };
  if (range === '30d') return { n: 30, stepMs: 86400000, unit: 'day' };
  return { n: 24, stepMs: 3600000, unit: 'hour' };
}

/** N buckets (hourly or daily), oldest first, for the sparkline. */
function buildTimeline(rows, range) {
  const { n, stepMs } = timelineSpec(range);
  const now = Date.now();
  const buckets = Array.from({ length: n }, (_, i) => ({
    t: new Date(now - (n - 1 - i) * stepMs).toISOString(),
    ok: 0,
    fail: 0
  }));
  for (const r of rows) {
    const age = now - new Date(r.at).getTime();
    if (age < 0 || age >= n * stepMs) continue;
    const idx = n - 1 - Math.floor(age / stepMs);
    if (idx < 0 || idx >= n) continue;
    if (r.result === 'forwarded') buckets[idx].ok++;
    else buckets[idx].fail++;
  }
  return buckets;
}

// ---------------------------------------------------------------------------
// Driver selection. A misconfigured durable store falls back to memory rather
// than crashing the relay: dropping KYC deliveries to protect a debug log would
// be the wrong trade. The dashboard shows which driver is actually live, so the
// fallback is visible rather than silent.
function pick() {
  const { driver, databaseUrl } = config.store;
  try {
    if (driver === 'postgres') {
      if (!databaseUrl) throw new Error('LOG_STORE=postgres but DATABASE_URL is not set');
      return postgresDriver({
        url: databaseUrl,
        table: config.store.table,
        ssl: config.store.pgSsl
      });
    }
    if (driver === 'supabase') {
      if (!config.store.supabaseUrl || !config.store.supabaseKey) {
        throw new Error('LOG_STORE=supabase but SUPABASE_URL / SUPABASE_SERVICE_KEY are not set');
      }
      return supabaseDriver({ url: config.store.supabaseUrl, key: config.store.supabaseKey, table: config.store.table });
    }
    if (driver === 'mongo' || driver === 'mongodb') {
      if (!config.store.mongoUrl) throw new Error('LOG_STORE=mongo but MONGO_URL is not set');
      return mongoDriver({ url: config.store.mongoUrl, collection: config.store.table });
    }
    if (driver === 'elasticsearch' || driver === 'elastic' || driver === 'es') {
      if (!config.store.esNode) throw new Error('LOG_STORE=elasticsearch but ELASTICSEARCH_URL is not set');
      return elasticsearchDriver({
        node: config.store.esNode,
        apiKey: config.store.esApiKey,
        username: config.store.esUsername,
        password: config.store.esPassword,
        index: config.store.table,
        rejectUnauthorized: config.store.esRejectUnauthorized
      });
    }
  } catch (e) {
    console.error(`Delivery log: ${e.message}. Falling back to the in-memory store.`);
  }
  return memoryDriver(config.store.ringSize);
}

const driver = pick();

module.exports = {
  newId,
  driverName: driver.name,
  isDurable: () => driver.durable,
  record: (e) => driver.record(e),
  list: (o) => driver.list(o),
  get: (id) => driver.get(id),
  clear: () => driver.clear(),
  stats: async (opts = {}) => summarise(await driver.all(opts), opts),
  // exported for tests
  _summarise: summarise,
  _memoryDriver: memoryDriver
};
