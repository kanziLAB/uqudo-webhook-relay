'use strict';
// Runs against a REAL Postgres, not a mock — the whole point of this driver is
// SQL behaviour, which a mock cannot tell you anything about.
//
//   docker run -d --name relay-pg-test -e POSTGRES_PASSWORD=relay \
//     -e POSTGRES_USER=relay -e POSTGRES_DB=relay -p 55432:5432 postgres:16-alpine
//   node test/postgres.test.js
//
// Skips (exit 0) when no database is reachable, so `npm test` still passes on a
// machine without Docker.

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgres://relay:relay@127.0.0.1:55432/relay';
process.env.PG_SSL = 'false';
process.env.LOG_STORE = 'postgres';
process.env.LOG_TABLE = 'webhook_deliveries_test';

const assert = require('assert');

const checks = [];
const check = (name, fn) => checks.push([name, fn]);

const row = (over = {}) => ({
  id: Math.random().toString(16).slice(2, 14),
  at: new Date().toISOString(),
  result: 'forwarded',
  verified: true,
  ...over
});

let store;

check('auto-migrates: first write creates the table with no manual SQL', async () => {
  await store.record(row({ id: 'pg-1', customer_number: 'CUST-1', riskLevel: 'Suspicious', totalRulesScore: 140, durationMs: 120, rulesTriggered: ['UQ_DA_R2'], authVia: 'url-token' }));
  const { rows, total } = await store.list({});
  assert.strictEqual(total, 1);
  assert.strictEqual(rows[0].customer_number, 'CUST-1');
});
check('round-trips the full detail object, not just the columns', async () => {
  const r = (await store.list({}))?.rows[0];
  assert.strictEqual(r.riskLevel, 'Suspicious');
  assert.strictEqual(r.totalRulesScore, 140);
  assert.deepStrictEqual(r.rulesTriggered, ['UQ_DA_R2']);
  assert.strictEqual(r.authVia, 'url-token');
});
check('orders newest first', async () => {
  await store.record(row({ id: 'pg-2', at: new Date(Date.now() + 1000).toISOString(), customer_number: 'CUST-2' }));
  const { rows } = await store.list({});
  assert.strictEqual(rows[0].id, 'pg-2');
});
check('filters by result', async () => {
  await store.record(row({ id: 'pg-3', result: 'rejected', reason: 'inbound auth failed' }));
  const { rows, total } = await store.list({ result: 'rejected' });
  assert.strictEqual(total, 1);
  assert.strictEqual(rows[0].id, 'pg-3');
});
check('free-text search hits customer, verification id and reason', async () => {
  assert.strictEqual((await store.list({ q: 'CUST-2' })).total, 1);
  assert.strictEqual((await store.list({ q: 'inbound' })).total, 1);
});
check('search is injection-safe', async () => {
  // If this were interpolated the table would be gone and the next check fails.
  const r = await store.list({ q: "'; DROP TABLE webhook_deliveries_test; --" });
  assert.strictEqual(r.total, 0);
  assert.strictEqual((await store.list({})).total, 3, 'table must still exist');
});
check('paginates with a correct total', async () => {
  const p = await store.list({ limit: 2, offset: 0 });
  assert.strictEqual(p.rows.length, 2);
  assert.strictEqual(p.total, 3, 'total is the full count, not the page size');
  assert.strictEqual((await store.list({ limit: 2, offset: 2 })).rows.length, 1);
});
check('get() fetches one by id, and misses return null', async () => {
  assert.strictEqual((await store.get('pg-1')).customer_number, 'CUST-1');
  assert.strictEqual(await store.get('nope'), null);
});
check('re-delivery of the same id does not duplicate (webhooks retry)', async () => {
  await store.record(row({ id: 'pg-1', customer_number: 'DIFFERENT' }));
  assert.strictEqual((await store.list({})).total, 3, 'ON CONFLICT DO NOTHING');
});
check('stats aggregate over real rows', async () => {
  const s = await store.stats();
  assert.strictEqual(s.total, 3);
  assert.strictEqual(s.forwarded, 2);
  assert.strictEqual(s.failed, 1);
  assert.strictEqual(s.topRules[0].name, 'UQ_DA_R2');
});
check('survives a reconnect — this is the whole point vs the memory store', async () => {
  // Drop every pooled connection and prove the data is in Postgres, not in RAM.
  delete require.cache[require.resolve('../lib/store')];
  delete require.cache[require.resolve('../lib/config')];
  const fresh = require('../lib/store');
  assert.strictEqual(fresh.driverName, 'postgres');
  assert.strictEqual(fresh.isDurable(), true);
  const { total } = await fresh.list({});
  assert.strictEqual(total, 3, 'a brand new process must see the earlier rows');
});
check('filters by time range (since) in SQL', async () => {
  await store.clear();
  const iso = (ms) => new Date(Date.now() - ms).toISOString();
  await store.record({ id: 't-old', at: iso(10 * 24 * 3600e3), result: 'forwarded' });
  await store.record({ id: 't-mid', at: iso(3 * 24 * 3600e3), result: 'forwarded' });
  await store.record({ id: 't-new', at: iso(2 * 3600e3), result: 'forwarded', riskLevel: 'Suspicious' });
  assert.strictEqual((await store.list({ since: iso(24 * 3600e3) })).total, 1, 'last 24h');
  assert.strictEqual((await store.list({ since: iso(7 * 24 * 3600e3) })).total, 2, 'last 7d');
  assert.strictEqual((await store.list({})).total, 3, 'no since = all');
  // stats honours since through all()
  assert.strictEqual((await store.stats({ since: iso(24 * 3600e3) })).total, 1);
  assert.strictEqual((await store.stats()).total, 3);
});
check('settings round-trip in SQL (shared across instances)', async () => {
  assert.strictEqual(await store.getSetting('logPayloads'), null, 'unset -> null');
  await store.setSetting('logPayloads', 'true');
  assert.strictEqual(await store.getSetting('logPayloads'), 'true');
  await store.setSetting('logPayloads', 'false');   // upsert, not duplicate
  assert.strictEqual(await store.getSetting('logPayloads'), 'false');
});
check('clear() empties the log', async () => {
  const n = await store.clear();
  assert.strictEqual(n, 3);
  assert.strictEqual((await store.list({})).total, 0);
});

(async () => {
  // Probe first so a machine with no Docker skips rather than fails.
  const { Client } = require('pg');
  const probe = new Client({ connectionString: process.env.DATABASE_URL });
  try {
    await probe.connect();
    await probe.query(`DROP TABLE IF EXISTS ${process.env.LOG_TABLE}`);
    await probe.end();
  } catch (e) {
    console.log(`postgres: SKIPPED (no database at ${process.env.DATABASE_URL.replace(/:[^:@]+@/, ':***@')})`);
    console.log(`          ${e.message}`);
    process.exit(0);
  }

  store = require('../lib/store');
  console.log('postgres (real database):');
  let passed = 0, failed = 0;
  for (const [name, fn] of checks) {
    try { await fn(); console.log(`  ok  ${name}`); passed++; }
    catch (e) { console.error(`  FAIL  ${name}\n        ${e.message}`); failed++; }
  }
  console.log(`\n${passed} checks passed${failed ? `, ${failed} FAILED` : ''}`);
  await store.close?.();
  process.exit(failed ? 1 : 0);
})();
