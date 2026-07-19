'use strict';
// Runs against a REAL Elasticsearch. Skips (exit 0) when none is reachable.
//
//   docker run --rm -d --name relay-es-test -p 59200:9200 \
//     -e discovery.type=single-node -e xpack.security.enabled=false \
//     -e ES_JAVA_OPTS='-Xms512m -Xmx512m' \
//     docker.elastic.co/elasticsearch/elasticsearch:8.15.0
//   ELASTICSEARCH_URL=http://127.0.0.1:59200 node test/elasticsearch.test.js

process.env.LOG_STORE = 'elasticsearch';
process.env.ELASTICSEARCH_URL = process.env.ELASTICSEARCH_URL || 'http://127.0.0.1:59200';
process.env.LOG_TABLE = 'webhook_deliveries_test';

const assert = require('assert');
const checks = [];
const check = (name, fn) => checks.push([name, fn]);
const row = (over = {}) => ({ id: Math.random().toString(16).slice(2, 14), at: new Date().toISOString(), result: 'forwarded', verified: true, ...over });
let store;

check('first write works with no manual index setup', async () => {
  await store.record(row({ id: 'e-1', customer_number: 'CUST-1', riskLevel: 'Suspicious', totalRulesScore: 140, rulesTriggered: ['UQ_DA_R2'] }));
  const { rows, total } = await store.list({});
  assert.strictEqual(total, 1);
  assert.strictEqual(rows[0].customer_number, 'CUST-1');
});
check('round-trips the full source document', async () => {
  const r = (await store.list({})).rows[0];
  assert.strictEqual(r.riskLevel, 'Suspicious');
  assert.deepStrictEqual(r.rulesTriggered, ['UQ_DA_R2']);
});
check('orders newest first', async () => {
  await store.record(row({ id: 'e-2', at: new Date(Date.now() + 1000).toISOString(), customer_number: 'CUST-2' }));
  assert.strictEqual((await store.list({})).rows[0].id, 'e-2');
});
check('filters by result (keyword term)', async () => {
  await store.record(row({ id: 'e-3', result: 'rejected', reason: 'inbound auth failed' }));
  const { rows, total } = await store.list({ result: 'rejected' });
  assert.strictEqual(total, 1);
  assert.strictEqual(rows[0].id, 'e-3');
});
check('free-text search hits customer and reason', async () => {
  assert.strictEqual((await store.list({ q: 'CUST-2' })).total, 1);
  assert.strictEqual((await store.list({ q: 'inbound' })).total, 1);
});
check('search input is a structured value, not an injected query', async () => {
  const r = await store.list({ q: 'DROP */ OR 1=1' });
  assert.strictEqual(r.total, 0);
  assert.strictEqual((await store.list({})).total, 3, 'index intact');
});
check('paginates with a correct total', async () => {
  const p = await store.list({ limit: 2, offset: 0 });
  assert.strictEqual(p.rows.length, 2);
  assert.strictEqual(p.total, 3);
  assert.strictEqual((await store.list({ limit: 2, offset: 2 })).rows.length, 1);
});
check('get() by id, misses return null', async () => {
  assert.strictEqual((await store.get('e-1')).customer_number, 'CUST-1');
  assert.strictEqual(await store.get('nope'), null);
});
check('re-delivery of the same id does not duplicate (op_type create)', async () => {
  await store.record(row({ id: 'e-1', customer_number: 'DIFFERENT' }));
  assert.strictEqual((await store.list({})).total, 3);
});
check('stats aggregate over real docs', async () => {
  const s = await store.stats();
  assert.strictEqual(s.total, 3);
  assert.strictEqual(s.forwarded, 2);
  assert.strictEqual(s.failed, 1);
  assert.strictEqual(s.topRules[0].name, 'UQ_DA_R2');
});
check('survives a reconnect — data is in Elasticsearch, not RAM', async () => {
  delete require.cache[require.resolve('../lib/store')];
  delete require.cache[require.resolve('../lib/config')];
  const fresh = require('../lib/store');
  assert.strictEqual(fresh.driverName, 'elasticsearch');
  assert.strictEqual(fresh.isDurable(), true);
  assert.strictEqual((await fresh.list({})).total, 3);
});
check('filters by time range (since)', async () => {
  await store.clear();
  const iso = (ms) => new Date(Date.now() - ms).toISOString();
  await store.record(row({ id: 't-old', at: iso(10 * 24 * 3600e3) }));
  await store.record(row({ id: 't-mid', at: iso(3 * 24 * 3600e3) }));
  await store.record(row({ id: 't-new', at: iso(2 * 3600e3) }));
  assert.strictEqual((await store.list({ since: iso(24 * 3600e3) })).total, 1);
  assert.strictEqual((await store.list({ since: iso(7 * 24 * 3600e3) })).total, 2);
  assert.strictEqual((await store.stats({ since: iso(24 * 3600e3) })).total, 1);
});
check('clear() empties the index', async () => {
  assert.strictEqual(await store.clear(), 3);
  assert.strictEqual((await store.list({})).total, 0);
});

(async () => {
  const { Client } = require('@elastic/elasticsearch');
  const probe = new Client({ node: process.env.ELASTICSEARCH_URL, requestTimeout: 3000, tls: { rejectUnauthorized: false } });
  try {
    await probe.ping();
    await probe.indices.delete({ index: process.env.LOG_TABLE }).catch(() => {});
    await probe.close();
  } catch (e) {
    console.log(`elasticsearch: SKIPPED (no cluster at ${process.env.ELASTICSEARCH_URL})`);
    console.log(`               ${e.message}`);
    process.exit(0);
  }
  store = require('../lib/store');
  console.log('elasticsearch (real cluster):');
  let passed = 0, failed = 0;
  for (const [name, fn] of checks) {
    try { await fn(); console.log(`  ok  ${name}`); passed++; }
    catch (e) { console.error(`  FAIL  ${name}\n        ${e.message}`); failed++; }
  }
  console.log(`\n${passed} checks passed${failed ? `, ${failed} FAILED` : ''}`);
  await store.close?.();
  process.exit(failed ? 1 : 0);
})();
