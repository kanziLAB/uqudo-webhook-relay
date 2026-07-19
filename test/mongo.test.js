'use strict';
// Runs against a REAL MongoDB. Skips (exit 0) when none is reachable, so
// `npm test` still passes on a machine without Docker.
//
//   docker run --rm -d --name relay-mongo-test -p 57017:27017 mongo:7
//   MONGO_URL=mongodb://127.0.0.1:57017/relaytest node test/mongo.test.js

process.env.LOG_STORE = 'mongo';
process.env.MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:57017/relaytest';
process.env.LOG_TABLE = 'webhook_deliveries_test';

const assert = require('assert');
const checks = [];
const check = (name, fn) => checks.push([name, fn]);
const row = (over = {}) => ({ id: Math.random().toString(16).slice(2, 14), at: new Date().toISOString(), result: 'forwarded', verified: true, ...over });
let store;

check('first write works with no manual setup (auto-creates indexes)', async () => {
  await store.record(row({ id: 'm-1', customer_number: 'CUST-1', riskLevel: 'Suspicious', totalRulesScore: 140, rulesTriggered: ['UQ_DA_R2'] }));
  const { rows, total } = await store.list({});
  assert.strictEqual(total, 1);
  assert.strictEqual(rows[0].customer_number, 'CUST-1');
  assert.strictEqual(rows[0]._id, undefined, 'internal _id must be stripped from results');
});
check('round-trips the full detail object', async () => {
  const r = (await store.list({})).rows[0];
  assert.strictEqual(r.riskLevel, 'Suspicious');
  assert.deepStrictEqual(r.rulesTriggered, ['UQ_DA_R2']);
});
check('orders newest first', async () => {
  await store.record(row({ id: 'm-2', at: new Date(Date.now() + 1000).toISOString(), customer_number: 'CUST-2' }));
  assert.strictEqual((await store.list({})).rows[0].id, 'm-2');
});
check('filters by result', async () => {
  await store.record(row({ id: 'm-3', result: 'rejected', reason: 'inbound auth failed' }));
  const { rows, total } = await store.list({ result: 'rejected' });
  assert.strictEqual(total, 1);
  assert.strictEqual(rows[0].id, 'm-3');
});
check('free-text search hits customer and reason', async () => {
  assert.strictEqual((await store.list({ q: 'CUST-2' })).total, 1);
  assert.strictEqual((await store.list({ q: 'inbound' })).total, 1);
});
check('search input is treated as a literal, not a regex/operator', async () => {
  const r = await store.list({ q: '.*|(){' });   // regex metachars — must be escaped, match nothing
  assert.strictEqual(r.total, 0);
  assert.strictEqual((await store.list({})).total, 3, 'collection intact');
});
check('paginates with a correct total', async () => {
  const p = await store.list({ limit: 2, offset: 0 });
  assert.strictEqual(p.rows.length, 2);
  assert.strictEqual(p.total, 3);
  assert.strictEqual((await store.list({ limit: 2, offset: 2 })).rows.length, 1);
});
check('get() by id, misses return null', async () => {
  assert.strictEqual((await store.get('m-1')).customer_number, 'CUST-1');
  assert.strictEqual(await store.get('nope'), null);
});
check('re-delivery of the same id does not duplicate (webhook retry)', async () => {
  await store.record(row({ id: 'm-1', customer_number: 'DIFFERENT' }));
  assert.strictEqual((await store.list({})).total, 3, 'duplicate _id ignored');
});
check('stats aggregate over real docs', async () => {
  const s = await store.stats();
  assert.strictEqual(s.total, 3);
  assert.strictEqual(s.forwarded, 2);
  assert.strictEqual(s.failed, 1);
  assert.strictEqual(s.topRules[0].name, 'UQ_DA_R2');
});
check('survives a reconnect — data is in Mongo, not RAM', async () => {
  delete require.cache[require.resolve('../lib/store')];
  delete require.cache[require.resolve('../lib/config')];
  const fresh = require('../lib/store');
  assert.strictEqual(fresh.driverName, 'mongo');
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
check('clear() empties the collection', async () => {
  assert.strictEqual(await store.clear(), 3);
  assert.strictEqual((await store.list({})).total, 0);
});

(async () => {
  const { MongoClient } = require('mongodb');
  const probe = new MongoClient(process.env.MONGO_URL, { serverSelectionTimeoutMS: 2500 });
  try {
    await probe.connect();
    await probe.db().collection(process.env.LOG_TABLE).drop().catch(() => {});
    await probe.close();
  } catch (e) {
    console.log(`mongo: SKIPPED (no database at ${process.env.MONGO_URL.replace(/\/\/[^@]*@/, '//***@')})`);
    console.log(`       ${e.message}`);
    process.exit(0);
  }
  store = require('../lib/store');
  console.log('mongodb (real database):');
  let passed = 0, failed = 0;
  for (const [name, fn] of checks) {
    try { await fn(); console.log(`  ok  ${name}`); passed++; }
    catch (e) { console.error(`  FAIL  ${name}\n        ${e.message}`); failed++; }
  }
  console.log(`\n${passed} checks passed${failed ? `, ${failed} FAILED` : ''}`);
  await store.close?.();
  process.exit(failed ? 1 : 0);
})();
