'use strict';
// Checks for the dashboard's supporting logic: redaction, auth tokens, the
// memory store and stats. No network, no live tenant.
//
// ADMIN_PASSWORD must be set before requiring the modules — config reads env at
// import time.
process.env.ADMIN_PASSWORD = 'test-admin-pw';
process.env.ADMIN_SESSION_SECRET = 'test-session-secret';

const assert = require('assert');
const redact = require('../lib/redact');
const auth = require('../lib/admin-auth');
const store = require('../lib/store');

let passed = 0;
// Await fn: several checks are async, and a harness that ignores the returned
// promise prints "ok" for assertions that never ran.
const checks = [];
const check = (name, fn) => checks.push([name, fn]);
const group = (name) => checks.push([name, null]);

group('redact:');
check('masks names, ID numbers and dates of birth', () => {
  const out = redact.redactDeep({
    fullName: 'ALEX TESTER',
    documentNumber: '784-1999-1234567-8',
    dateOfBirth: '1990-01-01',
    documentType: 'NATIONAL_ID'
  });
  assert.ok(!/ALEX/.test(JSON.stringify(out)), 'name must not survive');
  assert.ok(!/2038768/.test(JSON.stringify(out)), 'id number must not survive');
  assert.ok(!/1990-01-01/.test(JSON.stringify(out)), 'dob must not survive');
  // Non-identifying fields are the whole point of the log — keep them.
  assert.strictEqual(out.documentType, 'NATIONAL_ID');
});
check('masks snake_case keys from the MAPPED document, not just camelCase JWT keys', () => {
  // Regression: the key regex matched `documentNumber` but not `document_number`,
  // so real ID numbers from the mapped Intuition document reached the log.
  const out = redact.redactDeep({
    document_number: '784-1999-1234567-8',
    full_name: 'ALEX TESTER',
    date_of_birth: '1990-01-01',
    identity_number: '784199912345678',
    passport_number: 'P1234567'
  });
  const s = JSON.stringify(out);
  for (const leak of ['784-1999-1234567-8', 'ALEX', '1990-01-01', '784199912345678', 'P1234567']) {
    assert.ok(!s.includes(leak), `${leak} must be masked in snake_case form`);
  }
});
check('keeps customer_number and nationality_risk readable (needed to troubleshoot)', () => {
  const out = redact.redactDeep({ customer_number: 'CUST-1', nationality_risk: 70, nationality_code: 'SDN' });
  assert.strictEqual(out.customer_number, 'CUST-1', 'the key you search BY must stay readable');
  assert.strictEqual(out.nationality_risk, 70, 'a computed risk score is not PII');
});
check('drops image blobs but records that they existed', () => {
  const out = redact.redactDeep({ faceImage: 'A'.repeat(5000), face_image_url: 'B'.repeat(300) });
  assert.match(out.faceImage, /image omitted: 5000 chars/);
  assert.match(out.face_image_url, /image omitted: 300 chars/);
});
check('masking keeps first and last char for eyeball correlation', () => {
  const m = redact.maskValue('ABCDEFGH');
  assert.ok(m.startsWith('A') && m.endsWith('H') && !/BCDEFG/.test(m));
});
check('survives nested structures and cycles-by-depth without throwing', () => {
  let deep = { fullName: 'X' };
  for (let i = 0; i < 30; i++) deep = { nested: deep, fullName: 'LEAK' };
  assert.doesNotThrow(() => redact.redactDeep(deep));
});
check('payload bundle is absent unless explicitly enabled', () => {
  assert.strictEqual(redact.buildPayloadBundle({ enabled: false, kyc: { fullName: 'X' } }), undefined);
  assert.ok(redact.buildPayloadBundle({ enabled: true, kyc: { fullName: 'X' } }).jwt);
});
check('enabled bundle still masks - "full capture" is not a passport copy', () => {
  const b = redact.buildPayloadBundle({ enabled: true, kyc: { fullName: 'ALEX TESTER' } });
  assert.ok(!/ALEX TESTER/.test(JSON.stringify(b)));
});

group('admin-auth:');
check('accepts a freshly issued token', () => assert.ok(auth.valid(auth.issue())));
check('rejects a tampered token', () => {
  const t = auth.issue();
  assert.strictEqual(auth.valid(t.slice(0, -3) + 'xxx'), false);
});
check('rejects an expired token', () => {
  const past = String(Date.now() - 1000);
  const crypto = require('crypto');
  const mac = crypto.createHmac('sha256', 'test-session-secret').update(past).digest('base64url');
  assert.strictEqual(auth.valid(`${past}.${mac}`), false);
});
check('rejects garbage and empty tokens', () => {
  for (const t of ['', null, 'nope', 'a.b.c']) assert.strictEqual(auth.valid(t), false);
});
check('safeEqual is correct across differing lengths', () => {
  assert.strictEqual(auth.safeEqual('abc', 'abc'), true);
  assert.strictEqual(auth.safeEqual('abc', 'abcd'), false);
  assert.strictEqual(auth.safeEqual('abc', 'abd'), false);
});

group('store (memory):');
const mem = store._memoryDriver(3);
check('ring buffer evicts oldest beyond its size', async () => {
  for (const i of [1, 2, 3, 4]) await mem.record({ id: `r${i}`, at: new Date().toISOString(), result: 'forwarded' });
  const { rows, total } = await mem.list({});
  assert.strictEqual(total, 3);
  assert.strictEqual(rows[0].id, 'r4', 'newest first');
  assert.strictEqual(await mem.get('r1'), null, 'oldest evicted');
});
check('memory store filters by time range (since)', async () => {
  const d = store._memoryDriver(10);
  const iso = (ms) => new Date(Date.now() - ms).toISOString();
  await d.record({ id: 'old', at: iso(10 * 24 * 3600e3), result: 'forwarded' });   // 10 days ago
  await d.record({ id: 'mid', at: iso(3 * 24 * 3600e3), result: 'forwarded' });     // 3 days ago
  await d.record({ id: 'new', at: iso(2 * 3600e3), result: 'forwarded' });          // 2 hours ago
  const since24h = iso(24 * 3600e3), since7d = iso(7 * 24 * 3600e3);
  assert.strictEqual((await d.list({ since: since24h })).total, 1, 'only the 2h-old row in last 24h');
  assert.strictEqual((await d.list({ since: since7d })).total, 2, '2h + 3d rows in last 7 days');
  assert.strictEqual((await d.list({})).total, 3, 'no since = all rows');
  // stats path (all) honours since too
  assert.strictEqual((await d.all({ since: since24h })).length, 1);
  assert.strictEqual((await d.all()).length, 3);
});
check('filters by result and free-text search', async () => {
  const d = store._memoryDriver(10);
  await d.record({ id: 'a', at: new Date().toISOString(), result: 'forwarded', customer_number: 'CUST-1' });
  await d.record({ id: 'b', at: new Date().toISOString(), result: 'rejected', reason: 'inbound auth failed' });
  assert.strictEqual((await d.list({ result: 'rejected' })).total, 1);
  assert.strictEqual((await d.list({ q: 'CUST-1' })).rows[0].id, 'a');
  assert.strictEqual((await d.list({ q: 'inbound' })).rows[0].id, 'b');
});

group('settings (runtime payload-capture toggle):');
check('defaults to the LOG_PAYLOADS env value when nothing stored', async () => {
  const settings = require('../lib/settings');
  settings._resetCache();
  assert.strictEqual(await settings.logPayloads(), false, 'env default is off in tests');
});
check('toggle overrides the env default and persists through the store', async () => {
  const settings = require('../lib/settings');
  assert.strictEqual(await settings.setLogPayloads(true), true);
  settings._resetCache();                    // force a re-read from the store
  assert.strictEqual(await settings.logPayloads(), true, 'stored value wins');
  await settings.setLogPayloads(false);
  settings._resetCache();
  assert.strictEqual(await settings.logPayloads(), false);
});

group('manual acknowledgements:');
check('ack, list, isAcked and undo round-trip through the store', async () => {
  const settings = require('../lib/settings');
  await settings.ackSession('vid-ack-1');
  settings._resetCache();                    // force a re-read from the store
  assert.strictEqual(await settings.isAcked('vid-ack-1'), true, 'acked id must be found after re-read');
  assert.strictEqual(await settings.isAcked('vid-other'), false, 'other ids stay un-acked');
  const list = await settings.ackedSessions();
  assert.ok(list.some((a) => a.id === 'vid-ack-1' && a.at), 'list entry carries a timestamp');
  await settings.unackSession('vid-ack-1');
  settings._resetCache();
  assert.strictEqual(await settings.isAcked('vid-ack-1'), false, 'undo must remove the ack');
});
check('acking twice does not duplicate; list is capped at 100', async () => {
  const settings = require('../lib/settings');
  await settings.ackSession('vid-dup');
  await settings.ackSession('vid-dup');
  assert.strictEqual((await settings.ackedSessions()).filter((a) => a.id === 'vid-dup').length, 1);
  for (let i = 0; i < 120; i++) await settings.ackSession(`vid-bulk-${i}`);
  assert.ok((await settings.ackedSessions()).length <= 100, 'cap must hold');
  await settings.unackSession('vid-dup');
});

group('stats:');
check('counts, success rate and percentiles', () => {
  const now = new Date().toISOString();
  const s = store._summarise([
    { at: now, result: 'forwarded', durationMs: 100, riskLevel: 'Suspicious', rulesTriggered: ['UQ_DA_R2 ', 'DA_RS '] },
    { at: now, result: 'forwarded', durationMs: 200, riskLevel: 'Clean', rulesTriggered: ['UQ_DA_R2'] },
    { at: now, result: 'rejected', durationMs: 5 }
  ]);
  assert.strictEqual(s.total, 3);
  assert.strictEqual(s.forwarded, 2);
  assert.strictEqual(s.failed, 1);
  assert.strictEqual(s.successRate, 66.7);
  assert.strictEqual(s.avgMs, 102);
  // Rule names arrive space-padded from Intuition; they must fold together.
  assert.strictEqual(s.topRules[0].name, 'UQ_DA_R2');
  assert.strictEqual(s.topRules[0].count, 2);
});
check('timeline granularity follows the range (hourly 24h, daily 7d/30d)', () => {
  const rows = [{ at: new Date().toISOString(), result: 'forwarded' }];
  assert.strictEqual(store._summarise(rows).timeline.length, 24, 'default = 24 hourly');
  assert.strictEqual(store._summarise(rows).timelineUnit, 'hour');
  assert.strictEqual(store._summarise(rows, { range: '24h' }).timeline.length, 24);
  assert.strictEqual(store._summarise(rows, { range: '7d' }).timeline.length, 7, '7 daily buckets');
  assert.strictEqual(store._summarise(rows, { range: '7d' }).timelineUnit, 'day');
  assert.strictEqual(store._summarise(rows, { range: '30d' }).timeline.length, 30, '30 daily buckets');
});
check('a 3-day-old delivery lands in the 7d chart but not the 24h chart', () => {
  const rows = [{ at: new Date(Date.now() - 3 * 24 * 3600e3).toISOString(), result: 'forwarded' }];
  const in24h = store._summarise(rows, { range: '24h' }).timeline.reduce((a, b) => a + b.ok + b.fail, 0);
  const in7d  = store._summarise(rows, { range: '7d'  }).timeline.reduce((a, b) => a + b.ok + b.fail, 0);
  assert.strictEqual(in24h, 0, 'too old for the 24h chart');
  assert.strictEqual(in7d, 1, 'visible in the 7d chart');
});
check('empty log does not divide by zero', () => {
  const s = store._summarise([]);
  assert.strictEqual(s.total, 0);
  assert.strictEqual(s.successRate, 0);
  assert.strictEqual(s.avgMs, 0);
  assert.strictEqual(s.timeline.length, 24);
});
check('timeline buckets recent deliveries and ignores stale ones', () => {
  const s = store._summarise([
    { at: new Date().toISOString(), result: 'forwarded' },
    { at: new Date(Date.now() - 48 * 3600e3).toISOString(), result: 'forwarded' }
  ]);
  assert.strictEqual(s.timeline[23].ok, 1, 'now lands in the last bucket');
  assert.strictEqual(s.timeline.reduce((a, b) => a + b.ok + b.fail, 0), 1, '48h-old row excluded');
});

(async () => {
  let failed = 0;
  for (const [name, fn] of checks) {
    if (!fn) { console.log(name); continue; }
    try { await fn(); console.log(`  ok  ${name}`); passed++; }
    catch (e) { console.error(`  FAIL  ${name}\n        ${e.message}`); failed++; }
  }
  console.log(`\n${passed} checks passed${failed ? `, ${failed} FAILED` : ''}`);
  if (failed) process.exit(1);
})();
