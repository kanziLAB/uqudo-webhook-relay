'use strict';
// Inbound auth checks against a REAL running server on a random port.
// No network to Intuition: every request here is rejected at the auth layer
// before any forward happens.
process.env.WEBHOOK_URL_TOKEN = 'tok_correct_value_123';
process.env.WEBHOOK_AUTH_VALUE = 'hdr_secret_456';
process.env.WEBHOOK_AUTH_HEADER = 'x-api-key';
process.env.ADMIN_PASSWORD = 'pw';
// server.js binds a port on import unless it thinks it is serverless; set this
// so it just exports the app and the test owns the listener.
process.env.VERCEL = '1';

const assert = require('assert');
const app = require('../server');

const BASE = 'http://127.0.0.1:8199';
const post = (path, headers = {}) =>
  fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    // No jwsResult: an authorised request stops at 400 "missing jwsResult",
    // which is exactly how we tell "auth passed" from "auth rejected" (401)
    // without ever touching Intuition.
    body: JSON.stringify({})
  });

const checks = [];
const check = (name, fn) => checks.push([name, fn]);

check('capability URL: correct token authenticates (passes auth, stops at 400)', async () => {
  const r = await post('/api/uqudo-webhook/tok_correct_value_123');
  assert.strictEqual(r.status, 400, 'should pass auth and fail on the missing body');
});
check('capability URL: wrong token is rejected', async () => {
  assert.strictEqual((await post('/api/uqudo-webhook/wrong_token')).status, 401);
});
check('capability URL: near-miss token is rejected', async () => {
  assert.strictEqual((await post('/api/uqudo-webhook/tok_correct_value_12')).status, 401);
  assert.strictEqual((await post('/api/uqudo-webhook/tok_correct_value_1234')).status, 401);
});
check('capability URL: empty token segment does not authenticate', async () => {
  // /api/uqudo-webhook/ normalises to the tokenless route, so the header rules
  // apply — and with no header it must be rejected.
  assert.strictEqual((await post('/api/uqudo-webhook/')).status, 401);
});
check('a WRONG url token must NOT fall through to the header check', async () => {
  // The dangerous bug: if a bad token silently fell back to header auth, a
  // caller could bypass the path token entirely by sending the header.
  const r = await post('/api/uqudo-webhook/bogus', { 'x-api-key': 'hdr_secret_456' });
  assert.strictEqual(r.status, 401, 'bad token must be final, even with a valid header');
});
check('header auth still works on the tokenless route', async () => {
  assert.strictEqual((await post('/api/uqudo-webhook', { 'x-api-key': 'hdr_secret_456' })).status, 400);
});
check('tokenless route rejects a missing header', async () => {
  assert.strictEqual((await post('/api/uqudo-webhook')).status, 401);
});
check('tokenless route rejects a wrong header', async () => {
  assert.strictEqual((await post('/api/uqudo-webhook', { 'x-api-key': 'nope' })).status, 401);
});
check('the url token must never appear in the delivery log', async () => {
  await post('/api/uqudo-webhook/tok_correct_value_123');
  const store = require('../lib/store');
  const { rows } = await store.list({ limit: 20 });
  const dump = JSON.stringify(rows);
  assert.ok(!dump.includes('tok_correct_value_123'), 'secret path token leaked into the log');
  assert.ok(rows.some((r) => r.authVia === 'url-token'), 'auth method should be recorded');
});

(async () => {
  const server = app.listen(8199);
  let passed = 0, failed = 0;
  console.log('inbound auth:');
  for (const [name, fn] of checks) {
    try { await fn(); console.log(`  ok  ${name}`); passed++; }
    catch (e) { console.error(`  FAIL  ${name}\n        ${e.message}`); failed++; }
  }
  server.close();
  console.log(`\n${passed} checks passed${failed ? `, ${failed} FAILED` : ''}`);
  process.exit(failed ? 1 : 0);
})();
