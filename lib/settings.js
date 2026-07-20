'use strict';
// Runtime-togglable settings, persisted through the delivery-log store so a
// toggle flipped via one serverless instance is honoured by all of them.
// The LOG_PAYLOADS env var is the DEFAULT; the stored value (set from the
// dashboard toggle) overrides it. Cached briefly so the webhook path doesn't
// pay a query per delivery.

const config = require('./config');
const store = require('./store');

const TTL_MS = 5000;
let cache = { value: null, at: 0 };

async function logPayloads() {
  const now = Date.now();
  if (cache.value !== null && now - cache.at < TTL_MS) return cache.value;
  let stored = null;
  try {
    stored = await store.getSetting('logPayloads');
  } catch (e) {
    // A broken settings read must never break a delivery — fall back to env.
    console.error(`settings read failed: ${e.message}`);
  }
  const effective = stored === null || stored === undefined
    ? config.logPayloads
    : stored === 'true';
  cache = { value: effective, at: now };
  return effective;
}

async function setLogPayloads(on) {
  await store.setSetting('logPayloads', on ? 'true' : 'false');
  cache = { value: Boolean(on), at: Date.now() };
  return Boolean(on);
}

// ---- manual acknowledgements ------------------------------------------------
// Session ids the operator has acknowledged from the dashboard. The webhook
// handler answers 200 for these, which is the only thing that stops Uqudo's
// 5-minute retry loop. Stored as JSON through the settings store so every
// serverless instance honours an ack immediately-ish (same short cache).
let ackCache = { value: null, at: 0 };

async function ackedSessions() {
  const now = Date.now();
  if (ackCache.value !== null && now - ackCache.at < TTL_MS) return ackCache.value;
  let list = [];
  try {
    const stored = await store.getSetting('ackedSessions');
    if (stored) list = JSON.parse(stored);
  } catch (e) {
    // A broken read must never break a delivery — treat as "nothing acked".
    console.error(`ack list read failed: ${e.message}`);
  }
  ackCache = { value: list, at: now };
  return list;
}

async function isAcked(verificationId) {
  if (!verificationId) return false;
  return (await ackedSessions()).some((a) => a.id === verificationId);
}

async function ackSession(verificationId) {
  const list = (await ackedSessions()).filter((a) => a.id !== verificationId);
  list.push({ id: verificationId, at: new Date().toISOString() });
  // Retries only live for 2 hours; a capped list is plenty and keeps the row small.
  const pruned = list.slice(-100);
  await store.setSetting('ackedSessions', JSON.stringify(pruned));
  ackCache = { value: pruned, at: Date.now() };
  return pruned;
}

async function unackSession(verificationId) {
  const list = (await ackedSessions()).filter((a) => a.id !== verificationId);
  await store.setSetting('ackedSessions', JSON.stringify(list));
  ackCache = { value: list, at: Date.now() };
  return list;
}

module.exports = {
  logPayloads, setLogPayloads,
  ackedSessions, isAcked, ackSession, unackSession,
  _resetCache: () => { cache = { value: null, at: 0 }; ackCache = { value: null, at: 0 }; }
};
