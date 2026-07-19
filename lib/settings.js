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

module.exports = { logPayloads, setLogPayloads, _resetCache: () => { cache = { value: null, at: 0 }; } };
