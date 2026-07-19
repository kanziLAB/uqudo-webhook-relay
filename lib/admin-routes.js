'use strict';
// Admin dashboard API. Mounted at /api/admin by server.js.

const express = require('express');
const path = require('path');
const config = require('./config');
const store = require('./store');
const auth = require('./admin-auth');
const settings = require('./settings');
const intuition = require('./intuition');

const router = express.Router();

// ---- login / logout ---------------------------------------------------------
// Not behind requireAdmin, for obvious reasons.
router.post('/login', (req, res) => {
  if (!auth.enabled()) {
    return res.status(503).json({ error: 'Admin dashboard is disabled. Set ADMIN_PASSWORD to enable it.' });
  }
  const supplied = (req.body && req.body.password) || '';
  if (!auth.safeEqual(supplied, config.admin.password)) {
    return res.status(401).json({ error: 'Incorrect password' });
  }
  auth.setCookie(res, req);
  res.json({ ok: true });
});

router.post('/logout', (req, res) => {
  auth.clearCookie(res);
  res.json({ ok: true });
});

/** Lets the UI decide between login screen and dashboard without a 401 flash. */
router.get('/session', (req, res) => {
  res.json({ enabled: auth.enabled(), authed: auth.isAuthed(req) });
});

// ---- everything below requires a valid session -------------------------------
router.use(requireAdminExceptPublic);
function requireAdminExceptPublic(req, res, next) {
  return auth.requireAdmin(req, res, next);
}

/** Config + environment panel. Never returns secret VALUES, only whether set. */
router.get('/config', async (req, res) => {
  res.json({
    target: intuition.documentsUrl(),
    tenantId: config.intuition.tenantId,
    datasetId: config.intuition.datasetId,
    runStrategy: config.intuition.runStrategy,
    clientName: config.clientName,
    jwsVerification: config.uqudo.publicKey
      ? 'enabled'
      : config.uqudo.allowUnverified
        ? 'DISABLED (ALLOW_UNVERIFIED)'
        : 'not configured - posts rejected',
    inboundAuth: Boolean(config.inbound.headerValue || config.inbound.basicUser),
    inboundHeader: config.inbound.headerName,
    logStore: store.driverName,
    logDurable: store.isDurable(),
    logPayloads: await settings.logPayloads(),
    logPayloadsDefault: config.logPayloads,
    ringSize: config.store.ringSize,
    runtime: process.env.VERCEL ? 'vercel' : 'self-hosted',
    node: process.version
  });
});

// Time-range filter. The client sends a coarse range keyword; the server turns
// it into an absolute cutoff so both list and stats agree and client-clock skew
// can't matter. Anything unknown (incl. 'all') => no cutoff.
const RANGE_MS = { '24h': 24 * 3600e3, '7d': 7 * 24 * 3600e3, '30d': 30 * 24 * 3600e3 };
const rangeToSince = (range) =>
  RANGE_MS[range] ? new Date(Date.now() - RANGE_MS[range]).toISOString() : undefined;

router.get('/stats', async (req, res, next) => {
  try {
    // `since` scopes the data; `range` also drives the chart's bucket granularity.
    res.json(await store.stats({ since: rangeToSince(req.query.range), range: req.query.range }));
  } catch (e) {
    next(e);
  }
});

router.get('/deliveries', async (req, res, next) => {
  try {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
    const offset = Math.max(0, Number(req.query.offset) || 0);
    const { result, q } = req.query;
    res.json(await store.list({
      limit, offset,
      result: result || undefined,
      q: q || undefined,
      since: rangeToSince(req.query.range)
    }));
  } catch (e) {
    next(e);
  }
});

router.get('/deliveries/:id', async (req, res, next) => {
  try {
    const row = await store.get(req.params.id);
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json(row);
  } catch (e) {
    next(e);
  }
});

router.delete('/deliveries', async (req, res, next) => {
  try {
    const n = await store.clear();
    res.json({ ok: true, cleared: n });
  } catch (e) {
    next(e);
  }
});

/** Runtime settings — currently just the payload-capture toggle. */
router.get('/settings', async (req, res, next) => {
  try {
    res.json({ logPayloads: await settings.logPayloads() });
  } catch (e) { next(e); }
});
router.post('/settings', async (req, res, next) => {
  try {
    if (typeof (req.body || {}).logPayloads !== 'boolean') {
      return res.status(400).json({ error: 'logPayloads must be a boolean' });
    }
    const v = await settings.setLogPayloads(req.body.logPayloads);
    res.json({ ok: true, logPayloads: v });
  } catch (e) { next(e); }
});

/** Connectivity probe. Strictly READ-ONLY: a GET against the documents URL.
 *  It must never POST — a "ping" that pollutes Uqudo_KYC_Data with junk records
 *  would be a nasty surprise. Any HTTP answer (405/404 included) proves DNS,
 *  TLS and Cloudflare are fine, which is what we actually want to know. */
router.get('/ping-intuition', async (req, res) => {
  const started = Date.now();
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10000);
  try {
    const r = await fetch(intuition.documentsUrl(), {
      method: 'GET',
      headers: { 'User-Agent': intuition.BROWSER_UA, Accept: 'application/json' },
      signal: ctrl.signal
    });
    res.json({
      reachable: true,
      status: r.status,
      durationMs: Date.now() - started,
      note: 'Read-only probe: any HTTP response means the host and tenant route are reachable.'
    });
  } catch (e) {
    res.json({ reachable: false, error: e.message, durationMs: Date.now() - started });
  } finally {
    clearTimeout(t);
  }
});

module.exports = router;
module.exports.adminPagePath = path.join(__dirname, '..', 'public', 'admin.html');
