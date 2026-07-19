'use strict';
// Uqudo -> Intuition webhook relay.
//
// Uqudo's portal webhook POSTs {"jwsResult": "<signed JWT>"} for every completed
// onboarding session. Intuition's Data API wants a document matching the
// Uqudo_KYC_Data schema. This service bridges the two: verify -> decode -> map
// -> forward.
//
// Runs three ways from one file:
//   node server.js          (self-hosted / container)
//   docker compose up       (see Dockerfile)
//   Vercel                  (api/index.js re-exports the app)

const express = require('express');
const helmet = require('helmet');
const config = require('./lib/config');
const jws = require('./lib/jws');
const mapper = require('./lib/mapper');
const intuition = require('./lib/intuition');
const store = require('./lib/store');
const redact = require('./lib/redact');
const adminRoutes = require('./lib/admin-routes');
const adminAuth = require('./lib/admin-auth');
const enrich = require('./lib/enrich');

const app = express();
app.disable('x-powered-by');
// The dashboard is a self-contained page with inline styles/scripts; allow those
// and nothing else. No CDNs, no external origins.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
// Uqudo posts a small JSON body; the JWT can be sizeable with images inline.
app.use(express.json({ limit: '5mb' }));

// ---- delivery log ------------------------------------------------------------
// Persisted through lib/store (memory by default, supabase when configured).
// A logging failure must never fail the webhook — Uqudo would retry a delivery
// that actually succeeded, so we swallow and warn.
async function record(entry) {
  const row = { id: store.newId(), at: new Date().toISOString(), ...entry };
  try {
    await store.record(row);
  } catch (e) {
    console.error(`delivery log write failed (${store.driverName}): ${e.message}`);
  }
  return row;
}

const clientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || '';

// ---- inbound auth -----------------------------------------------------------
// Mirrors the portal's webhook auth options (Custom Headers / Basic), plus a
// capability URL for senders that can only be handed a URL.
function authorised(req) {
  const { headerName, headerValue, basicUser, basicPass, urlToken } = config.inbound;

  // Capability URL. Posting to /api/uqudo-webhook/<token> authenticates on the
  // path alone, so the portal's auth mode can stay "None". Sufficient by itself:
  // proving you know the token is the whole point, so we don't also demand the
  // header. Timing-safe, and a wrong/absent token is rejected outright rather
  // than falling through to the header check.
  if (req.params && req.params.token !== undefined) {
    return Boolean(urlToken) && adminAuth.safeEqual(req.params.token, urlToken);
  }

  if (headerValue) {
    const got = req.headers[headerName];
    if (!got || !adminAuth.safeEqual(String(got), headerValue)) return false;
  }
  if (basicUser || basicPass) {
    const h = req.headers.authorization || '';
    if (!/^Basic /i.test(h)) return false;
    const [u, p] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
    if (!adminAuth.safeEqual(u || '', basicUser) || !adminAuth.safeEqual(p || '', basicPass)) return false;
  }
  return true;
}

const secured = () =>
  Boolean(config.inbound.headerValue || config.inbound.basicUser || config.inbound.basicPass || config.inbound.urlToken);

// ---- routes -----------------------------------------------------------------
app.get('/healthz', async (req, res) => {
  let logged = null;
  try {
    logged = (await store.list({ limit: 1 })).total;
  } catch { /* a broken log store must not fail the health probe */ }
  res.json({
    ok: true,
    target: intuition.documentsUrl(),
    jwsVerification: config.uqudo.publicKey ? 'enabled' : (config.uqudo.allowUnverified ? 'DISABLED (ALLOW_UNVERIFIED)' : 'no key configured - requests will be rejected'),
    infoApiEnrichment: enrich.enabled() ? 'enabled' : 'disabled (no UQUDO_CLIENT_ID/SECRET) - FD_* detection rules cannot fire',
    inboundAuth: secured() ? 'enabled' : 'open (no shared secret configured)',
    admin: adminAuth.enabled() ? 'enabled' : 'disabled (no ADMIN_PASSWORD)',
    logStore: store.driverName,
    logDurable: store.isDurable(),
    deliveries: logged
  });
});

app.get('/debug/deliveries', async (req, res) => {
  if (!config.debugEnabled) return res.status(404).json({ error: 'debug disabled' });
  if (secured() && !authorised(req)) return res.status(401).json({ error: 'unauthorised' });
  res.json(await store.list({ limit: config.debugRingSize }));
});

// Both shapes hit the same handler:
//   /api/uqudo-webhook           - authenticated by header or basic auth
//   /api/uqudo-webhook/:token    - authenticated by the capability URL
app.post(['/api/uqudo-webhook', '/api/uqudo-webhook/:token'], async (req, res) => {
  const started = Date.now();
  const stages = {};
  // Never record the token itself — only which method was used.
  const meta = {
    ip: clientIp(req),
    userAgent: req.headers['user-agent'] || '',
    bytes: Number(req.headers['content-length']) || 0,
    authVia: req.params && req.params.token !== undefined ? 'url-token' : (secured() ? 'header' : 'none')
  };

  if (!authorised(req)) {
    await record({ result: 'rejected', reason: 'inbound auth failed (bad or missing shared secret)', httpStatus: 401, durationMs: Date.now() - started, ...meta });
    return res.status(401).json({ error: 'unauthorised' });
  }

  const token = req.body && (req.body.jwsResult || req.body.jws || req.body.token);
  if (!token) {
    await record({ result: 'rejected', reason: 'no jwsResult in body', httpStatus: 400, durationMs: Date.now() - started, bodyKeys: Object.keys(req.body || {}), ...meta });
    return res.status(400).json({ error: 'missing jwsResult' });
  }

  // ---- verify / decode ------------------------------------------------------
  let kyc, verified = false;
  const tVerify = Date.now();
  try {
    if (config.uqudo.publicKey) {
      kyc = jws.verify(token, config.uqudo.publicKey);
      verified = true;
    } else if (config.uqudo.allowUnverified) {
      kyc = jws.decode(token).payload;
    } else {
      await record({ result: 'rejected', reason: 'no public key and ALLOW_UNVERIFIED is off', httpStatus: 400, durationMs: Date.now() - started, ...meta });
      // 400 not 5xx: retrying will not fix a configuration problem.
      return res.status(400).json({ error: 'JWS verification not configured. Set UQUDO_PUBLIC_KEY, or ALLOW_UNVERIFIED=true for testing.' });
    }
    stages.verifyMs = Date.now() - tVerify;
  } catch (e) {
    await record({ result: 'rejected', reason: `jws: ${e.message}`, httpStatus: 400, durationMs: Date.now() - started, jwsAlg: safeAlg(token), ...meta });
    return res.status(400).json({ error: `Invalid jwsResult: ${e.message}` });
  }

  // ---- enrich (Info API) ----------------------------------------------------
  // Detection scores are NOT in the webhook JWT — they come from the Info API.
  // Best-effort: a failure logs and the delivery continues with fewer rules.
  if (enrich.enabled()) {
    const tEnrich = Date.now();
    const infoDocs = await enrich.fetchInfoDocuments(kyc.jti);
    stages.enrichMs = Date.now() - tEnrich;
    if (infoDocs) kyc.infoApiDocuments = infoDocs;
  }

  // ---- map ------------------------------------------------------------------
  let payload;
  const tMap = Date.now();
  try {
    payload = mapper.buildIntuitionPayload(kyc, {
      clientId: config.clientId,
      clientName: config.clientName
    });
    stages.mapMs = Date.now() - tMap;
  } catch (e) {
    await record({
      result: 'error', reason: `map: ${e.message}`, httpStatus: 500, stages,
      durationMs: Date.now() - started, verified,
      payloads: redact.buildPayloadBundle({ enabled: config.logPayloads, kyc }),
      ...meta
    });
    return res.status(500).json({ error: `Mapping failed: ${e.message}` });
  }

  // ---- forward --------------------------------------------------------------
  const tFwd = Date.now();
  try {
    const r = await intuition.submitDocument(payload);
    stages.forwardMs = Date.now() - tFwd;
    const body = r.body || {};
    await record({
      result: r.ok ? 'forwarded' : 'intuition-error',
      reason: r.ok ? undefined : `Intuition ${r.status}`,
      verified,
      verification_id: payload.verification_id,
      customer_number: payload.customer_number,
      intuitionStatus: r.status,
      httpStatus: r.ok ? 200 : 502,
      // Decision fields make the log readable at a glance without opening rows.
      riskLevel: body.RiskLevel,
      totalRulesScore: body.TotalRulesScore,
      rulesTriggered: body.RulesTriggered,
      // Parallel to RulesTriggered (same order/length) — the human-readable
      // reason for each rule, shown on hover in the dashboard.
      rulesDescriptions: body.RulesDescriptions,
      // Validation errors are the whole reason you open this dashboard — always
      // keep them, they describe schema mismatches, not people. Read from r.body,
      // not the {}-defaulted `body`: an empty error response must say so rather
      // than render as a misleading empty object.
      intuitionError: r.ok ? undefined : truncate(emptyBody(r.body) ? `(empty ${r.status} response body)` : r.body),
      stages,
      durationMs: Date.now() - started,
      payloads: redact.buildPayloadBundle({ enabled: config.logPayloads, kyc, document: payload, intuitionResponse: body }),
      ...meta
    });
    if (!r.ok) {
      // 502 so Uqudo retries — Intuition may be transiently unavailable.
      return res.status(502).json({ error: 'Intuition rejected the document', status: r.status, body: r.body });
    }
    return res.status(200).json({
      ok: true,
      verified,
      verification_id: payload.verification_id,
      customer_number: payload.customer_number,
      intuition: r.body
    });
  } catch (e) {
    stages.forwardMs = Date.now() - tFwd;
    await record({
      result: 'error', reason: `forward: ${e.message}`, httpStatus: 502, stages,
      verified, verification_id: payload.verification_id, customer_number: payload.customer_number,
      durationMs: Date.now() - started,
      payloads: redact.buildPayloadBundle({ enabled: config.logPayloads, kyc, document: payload }),
      ...meta
    });
    return res.status(502).json({ error: `Forward failed: ${e.message}` });
  }
});

/** Header alg of an unverifiable token, for the log. Best effort. */
function safeAlg(token) {
  try { return jws.decode(token).header.alg; } catch { return undefined; }
}

const truncate = (v) => {
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  return s && s.length > 4000 ? `${s.slice(0, 4000)}…[truncated]` : v;
};

/** Intuition answers some failures with no body at all. */
const emptyBody = (b) => b == null || b === '' || (typeof b === 'object' && Object.keys(b).length === 0);

// Dry-run: map a jwsResult and return the document WITHOUT sending it. Lets us
// eyeball the mapping before pointing the live webhook at this service.
app.post('/api/preview', (req, res) => {
  if (!authorised(req)) return res.status(401).json({ error: 'unauthorised' });
  const token = req.body && (req.body.jwsResult || req.body.jws || req.body.token);
  if (!token) return res.status(400).json({ error: 'missing jwsResult' });
  try {
    const kyc = config.uqudo.publicKey ? jws.verify(token, config.uqudo.publicKey) : jws.decode(token).payload;
    res.json({ ok: true, payload: mapper.buildIntuitionPayload(kyc, { clientId: config.clientId, clientName: config.clientName }) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ---- admin dashboard ---------------------------------------------------------
app.use('/api/admin', adminRoutes);

// The page itself is public; it renders a login form and every API call behind
// it is guarded. Serving it unauthenticated leaks nothing but markup.
app.get(['/admin', '/admin/'], (req, res) => res.sendFile(adminRoutes.adminPagePath));
app.get('/', (req, res) => res.redirect('/admin'));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(config.port, '0.0.0.0', () => {
    console.log(`Uqudo webhook relay listening on :${config.port}`);
    console.log(`Forwarding to: ${intuition.documentsUrl()}`);
    console.log(`Dashboard:     http://localhost:${config.port}/admin`);
    console.log(`Delivery log:  ${store.driverName}${store.isDurable() ? '' : ' (in-process; cleared on restart)'}`);
    if (!config.uqudo.publicKey) {
      console.warn(config.uqudo.allowUnverified
        ? 'WARNING: ALLOW_UNVERIFIED=true - JWS signatures are NOT checked. Test use only.'
        : 'WARNING: UQUDO_PUBLIC_KEY not set - webhook posts will be rejected.');
    }
    if (!secured()) console.warn('WARNING: no inbound shared secret set - anyone who knows the URL can post.');
    if (!adminAuth.enabled()) console.warn('WARNING: ADMIN_PASSWORD not set - the dashboard is disabled.');
    if (config.logPayloads) console.warn('WARNING: LOG_PAYLOADS=true - decoded KYC data is being written to the delivery log.');
  });
  module.exports = app;
}
