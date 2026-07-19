'use strict';
// Info API enrichment.
//
// The webhook JWT does NOT carry the fraud detection scores — those live in
// Uqudo's Info API (`GET /api/v1/info/{sessionId}`), which returns a JWS whose
// payload contains enriched documents with `scan.verifications` keys like
//   idPrintDetection:          { enabled, score }
//   idScreenDetection:         { enabled, score }
//   idPhotoTamperingDetection: { enabled, score }
// Without this call the FD_* rules can never fire on the webhook path, which is
// exactly the gap between "the app shows 5 rules" and "the relay shows 1".
//
// Auth is OAuth2 client-credentials against auth.uqudo.io. The token is cached
// until shortly before expiry. Enrichment is best-effort: any failure logs and
// returns null so the delivery still forwards (with fewer rules) rather than
// being dropped.

const config = require('./config');

let cached = { token: null, expiresAt: 0 };

async function getToken() {
  const now = Date.now();
  if (cached.token && now < cached.expiresAt - 30000) return cached.token;
  const { oauthUrl, clientId, clientSecret } = config.uqudo;
  const res = await fetch(oauthUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=client_credentials&client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}`,
    signal: AbortSignal.timeout(config.uqudo.enrichTimeoutMs)
  });
  if (!res.ok) throw new Error(`OAuth ${res.status}`);
  const body = await res.json();
  cached = {
    token: body.access_token,
    expiresAt: now + (Number(body.expires_in) || 300) * 1000
  };
  return cached.token;
}

/** Decode a JWS payload segment without verifying (the Info API response is
 *  fetched over TLS directly from Uqudo with our own bearer token). */
function decodePayload(jws) {
  const seg = String(jws).split('.')[1];
  if (!seg) return null;
  return JSON.parse(Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
}

const enabled = () => Boolean(config.uqudo.enrichWithInfoApi && config.uqudo.clientId && config.uqudo.clientSecret);

/**
 * Fetch the enriched documents for a session. Returns the documents array (the
 * same shape the Flutter app merges as `infoApiDocuments`) or null on any
 * failure — enrichment must never fail a delivery.
 */
async function fetchInfoDocuments(jti) {
  if (!enabled() || !jti) return null;
  try {
    const token = await getToken();
    const res = await fetch(`${config.uqudo.infoBaseUrl}/${encodeURIComponent(jti)}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: '*/*' },
      signal: AbortSignal.timeout(config.uqudo.enrichTimeoutMs)
    });
    if (!res.ok) throw new Error(`Info API ${res.status}`);
    const text = await res.text();
    const payload = text.startsWith('eyJ') ? decodePayload(text) : JSON.parse(text);
    const docs = payload && payload.data && payload.data.documents;
    return Array.isArray(docs) && docs.length ? docs : null;
  } catch (e) {
    console.error(`Info API enrichment failed for ${jti}: ${e.message}`);
    return null;
  }
}

module.exports = { fetchInfoDocuments, enabled, _decodePayload: decodePayload };
