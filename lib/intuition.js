'use strict';
// Thin client for the Intuition Data API.
const config = require('./config');

// Both Intuition data hosts sit behind Cloudflare, which 1010-blocks clients
// that don't look like browsers. This UA is required, not cosmetic.
const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

function documentsUrl() {
  const { baseUrl, tenantId, datasetId, runStrategy } = config.intuition;
  const qs = `runStrategy=${runStrategy ? 'true' : 'false'}&includeDetail=true`;
  return `${baseUrl}/api/v1/${tenantId}/dataSets/${datasetId}/documents?${qs}`;
}

async function submitDocument(payload) {
  const url = documentsUrl();
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'User-Agent': BROWSER_UA
  };
  if (config.intuition.token) headers.Authorization = `Bearer ${config.intuition.token}`;

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), config.intuition.timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: ctrl.signal
    });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    return { ok: res.ok, status: res.status, body, url, durationMs: Date.now() - started };
  } finally {
    clearTimeout(t);
  }
}

/** Info API — detection scores are not in the raw JWT; they come from here. */
async function fetchInfo(jti) {
  if (!jti) return null;
  const url = `${config.uqudo.infoBaseUrl}/${jti}`;
  const headers = { Accept: 'application/json', 'User-Agent': BROWSER_UA };
  if (config.uqudo.infoToken) headers.Authorization = `Bearer ${config.uqudo.infoToken}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`Info API ${res.status}`);
  return res.text();
}

module.exports = { submitDocument, fetchInfo, documentsUrl, BROWSER_UA };
