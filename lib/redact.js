'use strict';
// What the delivery log is allowed to keep.
//
// The webhook JWT carries real KYC data: names, ID numbers, dates of birth,
// document images. The log defaults to holding NONE of it — ids, status and
// timings only. Set LOG_PAYLOADS=true to capture the decoded JWT and mapped
// document for a debugging session, and turn it back off afterwards.
//
// Even with LOG_PAYLOADS on we mask the obvious identifiers and drop image
// blobs, so "full capture" still isn't a copy of someone's passport.

// Keys are matched with separators stripped. The two sides of this relay use
// different conventions — the Uqudo JWT is camelCase (`documentNumber`), the
// mapped Intuition document is snake_case (`document_number`) — and a raw regex
// silently missed the snake_case half, writing real ID numbers to the log.
// Normalising first means one list covers both.
const SENSITIVE_KEY = /(name|dob|dateofbirth|birth|identity|documentnumber|docnumber|passport|nationalid|address|phone|mobile|email|mrz|gender|placeofbirth|mothername|serialnumber)/;
const IMAGE_KEY = /(image|photo|face|selfie|frontside|backside|signature)/;

const normKey = (k) => String(k).replace(/[^a-z0-9]/gi, '').toLowerCase();

// Not masked, deliberately:
//   customer_number  - the pseudonymous key you search the log BY; masking it
//                      here while showing it in the table would be incoherent.
//   nationality*     - not a direct identifier, and needed to debug the
//                      nationality_risk rules. Masking it would also swallow the
//                      computed `nationality_risk` score itself.
const isSensitive = (k) => {
  const n = normKey(k);
  if (n === 'customernumber') return false;
  return SENSITIVE_KEY.test(n);
};

/** Keep the shape of a value visible while destroying its content. */
function maskValue(v) {
  if (v == null) return v;
  const s = String(v);
  if (!s) return s;
  if (s.length <= 2) return '••';
  // Keep first/last char so you can still correlate two records by eye.
  return `${s[0]}${'•'.repeat(Math.min(8, Math.max(1, s.length - 2)))}${s[s.length - 1]}`;
}

/** Recursively mask PII in an arbitrary object. Never throws. */
function redactDeep(value, depth = 0) {
  if (depth > 12 || value == null) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redactDeep(v, depth + 1));
  if (typeof value !== 'object') return value;

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (IMAGE_KEY.test(normKey(k)) && typeof v === 'string' && v.length > 200) {
      // Base64 image blob: record that it existed, not what it was.
      out[k] = `[image omitted: ${v.length} chars]`;
    } else if (isSensitive(k) && (typeof v === 'string' || typeof v === 'number')) {
      out[k] = maskValue(v);
    } else if (typeof v === 'object') {
      out[k] = redactDeep(v, depth + 1);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Build the payload bundle attached to a delivery record.
 * `enabled` is config.logPayloads. When off, returns undefined so the field is
 * simply absent rather than an empty husk.
 */
function buildPayloadBundle({ enabled, kyc, document, intuitionResponse }) {
  if (!enabled) return undefined;
  const safe = (v) => {
    try {
      return redactDeep(v);
    } catch (e) {
      return { _redactionError: e.message };
    }
  };
  return {
    jwt: safe(kyc),
    document: safe(document),
    intuitionResponse: intuitionResponse === undefined ? undefined : safe(intuitionResponse)
  };
}

module.exports = { redactDeep, maskValue, buildPayloadBundle };
