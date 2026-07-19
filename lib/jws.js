'use strict';
// JWS handling for the `jwsResult` Uqudo posts to the webhook.
//
// Uqudo signs the onboarding result; the docs require verifying it against
// Uqudo's public key before trusting the payload. Verification is done with
// node's crypto (no dependency) and supports RS256/RS512 and ES256/ES512.
const crypto = require('crypto');

const b64urlToBuf = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const decodeJson = (seg) => JSON.parse(b64urlToBuf(seg).toString('utf8'));

const ALGS = {
  RS256: { type: 'rsa', hash: 'sha256' },
  RS384: { type: 'rsa', hash: 'sha384' },
  RS512: { type: 'rsa', hash: 'sha512' },
  PS256: { type: 'rsa-pss', hash: 'sha256' },
  ES256: { type: 'ec', hash: 'sha256' },
  ES384: { type: 'ec', hash: 'sha384' },
  ES512: { type: 'ec', hash: 'sha512' }
};

function split(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('jwsResult is not a well-formed JWS (expected 3 dot-separated segments)');
  return parts;
}

/** Decode without verifying. Never use the result unless verify() passed or the
 *  operator explicitly set ALLOW_UNVERIFIED. */
function decode(token) {
  const [h, p] = split(token);
  return { header: decodeJson(h), payload: decodeJson(p) };
}

/** Verify the signature against a PEM public key. Returns the payload. */
function verify(token, publicKeyPem) {
  const [h, p, s] = split(token);
  const header = decodeJson(h);
  const spec = ALGS[header.alg];
  if (!spec) throw new Error(`Unsupported JWS alg: ${header.alg}`);

  const signingInput = Buffer.from(`${h}.${p}`);
  const signature = b64urlToBuf(s);
  const keyObj = crypto.createPublicKey(publicKeyPem);

  let ok;
  if (spec.type === 'ec') {
    // JWS ES* signatures are raw r||s; node expects DER unless told otherwise.
    ok = crypto.verify(spec.hash, signingInput, { key: keyObj, dsaEncoding: 'ieee-p1363' }, signature);
  } else if (spec.type === 'rsa-pss') {
    ok = crypto.verify(spec.hash, signingInput, { key: keyObj, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
  } else {
    ok = crypto.verify(spec.hash, signingInput, keyObj, signature);
  }
  if (!ok) throw new Error('JWS signature verification failed');

  const payload = decodeJson(p);
  // exp/nbf are advisory here: a webhook can legitimately be retried for up to
  // 2 hours, so an expired-but-authentic result should still be forwarded.
  return payload;
}

module.exports = { decode, verify, split };
