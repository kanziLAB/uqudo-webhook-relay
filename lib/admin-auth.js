'use strict';
// Admin dashboard auth.
//
// Deliberately fails closed: with no ADMIN_PASSWORD set the dashboard is
// DISABLED, not open. An unauthenticated log viewer would expose which people
// were onboarded and when, which is worse than having no dashboard.
//
// Login exchanges the password for an HMAC-signed, httpOnly cookie. No session
// store, so it works unchanged on serverless where there is no shared memory.

const crypto = require('crypto');
const config = require('./config');

const COOKIE = 'uq_admin';

/** Secret for signing cookies. Derived from the password when not set explicitly
 *  so a single-env deployment still gets unforgeable tokens. */
function secret() {
  return config.admin.sessionSecret || `derived:${config.admin.password}`;
}

const enabled = () => Boolean(config.admin.password);

/** Constant-time compare that tolerates differing lengths. */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Still burn a comparison so length isn't leaked by timing.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

function sign(payload) {
  return crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
}

function issue() {
  const exp = Date.now() + config.admin.sessionTtlMs;
  const body = `${exp}`;
  return `${body}.${sign(body)}`;
}

function valid(token) {
  if (!token || typeof token !== 'string') return false;
  const i = token.lastIndexOf('.');
  if (i < 1) return false;
  const body = token.slice(0, i);
  const mac = token.slice(i + 1);
  if (!safeEqual(mac, sign(body))) return false;
  const exp = Number(body);
  return Number.isFinite(exp) && Date.now() < exp;
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const cookieFrom = (req) => parseCookies(req.headers.cookie)[COOKIE];

function setCookie(res, req) {
  // `secure` only when actually on https, so local http testing still works.
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https';
  const bits = [
    `${COOKIE}=${issue()}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${Math.floor(config.admin.sessionTtlMs / 1000)}`
  ];
  if (isHttps) bits.push('Secure');
  res.setHeader('Set-Cookie', bits.join('; '));
}

function clearCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

const isAuthed = (req) => enabled() && valid(cookieFrom(req));

/** Express guard for every /api/admin route except login. */
function requireAdmin(req, res, next) {
  if (!enabled()) {
    return res.status(503).json({ error: 'Admin dashboard is disabled. Set ADMIN_PASSWORD to enable it.' });
  }
  if (!isAuthed(req)) return res.status(401).json({ error: 'unauthorised' });
  next();
}

module.exports = { COOKIE, enabled, isAuthed, requireAdmin, setCookie, clearCookie, safeEqual, issue, valid };
