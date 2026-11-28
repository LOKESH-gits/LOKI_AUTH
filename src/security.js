'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);
const PARAMS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// Cap parallel scrypt work so a burst cannot exhaust a small instance.
let active = 0; const queue = [];
async function limited(fn) {
  if (active >= 4) await new Promise(r => queue.push(r)); else active++;
  try { return await fn(); } finally { const next = queue.shift(); if (next) next(); else active--; }
}
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await limited(() => scrypt(pw, salt, 64, PARAMS));
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  const [, N, r, p, salt, hash] = stored.split('$');
  const want = Buffer.from(hash, 'base64');
  const got = await limited(() => scrypt(pw, Buffer.from(salt, 'base64'), want.length, { N: +N, r: +r, p: +p, maxmem: PARAMS.maxmem }));
  return crypto.timingSafeEqual(got, want);
}
const randomToken = (n = 32) => crypto.randomBytes(n).toString('base64url');
const sha256 = v => crypto.createHash('sha256').update(v).digest('hex');
const hmac = (key, v) => crypto.createHmac('sha256', key).update(v).digest('hex');
const safeEqual = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

// AES-256-GCM for TOTP secrets at rest.
const aesKey = secret => crypto.createHash('sha256').update('totp:' + secret).digest();
function seal(secret, text) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', aesKey(secret), iv);
  const body = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]).toString('base64');
}
function unseal(secret, data) {
  const b = Buffer.from(data, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', aesKey(secret), b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
}

// TOTP (RFC 6238, HMAC-SHA1, 30 s, 6 digits) — what authenticator apps expect.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) {
  let bits = '', out = '';
  for (const x of buf) bits += x.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
function fromBase32(s) {
  const bits = [...s].map(c => B32.indexOf(c).toString(2).padStart(5, '0')).join('');
  return Buffer.from((bits.match(/.{8}/g) || []).map(b => parseInt(b, 2)));
}
function totpAt(secret, step, digits = 6) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', fromBase32(secret)).update(msg).digest();
  const n = (h.readUInt32BE(h[h.length - 1] & 15) & 0x7fffffff) % 10 ** digits;
  return String(n).padStart(digits, '0');
}
// Returns the matched time step (greater than lastStep, so codes cannot be replayed) or 0.
function checkTotp(secret, code, lastStep = 0, now = Date.now()) {
  const cur = Math.floor(now / 30000);
  for (const s of [cur - 1, cur, cur + 1]) if (s > lastStep && safeEqual(totpAt(secret, s), code)) return s;
  return 0;
}
module.exports = { hashPassword, verifyPassword, randomToken, sha256, hmac, safeEqual, seal, unseal, base32, totpAt, checkTotp };
