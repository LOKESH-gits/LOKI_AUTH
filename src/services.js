'use strict';
const crypto = require('node:crypto');
const S = require('./security');
const { HttpError } = require('./validation');
const HOUR = 3600e3, DAY = 24 * HOUR;

function deviceLabel(ua = '') { // coarse label only; no IP or fingerprint is stored
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Unknown browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows'
    : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'unknown OS';
  return `${browser} on ${os}`;
}

function createServices(db, cfg) {
  const now = () => Date.now();

  async function rateLimit(name, id, max, windowMs) {
    const t = now(), key = S.hmac(cfg.appSecret, `${name}|${id}`);
    const row = await db.get(`INSERT INTO rate_limits(key,count,reset_at) VALUES(?,1,?)
      ON CONFLICT(key) DO UPDATE SET count = CASE WHEN reset_at <= ? THEN 1 ELSE count + 1 END,
      reset_at = CASE WHEN reset_at <= ? THEN excluded.reset_at ELSE reset_at END RETURNING count, reset_at`, [key, t + windowMs, t, t]);
    if (row.count > max) {
      const e = new HttpError(429, 'RATE_LIMITED', 'Too many attempts. Please wait and try again.');
      e.retryAfter = Math.ceil((row.reset_at - t) / 1000); throw e;
    }
  }

  // Tamper-evident activity chain: each block's HMAC covers the previous block's hash.
  const blockHash = (b) => S.hmac(cfg.appSecret, JSON.stringify([b.user_id, b.seq, b.event, b.device, b.created_at, b.prev_hash]));
  const locks = new Map();
  function log(userId, event, device) {
    const job = (locks.get(userId) || Promise.resolve()).catch(() => {}).then(async () => {
      for (let attempt = 0; ; attempt++) {
        const last = await db.get('SELECT seq, hash FROM activity_logs WHERE user_id=? ORDER BY seq DESC LIMIT 1', [userId]);
        const b = { user_id: userId, seq: (last?.seq || 0) + 1, event, device, created_at: now(), prev_hash: last?.hash || 'GENESIS' };
        try {
          return await db.run('INSERT INTO activity_logs(user_id,seq,event,device,created_at,prev_hash,hash) VALUES(?,?,?,?,?,?,?)',
            [b.user_id, b.seq, b.event, b.device, b.created_at, b.prev_hash, blockHash(b)]);
        } catch (e) { if (attempt >= 3 || !/UNIQUE/i.test(e.message)) throw e; }
      }
    });
    locks.set(userId, job);
    const clear = () => { if (locks.get(userId) === job) locks.delete(userId); };
    job.then(clear, clear);
    return job;
  }
  async function verifyChain(userId) {
    const rows = await db.all('SELECT * FROM activity_logs WHERE user_id=? ORDER BY seq', [userId]);
    let prev = 'GENESIS';
    for (let i = 0; i < rows.length; i++) {
      const b = rows[i];
      if (b.seq !== i + 1 || b.prev_hash !== prev || !S.safeEqual(b.hash, blockHash(b))) return { valid: false, blocks: rows.length, brokenAt: i + 1 };
      prev = b.hash;
    }
    return { valid: true, blocks: rows.length, brokenAt: null };
  }

  function newSession(userId, device, remember, expiresAt) {
    const token = S.randomToken(), t = now();
    const expires = expiresAt || t + (remember ? 30 * DAY : 12 * HOUR);
    return { token, expires, stmt: ['INSERT INTO sessions(id,token_hash,user_id,device,remember,created_at,last_seen_at,expires_at) VALUES(?,?,?,?,?,?,?,?)',
      [crypto.randomUUID(), S.sha256(token), userId, device, remember ? 1 : 0, t, t, expires]] };
  }

  async function authenticate(token) {
    if (!token) throw new HttpError(401, 'UNAUTHENTICATED', 'Please sign in to continue.');
    const row = await db.get(`SELECT s.id AS session_id, s.expires_at AS session_expires, s.last_seen_at, s.remember, u.*, d.expires_at AS demo_expires
      FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN demo_accounts d ON d.user_id=u.id WHERE s.token_hash=?`, [S.sha256(token)]);
    if (!row) throw new HttpError(401, 'UNAUTHENTICATED', 'Your session has ended. Please sign in again.');
    if (row.is_demo && !(row.demo_expires > now())) throw new HttpError(401, 'DEMO_EXPIRED', 'This demo has expired.');
    if (row.session_expires <= now()) {
      await db.run('DELETE FROM sessions WHERE id=?', [row.session_id]);
      throw new HttpError(401, 'SESSION_EXPIRED', 'Your session expired. Please sign in again.');
    }
    if (now() - row.last_seen_at > 60e3) await db.run('UPDATE sessions SET last_seen_at=? WHERE id=?', [now(), row.session_id]);
    return row;
  }

  async function startDemo(device) {
    const active = await db.get('SELECT COUNT(*) AS n FROM demo_accounts WHERE expires_at>?', [now()]);
    if (active.n >= 500) throw new HttpError(503, 'DEMO_BUSY', 'The demo is at capacity. Please try again shortly.');
    const id = crypto.randomUUID(), tag = crypto.randomBytes(8).toString('hex'), t = now(), expires = t + cfg.demoTtlMs;
    const passwordHash = await S.hashPassword(S.randomToken(48)); // generated, never returned or stored in clear
    const session = newSession(id, device, false, expires);
    await db.tx([
      ['INSERT INTO users(id,email,username,password_hash,is_demo,password_changed_at,created_at,updated_at) VALUES(?,?,?,?,1,?,?,?)',
        [id, `demo_${tag}@demo.invalid`, `demo_${tag}`, passwordHash, t, t, t]],
      ['INSERT INTO profiles(user_id,full_name) VALUES(?,?)', [id, 'Demo Explorer']],
      ['INSERT INTO user_preferences(user_id) VALUES(?)', [id]],
      ['INSERT INTO demo_accounts(user_id,expires_at) VALUES(?,?)', [id, expires]],
      session.stmt,
    ]);
    await log(id, 'demo_started', device);
    return { id, session };
  }

  // Retention: demo accounts are hard-deleted 1 hour after expiry (access stops at expiry).
  // The grace period lets the app say "demo expired". Cascades remove all related rows.
  async function cleanup(graceMs = HOUR) {
    const t = now();
    await db.tx([
      ['DELETE FROM users WHERE is_demo=1 AND id IN (SELECT user_id FROM demo_accounts WHERE expires_at<=?)', [t - graceMs]],
      ['DELETE FROM sessions WHERE expires_at<=?', [t - graceMs]],
      ['DELETE FROM email_verification_tokens WHERE expires_at<=?', [t]],
      ['DELETE FROM password_reset_tokens WHERE expires_at<=?', [t]],
      ['DELETE FROM rate_limits WHERE reset_at<=?', [t]],
    ]);
  }
  return { rateLimit, log, verifyChain, newSession, authenticate, startDemo, cleanup };
}
module.exports = { createServices, deviceLabel, HOUR, DAY };
