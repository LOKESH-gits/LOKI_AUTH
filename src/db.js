'use strict';
// One tiny interface for both drivers: all / get / run / tx. tx() is atomic.
const fs = require('node:fs');
const path = require('node:path');

const MIGRATIONS = [[
  `CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, email_verified_at INTEGER, is_demo INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT, totp_pending TEXT, totp_last_step INTEGER NOT NULL DEFAULT 0,
    password_changed_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
  `CREATE TABLE profiles(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE user_preferences(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme TEXT NOT NULL DEFAULT 'dark', login_alerts INTEGER NOT NULL DEFAULT 1)`,
  `CREATE TABLE sessions(id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, device TEXT NOT NULL, remember INTEGER NOT NULL,
    created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX idx_sessions_user ON sessions(user_id, expires_at)`,
  `CREATE TABLE email_verification_tokens(token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, used_at INTEGER)`,
  `CREATE TABLE password_reset_tokens(token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, used_at INTEGER)`,
  `CREATE TABLE recovery_codes(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL, PRIMARY KEY(user_id, code_hash))`,
  `CREATE TABLE activity_logs(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, seq INTEGER NOT NULL,
    event TEXT NOT NULL, device TEXT NOT NULL, created_at INTEGER NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(user_id, seq))`,
  `CREATE TABLE demo_accounts(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX idx_demo_expiry ON demo_accounts(expires_at)`,
  `CREATE TABLE rate_limits(key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL)`,
  `CREATE TABLE account_deletions(ref_hash TEXT NOT NULL, deleted_at INTEGER NOT NULL)`,
]];

function sqliteDriver(file) {
  const { DatabaseSync } = require('node:sqlite');
  if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const raw = new DatabaseSync(file);
  raw.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000');
  // node:sqlite is synchronous; queries here are tiny indexed lookups.
  const exec = (sql, args = []) => raw.prepare(sql).all(...args).map(r => ({ ...r }));
  return {
    async all(sql, args) { return exec(sql, args); },
    async tx(list) {
      raw.exec('BEGIN IMMEDIATE');
      try { const out = list.map(([s, a]) => exec(s, a)); raw.exec('COMMIT'); return out; }
      catch (e) { raw.exec('ROLLBACK'); throw e; }
    },
    async close() { raw.close(); },
  };
}

// Turso / libSQL over its HTTP pipeline protocol (Hrana v2). No SDK needed.
function tursoDriver(url, token) {
  const endpoint = url.replace(/^libsql:/, 'https:').replace(/\/+$/, '') + '/v2/pipeline';
  const enc = v => v === null || v === undefined ? { type: 'null' }
    : typeof v === 'number' ? (Number.isInteger(v) ? { type: 'integer', value: String(v) } : { type: 'float', value: v })
    : { type: 'text', value: String(v) };
  const dec = c => c.type === 'null' ? null : c.type === 'integer' ? Number(c.value) : c.value;
  const stmt = (sql, args = []) => ({ sql, args: args.map(enc), want_rows: true });
  async function pipeline(steps) {
    const res = await fetch(endpoint, {
      method: 'POST', signal: AbortSignal.timeout(10000),
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ requests: [{ type: 'batch', batch: { steps } }, { type: 'close' }] }),
    });
    if (!res.ok) throw new Error(`Database request failed (HTTP ${res.status})`);
    const first = (await res.json()).results?.[0];
    if (first?.type !== 'ok') throw new Error('Database request rejected');
    const { step_results: results, step_errors: errs } = first.response.result;
    const failed = errs.find(Boolean);
    if (failed) throw new Error(failed.message);
    return results.map(r => r && r.rows.map(row => Object.fromEntries(row.map((c, i) => [r.cols[i].name, dec(c)]))));
  }
  const fk = { stmt: stmt('PRAGMA foreign_keys=ON') };
  return {
    async all(sql, args) { return (await pipeline([fk, { stmt: stmt(sql, args), condition: { type: 'ok', step: 0 } }]))[1]; },
    async tx(list) {
      const steps = [fk, { stmt: stmt('BEGIN IMMEDIATE'), condition: { type: 'ok', step: 0 } }];
      for (const [s, a] of list) steps.push({ stmt: stmt(s, a), condition: { type: 'ok', step: steps.length - 1 } });
      steps.push({ stmt: stmt('COMMIT'), condition: { type: 'ok', step: steps.length - 1 } });
      steps.push({ stmt: stmt('ROLLBACK'), condition: { type: 'not', cond: { type: 'ok', step: steps.length - 1 } } });
      return (await pipeline(steps)).slice(2, 2 + list.length);
    },
    async close() {},
  };
}

async function openDb(cfg) {
  // No fallback: if Turso fails, startup fails. An empty local DB is never substituted.
  const d = cfg.dbDriver === 'turso' ? tursoDriver(cfg.tursoUrl, cfg.tursoToken) : sqliteDriver(cfg.sqlitePath);
  const db = {
    all: (s, a = []) => d.all(s, a),
    get: async (s, a = []) => (await d.all(s, a))[0],
    run: (s, a = []) => d.all(s, a),
    tx: list => d.tx(list),
    close: () => d.close(),
  };
  await db.run('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)');
  const done = (await db.get('SELECT COALESCE(MAX(version),0) AS v FROM schema_migrations')).v;
  for (let i = done; i < MIGRATIONS.length; i++) {
    await db.tx([...MIGRATIONS[i].map(s => [s, []]), ['INSERT INTO schema_migrations(version) VALUES(?)', [i + 1]]]);
  }
  return db;
}
module.exports = { openDb };
