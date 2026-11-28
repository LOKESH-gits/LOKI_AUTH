'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { openDb } = require('../src/db');
const { loadConfig } = require('../src/config');
const { start, account } = require('./helpers');

// Local stand-in for Turso: speaks the Hrana v2 pipeline "batch" request, backed by node:sqlite.
// It checks the adapter's wire format and transaction conditions. It is not the real Turso service.
async function fakeTurso() {
  const { DatabaseSync } = require('node:sqlite'), raw = new DatabaseSync(':memory:');
  const enc = v => v === null ? { type: 'null' } : typeof v === 'number' ? { type: Number.isInteger(v) ? 'integer' : 'float', value: Number.isInteger(v) ? String(v) : v } : { type: 'text', value: v };
  const server = http.createServer((req, res) => {
    let body = ''; req.on('data', d => body += d); req.on('end', () => {
      if (req.url !== '/v2/pipeline' || req.headers.authorization !== 'Bearer test-token') { res.writeHead(401); return res.end(); }
      const results = [], errors = [];
      const met = c => !c || (c.type === 'ok' ? !!results[c.step] : !met(c.cond));
      for (const step of JSON.parse(body).requests[0].batch.steps) {
        if (!met(step.condition)) { results.push(null); errors.push(null); continue; }
        try {
          const stmt = raw.prepare(step.stmt.sql), rows = stmt.all(...step.stmt.args.map(a => a.type === 'null' ? null : a.type === 'integer' ? Number(a.value) : a.value));
          const cols = stmt.columns().map(c => ({ name: c.name }));
          results.push({ cols, rows: rows.map(r => cols.map(c => enc(r[c.name]))) }); errors.push(null);
        } catch (e) { results.push(null); errors.push({ message: e.message }); }
      }
      res.end(JSON.stringify({ results: [{ type: 'ok', response: { type: 'batch', result: { step_results: results, step_errors: errors } } }] }));
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}
async function contract(db) {
  const ins = ['INSERT INTO users(id,email,username,password_hash,password_changed_at,created_at,updated_at) VALUES(?,?,?,?,1,1,1)', ['u1', 'a@b.co', 'a', 'h']];
  await db.tx([ins]);
  await assert.rejects(db.tx([['INSERT INTO profiles(user_id,full_name) VALUES(?,?)', ['u1', 'A']], ins]), /UNIQUE/);
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM profiles')).n, 0, 'failed transaction rolls back');
  await assert.rejects(db.run('INSERT INTO profiles(user_id,full_name) VALUES(?,?)', ['missing', 'x']), /FOREIGN KEY/);
  await db.run('INSERT INTO profiles(user_id,full_name) VALUES(?,?)', ['u1', "O'Brien; DROP TABLE users"]);
  assert.equal((await db.get('SELECT full_name, NULL AS z FROM profiles')).full_name, "O'Brien; DROP TABLE users");
  await db.run('DELETE FROM users WHERE id=?', ['u1']);
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM profiles')).n, 0, 'cascade');
  await assert.rejects(db.run('SELECT * FROM nope'));
}
test('SQLite: schema, transactions, foreign keys, errors', async () => {
  const db = await openDb(loadConfig({ SQLITE_PATH: ':memory:' })); await contract(db); await db.close();
});
test('migrations are idempotent and data persists across restarts', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'loki-db-')), cfg = loadConfig({ SQLITE_PATH: path.join(dir, 'a.db') });
  let db = await openDb(cfg); await db.run("INSERT INTO rate_limits VALUES('k',1,2)"); await db.close();
  db = await openDb(cfg); assert.equal((await db.get('SELECT COUNT(*) AS n FROM rate_limits')).n, 1); await db.close(); fs.rmSync(dir, { recursive: true });
});
test('Turso adapter passes the same contract against a protocol stand-in', async () => {
  const fake = await fakeTurso(), db = await openDb({ dbDriver: 'turso', tursoUrl: fake.url, tursoToken: 'test-token' });
  await contract(db);
  const s = await start({ db }), c = s.client();
  assert.equal((await c.post('/api/auth/register', account())).status, 201);
  assert.equal((await c.post('/api/demo/start')).status, 201);
  assert.equal((await c.get('/api/activity/verify')).body.data.valid, true);
  await s.stop(); fake.close();
});
test('Turso failure fails safely with no local fallback', async () => {
  await assert.rejects(openDb({ dbDriver: 'turso', tursoUrl: 'http://127.0.0.1:1', tursoToken: 'x', sqlitePath: ':memory:' }));
});
test('production configuration is validated without echoing values', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'production', APP_SECRET: 'shortsecretvalue' }), e => /APP_SECRET/.test(e.message) && !e.message.includes('shortsecretvalue'));
  assert.throws(() => loadConfig({ NODE_ENV: 'production', APP_SECRET: 'x'.repeat(40), DB_DRIVER: 'sqlite', BASE_URL: 'https://a.test' }), /turso/);
  assert.ok(loadConfig({ NODE_ENV: 'production', APP_SECRET: 'x'.repeat(40), TURSO_URL: 'libsql://d.turso.io', TURSO_TOKEN: 't', RENDER_EXTERNAL_URL: 'https://a.onrender.com' }));
});
