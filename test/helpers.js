'use strict';
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { loadConfig } = require('../src/config');
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');

// Every call gets its own in-memory database and temp outbox. Tests never touch a real database.
async function start(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'loki-test-'));
  const cfg = loadConfig({ SQLITE_PATH: ':memory:', EMAIL_PROVIDER: 'file', OUTBOX_PATH: path.join(dir, 'outbox.log'), ...env });
  const db = env.db || await openDb(cfg);
  const logs = [], app = createApp({ db, cfg, logger: { error: m => logs.push(m) } });
  await new Promise(r => app.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const origin = new URL(cfg.baseUrl).origin;
  function client(ua = 'Mozilla/5.0 (Linux; Android 14) Chrome/130') {
    const jar = {};
    async function req(method, url, body, headers = {}) {
      const h = { 'user-agent': ua, cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') };
      if (method !== 'GET') Object.assign(h, { origin, 'content-type': 'application/json', 'x-csrf-token': (await req('GET', '/api/csrf')).body.data.token });
      h.cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
      Object.assign(h, headers);
      const res = await fetch(base + url, { method, headers: h, body: method === 'GET' ? undefined : JSON.stringify(body || {}) });
      for (const c of res.headers.getSetCookie()) { const [k, v] = c.split(';')[0].split('='); if (v) jar[k] = v; else delete jar[k]; }
      const text = await res.text();
      return { status: res.status, headers: res.headers, text, body: res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
    }
    return { jar, req, get: u => req('GET', u), post: (u, b, h) => req('POST', u, b, h), patch: (u, b) => req('PATCH', u, b), del: (u, b) => req('DELETE', u, b) };
  }
  const outbox = () => fs.existsSync(cfg.outboxPath) ? fs.readFileSync(cfg.outboxPath, 'utf8').trim().split('\n').map(JSON.parse) : [];
  const stop = async () => { app.server.closeAllConnections(); await new Promise(r => app.server.close(r)); await app.drain(); await db.close(); fs.rmSync(dir, { recursive: true, force: true }); };
  return { cfg, db, app, logs, base, client, outbox, stop, mailToken: kind => outbox().filter(m => m.text.includes(kind)).at(-1)?.text.split('#token=')[1] };
}
const PASSWORD = 'Vault!Block9-Secure';
const account = (n = 'alice') => ({ fullName: 'Test ' + n, username: n, email: n + '@example.com', password: PASSWORD, confirmPassword: PASSWORD, acceptTerms: true });
module.exports = { start, account, PASSWORD };
