'use strict';
const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { start, account, PASSWORD } = require('./helpers');
let s;
beforeEach(async () => { s = await start(); });
afterEach(async () => { await s.stop(); });
const signup = async (n = 'alice') => { const c = s.client(); const r = await c.post('/api/auth/register', account(n)); assert.equal(r.status, 201, r.text); return c; };
const login = async (identifier, password = PASSWORD, extra = {}) => { const c = s.client(); const r = await c.post('/api/auth/login', { identifier, password, ...extra }); return { c, r }; };

test('registration normalizes input, hashes the password and creates a session', async () => {
  const c = s.client(), r = await c.post('/api/auth/register', { ...account(), email: '  Alice@Example.COM ', username: 'ALICE' });
  assert.equal(r.status, 201); assert.equal(r.body.data.user.email, 'alice@example.com'); assert.equal(r.body.data.user.username, 'alice');
  const row = await s.db.get('SELECT password_hash FROM users');
  assert.match(row.password_hash, /^scrypt\$32768\$/); assert.ok(!row.password_hash.includes(PASSWORD)); assert.ok(!r.text.includes('password_hash'));
  assert.equal((await c.get('/api/auth/me')).status, 200);
});
test('invalid registration returns field errors', async () => {
  const r = await s.client().post('/api/auth/register', { ...account(), username: '1', email: 'bad', password: 'short' });
  assert.equal(r.status, 422); assert.deepEqual(Object.keys(r.body.error.fields).sort(), ['email', 'password', 'username']);
  for (const [patch, key] of [[{ confirmPassword: 'x' }, 'confirmPassword'], [{ acceptTerms: false }, 'acceptTerms'], [{ fullName: '<img src=x>' }, 'fullName']])
    assert.ok((await s.client().post('/api/auth/register', { ...account(), ...patch })).body.error.fields[key]);
});
test('duplicate email and username are rejected, including concurrent requests', async () => {
  await signup();
  assert.ok((await s.client().post('/api/auth/register', { ...account('bob'), email: 'ALICE@example.com' })).body.error.fields.email);
  assert.ok((await s.client().post('/api/auth/register', { ...account('bob'), username: 'Alice' })).body.error.fields.username);
  const both = await Promise.all([1, 2].map(() => s.client().post('/api/auth/register', account('carol'))));
  assert.deepEqual(both.map(r => r.status).sort(), [201, 409]);
});
test('login by email or username; wrong password and unknown user look identical', async () => {
  await signup();
  assert.equal((await login('ALICE@example.com')).r.status, 200);
  assert.equal((await login('alice')).r.status, 200);
  const a = (await login('alice', 'wrong')).r, b = (await login('nobody', 'wrong')).r;
  assert.equal(a.status, 401); assert.equal(a.text, b.text);
});
test('login is rate limited', async () => {
  await signup(); let r;
  for (let i = 0; i < 7; i++) r = (await login('alice', 'wrong')).r;
  assert.equal(r.status, 429); assert.ok(Number(r.headers.get('retry-after')) > 0);
});
test('registration, reset-request and demo endpoints are rate limited', async () => {
  for (const [url, body, max] of [['/api/auth/register', {}, 5], ['/api/auth/forgot-password', { email: 'x@example.com' }, 5], ['/api/demo/start', {}, 10]]) {
    let r; for (let i = 0; i <= max; i++) r = await s.client().post(url, body);
    assert.equal(r.status, 429, url);
  }
});
test('logout invalidates the session on the server', async () => {
  const c = await signup(), stolen = c.jar.la_sid;
  assert.equal((await c.post('/api/auth/logout')).status, 200);
  c.jar.la_sid = stolen; assert.equal((await c.get('/api/auth/me')).status, 401);
});
test('CSRF token and exact origin are required', async () => {
  const c = s.client(), url = '/api/demo/start';
  assert.equal((await c.post(url, {}, { 'x-csrf-token': 'nope' })).body.error.code, 'CSRF');
  assert.equal((await c.post(url, {}, { origin: 'https://evil.example' })).body.error.code, 'BAD_ORIGIN');
  assert.equal((await c.post(url, {}, { origin: '' })).status, 403);
  assert.equal((await c.post(url, {}, { 'content-type': 'text/plain' })).status, 415);
});
test('security headers and cookie flags', async () => {
  const c = s.client(), r = await c.post('/api/demo/start');
  const sid = r.headers.getSetCookie().find(x => x.startsWith('la_sid='));
  assert.match(sid, /HttpOnly/); assert.match(sid, /SameSite=Strict/); assert.match(sid, /Path=\//);
  assert.ok(!r.text.includes(c.jar.la_sid));
  const page = await c.get('/');
  assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff'); assert.equal(page.headers.get('x-frame-options'), 'DENY');
  assert.equal(page.headers.get('referrer-policy'), 'no-referrer'); assert.ok(page.headers.get('permissions-policy'));
  assert.equal(page.headers.get('access-control-allow-origin'), null);
});
test('production uses __Host- Secure cookies and HSTS', async () => {
  const { loadConfig } = require('../src/config'), { createApp } = require('../src/app');
  const cfg = { ...loadConfig({ SQLITE_PATH: ':memory:' }), production: true, baseUrl: 'https://x.test' };
  const app = createApp({ db: s.db, cfg }); await new Promise(r => app.server.listen(0, '127.0.0.1', r));
  const res = await fetch(`http://127.0.0.1:${app.server.address().port}/api/csrf`);
  assert.match(res.headers.getSetCookie()[0], /^__Host-la_csrf=.*; Secure/); assert.ok(res.headers.get('strict-transport-security'));
  app.server.closeAllConnections(); app.server.close();
});
test('static serving blocks traversal and dotfiles; private pages are noindex', async () => {
  const http = require('node:http'), port = new URL(s.base).port;
  for (const p of ['/.env', '/.git/config', '/assets/../server.js', '/assets/%2e%2e%2fserver.js', '/server.js', '/src/config.js']) {
    const out = await new Promise(done => http.get({ port, path: p }, r => { let d = ''; r.on('data', x => d += x); r.on('end', () => done({ status: r.statusCode, d })); }));
    assert.equal(out.status, 404, p); assert.ok(!/APP_SECRET|require\(/.test(out.d), p);
  }
  const c = s.client();
  assert.match((await c.get('/dashboard')).text, /noindex/); assert.match((await c.get('/about')).text, /index,follow/);
  assert.match((await c.get('/robots.txt')).text, /Disallow: \/dashboard/); assert.match((await c.get('/sitemap.xml')).text, /\/security/);
});
test('protected endpoints reject anonymous requests', async () => {
  for (const u of ['/api/auth/me', '/api/profile', '/api/sessions', '/api/activity', '/api/activity/verify']) assert.equal((await s.client().get(u)).status, 401, u);
  for (const [m, u] of [['PATCH', '/api/profile'], ['DELETE', '/api/account'], ['POST', '/api/auth/change-password'], ['POST', '/api/sessions/logout-all']]) assert.equal((await s.client().req(m, u, {})).status, 401, u);
});
test('users cannot see or revoke each other’s data; SQL-like input is inert', async () => {
  const a = await signup('alice'), b = await signup('bob');
  const bs = (await b.get('/api/sessions')).body.data.sessions[0];
  assert.equal((await a.del('/api/sessions/' + bs.id)).status, 404);
  assert.equal((await b.get('/api/auth/me')).status, 200);
  assert.equal((await a.get('/api/sessions')).body.data.sessions.length, 1);
  assert.equal((await login("alice' OR '1'='1", 'x')).r.status, 401);
  assert.equal((await s.db.get('SELECT COUNT(*) AS n FROM users')).n, 2);
});
test('session fixation: login always issues a fresh token and retires the old one', async () => {
  const c = await signup(), old = c.jar.la_sid;
  await c.post('/api/auth/login', { identifier: 'alice', password: PASSWORD });
  assert.notEqual(c.jar.la_sid, old);
  const attacker = s.client(); attacker.jar.la_sid = old; assert.equal((await attacker.get('/api/auth/me')).status, 401);
  const planted = s.client(); planted.jar.la_sid = 'attacker-chosen';
  await planted.post('/api/auth/login', { identifier: 'alice', password: PASSWORD }); assert.notEqual(planted.jar.la_sid, 'attacker-chosen');
});
test('email verification token is hashed, expiring and single use', async () => {
  const c = await signup(), token = s.mailToken('/verify-email');
  assert.notEqual((await s.db.get('SELECT token_hash FROM email_verification_tokens')).token_hash, token);
  assert.equal((await c.post('/api/auth/verify-email', { token })).status, 200);
  assert.equal((await c.post('/api/auth/verify-email', { token })).status, 400);
  assert.equal((await c.get('/api/auth/me')).body.data.user.emailVerified, true);
  const b = await signup('bob'); await b.post('/api/auth/resend-verification');
  await s.db.run('UPDATE email_verification_tokens SET expires_at=1');
  assert.equal((await b.post('/api/auth/verify-email', { token: s.mailToken('/verify-email') })).status, 400);
});
test('password reset: generic response, single use, expiry, all sessions invalidated', async () => {
  const c = await signup(), anon = s.client();
  const a = await anon.post('/api/auth/forgot-password', { email: 'alice@example.com' }), b = await anon.post('/api/auth/forgot-password', { email: 'ghost@example.com' });
  assert.equal(a.text, b.text); await s.app.drain();
  const token = s.mailToken('/reset-password'); assert.ok(token); assert.ok(!a.text.includes(token));
  const next = 'Another#Strong7Pass', body = { token, password: next, confirmPassword: next };
  assert.equal((await anon.post('/api/auth/reset-password', body)).status, 200);
  assert.equal((await anon.post('/api/auth/reset-password', body)).status, 400);
  assert.equal((await c.get('/api/auth/me')).status, 401);
  assert.equal((await login('alice')).r.status, 401); assert.equal((await login('alice', next)).r.status, 200);
  await anon.post('/api/auth/forgot-password', { email: 'alice@example.com' }); await s.app.drain();
  await s.db.run('UPDATE password_reset_tokens SET expires_at=1');
  assert.equal((await anon.post('/api/auth/reset-password', { ...body, token: s.mailToken('/reset-password') })).status, 400);
});
test('unconfigured email never claims delivery', async () => {
  const x = await start({ EMAIL_PROVIDER: 'none' }), c = x.client();
  const r = await c.post('/api/auth/register', account()); assert.equal(r.body.data.emailSent, false); assert.match(r.body.message, /not configured/);
  assert.equal((await c.post('/api/auth/resend-verification')).status, 503);
  assert.match((await c.post('/api/auth/forgot-password', { email: 'alice@example.com' })).body.message, /not configured/);
  await x.stop();
});
test('session expiry and remember-me policy', async () => {
  await signup();
  const short = (await login('alice')), long = await login('alice', PASSWORD, { remember: true });
  assert.ok(!/Max-Age/.test(short.r.headers.getSetCookie().find(x => x.startsWith('la_sid='))));
  assert.match(long.r.headers.getSetCookie().find(x => x.startsWith('la_sid=')), /Max-Age=259\d{4}/);
  await s.db.run('UPDATE sessions SET expires_at=1 WHERE remember=0');
  assert.equal((await short.c.get('/api/auth/me')).body.error.code, 'SESSION_EXPIRED');
  assert.equal((await long.c.get('/api/auth/me')).status, 200);
});
test('multiple sessions: revoke one, current, others, then logout all with re-authentication', async () => {
  const a = await signup(), b = (await login('alice')).c, d = (await login('alice')).c;
  let list = (await a.get('/api/sessions')).body.data.sessions; assert.equal(list.length, 3);
  const bId = (await b.get('/api/sessions')).body.data.sessions.find(x => x.current).id;
  await a.del('/api/sessions/' + bId); assert.equal((await b.get('/api/auth/me')).status, 401);
  assert.equal((await a.post('/api/sessions/revoke-others')).body.data.revoked, 1); assert.equal((await d.get('/api/auth/me')).status, 401);
  assert.equal((await a.post('/api/sessions/logout-all', { currentPassword: 'wrong' })).status, 403);
  const e = (await login('alice')).c;
  assert.equal((await a.post('/api/sessions/logout-all', { currentPassword: PASSWORD })).status, 200);
  assert.equal((await e.get('/api/auth/me')).status, 401);
  const f = (await login('alice')).c; list = (await f.get('/api/sessions')).body.data.sessions;
  assert.equal((await f.del('/api/sessions/' + list[0].id)).body.data.current, true); assert.equal((await f.get('/api/auth/me')).status, 401);
});
test('profile updates are validated and cannot touch privileged fields', async () => {
  const c = await signup(); await signup('bob');
  assert.equal((await c.patch('/api/profile', { fullName: 'New Name', bio: 'Hi', username: 'alice2' })).body.data.user.username, 'alice2');
  assert.equal((await c.patch('/api/profile', { username: 'bob' })).status, 409);
  assert.equal((await c.patch('/api/profile', { bio: '<script>' })).status, 422);
  for (const bad of [{ is_demo: 1 }, { email: 'x@y.com' }, { emailVerified: true }]) assert.equal((await c.patch('/api/profile', bad)).status, 422);
});
test('password change needs re-authentication and signs out other devices', async () => {
  const c = await signup(), other = (await login('alice')).c, next = 'Changed$Pass42-ok';
  assert.equal((await c.post('/api/auth/change-password', { currentPassword: 'no', password: next, confirmPassword: next })).status, 403);
  assert.equal((await c.post('/api/auth/change-password', { currentPassword: PASSWORD, password: next, confirmPassword: next })).status, 200);
  assert.equal((await c.get('/api/auth/me')).status, 200); assert.equal((await other.get('/api/auth/me')).status, 401);
});
test('account deletion needs confirmation and removes dependent rows', async () => {
  const c = await signup();
  assert.equal((await c.del('/api/account', { confirm: 'no', currentPassword: PASSWORD })).status, 422);
  assert.equal((await c.del('/api/account', { confirm: 'DELETE', currentPassword: 'x' })).status, 403);
  assert.equal((await c.del('/api/account', { confirm: 'DELETE', currentPassword: PASSWORD })).status, 200);
  for (const t of ['users', 'profiles', 'sessions', 'activity_logs', 'user_preferences', 'email_verification_tokens'])
    assert.equal((await s.db.get(`SELECT COUNT(*) AS n FROM ${t}`)).n, 0, t);
  assert.equal((await s.db.get('SELECT COUNT(*) AS n FROM account_deletions')).n, 1);
});
test('activity chain records events, verifies, and detects tampering', async () => {
  const c = await signup(); await Promise.all([1, 2, 3].map(i => c.patch('/api/profile', { bio: 'v' + i }))); await login('alice', 'wrong');
  const events = (await c.get('/api/activity')).body.data.events;
  assert.ok(events.some(e => e.event === 'registration')); assert.ok(events.some(e => e.event === 'login_failed'));
  assert.deepEqual((await c.get('/api/activity/verify')).body.data, { valid: true, blocks: 5, brokenAt: null });
  await s.db.run("UPDATE activity_logs SET event='login' WHERE seq=2");
  assert.deepEqual((await c.get('/api/activity/verify')).body.data, { valid: false, blocks: 5, brokenAt: 2 });
});
test('two-factor: encrypted secret, login challenge, replay protection, recovery codes', async () => {
  const S = require('../src/security'), c = await signup();
  const { secret } = (await c.post('/api/mfa/setup', { currentPassword: PASSWORD })).body.data;
  assert.equal((await c.post('/api/mfa/enable', { code: 'abc' })).status, 422);
  const step = Math.floor(Date.now() / 30000);
  const on = await c.post('/api/mfa/enable', { code: S.totpAt(secret, step) }); assert.equal(on.status, 200, on.text);
  assert.ok(!(await s.db.get('SELECT totp_secret FROM users')).totp_secret.includes(secret));
  assert.equal((await login('alice')).r.body.error.code, 'MFA_REQUIRED');
  assert.equal((await login('alice', PASSWORD, { code: S.totpAt(secret, step) })).r.status, 401, 'used code cannot be replayed');
  assert.equal((await login('alice', PASSWORD, { code: S.totpAt(secret, step + 1) })).r.status, 200);
  const code = on.body.data.recoveryCodes[0];
  assert.equal((await login('alice', PASSWORD, { code })).r.status, 200);
  assert.equal((await login('alice', PASSWORD, { code })).r.status, 401);
  assert.equal((await c.post('/api/mfa/disable', { currentPassword: PASSWORD })).status, 200);
});
test('TOTP matches RFC 6238 SHA-1 vectors', () => {
  const S = require('../src/security'), k = S.base32(Buffer.from('12345678901234567890'));
  for (const [t, code] of [[59, '94287082'], [1111111109, '07081804'], [1234567890, '89005924'], [2000000000, '69279037']]) assert.equal(S.totpAt(k, Math.floor(t / 30), 8), code);
});
test('logs contain no secrets and errors expose no internals', async () => {
  const c = await signup(); const sid = c.jar.la_sid;
  const real = s.db.get; s.db.get = async () => { throw new Error(`boom ${PASSWORD} ${sid}`); };
  const r = await c.get('/api/auth/me'); s.db.get = real;
  assert.equal(r.status, 500); assert.ok(!/boom|stack|Vault!/.test(r.text));
  assert.equal(s.logs.length, 1); assert.ok(!s.logs[0].includes(PASSWORD) && !s.logs[0].includes(sid));
  const dump = JSON.stringify(await s.db.all('SELECT * FROM activity_logs')); assert.ok(!dump.includes(PASSWORD) && !dump.includes(sid));
});
