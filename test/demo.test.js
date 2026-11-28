'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { start, PASSWORD } = require('./helpers');

test('demo creates a unique account with a real session and safe output', async () => {
  const s = await start(), c = s.client(), r = await c.post('/api/demo/start');
  assert.equal(r.status, 201); assert.ok(r.body.data.user.isDemo); assert.ok(r.body.data.expiresAt > Date.now());
  assert.ok(!/password_hash|scrypt|token/i.test(r.text));
  assert.equal((await c.get('/api/sessions')).body.data.sessions.length, 1);
  assert.equal((await c.get('/api/activity')).body.data.events[0].event, 'demo_started');
  await s.stop();
});
test('concurrent demo requests create independent accounts', async () => {
  const s = await start(), clients = Array.from({ length: 8 }, () => s.client());
  const out = await Promise.all(clients.map(c => c.post('/api/demo/start')));
  assert.ok(out.every(r => r.status === 201));
  assert.equal(new Set(out.map(r => r.body.data.user.username)).size, 8);
  assert.equal(new Set(clients.map(c => c.jar.la_sid)).size, 8);
  await s.stop();
});
test('demo restrictions and isolation', async () => {
  const s = await start(), a = s.client(), b = s.client(); await a.post('/api/demo/start'); await b.post('/api/demo/start');
  for (const u of ['/api/auth/change-password', '/api/mfa/setup', '/api/mfa/disable', '/api/auth/resend-verification']) assert.equal((await a.post(u, { currentPassword: PASSWORD })).body.error.code, 'DEMO_RESTRICTED', u);
  assert.equal((await a.patch('/api/profile', { username: 'taken_over' })).status, 403);
  assert.equal((await a.get('/api/admin')).status, 404);
  const other = (await b.get('/api/sessions')).body.data.sessions[0];
  assert.equal((await a.del('/api/sessions/' + other.id)).status, 404);
  assert.equal((await a.post('/api/demo/test-session')).status, 200);
  assert.equal((await a.get('/api/sessions')).body.data.sessions.length, 2);
  assert.equal((await a.del('/api/account', { confirm: 'DELETE' })).status, 200);
  assert.equal((await b.get('/api/auth/me')).status, 200);
  await s.stop();
});
test('expiry is enforced by the server, then cleanup removes every related row', async () => {
  const s = await start({ DEMO_TTL_MS: '1000' }), c = s.client(); await c.post('/api/demo/start');
  await new Promise(r => setTimeout(r, 1100));
  assert.equal((await c.get('/api/auth/me')).body.error.code, 'DEMO_EXPIRED');
  assert.equal((await c.patch('/api/profile', { bio: 'late' })).status, 401);
  await s.app.svc.cleanup(0);
  for (const t of ['users', 'sessions', 'profiles', 'activity_logs', 'demo_accounts', 'user_preferences']) assert.equal((await s.db.get(`SELECT COUNT(*) AS n FROM ${t}`)).n, 0, t);
  assert.equal((await c.get('/api/auth/me')).status, 401);
  await s.stop();
});
