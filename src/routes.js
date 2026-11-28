'use strict';
const crypto = require('node:crypto');
const S = require('./security');
const { HttpError, validate, norm, str } = require('./validation');
const { HOUR } = require('./services');

function createRoutes({ db, cfg, svc, mail }) {
  const routes = [];
  const add = (method, path, handler, opts = {}) => routes.push({ method, parts: path.split('/'), handler, ...opts });
  const ok = (message, data = {}, status = 200) => ({ status, body: { success: true, message, data } });
  let dummyHash; const dummy = () => (dummyHash ||= S.hashPassword(S.randomToken()));

  async function publicUser(id) {
    const u = await db.get(`SELECT u.*, p.full_name, p.bio, p.location, f.theme, f.login_alerts, d.expires_at AS demo_expires
      FROM users u JOIN profiles p ON p.user_id=u.id JOIN user_preferences f ON f.user_id=u.id
      LEFT JOIN demo_accounts d ON d.user_id=u.id WHERE u.id=?`, [id]);
    return { fullName: u.full_name, username: u.username, email: u.email, bio: u.bio, location: u.location,
      emailVerified: !!u.email_verified_at, createdAt: u.created_at, passwordChangedAt: u.password_changed_at,
      isDemo: !!u.is_demo, demoExpiresAt: u.demo_expires || null, twoFactor: !!u.totp_secret,
      preferences: { theme: u.theme, loginAlerts: !!u.login_alerts } };
  }
  const notDemo = user => { if (user.is_demo) throw new HttpError(403, 'DEMO_RESTRICTED', 'This action is disabled for temporary demo accounts.'); };
  async function reauth(ctx, password) {
    await svc.rateLimit('reauth', ctx.user.id, 8, 15 * 60e3);
    if (!await S.verifyPassword(str(password).slice(0, 128), ctx.user.password_hash))
      throw new HttpError(403, 'REAUTH_FAILED', 'Password confirmation failed.', { currentPassword: 'Incorrect password.' });
  }
  async function issueToken(table, userId, ttl) {
    const token = S.randomToken();
    await db.tx([[`DELETE FROM ${table} WHERE user_id=?`, [userId]],
      [`INSERT INTO ${table}(token_hash,user_id,expires_at) VALUES(?,?,?)`, [S.sha256(token), userId, Date.now() + ttl]]]);
    return token; // goes only into the email; the link keeps it in the URL fragment so servers never log it
  }
  async function sendVerification(userId, email) {
    if (!mail.configured) return false;
    const token = await issueToken('email_verification_tokens', userId, 24 * HOUR);
    return mail.send(email, 'Verify your LOKI_AUTH email', `Verify your email (valid 24 hours):\n${cfg.baseUrl}/verify-email#token=${token}`);
  }
  async function taken(email, username, selfId = '') {
    const rows = await db.all('SELECT email, username FROM users WHERE (email=? OR username=?) AND id<>?', [email, username, selfId]);
    const f = {};
    if (rows.some(r => r.email === email)) f.email = 'An account already uses this email.';
    if (rows.some(r => r.username === username)) f.username = 'That username is taken.';
    return Object.keys(f).length ? new HttpError(409, 'CONFLICT', 'Account details already in use.', f) : null;
  }

  add('GET', '/api/health', async () => { await db.get('SELECT 1 AS ok'); return ok('Healthy.', { status: 'ok' }); });
  add('GET', '/api/config', async () => ok('Public configuration.', { emailConfigured: mail.configured, devOutbox: mail.provider === 'file', demoTtlMs: cfg.demoTtlMs }));

  add('POST', '/api/auth/register', async ctx => {
    await svc.rateLimit('register', ctx.ip, 5, HOUR);
    const v = validate(ctx.body, ['fullName', 'username', 'email', 'password']);
    if (ctx.body.confirmPassword !== v.password) throw new HttpError(422, 'VALIDATION', 'Please fix the highlighted fields.', { confirmPassword: 'Passwords do not match.' });
    if (ctx.body.acceptTerms !== true) throw new HttpError(422, 'VALIDATION', 'Please fix the highlighted fields.', { acceptTerms: 'You must accept the terms.' });
    const dup = await taken(v.email, v.username); if (dup) throw dup;
    const id = crypto.randomUUID(), t = Date.now(), session = svc.newSession(id, ctx.device, false);
    try {
      await db.tx([
        ['INSERT INTO users(id,email,username,password_hash,password_changed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)', [id, v.email, v.username, await S.hashPassword(v.password), t, t, t]],
        ['INSERT INTO profiles(user_id,full_name) VALUES(?,?)', [id, v.fullName]],
        ['INSERT INTO user_preferences(user_id) VALUES(?)', [id]], session.stmt]);
    } catch (e) { if (/UNIQUE/i.test(e.message)) throw (await taken(v.email, v.username)) || e; throw e; }
    ctx.setSession(session, false);
    await svc.log(id, 'registration', ctx.device);
    const sent = await sendVerification(id, v.email);
    return ok(sent ? 'Account created. A verification email was sent.' : 'Account created. No verification email was sent' + (mail.configured ? ' (delivery failed; try resending).' : ' because email is not configured.'),
      { user: await publicUser(id), emailSent: sent }, 201);
  });

  add('POST', '/api/auth/login', async ctx => {
    await svc.rateLimit('login-ip', ctx.ip, 30, 15 * 60e3);
    const id = norm(ctx.body.identifier).slice(0, 254), password = str(ctx.body.password).slice(0, 128);
    await svc.rateLimit('login-id', `${ctx.ip}|${id}`, 6, 15 * 60e3);
    const u = await db.get('SELECT * FROM users WHERE (email=? OR username=?) AND is_demo=0', [id, id]);
    const good = await S.verifyPassword(password, u ? u.password_hash : await dummy());
    const fail = new HttpError(401, 'INVALID_CREDENTIALS', 'Invalid email/username or password.');
    if (!u || !good) { if (u) await svc.log(u.id, 'login_failed', ctx.device); throw fail; }
    if (u.totp_secret) {
      const code = str(ctx.body.code).replace(/\s/g, '').toUpperCase();
      if (!code) throw new HttpError(401, 'MFA_REQUIRED', 'Enter your authenticator or recovery code.');
      await svc.rateLimit('mfa', u.id, 8, 15 * 60e3);
      const step = S.checkTotp(S.unseal(cfg.appSecret, u.totp_secret), code, u.totp_last_step);
      const claimed = step
        ? await db.get('UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<? RETURNING id', [step, u.id, step])
        : await db.get('DELETE FROM recovery_codes WHERE user_id=? AND code_hash=? RETURNING user_id', [u.id, S.sha256(code)]);
      if (!claimed) { await svc.log(u.id, 'login_failed', ctx.device); throw new HttpError(401, 'MFA_INVALID', 'That code is not valid.'); }
    }
    const remember = ctx.body.remember === true, session = svc.newSession(u.id, ctx.device, remember);
    // Session fixation defence: drop any session presented with this request, always mint a new token.
    await db.tx([['DELETE FROM sessions WHERE token_hash=?', [S.sha256(ctx.token || '')]], session.stmt]);
    ctx.setSession(session, remember);
    await svc.log(u.id, 'login', ctx.device);
    return ok('Signed in.', { user: await publicUser(u.id) });
  });

  add('POST', '/api/auth/logout', async ctx => {
    await db.run('DELETE FROM sessions WHERE id=?', [ctx.user.session_id]);
    await svc.log(ctx.user.id, 'logout', ctx.device); ctx.clearSession();
    return ok('Signed out.');
  }, { auth: true });

  add('GET', '/api/auth/me', async ctx => ok('Current user.', { user: await publicUser(ctx.user.id),
    session: { expiresAt: ctx.user.session_expires, remember: !!ctx.user.remember } }), { auth: true });

  add('POST', '/api/auth/forgot-password', async ctx => {
    await svc.rateLimit('forgot-ip', ctx.ip, 5, HOUR);
    const { email } = validate(ctx.body, ['email']);
    if (!mail.configured) return ok('Email delivery is not configured on this server, so no reset email can be sent.', { emailConfigured: false });
    // Not awaited: response time and content are the same whether or not the account exists.
    ctx.background((async () => {
      const u = await db.get('SELECT id FROM users WHERE email=? AND is_demo=0', [email]);
      if (!u) return;
      const token = await issueToken('password_reset_tokens', u.id, 30 * 60e3);
      await mail.send(email, 'Reset your LOKI_AUTH password', `Reset your password (valid 30 minutes):\n${cfg.baseUrl}/reset-password#token=${token}`);
    })());
    return ok('If an account exists for that address, a reset link will be sent.', { emailConfigured: true });
  });

  add('POST', '/api/auth/reset-password', async ctx => {
    await svc.rateLimit('reset-ip', ctx.ip, 10, HOUR);
    const { password } = validate(ctx.body, ['password']);
    if (ctx.body.confirmPassword !== password) throw new HttpError(422, 'VALIDATION', 'Passwords do not match.', { confirmPassword: 'Passwords do not match.' });
    const h = S.sha256(str(ctx.body.token)), t = Date.now(), passwordHash = await S.hashPassword(password);
    const owner = '(SELECT user_id FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?)';
    const [updated] = await db.tx([
      [`UPDATE users SET password_hash=?, password_changed_at=?, updated_at=? WHERE id=${owner} RETURNING id`, [passwordHash, t, t, h, t]],
      [`DELETE FROM sessions WHERE user_id=${owner}`, [h, t]],
      ['UPDATE password_reset_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL', [t, h]]]);
    if (!updated.length) throw new HttpError(400, 'INVALID_TOKEN', 'This reset link is invalid, expired or already used.');
    await svc.log(updated[0].id, 'password_reset', ctx.device); ctx.clearSession();
    return ok('Password updated. All sessions were signed out.');
  });

  add('POST', '/api/auth/verify-email', async ctx => {
    await svc.rateLimit('verify-ip', ctx.ip, 20, HOUR);
    const h = S.sha256(str(ctx.body.token)), t = Date.now();
    const [updated] = await db.tx([
      [`UPDATE users SET email_verified_at=?, updated_at=? WHERE id=(SELECT user_id FROM email_verification_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?) RETURNING id`, [t, t, h, t]],
      ['UPDATE email_verification_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL', [t, h]]]);
    if (!updated.length) throw new HttpError(400, 'INVALID_TOKEN', 'This verification link is invalid, expired or already used.');
    await svc.log(updated[0].id, 'email_verified', ctx.device);
    return ok('Email verified.');
  });

  add('POST', '/api/auth/resend-verification', async ctx => {
    notDemo(ctx.user);
    await svc.rateLimit('resend', ctx.user.id, 3, HOUR);
    if (ctx.user.email_verified_at) return ok('Your email is already verified.');
    if (!mail.configured) throw new HttpError(503, 'EMAIL_NOT_CONFIGURED', 'Email delivery is not configured on this server. Nothing was sent.');
    if (!await sendVerification(ctx.user.id, ctx.user.email)) throw new HttpError(502, 'EMAIL_FAILED', 'The email provider did not accept the message.');
    return ok('Verification email sent.');
  }, { auth: true });

  add('POST', '/api/auth/change-password', async ctx => {
    notDemo(ctx.user); await reauth(ctx, ctx.body.currentPassword);
    const { password } = validate(ctx.body, ['password']);
    if (ctx.body.confirmPassword !== password) throw new HttpError(422, 'VALIDATION', 'Passwords do not match.', { confirmPassword: 'Passwords do not match.' });
    if (password === ctx.body.currentPassword) throw new HttpError(422, 'VALIDATION', 'Choose a new password.', { password: 'Must differ from the current password.' });
    const t = Date.now(), session = svc.newSession(ctx.user.id, ctx.device, !!ctx.user.remember);
    await db.tx([
      ['UPDATE users SET password_hash=?, password_changed_at=?, updated_at=? WHERE id=?', [await S.hashPassword(password), t, t, ctx.user.id]],
      ['DELETE FROM sessions WHERE user_id=?', [ctx.user.id]],
      ['DELETE FROM password_reset_tokens WHERE user_id=?', [ctx.user.id]], session.stmt]);
    ctx.setSession(session, !!ctx.user.remember);
    await svc.log(ctx.user.id, 'password_changed', ctx.device);
    return ok('Password changed. Other devices were signed out.');
  }, { auth: true });

  add('POST', '/api/mfa/setup', async ctx => {
    notDemo(ctx.user); await reauth(ctx, ctx.body.currentPassword);
    if (ctx.user.totp_secret) throw new HttpError(409, 'MFA_ON', 'Two-factor authentication is already on.');
    const secret = S.base32(crypto.randomBytes(20));
    await db.run('UPDATE users SET totp_pending=? WHERE id=?', [S.seal(cfg.appSecret, secret), ctx.user.id]);
    return ok('Add this key to your authenticator app, then confirm a code.', { secret,
      uri: `otpauth://totp/LOKI_AUTH:${encodeURIComponent(ctx.user.username)}?secret=${secret}&issuer=LOKI_AUTH` });
  }, { auth: true });

  add('POST', '/api/mfa/enable', async ctx => {
    notDemo(ctx.user); await svc.rateLimit('mfa', ctx.user.id, 8, 15 * 60e3);
    const pending = ctx.user.totp_pending;
    const step = pending && S.checkTotp(S.unseal(cfg.appSecret, pending), str(ctx.body.code).trim());
    if (!step) throw new HttpError(422, 'MFA_INVALID', 'That code is not valid.', { code: 'Check the code and your device clock.' });
    const codes = Array.from({ length: 8 }, () => crypto.randomBytes(5).toString('hex').toUpperCase());
    await db.tx([['UPDATE users SET totp_secret=totp_pending, totp_pending=NULL, totp_last_step=? WHERE id=?', [step, ctx.user.id]],
      ['DELETE FROM recovery_codes WHERE user_id=?', [ctx.user.id]],
      ...codes.map(c => ['INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)', [ctx.user.id, S.sha256(c)]]),
      ['DELETE FROM sessions WHERE user_id=? AND id<>?', [ctx.user.id, ctx.user.session_id]]]);
    await svc.log(ctx.user.id, 'mfa_enabled', ctx.device);
    return ok('Two-factor authentication is on. Save your recovery codes now.', { recoveryCodes: codes });
  }, { auth: true });

  add('POST', '/api/mfa/disable', async ctx => {
    notDemo(ctx.user); await reauth(ctx, ctx.body.currentPassword);
    await db.tx([['UPDATE users SET totp_secret=NULL, totp_pending=NULL WHERE id=?', [ctx.user.id]],
      ['DELETE FROM recovery_codes WHERE user_id=?', [ctx.user.id]]]);
    await svc.log(ctx.user.id, 'mfa_disabled', ctx.device);
    return ok('Two-factor authentication is off.');
  }, { auth: true });

  add('GET', '/api/profile', async ctx => ok('Profile.', { user: await publicUser(ctx.user.id) }), { auth: true });

  add('PATCH', '/api/profile', async ctx => {
    const allowed = ['fullName', 'username', 'bio', 'location', 'theme', 'loginAlerts'];
    const keys = Object.keys(ctx.body);
    if (!keys.length || keys.some(k => !allowed.includes(k))) throw new HttpError(422, 'VALIDATION', 'The request contains fields that cannot be changed.');
    const v = validate(ctx.body, keys.filter(k => !['theme', 'loginAlerts'].includes(k)));
    if ('theme' in ctx.body && !['dark', 'light'].includes(ctx.body.theme)) throw new HttpError(422, 'VALIDATION', 'Invalid theme.');
    if ('loginAlerts' in ctx.body && typeof ctx.body.loginAlerts !== 'boolean') throw new HttpError(422, 'VALIDATION', 'Invalid preference.');
    const id = ctx.user.id, list = [['UPDATE users SET updated_at=? WHERE id=?', [Date.now(), id]]];
    if (v.username !== undefined && v.username !== ctx.user.username) {
      notDemo(ctx.user);
      const dup = await taken('', v.username, id); if (dup) throw dup;
      list.push(['UPDATE users SET username=? WHERE id=?', [v.username, id]]);
    }
    for (const [k, col] of [['fullName', 'full_name'], ['bio', 'bio'], ['location', 'location']])
      if (v[k] !== undefined) list.push([`UPDATE profiles SET ${col}=? WHERE user_id=?`, [v[k], id]]);
    if (ctx.body.theme) list.push(['UPDATE user_preferences SET theme=? WHERE user_id=?', [ctx.body.theme, id]]);
    if ('loginAlerts' in ctx.body) list.push(['UPDATE user_preferences SET login_alerts=? WHERE user_id=?', [ctx.body.loginAlerts ? 1 : 0, id]]);
    try { await db.tx(list); } catch (e) { if (/UNIQUE/i.test(e.message)) throw new HttpError(409, 'CONFLICT', 'That username is taken.', { username: 'That username is taken.' }); throw e; }
    await svc.log(id, 'profile_updated', ctx.device);
    return ok('Changes saved.', { user: await publicUser(id) });
  }, { auth: true });

  add('GET', '/api/sessions', async ctx => {
    const rows = await db.all('SELECT id,device,remember,created_at,last_seen_at,expires_at FROM sessions WHERE user_id=? AND expires_at>? ORDER BY created_at DESC', [ctx.user.id, Date.now()]);
    return ok('Active sessions.', { sessions: rows.map(r => ({ id: r.id, device: r.device, remember: !!r.remember, createdAt: r.created_at,
      lastSeenAt: r.last_seen_at, expiresAt: r.expires_at, current: r.id === ctx.user.session_id })) });
  }, { auth: true });

  add('DELETE', '/api/sessions/:id', async ctx => {
    const gone = await db.get('DELETE FROM sessions WHERE id=? AND user_id=? RETURNING id', [ctx.params.id, ctx.user.id]);
    if (!gone) throw new HttpError(404, 'NOT_FOUND', 'Session not found.');
    await svc.log(ctx.user.id, 'session_revoked', ctx.device);
    const current = gone.id === ctx.user.session_id; if (current) ctx.clearSession();
    return ok('Session revoked.', { current });
  }, { auth: true });

  add('POST', '/api/sessions/revoke-others', async ctx => {
    const gone = await db.all('DELETE FROM sessions WHERE user_id=? AND id<>? RETURNING id', [ctx.user.id, ctx.user.session_id]);
    await svc.log(ctx.user.id, 'sessions_revoked', ctx.device);
    return ok(`Signed out ${gone.length} other session(s).`, { revoked: gone.length });
  }, { auth: true });

  add('POST', '/api/sessions/logout-all', async ctx => {
    if (!ctx.user.is_demo) await reauth(ctx, ctx.body.currentPassword);
    await db.run('DELETE FROM sessions WHERE user_id=?', [ctx.user.id]);
    await svc.log(ctx.user.id, 'logout_all', ctx.device); ctx.clearSession();
    return ok('Signed out on all devices.');
  }, { auth: true });

  add('GET', '/api/activity', async ctx => {
    const rows = await db.all('SELECT seq,event,device,created_at,hash FROM activity_logs WHERE user_id=? ORDER BY seq DESC LIMIT 100', [ctx.user.id]);
    return ok('Activity.', { events: rows.map(r => ({ seq: r.seq, event: r.event, device: r.device, createdAt: r.created_at, hash: r.hash.slice(0, 16) })) });
  }, { auth: true });

  add('GET', '/api/activity/verify', async ctx => ok('Chain checked.', await svc.verifyChain(ctx.user.id)), { auth: true });

  // Demo only: adds a real second session row so revocation can be tried on one device. Its token is discarded.
  add('POST', '/api/demo/test-session', async ctx => {
    if (!ctx.user.is_demo) throw new HttpError(403, 'DEMO_ONLY', 'Available to demo accounts only.');
    await svc.rateLimit('test-session', ctx.user.id, 5, HOUR);
    await db.tx([svc.newSession(ctx.user.id, 'Test device (created by you)', false, ctx.user.demo_expires).stmt]);
    await svc.log(ctx.user.id, 'test_session_created', ctx.device);
    return ok('Test session created.');
  }, { auth: true });

  add('POST', '/api/demo/start', async ctx => {
    await svc.rateLimit('demo', ctx.ip, 10, HOUR);
    await svc.cleanup();
    const { id, session } = await svc.startDemo(ctx.device);
    if (ctx.token) await db.run('DELETE FROM sessions WHERE token_hash=?', [S.sha256(ctx.token)]);
    ctx.setSession(session, false);
    const user = await publicUser(id);
    return ok('Demo workspace ready.', { user, expiresAt: user.demoExpiresAt }, 201);
  });

  add('DELETE', '/api/account', async ctx => {
    if (ctx.body.confirm !== 'DELETE') throw new HttpError(422, 'VALIDATION', 'Type DELETE to confirm.', { confirm: 'Type DELETE exactly.' });
    if (!ctx.user.is_demo) await reauth(ctx, ctx.body.currentPassword);
    // Hard delete (cascades). Only a keyed hash and timestamp remain as proof of the request.
    await db.tx([['INSERT INTO account_deletions(ref_hash,deleted_at) VALUES(?,?)', [S.hmac(cfg.appSecret, ctx.user.id), Date.now()]],
      ['DELETE FROM users WHERE id=?', [ctx.user.id]]]);
    ctx.clearSession();
    return ok('Your account and its data were deleted.');
  }, { auth: true });

  return function match(method, pathname) {
    const parts = pathname.split('/');
    for (const r of routes) {
      if (r.method !== method || r.parts.length !== parts.length) continue;
      const params = {};
      if (r.parts.every((p, i) => p.startsWith(':') ? (params[p.slice(1)] = parts[i]) : p === parts[i])) return { ...r, params };
    }
    return null;
  };
}
module.exports = { createRoutes };
