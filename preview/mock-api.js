'use strict';
// STATIC PREVIEW ONLY. A throwaway in-memory simulation for viewing the design without a server.
// It provides no security and is never loaded by the real application.
(() => {
  let me = null, sessions = [], events = [];
  const MINUTES = 30, now = () => Date.now(), id = () => Math.random().toString(36).slice(2, 12);
  const ok = (message, data = {}) => ({ success: true, message, data });
  const fail = (code, message, fields) => ({ success: false, message, error: { code, fields } });
  const log = event => events.unshift({ seq: events.length + 1, event, device: 'Preview browser', createdAt: now(), hash: id() + id().slice(0, 6) });
  const session = (device, current) => ({ id: id(), device, current, remember: false, createdAt: now(), lastSeenAt: now(), expiresAt: me.demoExpiresAt });
  window.LOKI_MOCK = async (method, url, body = {}) => {
    await new Promise(r => setTimeout(r, 220));
    const key = method + ' ' + url;
    if (key === 'GET /api/config') return ok('', { emailConfigured: false });
    if (key === 'POST /api/demo/start') {
      const t = now();
      me = { fullName: 'Demo Explorer', username: 'demo_' + id(), email: 'preview@demo.invalid', bio: '', location: '', emailVerified: false, createdAt: t, passwordChangedAt: t, isDemo: true, demoExpiresAt: t + MINUTES * 60000, twoFactor: false, preferences: { theme: document.documentElement.dataset.theme, loginAlerts: true } };
      sessions = [session('Preview browser', true)]; events = []; log('demo_started');
      return ok('Preview demo ready (simulated).', { user: me });
    }
    if (method === 'POST' && url.startsWith('/api/auth/') && url !== '/api/auth/logout') return fail('PREVIEW', 'Accounts need the real server. This static preview only offers the simulated demo.');
    if (!me) return fail('UNAUTHENTICATED', 'Please start the demo.');
    if (now() >= me.demoExpiresAt) { me = null; return fail('DEMO_EXPIRED', 'This demo has expired.'); }
    const end = msg => { me = null; return ok(msg, { current: true }); };
    if (key === 'GET /api/auth/me') return ok('', { user: me });
    if (key === 'GET /api/sessions') return ok('', { sessions });
    if (key === 'GET /api/activity') return ok('', { events });
    if (key === 'GET /api/activity/verify') return ok('', { valid: true, blocks: events.length });
    if (key === 'PATCH /api/profile') {
      if (body.fullName !== undefined && body.fullName.trim().length < 2) return fail('VALIDATION', 'Please fix the highlighted fields.', { fullName: 'Use at least 2 characters.' });
      const { theme, loginAlerts, ...rest } = body;
      me = { ...me, ...rest, preferences: { theme: theme || me.preferences.theme, loginAlerts: loginAlerts ?? me.preferences.loginAlerts } };
      log('profile_updated'); return ok('Saved in this preview tab only.', { user: me });
    }
    if (key === 'POST /api/demo/test-session') { sessions.push(session('Test device (created by you)', false)); log('test_session_created'); return ok('Test session created (simulated).'); }
    if (key === 'POST /api/sessions/revoke-others') { sessions = sessions.filter(s => s.current); log('sessions_revoked'); return ok('Other sessions removed (simulated).'); }
    if (method === 'DELETE' && url.startsWith('/api/sessions/')) { const s = sessions.find(x => url.endsWith(x.id)); if (s?.current) return end('Preview session ended.'); sessions = sessions.filter(x => x !== s); log('session_revoked'); return ok('Session removed (simulated).'); }
    if (key === 'DELETE /api/account') return body.confirm === 'DELETE' ? end('Preview account cleared.') : fail('VALIDATION', 'Type DELETE to confirm.', { confirm: 'Type DELETE exactly.' });
    if (['POST /api/auth/logout', 'POST /api/sessions/logout-all'].includes(key)) return end('Preview session ended.');
    return fail('PREVIEW', 'This needs the real server.');
  };
})();
