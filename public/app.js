'use strict';
(() => {
const PREVIEW = !!window.LOKI_MOCK;
const $ = (s, el = document) => el.querySelector(s), $$ = (s, el = document) => [...el.querySelectorAll(s)];
const root = $('#root');

/* ---------- safe templating: every interpolated value is escaped unless it is an h`` result ---------- */
class Safe { constructor(s) { this.s = s; } toString() { return this.s; } }
const esc = v => String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const part = v => v instanceof Safe ? v.s : Array.isArray(v) ? v.map(part).join('') : v === false || v == null ? '' : esc(v);
const h = (strings, ...vals) => new Safe(strings.reduce((a, s, i) => a + s + (i < vals.length ? part(vals[i]) : ''), ''));

/* ---------- API ---------- */
let csrf = '', state = { user: null, session: null }, config = { emailConfigured: false };
async function api(method, url, body, retried) {
  if (PREVIEW) return unwrap(await window.LOKI_MOCK(method, url, body));
  let res, json;
  try {
    if (method !== 'GET' && !csrf) csrf = (await (await fetch('/api/csrf', { credentials: 'same-origin' })).json()).data.token;
    res = await fetch(url, { method, credentials: 'same-origin', signal: AbortSignal.timeout(20000),
      headers: method === 'GET' ? {} : { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: method === 'GET' ? undefined : JSON.stringify(body || {}) });
    json = await res.json();
  } catch { throw Object.assign(new Error('Network problem. Check your connection and try again.'), { code: 'NETWORK' }); }
  if (json.error?.code === 'CSRF' && !retried) { csrf = ''; return api(method, url, body, true); }
  if (method !== 'GET' && json.success) csrf = ''; // the CSRF seed rotates with new sessions
  return unwrap(json);
}
function unwrap(json) {
  if (json.success) return { ...json.data, message: json.message };
  const e = Object.assign(new Error(json.message), { code: json.error?.code, fields: json.error?.fields });
  if (['DEMO_EXPIRED', 'SESSION_EXPIRED', 'UNAUTHENTICATED'].includes(e.code) && state.user) {
    const wasDemo = state.user.isDemo; state.user = null; $$('dialog').forEach(d => d.remove());
    if (e.code === 'DEMO_EXPIRED' || (wasDemo && Date.now() >= demoEnd)) go('/demo-expired'); else { toast(e.message, true); go('/login'); }
  }
  throw e;
}
let demoEnd = 0;
function setUser(u) { state.user = u; if (u) { demoEnd = u.demoExpiresAt || 0; applyTheme(u.preferences.theme); } }

/* ---------- UI helpers ---------- */
function toast(msg, bad) { const t = document.createElement('div'); t.className = 'toast' + (bad ? ' bad' : ''); t.textContent = msg; $('#toasts').append(t); setTimeout(() => t.remove(), 5200); }
function applyTheme(t) { document.documentElement.dataset.theme = t; try { localStorage.setItem('loki-theme', t); } catch {} }
const when = t => new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const LABELS = { registration: 'Account registered', login: 'Signed in', logout: 'Signed out', login_failed: 'Failed sign-in attempt', password_changed: 'Password changed', password_reset: 'Password reset', email_verified: 'Email verified', session_revoked: 'Session revoked', sessions_revoked: 'Other sessions revoked', logout_all: 'Signed out everywhere', profile_updated: 'Account updated', demo_started: 'Demo started', test_session_created: 'Test session created', mfa_enabled: 'Two-factor enabled', mfa_disabled: 'Two-factor disabled' };
const label = e => LABELS[e] || e;

const mark = h`<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 3 43 13.5v21L24 45 5 34.500v-21Z" fill="#0b1730" stroke="#38e1ff" stroke-width="2"/><path d="M5 13.500 24 24l19-10.500M24 24v21" fill="none" stroke="#4d7cff" stroke-width="1.500" opacity=".6"/><circle cx="24" cy="22" r="5.500" fill="#38e1ff"/><path d="M21.500 25h5l2 10h-9z" fill="#38e1ff"/></svg>`;
const brand = h`<a class="brand" href="/">${mark}<span>LOKI_AUTH<small>BLOCK-SOLID VAULT</small></span></a>`;

/* ---------- router (History API on the server, hash routing in the static preview) ---------- */
const path = () => PREVIEW ? (location.hash.slice(1).split('?')[0] || '/') : location.pathname;
function go(to, replace) {
  if (PREVIEW) { if (location.hash === '#' + to) render(); else if (replace) { history.replaceState(null, '', '#' + to); render(); } else location.hash = to; }
  else { history[replace ? 'replaceState' : 'pushState'](null, '', to); render(); }
}
document.addEventListener('click', e => {
  const a = e.target.closest('a[href^="/"]');
  if (!a || e.ctrlKey || e.metaKey || e.button) return;
  e.preventDefault(); go(a.getAttribute('href'));
});
addEventListener(PREVIEW ? 'hashchange' : 'popstate', () => render());

function shell(content, { bare } = {}) {
  const p = path(), u = state.user;
  const nl = (to, t) => h`<a href="${to}" ${p === to ? h`aria-current="page"` : ''}>${t}</a>`;
  return h`${PREVIEW ? h`<div class="preview-flag">STATIC PREVIEW · simulated in this browser tab, no real security · never type a real password</div>` : ''}
  <header class="nav"><div class="wrap">${brand}<span class="lb" title="Created by LOKESH B">&lt;LB/&gt; LOKESH B</span>
    <button class="btn sm burger" data-act="menu" aria-expanded="false" aria-controls="menu">Menu</button>
    <nav class="links" id="menu" aria-label="Main">${nl('/', 'Home')}${nl('/security', 'Security')}${nl('/about', 'About')}
    <button class="btn sm" data-act="theme">Theme</button><button class="btn sm" data-act="palette" aria-label="Open command palette">⌘K</button>
    ${u ? h`<a class="btn sm primary" href="/dashboard">Dashboard</a>` : h`${nl('/login', 'Sign In')}<a class="btn sm primary" href="/register">Get Started</a>`}</nav></div></header>
  ${content}
  ${bare ? '' : h`<footer><div class="wrap row between"><div>${brand}<p class="mute small">Your Identity. Your Control. Your Security.<br>Created by <b>LOKESH B</b> &lt;LB/&gt;</p></div>
  <nav class="row small" aria-label="Footer"><a href="/about">About</a><a href="/security">Security</a><a href="/privacy">Privacy Policy</a><a href="/terms">Terms of Service</a><a href="/contact">Contact</a></nav></div></footer>`}`;
}

/* ---------- public pages ---------- */
const FEATURES = [['KDF', 'Memory-hard passwords', 'Salted scrypt hashes. Plain-text passwords are never stored.'], ['SID', 'Server-side sessions', 'HttpOnly cookies, hashed tokens, instant revocation per device.'], ['2FA', 'Authenticator codes', 'TOTP with single-use recovery codes and replay protection.'], ['⛓', 'Block-chained activity', 'Each security event is HMAC-linked to the one before. Verify it yourself.'], ['CSRF', 'Layered request defence', 'Signed CSRF tokens, origin checks, strict CSP and rate limits.'], ['⌛', 'Disposable live demo', 'A private temporary account, expired by the server and then deleted.']];
const FAQ = [['Is the live demo a shared account?', 'No. Every click creates its own account with a random password nobody sees, including you.'], ['Where are passwords stored?', 'Only a salted scrypt hash is stored.'], ['Why did I not get an email?', 'Email only works when the operator configures a provider. The app says so when it is not configured.'], ['Can LOKI_AUTH read my authenticator codes?', 'The server stores your TOTP secret encrypted, because it needs it to check codes.']];
function landing() {
  return shell(h`<main id="main" class="wrap">
  <section class="hero"><div class="stack">
    <span class="pill"><span class="dot"></span> The Block-Solid Authentication &amp; Identity Vault</span>
    <h1>LOKI_AUTH<br><span class="grad" data-scramble>Your identity, locked block by block.</span></h1>
    <p class="mute">Your Identity. Your Control. Your Security. Real sessions, two-factor sign-in and a verifiable history of what happened to your account.</p>
    <div class="row"><button class="btn cyan" data-act="demo">▶ Try Live Demo</button><a class="btn primary" href="/register">Get Started</a><a class="btn" href="/login">Sign In</a></div>
    <p class="small mute">Demo: one click, no sign-up, no shared password. Crafted by <b>LOKESH B</b>.</p></div>
    <canvas id="vault" role="img" aria-label="Rotating shield assembled from blocks with a glowing keyhole"></canvas></section>
  <section class="block"><h2>Security features</h2><br><div class="grid">${FEATURES.map(f => h`<article class="card reveal"><div class="ico">${f[0]}</div><h3>${f[1]}</h3><p class="mute">${f[2]}</p></article>`)}</div></section>
  <section class="block"><h2>How authentication works</h2><br><div class="grid flow">${[['Prove', 'You submit credentials. The server compares a scrypt hash in constant time.'], ['Challenge', 'If two-factor is on, a fresh authenticator or recovery code is required.'], ['Issue', 'A new random session token goes into an HttpOnly cookie. Only its hash is stored.'], ['Control', 'See every session and revoke any of them immediately.']].map(s => h`<article class="card reveal"><h3>${s[0]}</h3><p class="mute">${s[1]}</p></article>`)}</div></section>
  <section class="block"><h2>Security architecture</h2><p class="mute">Every state-changing request passes through each layer in order.</p><br><div class="arch">${[['1 · Browser', 'CSP, escaped rendering'], ['2 · Edge checks', 'Origin, CSRF, size limits'], ['3 · Abuse control', 'Database-backed rate limits'], ['4 · Identity', 'Session lookup and authorization'], ['5 · Data', 'Parameterized, atomic queries']].map(a => h`<div><b>${a[0]}</b><p class="small mute">${a[1]}</p></div>`)}</div></section>
  <section class="block card reveal"><h2>Privacy by restraint</h2><p class="mute">No analytics, trackers or third-party scripts. Sessions show only a coarse browser and operating-system label. IP addresses are not stored; rate-limit keys are keyed hashes. <a href="/privacy">Read the Privacy Policy</a>.</p></section>
  <section class="block"><h2>Frequently asked questions</h2>${FAQ.map(q => h`<details><summary>${q[0]}</summary><p class="mute">${q[1]}</p></details>`)}</section></main>`);
}
const DOCS = {
  '/about': ['About LOKI_AUTH', [['The project', 'LOKI_AUTH — The Block-Solid Authentication & Identity Vault is a full-stack identity platform: registration, sign-in, two-factor, session control and a verifiable activity chain.'], ['Created by LOKESH B', 'Designed and branded by LOKESH B <LB/>, an IT undergraduate focused on cybersecurity.']]],
  '/security': ['Security', [['Passwords and sessions', 'Passwords use salted scrypt. Session, reset and verification tokens are random and stored only as SHA-256 hashes.'], ['Requests', 'Signed CSRF tokens, exact-origin checks, a strict Content Security Policy and rate limits protect state-changing requests.'], ['Activity chain', 'Events are linked with keyed hashes, so editing or removing an earlier record is detectable. Removing only the newest records, or an attacker holding the server secret, would not be detected.'], ['Honest limits', 'This project has not had an independent security audit. No system is unbreakable.']]],
  '/privacy': ['Privacy Policy', [['What is stored', 'Name, username, email, optional bio and location, a password hash, session records with a coarse device label, preferences and account activity.'], ['What is not stored', 'Plain-text passwords, raw session tokens, IP addresses, trackers or advertising identifiers.'], ['Retention and deletion', 'Deleting your account removes your records immediately; a keyed reference and time of deletion remain. Demo accounts are removed about one hour after they expire.'], ['Third parties', 'The operator may use a hosting provider, a Turso database and an email provider, which process data to run the service.']]],
  '/terms': ['Terms of Service', [['Use', 'Use the service lawfully. Do not attack it, access other people’s accounts or automate abuse.'], ['Demo', 'Demo accounts are temporary. Do not put personal information in them.'], ['No warranty', 'This is a portfolio project provided as is, without warranty. These terms are a template, not legal advice.']]],
  '/contact': ['Contact & Support', [['Support', 'LOKI_AUTH is maintained by LOKESH B. For help, contact the person or team who shared this deployment with you, or open an issue in the project repository.'], ['Reporting a vulnerability', 'Report it privately to the maintainer. Include steps to reproduce, and do not access data that is not yours.'], ['Before you ask', 'Never send your password, codes or reset links to anyone, including the maintainer.']]],
};
const docPage = ([title, parts]) => shell(h`<main id="main" class="wrap stack"><br><h1>${title}</h1>${parts.map(p => h`<section class="card reveal"><h2>${p[0]}</h2><p class="mute">${p[1]}</p></section>`)}</main>`);
const notice = (title, text, actions) => shell(h`<main id="main" class="wrap"><section class="card auth stack panel"><h1>${title}</h1><p class="mute">${text}</p><div class="row">${actions}</div></section></main>`);

/* ---------- forms ---------- */
const field = (name, text, type = 'text', auto = 'off', value = '') => h`<div><label for="f-${name}">${text}</label>
  <div class="${type === 'password' ? 'pw' : ''}"><input id="f-${name}" name="${name}" type="${type}" autocomplete="${auto}" value="${value}" aria-describedby="e-${name}">
  ${type === 'password' ? h`<button type="button" data-act="reveal" aria-label="Show ${text}">Show</button>` : ''}</div><p class="err" id="e-${name}"></p></div>`;
const box = (name, text, checked) => h`<div><label class="check"><input type="checkbox" name="${name}" ${checked ? h`checked` : ''}> <span>${text}</span></label><p class="err" id="e-${name}"></p></div>`;
const strength = h`<div class="meter" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i></div><p class="small mute" id="meter-text">10+ characters with upper, lower, number and symbol.</p>`;
const form = (id, body, button, cls = 'primary') => h`<form class="stack" data-form="${id}" novalidate><div class="alert bad" role="alert" hidden></div>${body}<button class="btn ${cls}" type="submit">${button}</button></form>`;

function bindForm(name, onSubmit) {
  const f = $(`[data-form="${name}"]`); if (!f) return;
  f.addEventListener('submit', async e => {
    e.preventDefault(); const btn = $('[type=submit]', f); if (btn.disabled) return;
    const alertBox = $('.alert', f); alertBox.hidden = true;
    $$('.err', f).forEach(x => x.textContent = ''); $$('[aria-invalid]', f).forEach(x => x.removeAttribute('aria-invalid'));
    const data = {}; $$('input[name],textarea[name]', f).forEach(i => data[i.name] = i.type === 'checkbox' ? i.checked : i.value);
    const missing = $$('input[name],textarea[name]', f).filter(i => i.type !== 'checkbox' && !i.value.trim() && !i.closest('[hidden]') && !['bio', 'location'].includes(i.name));
    const show = (k, msg) => { const out = $(`#e-${k}`, f), inp = f.elements[k]; if (out) out.textContent = msg; if (inp) inp.setAttribute('aria-invalid', 'true'); };
    if (missing.length) { missing.forEach(i => show(i.name, 'This field is required.')); return missing[0].focus(); }
    btn.disabled = true; btn.classList.add('busy');
    try { await onSubmit(data, f); }
    catch (err) {
      Object.entries(err.fields || {}).forEach(([k, m]) => show(k, m));
      alertBox.textContent = err.message; alertBox.hidden = false; f.classList.remove('shake'); void f.offsetWidth; f.classList.add('shake');
      if (err.code === 'MFA_REQUIRED') { $('#mfa', f).hidden = false; f.elements.code.focus(); }
      $('[aria-invalid]', f)?.focus();
    } finally { btn.disabled = false; btn.classList.remove('busy'); }
  });
}
function bindMeter() {
  const input = $('[data-form] #f-password'), meter = $('.meter'); if (!input || !meter) return;
  input.addEventListener('input', () => {
    const v = input.value, sets = [[/[a-z]/, 26], [/[A-Z]/, 26], [/\d/, 10], [/[^A-Za-z0-9]/, 32]].filter(s => s[0].test(v));
    // Upper-bound entropy estimate, discounted for repeated characters.
    const bits = Math.round(Math.min(v.length, new Set(v).size * 2) * Math.log2(sets.reduce((a, s) => a + s[1], 0) || 1));
    const ok = v.length >= 10 && sets.length === 4;
    const level = !v ? 0 : Math.min(ok ? 5 : 3, Math.max(1, Math.floor(bits / 16)));
    meter.dataset.l = level; $$('i', meter).forEach((x, i) => x.classList.toggle('on', i < level));
    $('#meter-text').textContent = v ? `${ok ? 'Meets the format rules' : 'Not yet meeting the rules'} · rough estimate ${bits} bits` : '10+ characters with upper, lower, number and symbol.';
  });
}
const authPage = (title, sub, body) => shell(h`<main id="main" class="wrap"><section class="card auth stack panel"><div class="row between">${brand}<span class="lb">LOKESH B</span></div><h1>${title}</h1><p class="mute">${sub}</p>${body}</section></main>`);
const emailNote = () => config.emailConfigured ? (config.devOutbox ? h`<p class="alert warn small">Development mode: emails are written to the server’s local outbox file, not sent.</p>` : '') : h`<p class="alert warn small">Email delivery is not configured here, so verification and reset emails are not sent.</p>`;
const tokenFromUrl = () => new URLSearchParams(PREVIEW ? location.hash.split('?')[1] : location.hash.slice(1)).get('token') || '';
let linkToken = '';

const AUTH = {
  '/register': () => authPage('Create your vault', 'Takes under a minute.', h`${emailNote()}${form('register', h`${field('fullName', 'Full name', 'text', 'name')}${field('username', 'Username', 'text', 'username')}${field('email', 'Email address', 'email', 'email')}<div>${field('password', 'Password', 'password', 'new-password')}${strength}</div>${field('confirmPassword', 'Confirm password', 'password', 'new-password')}${box('acceptTerms', h`I accept the <a href="/terms">Terms</a> and <a href="/privacy">Privacy Policy</a>.`)}`, 'Create account')}<p class="small">Already registered? <a href="/login">Sign in</a></p>`),
  '/login': () => authPage('Welcome back', 'Sign in with your email or username.', h`${form('login', h`${field('identifier', 'Email or username', 'text', 'username')}${field('password', 'Password', 'password', 'current-password')}<div id="mfa" hidden>${field('code', 'Authenticator or recovery code', 'text', 'one-time-code')}</div>${box('remember', 'Remember me for 30 days')}`, 'Sign In')}<div class="row between small"><a href="/forgot-password">Forgot password?</a><a href="/register">Create an account</a></div><button class="btn cyan" data-act="demo">▶ Try Live Demo (no password needed)</button>`),
  '/forgot-password': () => authPage('Forgot password', 'We never reveal whether an address has an account.', h`${emailNote()}${form('forgot', field('email', 'Email address', 'email', 'email'), 'Request reset link')}<p class="small"><a href="/login">Back to sign in</a></p>`),
  '/reset-password': () => authPage('Choose a new password', 'All existing sessions will be signed out.', linkToken ? form('reset', h`<div>${field('password', 'New password', 'password', 'new-password')}${strength}</div>${field('confirmPassword', 'Confirm password', 'password', 'new-password')}`, 'Update password') : h`<p class="alert bad">This page needs a reset link from your email.</p><a class="btn" href="/forgot-password">Request a link</a>`),
  '/verify-email': () => authPage('Verify your email', 'Confirm that this address is yours.', linkToken ? form('verify', '', 'Verify email') : h`<p class="alert bad">This page needs a verification link from your email.</p><a class="btn" href="/dashboard">Go to dashboard</a>`),
};
function bindAuth() {
  const enter = r => { setUser(r.user); toast(r.message); go('/dashboard'); };
  bindForm('register', async d => enter(await api('POST', '/api/auth/register', d)));
  bindForm('login', async d => enter(await api('POST', '/api/auth/login', d)));
  const done = (f, msg, to, text) => { f.outerHTML = h`<div class="alert ok" role="status">${msg}</div><a class="btn primary" href="${to}">${text}</a>`.s; };
  bindForm('forgot', async (d, f) => done(f, (await api('POST', '/api/auth/forgot-password', d)).message, '/login', 'Back to sign in'));
  bindForm('reset', async (d, f) => { const r = await api('POST', '/api/auth/reset-password', { ...d, token: linkToken }); linkToken = ''; state.user = null; done(f, r.message, '/login', 'Sign in'); });
  bindForm('verify', async (d, f) => { const r = await api('POST', '/api/auth/verify-email', { token: linkToken }); linkToken = ''; if (state.user) state.user.emailVerified = true; done(f, r.message, '/dashboard', 'Continue'); });
}

/* ---------- dashboard ---------- */
const TABS = [['/dashboard', 'Overview'], ['/dashboard/profile', 'Profile'], ['/dashboard/security', 'Security Center'], ['/dashboard/sessions', 'Sessions'], ['/dashboard/activity', 'Activity Chain'], ['/dashboard/settings', 'Settings']];
function checklist(u, sessions) {
  // Score = share of these real conditions that are met.
  return [[u.emailVerified, 'Email address verified', '/dashboard/settings'], [u.twoFactor, 'Two-factor authentication on', '/dashboard/security'],
    [!!(u.bio && u.location), 'Profile bio and location filled in', '/dashboard/profile'], [sessions.length <= 3, 'Three or fewer active sessions', '/dashboard/sessions'], [u.preferences.loginAlerts, 'New-login indicators enabled', '/dashboard/settings']];
}
const checkRows = list => list.map(c => h`<div class="item"><span>${c[1]}</span>${c[0] ? h`<span class="badge ok">✓ Met</span>` : h`<a class="badge warn" href="${c[2]}">Improve →</a>`}</div>`);
const isNew = (s, u) => u.preferences.loginAlerts && !s.current && Date.now() - s.createdAt < 864e5;
const sessionRows = (list, u) => list.map(s => h`<div class="item"><div><b>${s.device}</b> ${s.current ? h`<span class="badge ok"><span>This session</span></span>` : isNew(s, u) ? h`<span class="badge warn">New sign-in</span>` : ''}<p class="small mute">Started ${when(s.createdAt)} · last seen ${when(s.lastSeenAt)} · expires ${when(s.expiresAt)}${s.remember ? ' · remembered' : ''}</p></div><button class="btn sm danger" data-revoke="${s.id}">${s.current ? 'End this session' : 'Revoke'}</button></div>`);
function orbit(list) {
  return h`<svg class="orbit" viewBox="0 0 300 300" role="img" aria-label="${list.length} active sessions orbiting your account"><circle class="ring" cx="150" cy="150" r="72"/><circle class="ring" cx="150" cy="150" r="118"/><g class="spin">${list.slice(0, 12).map((s, i) => { const a = i / Math.min(list.length, 12) * 6.283, r = s.current ? 72 : 118, x = (150 + r * Math.cos(a)).toFixed(1), y = (150 + r * Math.sin(a)).toFixed(1); return h`<line x1="150" y1="150" x2="${x}" y2="${y}" stroke="${s.current ? '#3ee6a0' : '#4d7cff'}" opacity=".45"/><rect x="${x - 9}" y="${y - 9}" width="18" height="18" rx="4" fill="${s.current ? '#3ee6a0' : '#4d7cff'}"><title>${s.device}</title></rect>`; })}</g><circle cx="150" cy="150" r="30" fill="#0b1730" stroke="#38e1ff" stroke-width="2"/><text x="150" y="156" text-anchor="middle" fill="#38e1ff" font-weight="800">YOU</text></svg>`;
}
const demoLock = what => h`<p class="alert warn small">${what} is disabled in demo accounts, because their random password is never revealed. <a href="/register">Create a free account</a> to use it.</p>`;
const PANELS = {
  async '/dashboard'(u) {
    const [{ sessions }, { events }] = await Promise.all([api('GET', '/api/sessions'), api('GET', '/api/activity')]);
    const list = checklist(u, sessions), score = Math.round(list.filter(c => c[0]).length / list.length * 100), logins = events.filter(e => ['login', 'login_failed', 'registration', 'demo_started'].includes(e.event)).slice(0, 5);
    const counts = Object.entries(events.reduce((a, e) => (a[e.event] = (a[e.event] || 0) + 1, a), {})), max = Math.max(1, ...counts.map(c => c[1])), fresh = sessions.filter(s => isNew(s, u));
    return h`<h1>Welcome, ${u.fullName}</h1><p class="mute">@${u.username} · member since ${when(u.createdAt)}</p><br>
    ${fresh.length ? h`<p class="alert warn">${fresh.length} other new sign-in(s) in the last 24 hours. <a href="/dashboard/sessions">Review sessions</a></p><br>` : ''}
    <div class="grid stats"><div class="card row"><svg class="score" viewBox="0 0 120 120" role="img" aria-label="Security score ${score} of 100"><defs><linearGradient id="sg"><stop stop-color="#38e1ff"/><stop offset="1" stop-color="#9d7bff"/></linearGradient></defs><circle class="track" cx="60" cy="60" r="50"/><circle class="val" cx="60" cy="60" r="50" stroke-dasharray="314.16" stroke-dashoffset="314.16" data-offset="${314.16 * (1 - score / 100)}"/><text x="60" y="70">${score}</text></svg><div><h3>Security score</h3><p class="small mute">${list.filter(c => c[0]).length} of ${list.length} checks met</p></div></div>
    <div class="card"><p class="mute">Active sessions</p><p class="num" data-count="${sessions.length}">0</p><p class="small"><span class="pill"><span class="dot"></span> ${PREVIEW ? 'simulated preview' : 'live from server'}</span></p></div>
    <div class="card"><p class="mute">Email status</p><p><span class="badge ${u.emailVerified ? 'ok' : 'warn'}">${u.emailVerified ? 'Verified' : 'Not verified'}</span></p><p class="small mono">${u.email}</p></div>
    <div class="card"><p class="mute">Recorded events (latest 100)</p><p class="num" data-count="${events.length}">0</p><p class="small"><a href="/dashboard/activity">Inspect the chain</a></p></div></div><br>
    <div class="grid"><div class="card"><h3>Security checklist and recommendations</h3>${checkRows(list)}</div><div class="card"><h3>Session constellation</h3>${orbit(sessions)}<p class="small mute">Green is this session.</p></div></div><br>
    <div class="grid"><div class="card"><h3>Recent activity</h3>${events.slice(0, 5).map(e => h`<div class="item"><span>${label(e.event)}</span><span class="small mute">${when(e.createdAt)}</span></div>`)}</div>
    <div class="card"><h3>Recent sign-in information</h3>${logins.length ? logins.map(e => h`<div class="item"><span>${label(e.event)}<br><span class="small mute">${e.device}</span></span><span class="small mute">${when(e.createdAt)}</span></div>`) : h`<p class="mute">No sign-in events yet.</p>`}</div></div><br>
    <div class="card"><h3>Events by type</h3><br>${counts.length ? h`<div class="bars">${counts.map(c => h`<span>${label(c[0])}</span><span><i data-w="${c[1] / max * 100}"></i></span><b>${c[1]}</b>`)}</div>` : h`<p class="mute">No data yet.</p>`}</div>`;
  },
  async '/dashboard/profile'(u) {
    const done = [u.fullName, u.bio, u.location].filter(Boolean).length;
    return h`<h1>Profile</h1><p class="mute">Profile ${Math.round(done / 3 * 100)}% complete · email ${u.emailVerified ? 'verified' : 'not verified'}</p><br><div class="card">${form('profile', h`${field('fullName', 'Full name', 'text', 'name', u.fullName)}${field('username', 'Username', 'text', 'username', u.username)}<div><label for="f-bio">Bio</label><textarea id="f-bio" name="bio" rows="3" maxlength="240">${u.bio}</textarea><p class="err" id="e-bio"></p></div>${field('location', 'Location (optional, typed by you)', 'text', 'off', u.location)}`, 'Save profile')}${u.isDemo ? h`<p class="small mute">Demo accounts keep their generated username.</p>` : ''}</div>`;
  },
  async '/dashboard/security'(u) {
    const { sessions } = await api('GET', '/api/sessions');
    return h`<h1>Security Center</h1><br><div class="grid"><div class="card stack"><h3>Change password</h3>${u.isDemo ? demoLock('Password change') : h`<p class="small mute">Last changed ${when(u.passwordChangedAt)}</p>${form('password', h`${field('currentPassword', 'Current password', 'password', 'current-password')}<div>${field('password', 'New password', 'password', 'new-password')}${strength}</div>${field('confirmPassword', 'Confirm new password', 'password', 'new-password')}`, 'Change password')}`}</div>
    <div class="card stack"><h3>Two-factor authentication <span class="badge ${u.twoFactor ? 'ok' : 'warn'}">${u.twoFactor ? 'On' : 'Off'}</span></h3>${u.isDemo ? demoLock('Two-factor setup') : u.twoFactor ? form('mfa-off', field('currentPassword', 'Current password', 'password', 'current-password'), 'Turn off 2FA', 'danger') : h`<div id="mfa-area">${form('mfa-setup', field('currentPassword', 'Current password', 'password', 'current-password'), 'Set up 2FA')}</div>`}</div>
    <div class="card"><h3>Security checklist</h3>${checkRows(checklist(u, sessions))}</div>
    <div class="card stack"><h3>Sessions and sign-ins</h3><p class="mute">${sessions.length} active session(s).</p><div class="row"><a class="btn" href="/dashboard/sessions">Manage devices</a><a class="btn" href="/dashboard/activity">Login activity</a><a class="btn danger" href="/dashboard/settings">Delete account</a></div></div></div>`;
  },
  async '/dashboard/sessions'(u) {
    const { sessions } = await api('GET', '/api/sessions');
    return h`<h1>Sessions</h1><p class="mute">Device labels are approximate. No location or IP address is stored.</p><br><div class="card">${sessionRows(sessions, u)}</div><br><div class="row">${u.isDemo ? h`<button class="btn" data-act="test-session">+ Create test session (demo)</button>` : ''}<button class="btn" data-act="revoke-others">Terminate other sessions</button><button class="btn danger" data-act="logout-all">Log out from all devices</button></div>`;
  },
  async '/dashboard/activity'() {
    const { events } = await api('GET', '/api/activity');
    return h`<h1>Activity Chain</h1><p class="mute">Each block carries a keyed hash that covers the block before it.</p><br><div class="row"><button class="btn primary" data-act="verify-chain">⛓ Verify chain integrity</button><span id="chain-result" role="status"></span></div><br>${events.length ? h`<ol class="chain">${events.map(e => h`<li><div class="row between"><b>#${e.seq} ${label(e.event)}</b><span class="small mute">${when(e.createdAt)}</span></div><p class="small mute">${e.device}</p><p class="small mono">hash ${e.hash}…</p></li>`)}</ol>` : h`<div class="card"><p class="mute">No activity yet.</p></div>`}`;
  },
  async '/dashboard/settings'(u) {
    return h`<h1>Account settings</h1><br><div class="grid"><div class="card stack"><h3>Preferences</h3>${form('prefs', box('loginAlerts', 'Show new-login indicators in the dashboard', u.preferences.loginAlerts), 'Save preferences')}<button class="btn" data-act="theme">Switch light / dark theme</button></div>
    <div class="card stack"><h3>Email verification</h3><p><span class="badge ${u.emailVerified ? 'ok' : 'warn'}">${u.emailVerified ? 'Verified' : 'Not verified'}</span></p>${u.isDemo ? demoLock('Email verification') : u.emailVerified ? '' : h`${emailNote()}<button class="btn" data-act="resend">Resend verification email</button>`}</div>
    <div class="card stack"><h3>Delete account</h3><p class="mute">Permanently removes your profile, sessions and activity.</p><button class="btn danger" data-act="delete">Delete my account</button></div>
    <div class="card"><h3>About</h3><p class="mute">LOKI_AUTH · The Block-Solid Authentication &amp; Identity Vault<br>Created by <b>LOKESH B</b> &lt;LB/&gt;</p></div></div>`;
  },
};
function dashboard(p) {
  const u = state.user;
  root.innerHTML = shell(h`${u.isDemo ? h`<div class="bar-demo"><div class="wrap row between"><span><span class="badge">LIVE DEMO</span> Private temporary account · expires in <b id="countdown" class="mono">--:--</b></span><button class="btn sm" data-act="logout">Exit demo</button></div></div>` : ''}
  <div class="wrap dash"><aside class="card side"><div class="who"><p><b>${u.fullName}</b></p><p class="small mute">@${u.username}</p><p class="small"><span class="lb">by LOKESH B</span></p><br></div><nav aria-label="Dashboard">${TABS.map(t => h`<a href="${t[0]}" ${t[0] === p ? h`aria-current="page"` : ''}>${t[1]}</a>`)}</nav><button class="btn sm danger" data-act="logout">Log out</button></aside><main id="main" class="panel"><div class="skel"></div><div class="skel"></div></main></div>`, { bare: true }).s;
  tick(); fill(p);
}
async function fill(p) {
  const main = $('#main');
  try {
    const html = await PANELS[p](state.user);
    if (!main.isConnected) return;
    main.innerHTML = html.s; enhance(main); bindDash(p); bindMeter();
  } catch (e) { if (main.isConnected && state.user) main.innerHTML = h`<div class="card stack"><p class="alert bad">${e.message}</p><button class="btn" data-act="retry">Try again</button></div>`.s; }
}
function bindDash(p) {
  const saved = r => { if (r.user) setUser(r.user); toast(r.message); };
  bindForm('profile', async d => { if (state.user.isDemo) delete d.username; saved(await api('PATCH', '/api/profile', d)); dashboard(p); });
  bindForm('prefs', async d => { saved(await api('PATCH', '/api/profile', d)); });
  bindForm('password', async (d, f) => { toast((await api('POST', '/api/auth/change-password', d)).message); f.reset(); await refresh(); dashboard(p); });
  bindForm('mfa-off', async d => { toast((await api('POST', '/api/mfa/disable', d)).message); await refresh(); dashboard(p); });
  bindForm('mfa-setup', async d => {
    const r = await api('POST', '/api/mfa/setup', d);
    $('#mfa-area').innerHTML = h`<p class="small">${r.message}</p><p class="alert mono">${r.secret}</p><p class="small"><a href="${r.uri}">Open in authenticator app</a> · time-based, 6 digits</p>${form('mfa-enable', field('code', '6-digit code', 'text', 'one-time-code'), 'Confirm and enable')}`.s;
    bindForm('mfa-enable', async d2 => {
      const out = await api('POST', '/api/mfa/enable', d2); await refresh();
      $('#mfa-area').innerHTML = h`<p class="alert ok">${out.message} Each works once and they are shown only now.</p><p class="mono">${out.recoveryCodes.join('  ·  ')}</p><button class="btn primary" data-act="retry">I have saved them</button>`.s;
    });
  });
}
async function refresh() { const r = await api('GET', '/api/auth/me'); setUser(r.user); state.session = r.session; }
function tick() {
  const el = $('#countdown'); if (!el || !state.user?.demoExpiresAt) return;
  const left = Math.max(0, state.user.demoExpiresAt - Date.now());
  el.textContent = `${String(Math.floor(left / 60000)).padStart(2, '0')}:${String(Math.floor(left / 1000) % 60).padStart(2, '0')}`;
  // The server decides: at zero, ask it, and it answers DEMO_EXPIRED.
  if (!left && !tick.asked) { tick.asked = true; setTimeout(() => api('GET', '/api/auth/me').catch(() => {}).finally(() => tick.asked = false), 600); }
}
setInterval(tick, 1000);

/* ---------- dialogs ---------- */
function dialog(html) {
  const d = document.createElement('dialog'); d.innerHTML = html.s; document.body.append(d);
  d.addEventListener('close', () => d.remove()); $$('[data-close]', d).forEach(b => b.onclick = () => d.close()); d.showModal(); return d;
}
function confirmBox({ title, text, action, password, typed, run }) {
  const d = dialog(h`<div class="stack"><h2>${title}</h2><p class="mute">${text}</p>${form('confirm', h`${typed ? field('confirm', 'Type DELETE to confirm') : ''}${password ? field('currentPassword', 'Confirm your password', 'password', 'current-password') : ''}`, action, 'danger')}<button class="btn" data-close>Cancel</button></div>`);
  bindForm('confirm', async data => { await run(data); d.close(); });
}
function palette() {
  if ($('dialog')) return;
  const items = [...(state.user ? TABS : [['/', 'Home'], ['/login', 'Sign In'], ['/register', 'Get Started']]), ['/security', 'Security page'], ['/about', 'About LOKESH B'], ['demo', 'Try Live Demo'], ['theme', 'Switch theme']];
  const d = dialog(h`<div class="cmd"><label for="cmd-q">Command palette</label><input id="cmd-q" placeholder="Type to filter…" autocomplete="off"><div>${items.map(i => h`<button data-cmd="${i[0]}">${i[1]}</button>`)}</div><button data-close>Close (Esc)</button></div>`);
  const q = $('#cmd-q', d), buttons = $$('[data-cmd]', d);
  q.oninput = () => buttons.forEach(b => b.hidden = !b.textContent.toLowerCase().includes(q.value.toLowerCase()));
  q.onkeydown = e => { if (e.key === 'Enter') buttons.find(b => !b.hidden)?.click(); };
  buttons.forEach(b => b.onclick = () => { const c = b.dataset.cmd; d.close(); if (c === 'theme') ACTIONS.theme(); else if (c === 'demo') ACTIONS.demo(); else go(c); });
}
addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); palette(); } });

/* ---------- actions ---------- */
const leave = msg => { state.user = null; toast(msg); go('/'); };
const ACTIONS = {
  menu(b) { const open = $('#menu').classList.toggle('open'); b.setAttribute('aria-expanded', open); },
  async theme() { const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; applyTheme(t); if (state.user) setUser((await api('PATCH', '/api/profile', { theme: t })).user); },
  palette,
  reveal(b) { const i = b.previousElementSibling, show = i.type === 'password'; i.type = show ? 'text' : 'password'; b.textContent = show ? 'Hide' : 'Show'; },
  async demo() { const r = await api('POST', '/api/demo/start'); setUser(r.user); toast(r.message); go('/dashboard'); },
  retry() { dashboard(path()); },
  logout() { const demo = state.user.isDemo; confirmBox({ title: demo ? 'Exit demo?' : 'Log out?', text: 'This ends the current session on the server.', action: 'Log out', run: async () => leave((await api('POST', '/api/auth/logout')).message) }); },
  async resend() { toast((await api('POST', '/api/auth/resend-verification')).message); },
  async 'test-session'() { toast((await api('POST', '/api/demo/test-session')).message); dashboard(path()); },
  'revoke-others'() { confirmBox({ title: 'Terminate other sessions?', text: 'Every session except this one will end.', action: 'Terminate', run: async () => { toast((await api('POST', '/api/sessions/revoke-others')).message); dashboard(path()); } }); },
  'logout-all'() { confirmBox({ title: 'Log out everywhere?', text: 'All sessions, including this one, will end.', password: !state.user.isDemo, action: 'Log out all', run: async d => leave((await api('POST', '/api/sessions/logout-all', d)).message) }); },
  delete() { confirmBox({ title: 'Delete account permanently?', text: 'This cannot be undone.', typed: true, password: !state.user.isDemo, action: 'Delete account', run: async d => leave((await api('DELETE', '/api/account', d)).message) }); },
  async 'verify-chain'() {
    const r = await api('GET', '/api/activity/verify'), out = $('#chain-result');
    out.innerHTML = r.valid ? h`<span class="badge ok">✓ ${r.blocks} blocks verified${PREVIEW ? ' (preview)' : ''}</span>`.s : h`<span class="badge bad">Chain broken at block #${r.brokenAt}</span>`.s;
    if (r.valid) $$('.chain li').reverse().forEach((li, i) => setTimeout(() => li.classList.add('good'), i * 90));
  },
};
document.addEventListener('click', async e => {
  const b = e.target.closest('[data-act],[data-revoke]'); if (!b || b.disabled) return;
  const run = async fn => { const keep = !['menu', 'reveal'].includes(b.dataset.act); if (keep) { b.disabled = true; b.classList.add('busy'); } try { await fn(); } catch (err) { toast(err.message, true); } finally { b.disabled = false; b.classList.remove('busy'); } };
  if (b.dataset.act) return run(() => ACTIONS[b.dataset.act](b));
  confirmBox({ title: 'Revoke this session?', text: 'That device will need to sign in again.', action: 'Revoke', run: async () => { const r = await api('DELETE', '/api/sessions/' + encodeURIComponent(b.dataset.revoke)); if (r.current) leave(r.message); else { toast(r.message); dashboard(path()); } } });
});

/* ---------- effects ---------- */
const calm = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
function enhance(el) {
  // Values are applied through the CSSOM, which the strict CSP allows (no inline style attributes).
  requestAnimationFrame(() => requestAnimationFrame(() => { $$('[data-w]', el).forEach(i => i.style.width = i.dataset.w + '%'); $$('[data-offset]', el).forEach(c => c.style.strokeDashoffset = c.dataset.offset); }));
  $$('[data-count]', el).forEach(n => { const to = +n.dataset.count, t0 = performance.now(); const step = t => { const k = calm() ? 1 : Math.min(1, (t - t0) / 900); n.textContent = Math.round(to * (1 - (1 - k) ** 3)); if (k < 1) requestAnimationFrame(step); }; requestAnimationFrame(step); });
  const io = new IntersectionObserver(es => es.forEach((x, i) => { if (x.isIntersecting) { setTimeout(() => x.target.classList.add('in'), i * 80); io.unobserve(x.target); } }));
  $$('.reveal', el).forEach(x => io.observe(x));
  const s = $('[data-scramble]', el);
  if (s && !calm()) { const text = s.textContent; let i = 0; s.setAttribute('aria-label', text); const id = setInterval(() => { s.textContent = [...text].map((c, n) => n < i || c === ' ' ? c : '▖▘▝▗▚▞█▓01'[Math.random() * 10 | 0]).join(''); if ((i += 1.4) > text.length) { s.textContent = text; clearInterval(id); } }, 28); }
}
addEventListener('pointermove', e => { const c = e.target.closest?.('.card'); if (c) { const r = c.getBoundingClientRect(); c.style.setProperty('--mx', e.clientX - r.left + 'px'); c.style.setProperty('--my', e.clientY - r.top + 'px'); } }, { passive: true });

const TITLES = { '/': 'Your Identity. Your Control. Your Security.', ...Object.fromEntries(Object.entries(DOCS).map(([k, v]) => [k, v[0]])), ...Object.fromEntries(TABS), '/login': 'Sign In', '/register': 'Register', '/forgot-password': 'Forgot password', '/reset-password': 'Reset password', '/verify-email': 'Verify email', '/demo-expired': 'Demo expired' };
let shown;
function render() {
  const p = path(), changed = p !== shown; shown = p;
  document.title = `${TITLES[p] || 'Page not found'} · LOKI_AUTH`;
  $$('dialog').forEach(d => d.remove());
  const paint = () => {
    if (PANELS[p]) return state.user ? dashboard(p) : go('/login', true);
    if (['/reset-password', '/verify-email'].includes(p)) { const t = tokenFromUrl(); if (t) { linkToken = t; if (!PREVIEW) history.replaceState(null, '', p); } }
    const view = p === '/' ? landing() : DOCS[p] ? docPage(DOCS[p]) : AUTH[p] ? AUTH[p]()
      : p === '/demo-expired' ? notice('⌛ Demo expired', 'The server ended this temporary account. Its data is deleted shortly afterwards.', h`<button class="btn cyan" data-act="demo">Start another demo</button><a class="btn" href="/">Home</a>`)
      : notice('404 — block not found', 'That page is not part of the vault.', h`<a class="btn primary" href="/">Return home</a>`);
    root.innerHTML = view.s; enhance(root); bindAuth(); bindMeter();
    const canvas = $('#vault'); if (canvas) window.VaultScene.mount(canvas);
  };
  if (changed && document.startViewTransition && !calm()) { const vt = document.startViewTransition(paint); [vt.ready, vt.finished, vt.updateCallbackDone].forEach(x => x.catch(() => {})); } else paint();
  if (changed) scrollTo(0, 0);
}

(async () => {
  try { applyTheme(localStorage.getItem('loki-theme') === 'light' ? 'light' : 'dark'); } catch {}
  try { config = await api('GET', '/api/config'); } catch {}
  try { await refresh(); } catch (e) { if (e.code === 'DEMO_EXPIRED' && PANELS[path()]) return go('/demo-expired', true); }
  render();
})();
})();
