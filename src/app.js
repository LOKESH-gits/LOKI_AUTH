'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const S = require('./security');
const { HttpError } = require('./validation');
const { createServices, deviceLabel } = require('./services');
const { createRoutes } = require('./routes');
const { createMailer } = require('./email');

const PAGES = {
  '/': ['Your Identity. Your Control. Your Security.', 'LOKI_AUTH is a block-solid authentication and identity vault by LOKESH B.'],
  '/about': ['About', 'About LOKI_AUTH, created by LOKESH B.'], '/security': ['Security', 'How LOKI_AUTH protects accounts and sessions.'],
  '/privacy': ['Privacy Policy', 'What LOKI_AUTH stores and why.'], '/terms': ['Terms of Service', 'Terms for using LOKI_AUTH.'],
  '/contact': ['Contact & Support', 'Support information for LOKI_AUTH.'],
};
const PRIVATE = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-email', '/demo-expired',
  '/dashboard', '/dashboard/profile', '/dashboard/security', '/dashboard/sessions', '/dashboard/activity', '/dashboard/settings'];
const TYPES = { '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };

function createApp({ db, cfg, logger = console }) {
  const svc = createServices(db, cfg), mail = createMailer(cfg), pending = new Set();
  const match = createRoutes({ db, cfg, svc, mail });
  const origin = new URL(cfg.baseUrl).origin;
  const pub = path.join(__dirname, '..', 'public');
  // Allow-list loaded at startup: request paths never touch the filesystem (no traversal, no dotfiles).
  const assets = new Map(fs.readdirSync(pub).filter(f => TYPES[path.extname(f)]).map(f => ['/assets/' + f, { body: fs.readFileSync(path.join(pub, f)), type: TYPES[path.extname(f)] }]));
  const shell = fs.readFileSync(path.join(pub, 'index.html'), 'utf8');
  const cookieName = n => (cfg.production ? '__Host-' : '') + n;
  const cookie = (n, v, maxAge) => `${cookieName(n)}=${v}; Path=/; HttpOnly; SameSite=Strict${cfg.production ? '; Secure' : ''}${maxAge === undefined ? '' : `; Max-Age=${maxAge}`}`;
  const readCookies = h => Object.fromEntries(String(h || '').split(';').map(c => c.trim().split('=')).filter(p => p.length === 2));
  const csrfFor = seed => S.hmac(cfg.appSecret, 'csrf|' + seed);

  function headers(res) {
    const h = {
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
    };
    if (cfg.production) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    for (const [k, v] of Object.entries(h)) res.setHeader(k, v);
  }
  const send = (res, status, type, body, cache = 'no-store') => { res.writeHead(status, { 'content-type': type + '; charset=utf-8', 'cache-control': cache }); res.end(body); };

  async function readJson(req) {
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) throw new HttpError(415, 'BAD_CONTENT_TYPE', 'Send JSON.');
    let size = 0; const chunks = [];
    for await (const c of req) { size += c.length; if (size > 16384) throw new HttpError(413, 'TOO_LARGE', 'Request is too large.'); chunks.push(c); }
    try { const b = JSON.parse(Buffer.concat(chunks).toString() || '{}'); if (b && typeof b === 'object' && !Array.isArray(b)) return b; } catch {}
    throw new HttpError(400, 'BAD_JSON', 'Request body is not valid JSON.');
  }

  async function api(req, res, pathname) {
    const cookies = readCookies(req.headers.cookie), setCookies = [];
    const flush = () => { if (setCookies.length) res.setHeader('Set-Cookie', setCookies); };
    try {
      if (pathname === '/api/csrf' && req.method === 'GET') {
        let seed = cookies[cookieName('la_csrf')];
        if (!/^[\w-]{32}$/.test(seed || '')) { seed = S.randomToken(24); setCookies.push(cookie('la_csrf', seed)); }
        flush(); return send(res, 200, 'application/json', JSON.stringify({ success: true, message: 'CSRF token.', data: { token: csrfFor(seed) } }));
      }
      const route = match(req.method, pathname);
      if (!route) throw new HttpError(404, 'NOT_FOUND', 'Endpoint not found.');
      let body = {};
      if (req.method !== 'GET') {
        if (req.headers.origin !== origin) throw new HttpError(403, 'BAD_ORIGIN', 'Request origin was rejected.');
        const seed = cookies[cookieName('la_csrf')];
        if (!seed || !S.safeEqual(req.headers['x-csrf-token'] || '', csrfFor(seed))) throw new HttpError(403, 'CSRF', 'Security token missing or invalid. Reload and try again.');
        body = await readJson(req);
      }
      // Behind Render's proxy the last X-Forwarded-For entry is the one the proxy appended.
      const ip = (cfg.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',').pop().trim()) || req.socket.remoteAddress;
      const ctx = {
        body, ip, params: route.params, token: cookies[cookieName('la_sid')], device: deviceLabel(req.headers['user-agent']),
        setSession(s, remember) {
          setCookies.push(cookie('la_sid', s.token, remember ? Math.floor((s.expires - Date.now()) / 1000) : undefined));
          setCookies.push(cookie('la_csrf', S.randomToken(24))); // rotate CSRF seed on every new session
        },
        clearSession() { setCookies.push(cookie('la_sid', '', 0)); },
        background(p) { const q = p.catch(() => logger.error('Background task failed')).finally(() => pending.delete(q)); pending.add(q); },
      };
      if (route.auth) ctx.user = await svc.authenticate(ctx.token);
      const out = await route.handler(ctx);
      flush(); send(res, out.status, 'application/json', JSON.stringify(out.body));
    } catch (e) {
      const known = e instanceof HttpError;
      if (!known) logger.error(`Internal error on ${req.method} ${pathname.replace(/[0-9a-f-]{36}/g, ':id')} (${e.name})`); // no messages, bodies or secrets
      if (known && ['UNAUTHENTICATED', 'SESSION_EXPIRED'].includes(e.code)) setCookies.push(cookie('la_sid', '', 0));
      if (e.retryAfter) res.setHeader('Retry-After', e.retryAfter);
      flush();
      send(res, known ? e.status : 500, 'application/json', JSON.stringify({ success: false,
        message: known ? e.message : 'Something went wrong. Please try again.', error: { code: known ? e.code : 'INTERNAL', fields: e.fields } }));
    }
  }

  function handle(req, res) {
    headers(res);
    let pathname;
    try { pathname = new URL(req.url, 'http://x').pathname; } catch { return send(res, 400, 'text/plain', 'Bad request'); }
    if (pathname.startsWith('/api/')) return api(req, res, pathname);
    if (!['GET', 'HEAD'].includes(req.method)) return send(res, 405, 'text/plain', 'Method not allowed');
    const asset = assets.get(pathname);
    if (asset) return send(res, 200, asset.type, asset.body, 'public, max-age=300');
    if (pathname === '/robots.txt') return send(res, 200, 'text/plain', `User-agent: *\nDisallow: /dashboard\nDisallow: /api/\nSitemap: ${cfg.baseUrl}/sitemap.xml\n`);
    if (pathname === '/sitemap.xml') return send(res, 200, 'application/xml', `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${Object.keys(PAGES).map(p => `<url><loc>${cfg.baseUrl}${p}</loc></url>`).join('')}</urlset>`);
    const page = PAGES[pathname], known = page || PRIVATE.includes(pathname);
    const [title, desc] = page || [known ? 'Account' : 'Page not found', 'LOKI_AUTH by LOKESH B.'];
    const html = shell.replaceAll('{{TITLE}}', `${title} · LOKI_AUTH`).replaceAll('{{DESC}}', desc)
      .replaceAll('{{URL}}', cfg.baseUrl + (page ? pathname : '/')).replace('{{ROBOTS}}', page ? 'index,follow' : 'noindex,nofollow');
    send(res, known ? 200 : 404, 'text/html', html);
  }
  const server = http.createServer(handle);
  server.requestTimeout = 15000; server.headersTimeout = 10000;
  return { server, svc, drain: () => Promise.all([...pending]) };
}
module.exports = { createApp };
