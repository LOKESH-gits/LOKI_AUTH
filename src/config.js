'use strict';
const crypto = require('node:crypto');

function loadConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const port = Number(env.PORT || 3000);
  const cfg = {
    production, port,
    host: env.HOST || (production ? '0.0.0.0' : '127.0.0.1'),
    // Render sets RENDER_EXTERNAL_URL automatically.
    baseUrl: (env.BASE_URL || env.RENDER_EXTERNAL_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
    appSecret: env.APP_SECRET || (production ? '' : crypto.randomBytes(32).toString('hex')),
    dbDriver: env.DB_DRIVER || (production ? 'turso' : 'sqlite'),
    sqlitePath: env.SQLITE_PATH || 'data/loki-auth.db',
    tursoUrl: env.TURSO_URL || '', tursoToken: env.TURSO_TOKEN || '',
    demoTtlMs: Number(env.DEMO_TTL_MS || 30 * 60 * 1000),
    emailProvider: env.EMAIL_PROVIDER || 'none',
    emailFrom: env.EMAIL_FROM || '', resendKey: env.RESEND_API_KEY || '',
    outboxPath: env.OUTBOX_PATH || 'data/outbox.log',
    trustProxy: env.TRUST_PROXY ? env.TRUST_PROXY === 'true' : production,
  };
  const errors = [];
  if (!['sqlite', 'turso'].includes(cfg.dbDriver)) errors.push('DB_DRIVER must be sqlite or turso');
  if (cfg.dbDriver === 'turso' && (!cfg.tursoUrl || !cfg.tursoToken)) errors.push('TURSO_URL and TURSO_TOKEN are required');
  if (!['none', 'resend', 'file'].includes(cfg.emailProvider)) errors.push('EMAIL_PROVIDER must be none, resend or file');
  if (cfg.emailProvider === 'resend' && (!cfg.resendKey || !cfg.emailFrom)) errors.push('RESEND_API_KEY and EMAIL_FROM are required');
  if (!Number.isFinite(cfg.demoTtlMs) || cfg.demoTtlMs < 1000) errors.push('DEMO_TTL_MS must be a number >= 1000');
  if (production) {
    if (cfg.appSecret.length < 32) errors.push('APP_SECRET must be at least 32 characters');
    if (cfg.dbDriver !== 'turso') errors.push('Production requires DB_DRIVER=turso');
    if (!cfg.baseUrl.startsWith('https://')) errors.push('BASE_URL must use https');
    if (cfg.emailProvider === 'file') errors.push('EMAIL_PROVIDER=file is for development only');
  }
  if (errors.length) throw new Error('Invalid configuration: ' + errors.join('; ')); // names only, never values
  return cfg;
}
module.exports = { loadConfig };
