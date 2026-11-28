'use strict';
const { loadConfig } = require('./src/config');
const { openDb } = require('./src/db');
const { createApp } = require('./src/app');

(async () => {
  let cfg, db;
  try { cfg = loadConfig(); } catch (e) { console.error(e.message); process.exit(1); }
  try { db = await openDb(cfg); } catch { console.error(`Database unavailable (driver: ${cfg.dbDriver}). Check configuration. Not starting.`); process.exit(1); }
  const { server, svc, drain } = createApp({ db, cfg });
  const timer = setInterval(() => svc.cleanup().catch(() => console.error('Cleanup failed')), 60e3); timer.unref();
  server.listen(cfg.port, cfg.host, () => {
    console.log(`LOKI_AUTH by LOKESH B — ${cfg.baseUrl} (db: ${cfg.dbDriver}, email: ${cfg.emailProvider})`);
    if (cfg.emailProvider === 'none') console.log('Email is not configured: verification and reset emails will not be sent. See README.');
  });
  const stop = () => { clearInterval(timer); server.close(async () => { await drain(); await db.close(); process.exit(0); }); setTimeout(() => process.exit(1), 8000).unref(); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
})();
