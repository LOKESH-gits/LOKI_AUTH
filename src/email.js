'use strict';
const fs = require('node:fs');
const path = require('node:path');

function createMailer(cfg) {
  const configured = cfg.emailProvider !== 'none';
  return {
    configured, provider: cfg.emailProvider,
    // Resolves true only when the provider accepted the message.
    async send(to, subject, text) {
      if (!configured) return false;
      if (cfg.emailProvider === 'file') { // development only: git-ignored local outbox
        fs.mkdirSync(path.dirname(path.resolve(cfg.outboxPath)), { recursive: true });
        fs.appendFileSync(cfg.outboxPath, JSON.stringify({ to, subject, text }) + '\n', { mode: 0o600 });
        return true;
      }
      try {
        const r = await fetch('https://api.resend.com/emails', {
          method: 'POST', signal: AbortSignal.timeout(10000),
          headers: { authorization: `Bearer ${cfg.resendKey}`, 'content-type': 'application/json' },
          body: JSON.stringify({ from: cfg.emailFrom, to: [to], subject, text }),
        });
        return r.ok;
      } catch { return false; }
    },
  };
}
module.exports = { createMailer };
