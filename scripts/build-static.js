'use strict';
// Builds dist/LOKI_AUTH-static-preview.html: one self-contained file, opens by double-click.
const fs = require('node:fs'), path = require('node:path');
const read = f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
const js = ['preview/mock-api.js', 'public/scene.js', 'public/app.js'].map(f => `<script>\n${read(f).replace(/<\/script/gi, '<\\/script')}\n</script>`).join('\n');
const html = `<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LOKI_AUTH Preview</title><style>\n${read('public/styles.css')}\n</style></head>
<body><div id="root"></div><div id="toasts" role="status" aria-live="polite"></div>\n${js}\n</body></html>`;
fs.mkdirSync(path.join(__dirname, '..', 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, '..', 'dist', 'LOKI_AUTH-static-preview.html'), html);
console.log('Built static preview:', html.length, 'bytes');
