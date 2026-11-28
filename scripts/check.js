'use strict';
const fs = require('node:fs'), path = require('node:path'), { execFileSync } = require('node:child_process');
const root = path.join(__dirname, '..'); let n = 0;
for (const dir of ['.', 'src', 'public', 'preview', 'scripts', 'test'])
  for (const f of fs.readdirSync(path.join(root, dir))) if (f.endsWith('.js')) { execFileSync(process.execPath, ['--check', path.join(root, dir, f)]); n++; }
console.log(`Syntax OK in ${n} files`);
