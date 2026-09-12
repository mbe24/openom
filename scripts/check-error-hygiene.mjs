// Guard (design A2): no code path may read an error's `.stack` — the stack is dev-console-only, NEVER the
// DOM or any user-facing surface. Scans apps/app/src (excluding vendor + generated files + comment lines)
// and fails CI on any `.stack` read. Run: `node scripts/check-error-hygiene.mjs`.
//
// The broader "no raw `.message` rendered to the UI" enforcement lands together with the client adapters
// (the sync-driver status + JoinError sites migrate onto AppError there); this narrow stack ban is enforceable
// now and catches the sharpest leak (a raw stack trace in the UI).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = path.join(REPO, 'apps', 'app', 'src');
const SKIP = /[\\/]vendor[\\/]|\.generated\.js$/;

function* jsFiles(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* jsFiles(p);
    else if (entry.name.endsWith('.js') && !SKIP.test(p)) yield p;
  }
}

const hits = [];
for (const file of jsFiles(ROOT)) {
  fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) return; // comment line
    if (/\.stack\b/.test(line)) hits.push(`${path.relative(REPO, file)}:${i + 1}: ${trimmed}`);
  });
}

if (hits.length) {
  console.error('error-hygiene: `.stack` must never be read for display — it is dev-console-only (A2):');
  for (const h of hits) console.error('  ' + h);
  process.exit(1);
}
console.log('error-hygiene: no `.stack` reads in app source');
