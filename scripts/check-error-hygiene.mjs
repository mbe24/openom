// Guard (design A2): errors are rendered from an AppError `code` (via errText/Fluent), never from a raw
// `.message`/`.stack`. This fails CI on:
//   - ANY `.stack` read (the stack is dev-console-only, never a user-facing surface); and
//   - a raw `.message` flowing into a UI sink (`toast(...)`, `.innerHTML`/`.textContent`, `gateError`).
// It does NOT flag `.message` used for classification or carried in a thrown/status object (the sync-driver
// status + JoinError) — those are migrated onto AppError by the client adapters (OPE-418/419); this guard
// blocks the DISPLAY leak, which is what "no .message to the DOM" means. Run: `node scripts/check-error-hygiene.mjs`.

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

const UI_SINK = /\b(toast|innerHTML|textContent|gateError)\b/;

const hits = [];
for (const file of jsFiles(ROOT)) {
  fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) return; // comment line
    const at = `${path.relative(REPO, file)}:${i + 1}: ${trimmed}`;
    if (/\.stack\b/.test(line)) hits.push(`[.stack read] ${at}`);
    else if (UI_SINK.test(line) && /\.message\b/.test(line)) hits.push(`[.message → UI sink] ${at}`);
  });
}

if (hits.length) {
  console.error('error-hygiene: render errors from an AppError code (errText), never a raw .message/.stack (A2):');
  for (const h of hits) console.error('  ' + h);
  process.exit(1);
}
console.log('error-hygiene: no raw .stack reads or .message-to-UI-sink in app source');
