// Guard: no build path may invoke `tauri build --debug` (or `-d`).
//
// store-schema gates its destructive schema-reset behind `#[cfg(debug_assertions)]`, so it is absent from a
// RELEASE binary. `tauri build --debug` breaks that: it compiles the DEV profile (debug_assertions ON) into a
// shipped, installable artifact — which would put the "self-heal wipes the DB on a schema mismatch" branch into
// users' hands. The compile-time gate only protects a build that is genuinely a release build; this keeps every
// shipping path a release build. (See packages/store-schema and the design reviews, finding H2.)

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const targets = [];
const wfDir = join(root, '.github', 'workflows');
try {
  for (const f of readdirSync(wfDir)) if (f.endsWith('.yml') || f.endsWith('.yaml')) targets.push(join(wfDir, f));
} catch { /* no workflows dir — nothing to scan */ }
targets.push(join(root, 'apps', 'scripts', 'tauri.mjs')); // the build wrapper, in case a flag is hardcoded there

const isBuild = /tauri(\.mjs)?\s+build\b/;      // however `tauri build` is invoked
const hasDebug = /(^|\s)(--debug|-d)(\s|=|$)/;  // …carrying the debug flag

const offenders = [];
for (const file of targets) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch { continue; }
  text.split('\n').forEach((line, i) => {
    if (isBuild.test(line) && hasDebug.test(line)) offenders.push(`${file}:${i + 1}: ${line.trim()}`);
  });
}

if (offenders.length) {
  console.error('FAIL: a build path uses `tauri build --debug` — that ships debug_assertions (destructive schema-reset in the binary):');
  for (const o of offenders) console.error('  ' + o);
  process.exit(1);
}
console.log('ok: no `tauri build --debug` in any build path — every shipping build stays a release build');
