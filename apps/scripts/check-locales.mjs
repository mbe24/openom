// Prueft, dass jede Sprache dieselben Schluessel traegt wie Englisch.
// Fehlende Schluessel fallen sonst erst auf, wenn jemand die Sprache umstellt
// und einen englischen Satz mitten im Formular findet.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = 'app/locales';
const keysOf = (file) => new Set(
  readFileSync(join(dir, file), 'utf8')
    .split('\n')
    .map((line) => line.match(/^([a-z0-9-]+)\s*=/i))
    .filter(Boolean)
    .map((m) => m[1])
);

const base = keysOf('en.ftl');
let bad = false;

for (const file of readdirSync(dir).filter((f) => f.endsWith('.ftl') && f !== 'en.ftl')) {
  const keys = keysOf(file);
  const missing = [...base].filter((k) => !keys.has(k));
  const extra = [...keys].filter((k) => !base.has(k));
  if (missing.length || extra.length) {
    bad = true;
    console.error(file + ':');
    if (missing.length) console.error('  missing: ' + missing.join(', '));
    if (extra.length) console.error('  unknown: ' + extra.join(', '));
  }
}

if (bad) process.exit(1);
console.log('locales complete (' + base.size + ' keys)');
