// Prueft die Locale-Schluessel gegen Englisch (die Referenz).
//   * FEHLENDE Schluessel (noch nicht uebersetzt) sind eine WARNUNG — sie brechen die Pipeline NICHT,
//     damit neue englische Strings landen koennen, bevor jede Sprache nachzieht. Sichtbar, nicht blockierend.
//   * UNBEKANNTE Schluessel (in einer Sprache, aber nicht in en.ftl) sind ein FEHLER (exit 1): ein Tippfehler
//     oder ein veralteter Schluessel, der niemals aufgeloest wird.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = 'app/locales';
const keysOf = (file) => new Set(
  readFileSync(join(dir, file), 'utf8')
    .split('\n')
    .map((line) => line.match(/^([a-z0-9_-]+)\s*=/i))
    .filter(Boolean)
    .map((m) => m[1])
);

const base = keysOf('en.ftl');
let hasUnknown = false;   // fatal
let untranslated = 0;     // warn only

for (const file of readdirSync(dir).filter((f) => f.endsWith('.ftl') && f !== 'en.ftl')) {
  const keys = keysOf(file);
  const missing = [...base].filter((k) => !keys.has(k));
  const extra = [...keys].filter((k) => !base.has(k));
  if (missing.length) {
    untranslated += missing.length;
    console.warn(`::warning:: ${file}: ${missing.length} untranslated key(s): ${missing.join(', ')}`);
  }
  if (extra.length) {
    hasUnknown = true;
    console.error(`${file}: unknown key(s) not in en.ftl: ${extra.join(', ')}`);
  }
}

// Unknown keys fail the build; missing translations only warn (the pipeline stays green).
if (hasUnknown) process.exit(1);
if (untranslated) {
  console.warn(`locales: ${base.size} keys in en.ftl; ${untranslated} still untranslated across locales (warning only)`);
} else {
  console.log('locales complete (' + base.size + ' keys)');
}
