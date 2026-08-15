import { FluentBundle, FluentResource } from '../vendor/fluent.js';
import { setSortLocale } from './sort.js';

const bundles = new Map();
let current = 'en';

/**
 * Sprachen. `dir` steuert die Leserichtung, `script` das Schriftsystem: nicht
 * jede Sprache braucht eine eigene Schriftdatei, aber jedes Schriftsystem
 * schon. Geladen wird nur, was die gewaehlte Sprache verlangt — bei zwanzig
 * Sprachen sind das nicht zwanzig Downloads, sondern eine Handvoll Systeme.
 */
export const LOCALES = [
  { id: 'en', label: 'English', dir: 'ltr', script: 'latin' },
  { id: 'de', label: 'Deutsch', dir: 'ltr', script: 'latin' },
  { id: 'fr', label: 'Français', dir: 'ltr', script: 'latin' },
  { id: 'es', label: 'Español', dir: 'ltr', script: 'latin' },
  { id: 'ar', label: 'العربية', dir: 'rtl', script: 'arabic' },
  { id: 'am', label: 'አማርኛ', dir: 'ltr', script: 'ethiopic' },
  { id: 'ti', label: 'ትግርኛ', dir: 'ltr', script: 'ethiopic' }
];

// Fonts for every script (latin/arabic/ethiopic) are declared once in styles/fonts.css,
// vendored locally — no runtime CDN fetch. @font-face + unicode-range means the browser only
// downloads a subset when a matching glyph is actually rendered, so declaring all of them
// upfront stays lazy. `data-script` on <html> (set in loadLocale) switches the family via CSS.

export function localeInfo(id = current) {
  return LOCALES.find((l) => l.id === id) ?? LOCALES[0];
}

const LOCALE_KEY = 'openom.locale';

/**
 * The locale to start in: a previously-chosen one (persisted), else the best match from the
 * browser's languages, else English. Runs before any UI — including the pre-unlock gate,
 * which is why the choice can't live in the (locked) tree and must be in localStorage.
 */
export function detectLocale() {
  try {
    const saved = localStorage.getItem(LOCALE_KEY);
    if (saved && LOCALES.some((l) => l.id === saved)) return saved;
  } catch {
    /* no storage — fall through to the browser preference */
  }
  const prefs = navigator.languages?.length ? navigator.languages : [navigator.language || 'en'];
  for (const pref of prefs) {
    const base = String(pref).toLowerCase().split('-')[0];
    const hit = LOCALES.find((l) => l.id === base);
    if (hit) return hit.id;
  }
  return 'en';
}

/** Remember the chosen locale across launches. */
export function persistLocale(id) {
  try {
    localStorage.setItem(LOCALE_KEY, id);
  } catch {
    /* ephemeral */
  }
}

export function isRTL() {
  return localeInfo().dir === 'rtl';
}

export async function loadLocale(id) {
  if (!bundles.has(id)) {
    const text = await fetch('./locales/' + id + '.ftl').then((r) => r.text());
    const bundle = new FluentBundle(id);
    bundle.addResource(new FluentResource(text));
    bundles.set(id, bundle);
  }
  current = id;
  const info = localeInfo(id);
  setSortLocale(id);
  document.documentElement.lang = id;
  document.documentElement.dir = info.dir;
  document.documentElement.dataset.script = info.script;
  return id;
}

export function locale() {
  return current;
}

/** Uebersetzt eine Nachricht; fehlt sie, erscheint der Schluessel — sichtbar, aber nicht kaputt. */
export function t(key, args) {
  const bundle = bundles.get(current);
  const msg = bundle && bundle.getMessage(key);
  if (!msg || !msg.value) return key;
  return bundle.formatPattern(msg.value, args);
}

/** Lebensdaten-Symbole sind kulturell, nicht universell. */
export function dateSymbols() {
  return { birth: t('symbol-birth'), death: t('symbol-death'), marriage: t('symbol-marriage') };
}
