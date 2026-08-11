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

/**
 * Schriften je System. Im Mockup vom CDN; fuer Tauri gehoeren die Dateien
 * neben die App (siehe README, Abschnitt „Schriften").
 */
const FONTS = {
  latin: null,   // Newsreader und Systemschrift sind schon geladen
  arabic: 'https://fonts.googleapis.com/css2?family=Noto+Naskh+Arabic:wght@400;500;600;700&display=swap',
  ethiopic: 'https://fonts.googleapis.com/css2?family=Noto+Sans+Ethiopic:wght@400;500;600;700&display=swap'
};
const loaded = new Set(['latin']);

function ensureFont(script) {
  if (loaded.has(script) || !FONTS[script]) return;
  loaded.add(script);
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = FONTS[script];
  document.head.appendChild(link);
}

export function localeInfo(id = current) {
  return LOCALES.find((l) => l.id === id) ?? LOCALES[0];
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
  ensureFont(info.script);
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
