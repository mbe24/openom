import { parseDate } from './dates.js';

let collator = new Intl.Collator('en', { sensitivity: 'base', numeric: true });
export function setSortLocale(locale) {
  collator = new Intl.Collator(locale, { sensitivity: 'base', numeric: true });
}
export function compareNames(a, b) {
  return collator.compare(a ?? '', b ?? '');
}

/**
 * Geschwister: nach Geburtsjahr, wenn eines ableitbar ist — auch aus
 * "ca. 1712" oder "vor 1700". Ganz unbekannte hinten, dort nach Vorname.
 */
export function compareSiblings(a, b) {
  const ya = parseDate(a.birth).sortYear;
  const yb = parseDate(b.birth).sortYear;
  if (ya != null && yb != null && ya !== yb) return ya - yb;
  if (ya != null && yb == null) return -1;
  if (ya == null && yb != null) return 1;
  return compareNames(a.given, b.given);
}

export function comparePeople(a, b, key = 'surname') {
  if (key === 'birth') return compareSiblings(a, b);
  if (key === 'given') return compareNames(a.given, b.given) || compareNames(a.surname, b.surname);
  return compareNames(a.surname, b.surname) || compareNames(a.given, b.given);
}
