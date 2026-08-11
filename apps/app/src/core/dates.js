// Tolerante Datumsangaben: gespeichert wird, was die Quelle sagt.
// Daneben liegt ein sortierbarer Bereich, den der Parser ableitet.
const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

export function parseDate(raw) {
  const s = (raw ?? '').trim();
  if (!s) return { kind: 'empty', text: '', sortYear: null, display: '' };
  const year = (s.match(/\d{4}/) || [])[0];
  const y = year ? Number(year) : null;
  const low = s.toLowerCase();

  if (/^(ca\.?|circa|about|abt|um|etwa)/.test(low) || /\?$/.test(s)) {
    return { kind: 'about', text: s, sortYear: y, from: y ? y - 5 : null, to: y ? y + 5 : null, display: s };
  }
  if (/^(before|vor|bef)/.test(low)) return { kind: 'before', text: s, sortYear: y ? y - 1 : null, to: y, display: s };
  if (/^(after|nach|aft)/.test(low)) return { kind: 'after', text: s, sortYear: y ? y + 1 : null, from: y, display: s };

  const range = s.match(/(\d{4})\s*[–-]\s*(\d{4})/);
  if (range) {
    const a = Number(range[1]), b = Number(range[2]);
    return { kind: 'range', text: s, sortYear: a, from: a, to: b, display: s };
  }
  const full = s.match(/^(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})$/);
  if (full) {
    const d = Number(full[1]), m = Number(full[2]);
    return { kind: 'exact', text: s, sortYear: Number(full[3]), day: d, month: m,
             display: `${d} ${MONTHS[m - 1] ?? '?'} ${full[3]}` };
  }
  if (year) return { kind: 'year', text: s, sortYear: y, display: s };
  return { kind: 'text', text: s, sortYear: null, display: s };
}

/** Kurzform für Karten: "1685" oder "ca. 1712". */
export function shortDate(raw) {
  const p = parseDate(raw);
  if (p.kind === 'empty') return '';
  if (p.kind === 'exact' || p.kind === 'year') return String(p.sortYear);
  return p.text;
}

export function lifeLine(person, { symbols = { birth: '∗', death: '†' } } = {}) {
  const b = shortDate(person.birth), d = shortDate(person.death);
  if (!b && !d) return '';
  const parts = [];
  if (b) parts.push(`${symbols.birth} ${b}`);
  if (d) parts.push(`${symbols.death} ${d}`);
  return parts.join(' · ');
}

/** Jahr – Jahr, wie im Graphen. Fehlt eine Seite, steht nur die andere. */
export function lifeSpan(person) {
  if (!person) return '';
  return [shortDate(person.birth), shortDate(person.death)].filter(Boolean).join(' – ');
}
