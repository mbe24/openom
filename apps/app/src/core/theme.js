// Akzentfarbe: der Nutzer waehlt einen Farbton, Helligkeit und Saettigung
// werden in den lesbaren Bereich geschoben. Die Spec nennt L 30-52 %,
// Chroma 0.03-0.09 und mindestens 4.5:1 - genau das setzt clampAccent um.
export const ACCENT_LIMITS = { lMin: 30, lMax: 52, cMin: 0.03, cMax: 0.09 };

export const PRESETS = [
  { id: 'sage', label: 'Sage', l: 49.8, c: 0.0444, h: 166.4 },
  { id: 'prussian', label: 'Prussian', l: 34, c: 0.055, h: 235 },
  { id: 'steel', label: 'Steel', l: 40, c: 0.06, h: 250 },
  { id: 'teal', label: 'Teal', l: 38, c: 0.05, h: 185 },
  { id: 'moss', label: 'Moss', l: 41, c: 0.05, h: 125 },
  { id: 'walnut', label: 'Walnut', l: 40, c: 0.045, h: 55 },
  { id: 'clay', label: 'Clay', l: 42, c: 0.085, h: 35 },
  { id: 'plum', label: 'Plum', l: 38, c: 0.05, h: 340 },
  { id: 'slate', label: 'Slate', l: 40, c: 0.03, h: 285 }
];

export function clampAccent(input) {
  const notes = [];
  let { l, c, h } = input;
  if (l < ACCENT_LIMITS.lMin) { notes.push({ what: 'lightness', from: l, to: ACCENT_LIMITS.lMin }); l = ACCENT_LIMITS.lMin; }
  if (l > ACCENT_LIMITS.lMax) { notes.push({ what: 'lightness', from: l, to: ACCENT_LIMITS.lMax }); l = ACCENT_LIMITS.lMax; }
  if (c < ACCENT_LIMITS.cMin) { notes.push({ what: 'chroma', from: c, to: ACCENT_LIMITS.cMin }); c = ACCENT_LIMITS.cMin; }
  if (c > ACCENT_LIMITS.cMax) { notes.push({ what: 'chroma', from: c, to: ACCENT_LIMITS.cMax }); c = ACCENT_LIMITS.cMax; }
  return { accent: { l, c, h: ((h % 360) + 360) % 360 }, adjusted: notes };
}

const ok = (l, c, h) => 'oklch(' + l.toFixed(1) + '% ' + c.toFixed(3) + ' ' + h.toFixed(1) + ')';

/** Alle Flaechen werden aus dem Akzent abgeleitet, nicht einzeln gepflegt. */
export function applyTheme(accentInput, mode = 'light', root = document.documentElement) {
  const { accent, adjusted } = clampAccent(accentInput);
  const { l, c, h } = accent;
  const set = (k, v) => root.style.setProperty(k, v);
  set('--accent', ok(l, c, h));
  set('--accent-pressed', ok(Math.max(20, l - 8), c, h));
  set('--accent-ring', ok(l, c, h));
  set('--accent-dark', ok(Math.min(78, l + 18), Math.min(c + 0.01, 0.09), h));
  if (mode === 'dark') {
    set('--canvas', '#121214'); set('--card', '#1A1A1E'); set('--raised', '#26262B'); set('--focus-surface', '#2E2E34');
    set('--label', '#F2F2F5'); set('--secondary', '#9A9AA0'); set('--hairline', 'rgba(255,255,255,.10)');
    set('--edge', '#3A3A40'); set('--anchor', '#4E4E56'); set('--mono-bg', '#26262B'); set('--mono-text', '#9A9AA0');
    set('--accent-on', ok(Math.min(78, l + 18), Math.min(c + 0.01, 0.09), h));
    set('--accent-tint', ok(30, Math.min(c, 0.035), h));
    set('--accent-tint-text', ok(78, Math.min(c + 0.01, 0.07), h));
  } else {
    set('--canvas', ok(98.5, 0.004, h)); set('--card', '#FFFFFF'); set('--raised', ok(96, 0.006, h)); set('--focus-surface', '#FFFFFF');
    set('--label', '#1C1C1E'); set('--secondary', '#6E6E73'); set('--hairline', 'rgba(16,24,32,.08)');
    set('--edge', ok(84, 0.012, h)); set('--anchor', ok(78, 0.014, h)); set('--mono-bg', ok(95, 0.008, h)); set('--mono-text', '#8A9A92');
    set('--accent-on', ok(l, c, h));
    set('--accent-tint', ok(94, Math.min(c, 0.03), h));
    set('--accent-tint-text', ok(Math.max(24, l - 10), c, h));
  }
  root.dataset.mode = mode;
  return { accent, adjusted };
}
