// Eine Stelle fuer die Groessenfragen, damit Ansichten dieselbe Antwort geben.
//
// narrow  = schmales Geraet (Handy hochkant): eigene, hohe Geometrie.
// compact = wenig Hoehe ODER wenig Breite: Arbeitsflaeche statt Seite —
//           ziehen und zoomen, schwebende Knoepfe, kein Seitenpanel.

export function isNarrow() {
  return (window.innerWidth || 1280) <= 820;
}

export function isShort() {
  return (window.innerHeight || 800) <= 520;
}

export function isCompact() {
  return isNarrow() || isShort();
}

/**
 * Eingabeart: Wischen gegen Kreuz-Knopf. Die Groesse taugt dafuer nicht — ein
 * verkleinertes Desktop-Fenster ist schmal, hat aber keine Wischgeste.
 *
 * ?touch=1 erzwingt die Touch-Fassung, ?touch=0 die Zeiger-Fassung. Nur zum
 * Ansehen am Rechner, wo pointer:coarse immer falsch meldet.
 */
const TOUCH_KEY = 'openom.forceTouch';

/**
 * Wurde die Touch-Fassung von Hand eingeschaltet? Dann darf auch die Maus
 * wischen. ?touch=1 / ?touch=0 in der Adresse geht vor, sonst gilt der
 * Schalter aus den Einstellungen.
 */
export function isTouchForced() {
  const q = new URLSearchParams(location.search).get('touch');
  if (q === '1') return true;
  if (q === '0') return false;
  try { return localStorage.getItem(TOUCH_KEY) === '1'; } catch { return false; }
}

export function setTouchForced(on) {
  try { localStorage.setItem(TOUCH_KEY, on ? '1' : '0'); } catch { /* ohne Speicher eben nur diese Sitzung */ }
  window.dispatchEvent(new Event('openom:touchmode'));
}

export function isTouchInput() {
  const q = new URLSearchParams(location.search).get('touch');
  if (q === '1') return true;
  if (q === '0') return false;
  if (isTouchForced()) return true;
  return window.matchMedia('(pointer: coarse)').matches;
}

/**
 * Layout bucket a resize could actually change. Comparing this instead of raw
 * pixels keeps the app from re-rendering when a phone's virtual keyboard
 * shrinks the window — a re-render there replaces the focused input and
 * dismisses the keyboard again.
 */
export function layoutBucket() {
  return [isNarrow(), isShort(), Math.round((window.innerWidth || 1280) / 60)].join(':');
}

/** True while a text field or editable element has focus. */
export function isTyping() {
  const el = document.activeElement;
  if (!el) return false;
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable;
}
