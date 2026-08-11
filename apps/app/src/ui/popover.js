/**
 * Setzt eine Aufklappkarte an einen Anker. Gerechnet wird gegen den
 * *sichtbaren* Bereich, nicht gegen die Pane: im Editor ist die Pane der ganze
 * scrollbare Inhalt (2143 px hoch), eine Begrenzung darauf wirkt also nie und
 * die Karte landet unter der Fensterkante.
 *
 * host traegt die Karte (position: relative), viewport ist das, was man sieht.
 */
export function placeCard(anchor, host, card, { maxHeight = 380, width = 320, gap = 8 } = {}) {
  const ar = anchor.getBoundingClientRect();
  const hr = host.getBoundingClientRect();
  const scroller = host.closest('.content') ?? host;
  const vr = scroller === host
    ? { top: 0, bottom: window.innerHeight }
    : scroller.getBoundingClientRect();

  const w = Math.min(width, hr.width - 24);
  card.style.width = w + 'px';

  // Platz ober- und unterhalb des Ankers in Fensterkoordinaten.
  const below = Math.max(0, vr.bottom - ar.bottom - gap - 12);
  const above = Math.max(0, ar.top - vr.top - gap - 12);
  const up = below < Math.min(maxHeight, above);
  card.style.maxHeight = Math.round(Math.max(120, Math.min(maxHeight, up ? above : below))) + 'px';

  const left = ar.left - hr.left + ar.width / 2 - w / 2;
  card.style.left = Math.round(Math.max(12, Math.min(hr.width - w - 12, left))) + 'px';

  // offsetHeight erst lesen, wenn maxHeight steht — sonst rechnet man mit der
  // ungebremsten Hoehe.
  const need = card.offsetHeight;
  let top = up ? ar.top - need - gap : ar.bottom + gap;
  // Der Lesbarkeits-Boden (120 px) kann die Karte hoeher machen, als neben dem
  // Anker Platz ist. Deshalb am Ende ins sichtbare Band klemmen: sie rutscht
  // dann ins Bild, statt an der Kante angeschnitten zu werden.
  top = Math.min(Math.max(top, vr.top + 12), Math.max(vr.top + 12, vr.bottom - need - 12));
  card.style.top = Math.round(top - hr.top) + 'px';
}
