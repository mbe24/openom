import { h, svg, fullName } from '../ui/dom.js';
import { ancestorRings } from '../core/queries.js';
import { t, isRTL } from '../core/i18n.js';
import { isNarrow, isShort, isCompact } from '../ui/viewport.js';

const P = (cx, cy, a, r) => [cx + r * Math.cos((a * Math.PI) / 180), cy - r * Math.sin((a * Math.PI) / 180)];

/**
 * Faecher. Im Hochformat oeffnet er nach rechts (Verhaeltnis 1:2), im
 * Querformat nach oben — dieselbe Geometrie, nur andere Spannweite.
 * Namen laufen auf dem Bogen ihres Segments; umgekehrt wird der Bogen nur dort,
 * wo die Schrift sonst kopfstuende.
 */
export function fanView(app) {
  const { tree, focusId } = app;
  // Nur schmal UND hoch heisst Hochformat. Die reine Breitenpruefung hielt ein
  // querliegendes Handy (740 px) fuer hochkant und liess den Faecher nach
  // rechts zeigen, statt die Gerade an die lange Seite zu legen.
  const upright = isNarrow() && !isShort();
  // Rechts nach links: der Faecher oeffnet im Hochformat nach links.
  const rtl = isRTL();
  const dir = upright ? (rtl ? 180 : 0) : 90;
  const flat = dir === 0 || dir === 180;
  const span = flat ? 150 : 180;
  // Der Faecher waechst mit dem Platz. Seine Form ist bei 180 Grad festgelegt
  // auf 2:1 (Breite zu Hoehe) — mehr Spannweite macht ihn wieder schmaler.
  // Also lassen sich nur die Ringe an den Platz anpassen: wo das Bild breiter
  // ist als die Form braucht, tragen zusaetzliche Ringe die Generationen, statt
  // die Flaeche leer zu lassen.
  const availW = Math.max(240, (window.innerWidth || 1280) - (isNarrow() ? 32 : 96));
  const availH = Math.max(200, (window.innerHeight || 800) - (isCompact() ? 130 : 120));
  // Bildseitenverhaeltnis gegen die Form: > 2 heisst breiter Rand, < 0.52 heisst
  // hoher Rand. Danach richtet sich die Tiefe.
  const ratio = flat ? availH / availW : availW / availH;
  const deep = flat ? ratio > 2.1 : ratio > 2.3;
  const rings = isCompact() ? (deep ? 4 : 3) : (deep ? 5 : 4);
  const r0 = isCompact() ? 70 : 84;
  const dr = isCompact() ? 58 : 70;
  const R = r0 + rings * dr;
  const pad = 4;
  const half = span / 2;
  const w = flat ? R + pad : 2 * R * Math.sin((half * Math.PI) / 180) + pad;
  const hgt = flat ? 2 * R * Math.sin((half * Math.PI) / 180) + pad : R + pad;
  const cx = dir === 0 ? pad / 2 : dir === 180 ? w - pad / 2 : w / 2;
  const cy = flat ? hgt / 2 : hgt - pad / 2;

  const root = svg('svg', { viewBox: '0 0 ' + w.toFixed(0) + ' ' + hgt.toFixed(0),
    preserveAspectRatio: 'xMidYMid meet',
    style: 'display:block;width:100%;height:100%' });
  const defs = svg('defs');
  root.appendChild(defs);

  const people = ancestorRings(tree, focusId, rings);
  const fits = [];

  const seg = (a1, a2, rr1, rr2) => {
    const [x1, y1] = P(cx, cy, a1, rr2), [x2, y2] = P(cx, cy, a2, rr2);
    const [x3, y3] = P(cx, cy, a2, rr1), [x4, y4] = P(cx, cy, a1, rr1);
    return 'M' + x1 + ' ' + y1 + ' A' + rr2 + ' ' + rr2 + ' 0 0 1 ' + x2 + ' ' + y2 +
           ' L' + x3 + ' ' + y3 + ' A' + rr1 + ' ' + rr1 + ' 0 0 0 ' + x4 + ' ' + y4 + ' Z';
  };

  for (let k = 0; k < rings; k++) {
    const n = Math.pow(2, k + 1);
    const step = span / n;
    const rr1 = r0 + k * dr, rr2 = r0 + (k + 1) * dr - 3;
    for (let i = 0; i < n; i++) {
      const slot = rtl ? n - 1 - i : i;
      const a1 = dir + half - slot * step, a2 = a1 - step;
      const person = people[k] ? people[k][i] : null;
      const sourced = person && person.sources && person.sources.length > 0;
      root.appendChild(svg('path', {
        d: seg(a1, a2, rr1, rr2),
        fill: !person ? 'var(--raised)' : sourced ? 'var(--accent)' : 'var(--accent-dark)',
        stroke: 'var(--card)', 'stroke-width': 2.5,
        style: person ? 'cursor:pointer' : '',
        'data-person': person ? person.id : ''
      }));
      if (!person || k > 1) continue;
      const rm = (rr1 + rr2) / 2;
      const mid = (a1 + a2) / 2;
      const label0 = k === 0 ? shortName(person) : initialsName(person);
      // Namen laufen auf dem Bogen. Umgekehrt wird er nur, wo er sonst
      // kopfstuende — im Querformat liegt alles oberhalb der Achse, also nie.
      // Umgekehrt wird der Bogen, wo die Schrift sonst kopfstuende.
      const norm = ((mid + 180) % 360 + 360) % 360 - 180;
      const flip = flat ? norm < 0 : false;
      const [sx, sy] = P(cx, cy, flip ? a2 : a1, rm);
      const [ex, ey] = P(cx, cy, flip ? a1 : a2, rm);
      const id = 'fan-' + k + '-' + i;
      defs.appendChild(svg('path', { id, fill: 'none',
        d: 'M' + sx + ' ' + sy + ' A' + rm + ' ' + rm + ' 0 0 ' + (flip ? 0 : 1) + ' ' + ex + ' ' + ey }));
      const text = svg('text', { fill: sourced ? 'var(--card)' : 'var(--label)',
        'font-family': 'var(--font-name)', 'font-size': k === 0 ? 15 : 13, 'dominant-baseline': 'middle' });
      const tp = svg('textPath', { href: '#' + id, startOffset: '50%', 'text-anchor': 'middle' });
      tp.textContent = label0;
      text.appendChild(tp);
      root.appendChild(text);
      // Abgeschnittene Namen gibt es nicht: passt der Name nicht auf den Bogen,
      // wird er gekuerzt, bis er passt — notfalls bis aufs Monogramm.
      fits.push({ tp, pathId: id, options: labelChain(person, label0) });
    }
  }
  root.appendChild(svg('path', { d: seg(dir + half, dir - half, 0, r0 - 3), fill: 'var(--accent-pressed)' }));
  const me = tree.person(focusId);
  // Der Kern laeuft in jeder Lage auf einem Bogen — gerader Text im Kreis sieht
  // fremd aus, und ohne Bogen greift die Kuerzungspruefung nicht.
  {
    const rm = (r0 - 3) * 0.62;
    const [sx, sy] = P(cx, cy, dir + half, rm), [ex, ey] = P(cx, cy, dir - half, rm);
    defs.appendChild(svg('path', { id: 'fan-core', fill: 'none',
      d: 'M' + sx + ' ' + sy + ' A' + rm + ' ' + rm + ' 0 0 1 ' + ex + ' ' + ey }));
    const core = svg('text', { fill: 'var(--card)', 'font-family': 'var(--font-name)',
      'font-size': 15, 'dominant-baseline': 'middle' });
    const ctp = svg('textPath', { href: '#fan-core', startOffset: '50%', 'text-anchor': 'middle' });
    ctp.textContent = shortName(me);
    core.appendChild(ctp);
    root.appendChild(core);
    fits.push({ tp: ctp, pathId: 'fan-core', options: labelChain(me, shortName(me)) });
  }

  // Gemessen wird der Pfad selbst: eine Schaetzung aus Spannweite und Radius lag
  // ueber der echten Laenge. Und zweimal gemessen — beim ersten Frame ist die
  // Namensschrift noch nicht geladen, die Ersatzschrift misst kuerzer, und der
  // Name waechst danach ueber den Bogen hinaus.
  const applyFits = () => {
    for (const { tp, pathId, options } of fits) {
      const path = defs.querySelector('#' + pathId);
      if (!path) continue;
      const room = path.getTotalLength() - 16;
      for (const option of options) {
        tp.textContent = option;
        if (tp.parentNode.getComputedTextLength() <= room) break;
      }
    }
  };
  requestAnimationFrame(applyFits);
  if (document.fonts?.ready) document.fonts.ready.then(() => { if (root.isConnected) applyFits(); });

  root.addEventListener('click', (e) => {
    const id = e.target?.dataset?.person;
    if (id) app.setFocus(id);
  });

  const stats = t('label-generations', { count: rings + 1, total: app.generations });
  return h('div', { class: 'pane stack', style: {
      height: '100%', gap: '4px', position: 'relative',
      ...(isShort() ? { padding: '4px 10px 6px' } : null)
    } },
    h('div', { class: 'muted', style: {
      position: 'absolute', top: '16px', right: '16px', zIndex: '6',
      fontSize: 'var(--t-tiny)', pointerEvents: 'none'
    } }, stats),
    h('div', { class: 'no-bar', style: { flex: '1', minHeight: '0', minWidth: '0', display: 'flex' } }, root)
  );
}

function shortName(person) {
  if (!person) return '';
  const given = (person.given ?? '').split(/\s+/);
  const first = given[0] ?? '';
  const second = given[1];
  const initial = second ? first.slice(0, 1) + '.\u00A0' + second : first;
  return (initial + ' ' + (person.surname ?? '')).trim();
}

function initialsName(person) {
  if (!person) return '';
  const g = (person.given ?? '').split(/\s+/)[0] ?? '';
  return (g.slice(0, 1) + '.\u00A0' + (person.surname ?? '')).trim();
}

/** Namensvarianten von lang nach kurz — die erste, die auf den Bogen passt, gewinnt. */
function labelChain(person, longest) {
  const given = (person.given ?? '').split(/\s+/).filter(Boolean);
  const surname = person.surname ?? '';
  const inits = given.map((g) => g.slice(0, 1) + '.').join('\u00A0');
  const chain = [longest, initialsName(person)];
  if (given.length) {
    chain.push(inits + '\u00A0' + surname);
    if (surname) chain.push(inits + '\u00A0' + surname.slice(0, 1) + '.');
  }
  chain.push(surname || longest);
  chain.push((given.map((g) => g.slice(0, 1)).join('') + surname.slice(0, 1)).toUpperCase());
  return chain.filter((v, i, a) => v && a.indexOf(v) === i);
}
