import { h, initials, fullName } from './dom.js';
import { lifeSpan, shortDate } from '../core/dates.js';
import { dateSymbols } from '../core/i18n.js';

/**
 * Bildkachel: zeigt das Portraet, sonst die Initialen. Der Zuschnitt kommt vom
 * Link (crop), nicht aus der Datei — dasselbe Foto passt in Kreis und Galerie.
 */
export function faceOf(tree, person, el) {
  if (!tree || !person) return el;
  const p = tree.portraitOf?.(person.id);
  if (!p) return el;
  // Nur die Initialen entfernen — Anker und andere Kinder bleiben stehen.
  for (const n of [...el.childNodes]) if (n.nodeType === 3) n.remove();
  // Absolut ueber der Kachel: in einem Grid mit place-items:center wuerde sich
  // das Bild nicht strecken, height:100% liefe ins Leere und cover griffe nie.
  const img = h('img', {
    alt: '', loading: 'lazy',
    style: {
      position: 'absolute', inset: '0', width: '100%', height: '100%',
      objectFit: 'cover', display: 'block', borderRadius: 'inherit',
      objectPosition: p.link.crop ? (p.link.crop.x * 100) + '% ' + (p.link.crop.y * 100) + '%' : '50% 35%'
    }
  });
  el.style.padding = '0';
  el.style.overflow = 'hidden';
  // Ohne eigenen Bezugsrahmen spannt sich das Bild ueber einen Vorfahren auf.
  // (getComputedStyle taugt hier nicht: das Element haengt noch nicht im Baum.)
  if (!el.style.position) el.style.position = 'relative';
  el.insertBefore(img, el.firstChild);
  tree.blobs?.url?.(p.media.hash).then((u) => { if (u) img.src = u; });
  return el;
}

export function personCard(person, opts = {}) {
  const { variant = 'standard', onSelect, anchors = [], place = null, focusable = true, label = null, tree = null } = opts;
  const cls = ['person-card', variant === 'compact' ? 'compact' : '', variant === 'focus' ? 'focus' : '']
    .filter(Boolean).join(' ');
  // Lebensdaten wie im Graphen: Jahr – Jahr statt Stern und Kreuz.
  const dates = lifeSpan(person);
  return h('button', {
      class: cls, type: 'button', tabindex: focusable ? 0 : -1,
      'data-person': person?.id, onClick: onSelect ? () => onSelect(person) : null
    },
    faceOf(opts.tree, person, h('span', { class: 'mono' }, initials(person))),
    h('span', { class: 'who' },
      h('span', { class: 'name' }, label ?? fullName(person)),
      dates ? h('span', { class: 'dates' }, dates + (place && person?.birthPlace ? ' · ' + person.birthPlace : '')) : null
    ),
    anchors.includes('top') ? h('span', { class: 'anchor-top' }) : null,
    anchors.includes('bottom') ? h('span', { class: 'anchor-bottom' }) : null
  );
}

export function monoNode(person, opts = {}) {
  const { onSelect, withYear = false, accentLabel = null, anchor = false } = opts;
  const node = h('button', {
    class: 'mono-node' + (accentLabel ? ' accent' : ''), type: 'button',
    'data-person': person?.id,
    title: accentLabel ? accentLabel : fullName(person),
    // Das Ereignis wird durchgereicht, damit ein Aufklappmenue sich am
    // geklickten Knoten verankern kann.
    onClick: onSelect ? (e) => onSelect(person, e) : null
  }, accentLabel ?? initials(person),
    anchor ? h('span', { class: 'anchor-top' }) : null);
  if (!accentLabel && opts.tree) faceOf(opts.tree, person, node);
  if (!withYear) return node;
  // Leere Jahreszeile auch beim "+X"-Knoten, sonst sitzt er hoeher als die Reihe.
  return h('span', { class: 'mono-stack' }, node,
    h('span', { class: 'mono-year' }, person ? (shortDate(person.birth) || '\u00A0') : '\u00A0'));
}

export function marriageNode(family, opts = {}) {
  const { soft = false, empty = false, onSelect } = opts;
  return h('button', {
    class: 'diamond' + (soft ? ' soft' : '') + (empty ? ' empty' : ''),
    type: 'button', 'aria-label': 'marriage',
    onClick: onSelect ? () => onSelect(family) : null
  });
}

export function emptySlot(label, onClick) {
  return h('button', {
    class: 'person-card compact', type: 'button',
    style: { justifyContent: 'center', color: 'var(--secondary)', boxShadow: 'inset 0 0 0 2px var(--edge)', background: 'transparent' },
    onClick
  }, h('span', {}, '+ ' + label));
}
