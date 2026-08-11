import { h } from './dom.js';
import { t } from '../core/i18n.js';
import { placeCard } from './popover.js';
import { icons } from './icons.js';

/**
 * Kontextmenue an einem Knoten. Eine Spalte, keine Untermenues: bei drei
 * Beziehungen kostet eine Kaskade einen zweiten Zielvorgang und bringt nichts.
 * Vater und Mutter entfallen, sobald sie existieren — ein grauer Eintrag, der
 * nie klickbar wird, ist toter Platz.
 *
 * Kinder fehlen hier bewusst: bei mehreren Ehen sagt der Eintrag nicht, zu
 * welcher das Kind gehoert. Das geht ueber die Beziehungen im Editor, wo die
 * Ehe sichtbar ist, an der es haengt.
 */
export function personMenu(app, personId, x, y) {
  const host = document.querySelector('.pane');
  if (!host) return;
  host.querySelector('.ctx-layer')?.remove();
  if (getComputedStyle(host).position === 'static') host.style.position = 'relative';

  const { father, mother } = app.tree.parentsOf(personId);

  const act = (label, run) => h('button', { class: 'ctx-item', type: 'button',
    onClick: () => { layer.remove(); run(); } }, label);

  const items = [
    act(t('action-edit'), () => { app.setFocus(personId); app.setView('editor'); }),
    h('div', { class: 'ctx-sep' }),
    father ? null : act(t('action-add-father'), () => app.addParentFor(personId, 'M')),
    mother ? null : act(t('action-add-mother'), () => app.addParentFor(personId, 'F')),
    act(t('action-add-marriage'), () => { app.setFocus(personId); app.addMarriage(); })
  ].filter(Boolean);

  const card = h('div', { class: 'ctx-card' }, ...items);
  const layer = h('div', { class: 'ctx-layer',
    onClick: () => layer.remove(),
    onContextmenu: (e) => { e.preventDefault(); layer.remove(); } }, card);
  host.appendChild(layer);

  // Am Zeiger, aber innerhalb der Flaeche: an der Kante klappt es um.
  const hr = host.getBoundingClientRect();
  const w = card.offsetWidth, hgt = card.offsetHeight;
  card.style.left = Math.round(Math.max(8, Math.min(hr.width - w - 8, x - hr.left))) + 'px';
  card.style.top = Math.round(Math.max(8, Math.min(hr.height - hgt - 8, y - hr.top))) + 'px';
}

/**
 * Zwei Wege, ein Knopf: "Neu anlegen" oder "Vorhandene verknuepfen". Am Anker
 * statt am Zeiger, weil der Knopf klein ist und das Menue zu ihm gehoert.
 */
export function choiceMenu(anchor, items) {
  const host = anchor.closest('.pane');
  if (!host) return;
  if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
  host.querySelector('.ctx-layer')?.remove();

  const card = h('div', { class: 'ctx-card' },
    ...items.filter(Boolean).map(({ label, run }) =>
      h('button', { class: 'ctx-item', type: 'button',
        onClick: (ev) => { ev.stopPropagation(); layer.remove(); run(); } }, label)));
  const layer = h('div', { class: 'ctx-layer', onClick: () => layer.remove() }, card);
  host.appendChild(layer);
  placeCard(anchor, host, card, { maxHeight: card.offsetHeight, width: card.offsetWidth });
}

/**
 * Ein Plus, zwei Wege: neu anlegen oder eine vorhandene Person verknuepfen.
 * Beide Eintraege nennen die Rolle — "Add child" gegen "Link child" liest sich
 * ohne Nachdenken, "Neu anlegen" gegen "Verknuepfen" nicht.
 */
export function addChoiceButton({ label, linkLabel, create, link, size = 18, klass = 'icon-button' }) {
  const btn = h('button', { class: klass, type: 'button', style: { flex: 'none' },
    title: label, 'aria-label': label,
    onClick: () => choiceMenu(btn, [
      { label, run: create },
      { label: linkLabel, run: () => link(btn, linkLabel) }
    ]) }, icons.plus(size));
  return btn;
}
