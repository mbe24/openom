import { h, fullName } from './dom.js';
import { t } from '../core/i18n.js';
import { shortDate } from '../core/dates.js';

/**
 * Personensuche — verknuepft eine *vorhandene* Person, ohne jemanden anzulegen.
 *
 * Bewusst derselbe Dialog wie die Lupe (⌘K): gleiche Aufgabe, gleiche Form.
 * Nur die Ueberschrift sagt, wofuer gesucht wird. exclude verhindert Unsinn:
 * sich selbst, schon Verknuepfte, bei Kindern die Vorfahren (Zyklus) und alle,
 * die bereits Eltern haben.
 */
export function pickPerson(_anchor, { tree, exclude, title, onPick }) {
  document.querySelector('.command-palette.picker')?.remove();

  const candidates = tree.allPeople()
    .filter((p) => !exclude.has(p.id))
    .sort((a, b) => fullName(a).localeCompare(fullName(b)));

  const results = h('div', { class: 'command-results' });
  const footer = h('div', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } });

  const update = (raw) => {
    const needle = String(raw).trim().toLowerCase();
    const hits = candidates.filter((p) => !needle || fullName(p).toLowerCase().includes(needle)).slice(0, 50);
    footer.textContent = hits.length ? t('search-hits', { count: hits.length }) : t('rel-no-match');
    results.replaceChildren(...hits.map((p) => h('button', {
      type: 'button', onClick: () => { close(); onPick(p.id); }
    },
      // Name oben, Lebensdaten darunter — wie in der Lupe.
      h('span', { class: 'stack', style: { gap: '2px', minWidth: '0', width: '100%' } },
        h('span', { style: { fontFamily: 'var(--font-name)', fontSize: '17px', display: 'block' } }, fullName(p)),
        h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)', display: 'block' } },
          [shortDate(p.birth), shortDate(p.death)].filter(Boolean).join(' – ') || t('label-no-year'))))));
  };

  const input = h('input', { placeholder: t('rel-search'), 'aria-label': title,
    onInput: (e) => update(e.target.value) });
  const layer = h('div', { class: 'command-palette picker',
    onClick: (e) => { if (e.target === layer) close(); } },
    h('div', { class: 'command-panel' },
      h('div', { class: 'section-label' }, title),
      input, results, footer));

  const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
  const close = () => { document.removeEventListener('keydown', onKey, true); layer.remove(); };
  document.addEventListener('keydown', onKey, true);

  update('');
  document.body.appendChild(layer);
  input.focus();
}

/** Alle Personen, die schon in einer Familie Kind sind — koennen es nicht zweimal sein. */
export function alreadyChildIds(tree) {
  return tree.allPeople().filter((p) => tree.childFamilyOf(p.id)).map((p) => p.id);
}
