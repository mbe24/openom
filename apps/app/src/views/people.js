import { h, fullName, initials } from '../ui/dom.js';
import { list, nameShortener } from '../core/queries.js';
import { faceOf } from '../ui/components.js';
import { shortDate, parseDate } from '../core/dates.js';
import { t } from '../core/i18n.js';

export function peopleView(app) {
  const { tree } = app;
  const sort = app.peopleSort;
  let rows = list(tree, sort);
  const filter = app.peopleFilter;
  if (filter?.kind === 'siblings') {
    const ids = new Set(tree.siblingsOf(filter.of).map((s) => s.id));
    rows = rows.filter((r) => ids.has(r.id));
  } else if (filter?.kind === 'children') {
    const fam = tree.family(filter.familyId);
    const ids = new Set(fam ? fam.children : []);
    rows = rows.filter((r) => ids.has(r.id));
  }
  let currentInitial = null;

  // Lange Namen werden gekuerzt, nicht abgeschnitten: haeufige Vor- und
  // Nachnamen (Johann, Bach) weichen zuerst auf Initialen aus.
  const width = window.innerWidth || 1280;
  const shorten = nameShortener(tree, width <= 820 ? Math.max(18, Math.floor((width - 110) / 8.6)) : 44);
  const items = [];
  for (const p of rows) {
    // Trenner passt zur Sortierung: Buchstabe bei Namen, Jahrzehnt bei Geburt.
    let letter;
    if (sort === 'birth') {
      const y = parseDate(p.birth).sortYear;
      letter = y == null ? t('label-no-year') : String(Math.floor(y / 10) * 10);
    } else {
      letter = (sort === 'given' ? p.given : p.surname || '·').slice(0, 1).toUpperCase();
    }
    if (letter !== currentInitial) {
      currentInitial = letter;
      items.push(h('div', { class: 'section-label', style: {
        padding: '14px 4px 4px', gridColumn: '1 / -1',
        borderTop: items.length ? '1px solid var(--hairline)' : 'none', marginTop: items.length ? '10px' : '0'
      } }, letter));
    }
    items.push(h('button', {
        class: 'row', type: 'button',
        style: { gap: '14px', padding: '10px 6px', width: '100%', textAlign: 'left', borderRadius: '12px' },
        onClick: () => { app.setFocus(p.id); app.setView('detail'); }
      },
      faceOf(tree, p, h('span', { class: 'mono-node' }, initials(p))),
      h('span', { style: { flex: '1', minWidth: '0' } },
        h('span', { style: {
          fontFamily: 'var(--font-name)', fontSize: '17px', display: 'block',
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'
        } }, shorten(p)),
        // Lebensdaten allein auf ihrer Zeile: unterschiedlich lange Berufe
        // haben die Spalte vorher zerfranst. Der Beruf steht in der Person.
        h('span', { class: 'muted tabular', style: {
          fontSize: 'var(--t-small)', display: 'block', whiteSpace: 'nowrap'
        } },
          [shortDate(p.birth), shortDate(p.death)].filter(Boolean).join(' – ') || t('label-no-year')))
    ));
  }

  return h('div', { class: 'pane stack', style: { width: '100%' } },
    h('div', { class: 'row between' },
      // Der Platz fuer den Filter-Chip ist immer da — sonst springt die Liste,
      // sobald man ihn entfernt.
      h('div', { class: 'row', style: { gap: '10px', alignItems: 'center', minHeight: '34px' } },
        h('div', { class: 'section-label' }, t('label-people-count', { count: rows.length })),
        filter ? h('button', { class: 'chip accent small', onClick: () => app.clearPeopleFilter() }, filter.label + ' ×') : null),
      h('div', { class: 'segmented' },
        ...[['surname', t('label-surname')], ['given', t('label-given')], ['birth', t('label-born')]].map(([key, label]) =>
          h('button', { type: 'button', 'aria-pressed': String(sort === key), onClick: () => app.setPeopleSort(key) }, label)))
    ),
    // Kein Panel: die Liste IST der Inhalt der Seite, das Weiss wuerde nur den
    // Bildschirmrand doppeln.
    h('div', { style: {
        display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(min(320px, 100%), 1fr))',
        gap: '2px 28px', alignContent: 'start'
      } }, ...items)
  );
}
