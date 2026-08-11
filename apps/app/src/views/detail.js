import { h, fullName, initials } from '../ui/dom.js';
import { icons } from '../ui/icons.js';
import { isCompact } from '../ui/viewport.js';
import { faceOf } from '../ui/components.js';
import { familiesOf } from '../core/queries.js';
import { parseDate, shortDate } from '../core/dates.js';
import { t, dateSymbols } from '../core/i18n.js';

export function detailView(app) {
  const { tree, focusId } = app;
  const person = tree.person(focusId);
  if (!person) return h('div', { class: 'pane' }, t('label-unknown'));
  const sym = dateSymbols();
  const fams = familiesOf(tree, focusId);
  const activeId = app.activeFamilyId && fams.some((f) => f.family.id === app.activeFamilyId) ? app.activeFamilyId : null;
  const shownChildren = activeId
    ? fams.find((f) => f.family.id === activeId).children
    : fams.flatMap((f) => f.children);

  const birth = parseDate(person.birth);
  const death = parseDate(person.death);

  const { father, mother } = tree.parentsOf(person.id);
  /**
   * Ein Plus, zwei Wege: neu anlegen oder eine vorhandene Person verknuepfen.
   * Vorher trug derselbe Knopf nur die erste Bedeutung, ohne es zu sagen.
   */

  const portrait = isCompact();
  // Die Personenseite scrollt — die Knoepfe haengen am Fenster, nicht am Inhalt.
  // Hochformat: die beiden Knoepfe schweben unten rechts uebereinander, wie im
  // Graphen — am Daumen statt oben am Rand. Sonst neben dem Namen.
  const actions = h('div', { class: 'graph-fabs floating' },
    h('button', { class: 'fab primary', type: 'button', style: { flex: 'none' },
      title: t('action-edit'), 'aria-label': t('action-edit'),
      onClick: () => app.setView('editor') }, icons.edit(22)),
    h('button', { class: 'fab', type: 'button', style: { flex: 'none' },
      title: t('action-show-in-tree'), 'aria-label': t('action-show-in-tree'),
      onClick: () => app.setView('tree') }, icons.tree(22)));

  return h('div', { class: 'pane', style: {
      display: 'flex', flex: '0 0 auto', minHeight: '100%', boxSizing: 'border-box',
      // Platz fuer den schwebenden Knopfstapel: sonst bleibt der letzte Eintrag
      // am Scrollende dauerhaft darunter liegen.
      paddingBottom: '120px'
    } },
    // Hochformat: kein Panel — die Person IST der Bildschirm.
    h('div', { class: 'stack', style: { gap: '22px', width: '100%' } },
      h('div', { class: 'row', style: { gap: '18px' } },
        faceOf(tree, person, h('span', { class: 'mono', style: {
          width: '84px', height: '84px', borderRadius: '22px', display: 'grid', placeItems: 'center',
          background: 'var(--accent-tint)', color: 'var(--accent-tint-text)',
          fontFamily: 'var(--font-name)', fontSize: '30px', overflow: 'hidden'
        } }, initials(person))),
        h('div', { class: 'stack', style: { gap: '6px', minWidth: '0' } },
          h('div', { style: { fontFamily: 'var(--font-name)', fontSize: '30px' } }, fullName(person)),
          h('div', { class: 'muted tabular' },
            [birth.display && sym.birth + ' ' + birth.display + (person.birthPlace ? ' ' + person.birthPlace : ''),
             death.display && sym.death + ' ' + death.display + (person.deathPlace ? ' ' + person.deathPlace : '')]
              .filter(Boolean).join(' · ')),
          h('div', { class: 'row', style: { gap: '8px' } },
            person.custom?.occupation ? h('span', { class: 'chip accent' }, person.custom.occupation) : null,
            h('span', { class: 'chip' }, (person.sources?.length ?? 0) + ' ' + t('label-sources')))),
        null
      ),

      // Die Biografie steht vor allem anderen: sie erklaert die Person, die
      // Beziehungen ordnen sie nur ein. Ueber die ganze Breite, weil ein
      // Absatz in einer halben Spalte zu schmal laeuft.
      person.note ? h('div', { class: 'stack' },
        h('div', { class: 'section-label' }, t('label-note')),
        h('p', { style: { margin: 0, lineHeight: '1.55', maxWidth: '70ch' } }, person.note)) : null,

h('div', { style: { display: 'grid',
          gridTemplateColumns: (window.innerWidth || 1280) <= 820 ? '1fr' : 'minmax(0, 1fr) minmax(0, 1.1fr)',
          gap: (window.innerWidth || 1280) <= 820 ? '20px' : '32px', alignItems: 'start' } },
        h('div', { class: 'stack', style: { gap: '18px' } },
          h('div', { class: 'stack', style: { gap: '6px' } },
            h('div', { class: 'section-label' }, t('label-parents')),
            ...[['M', father, t('label-father-unknown'), t('action-add-father')],
                ['F', mother, t('label-mother-unknown'), t('action-add-mother')]].map(([sex, p, what, add]) =>
              p
                ? h('button', { class: 'row', type: 'button',
                    style: { gap: '12px', padding: '8px 0 8px 4px', width: '100%', textAlign: 'left' },
                    onClick: () => app.setFocus(p.id) },
                    faceOf(tree, p, h('span', { class: 'mono-node' }, initials(p))),
                    h('span', { style: { flex: '1', fontFamily: 'var(--font-name)', fontSize: '17px' } }, fullName(p)),
                    h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)' } },
                      [shortDate(p.birth), shortDate(p.death)].filter(Boolean).join(' – ')))
                // Diese Ansicht zeigt nur — ergaenzt wird im Editor.
                : h('div', { class: 'row', style: { gap: '12px', padding: '8px 0 8px 4px', alignItems: 'center' } },
                    h('span', { class: 'muted', style: { flex: '1' } }, what)))),

          h('div', { class: 'stack' },
            h('div', { class: 'row between', style: { alignItems: 'center' } },
              h('div', { class: 'section-label' }, t('label-marriages')),
              null),
            ...fams.map(({ family, spouse, children }) => h('button', {
                class: 'stack', type: 'button',
                style: {
                  gap: '4px', padding: '12px 14px', borderRadius: '14px', textAlign: 'left', width: '100%',
                  background: family.id === activeId ? 'var(--accent-tint)' : 'transparent',
                  boxShadow: family.id === activeId ? 'inset 0 0 0 2px var(--accent)' : 'none'
                },
                onClick: () => app.setActiveFamily(family.id === activeId ? null : family.id)
              },
              h('span', { class: 'row between', style: { gap: '16px' } },
                h('span', { style: { fontFamily: 'var(--font-name)', fontSize: '19px' } }, fullName(spouse, t('label-unknown'))),
                h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)' } },
                  family.facts?.marriage ? sym.marriage + ' ' + family.facts.marriage + (family.facts.place ? ' ' + family.facts.place : '') : '')),
              h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)' } },
                [shortDate(spouse?.birth), shortDate(spouse?.death)].filter(Boolean).join(' – ')
                + ' · ' + children.length + ' ' + t('label-children'))
            )),
            fams.length === 0 ? h('div', { class: 'muted' }, '—') : null),

          h('div', { class: 'stack', style: { gap: '6px' } },
            h('div', { class: 'row between', style: { alignItems: 'center' } },
              h('div', { class: 'section-label' }, t('label-children')),
              h('div', { class: 'row', style: { gap: '8px', alignItems: 'center' } },
                activeId ? h('button', { class: 'chip accent', onClick: () => app.setActiveFamily(null) },
                  fullName(fams.find((f) => f.family.id === activeId).spouse, t('label-unknown')) + ' ×') : null,
                null)),
            h('div', { style: {
                display: 'flex', flexDirection: 'column', gap: '2px',
                maxHeight: 'min(440px, max(160px, 40vh))', overflowY: 'auto', paddingRight: '4px',
                maskImage: shownChildren.length > 7
                  ? 'linear-gradient(to bottom, transparent 0, #000 12px, #000 calc(100% - 12px), transparent 100%)'
                  : 'none'
              } },
              ...shownChildren.map((c) => h('button', {
                  class: 'row', type: 'button',
                  style: { gap: '12px', padding: '8px 0 8px 4px', width: '100%', textAlign: 'left', flex: 'none' },
                  onClick: () => { app.setFocus(c.id); }
                },
                faceOf(tree, c, h('span', { class: 'mono-node' }, initials(c))),
                h('span', { style: { flex: '1', fontFamily: 'var(--font-name)', fontSize: '17px' } }, fullName(c)),
                h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)' } },
                  [shortDate(c.birth), shortDate(c.death)].filter(Boolean).join(' – '))))),
            h('div', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } },
              shownChildren.length + ' ' + t('label-children')))),

        h('div', { class: 'stack', style: { gap: '22px' } },
          person.sources?.length ? h('div', { class: 'stack' },
            h('div', { class: 'section-label' }, t('label-sources')),
            ...person.sources.map((s) => h('div', { class: 'stack', style: { gap: '2px', padding: '8px 0' } },
              h('div', { style: { fontWeight: '500' } }, s.title),
              h('div', { class: 'muted', style: { fontSize: 'var(--t-small)' } },
                [s.detail, s.supports].filter(Boolean).join(' · '))))) : null)
      )
    ),
    actions
  );
}