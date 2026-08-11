import { h, svg } from '../ui/dom.js';
import { t } from '../core/i18n.js';

/** Leerer Baum: eine Entscheidung, zwei Wege hinein. */
export function onboardingView(app) {
  const glyph = svg('svg', { viewBox: '0 0 100 100', width: 108, height: 108, fill: 'none', 'stroke-linecap': 'round' });
  const parts = [
    svg('rect', { x: 6, y: 6, width: 30, height: 20, rx: 7, stroke: 'var(--edge)', 'stroke-width': 2.5, 'stroke-dasharray': '6 6' }),
    svg('rect', { x: 64, y: 6, width: 30, height: 20, rx: 7, stroke: 'var(--edge)', 'stroke-width': 2.5, 'stroke-dasharray': '6 6' }),
    svg('path', { d: 'M21 26 Q34 33 42 43 M79 26 Q66 33 58 43 M50 57 V68', stroke: 'var(--edge)', 'stroke-width': 2.5 }),
    svg('rect', { x: 43.5, y: 41.5, width: 13, height: 13, rx: 4, fill: 'var(--accent-dark)', transform: 'rotate(45 50 48)' }),
    svg('rect', { x: 30, y: 68, width: 40, height: 26, rx: 9, fill: 'var(--accent-tint)', stroke: 'var(--accent)', 'stroke-width': 2.5 }),
    svg('circle', { cx: 21, cy: 26, r: 3.4, fill: 'var(--edge)' }),
    svg('circle', { cx: 79, cy: 26, r: 3.4, fill: 'var(--edge)' }),
    svg('circle', { cx: 50, cy: 68, r: 3.4, fill: 'var(--anchor)' })
  ];
  for (const p of parts) glyph.appendChild(p);

  return h('div', { class: 'pane', style: { display: 'flex' } },
    h('div', { class: 'card empty', style: { maxWidth: '640px', width: '100%', margin: 'auto' } },
      h('div', { style: { width: '150px', height: '150px', borderRadius: '38px', background: 'var(--raised)', display: 'grid', placeItems: 'center' } }, glyph),
      h('div', { style: { fontFamily: 'var(--font-name)', fontSize: '30px' } }, t('hint-empty-tree')),
      h('div', { class: 'muted', style: { maxWidth: '46ch' } }, t('hint-empty-tree-body')),
      h('div', { class: 'row', style: { gap: '10px' } },
        h('input', { id: 'first-name', placeholder: t('label-given') + ' ' + t('label-surname'),
          style: { padding: '14px 16px', borderRadius: 'var(--r-control)', border: 0, background: 'var(--raised)', minWidth: '260px' } }),
        h('button', { class: 'button-primary', onClick: () => {
          const raw = document.getElementById('first-name').value.trim();
          if (!raw) return;
          const parts2 = raw.split(/\s+/);
          const surname = parts2.length > 1 ? parts2.pop() : '';
          app.createFirstPerson({ given: parts2.join(' '), surname });
        } }, t('action-new-person'))),
      h('button', { class: 'button-quiet', onClick: () => app.setView('transfer') }, t('action-import'))
    )
  );
}
