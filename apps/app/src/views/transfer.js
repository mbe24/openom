import { h } from '../ui/dom.js';
import { t } from '../core/i18n.js';
import { toast } from '../ui/dom.js';

export function transferView(app) {
  const formats = app.transfer.formats();
  const report = app.importReport;

  const drop = h('div', {
    class: 'card',
    style: { display: 'grid', placeItems: 'center', gap: '10px', padding: '48px 24px',
      boxShadow: 'inset 0 0 0 2px var(--edge)', background: 'var(--raised)', textAlign: 'center' },
    onDragover: (e) => { e.preventDefault(); },
    onDrop: async (e) => {
      e.preventDefault();
      const file = e.dataTransfer?.files?.[0];
      if (file) app.parseImport(file);
    }
  },
    h('div', { style: { fontFamily: 'var(--font-name)', fontSize: '22px' } }, t('transfer-drop')),
    h('div', { class: 'muted', style: { fontSize: 'var(--t-small)' } },
      formats.map((f) => f.label + (f.caps.import ? '' : ' (—)')).join(' · ')),
    h('label', { class: 'button-secondary', style: { cursor: 'pointer' } }, t('action-import'),
      h('input', { type: 'file', style: { display: 'none' },
        onChange: (e) => { const f = e.target.files?.[0]; if (f) app.parseImport(f); } }))
  );

  return h('div', { class: 'pane stack', style: { maxWidth: '1000px', width: '100%', margin: '0 auto' } },
    h('div', { class: 'section-label' }, t('view-transfer')),
    drop,
    report
      ? h('div', { class: 'card stack' },
          h('div', { class: 'row between' },
            h('span', {}, t('transfer-report', { people: report.people, families: report.families })),
            h('span', { class: 'chip' }, report.formatLabel)),
          report.diagnostics.length
            ? h('div', { class: 'stack', style: { gap: '4px' } },
                ...report.diagnostics.slice(0, 8).map((d) => h('div', { class: 'muted', style: { fontSize: 'var(--t-small)' } }, d.message ?? String(d))))
            : null,
          h('div', { class: 'row', style: { gap: '10px' } },
            h('button', { class: 'button-primary', onClick: () => app.applyImport('merge') }, t('transfer-apply')),
            h('button', { class: 'button-secondary', onClick: () => app.clearImport() }, t('action-cancel'))))
      : null,
    h('div', { class: 'card stack' },
      h('div', { class: 'section-label' }, t('action-export')),
      h('div', { class: 'row', style: { gap: '10px', flexWrap: 'wrap' } },
        ...formats.map((f) => h('button', {
          class: f.caps.export ? 'button-secondary' : 'chip',
          onClick: f.caps.export ? () => app.exportAs(f.id) : () => toast(t('transfer-unsupported', { format: f.label }))
        }, f.label + (f.caps.lossless ? '' : ' ·  lossy')))),
      h('div', { class: 'muted', style: { fontSize: 'var(--t-small)' } },
        'openom JSON is lossless; GEDCOM is registered but not implemented yet.'))
  );
}
