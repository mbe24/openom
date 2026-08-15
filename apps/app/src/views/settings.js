import { h, toast } from '../ui/dom.js';
import { icons } from '../ui/icons.js';
import { DATASETS } from '../core/library.js';
import { isCompact, isTouchForced, setTouchForced } from '../ui/viewport.js';
import { PRESETS, clampAccent } from '../core/theme.js';
import { LOCALES, locale as currentLocale } from '../core/i18n.js';
import { t } from '../core/i18n.js';
import { stats } from '../core/queries.js';

export function settingsView(app) {
  const portrait = (window.innerWidth || 1280) <= 820;
  const compact = isCompact();
  // Passt beides nicht in eine Zeile, rutscht der Wert nach unten — aber bleibt
  // rechtsbuendig, damit die Spalte steht.
  const line = (label, right, hint) => {
    if (right && right.style) right.style.marginLeft = 'auto';
    const top = h('div', {
      class: 'row between',
      style: { gap: '10px 14px', alignItems: 'center', minHeight: '44px' }
    }, h('span', { style: { minWidth: '0' } }, label), right);
    if (!hint) return top;
    // Die Beschreibung steht unter Name und Bedienelement und nimmt die ganze
    // Breite — nebeneinander bliebe fuer sie nur ein Streifen.
    return h('div', { class: 'stack', style: { gap: '2px' } },
      top,
      h('span', { class: 'muted', style: {
        fontSize: 'var(--t-small)', textWrap: 'pretty', paddingBottom: '6px'
      } }, hint));
  };
  const s = stats(app.tree);
  const accent = app.accent;

  const swatch = (preset) => h('button', {
    type: 'button', title: preset.label,
    style: {
      width: '100%', height: '52px', borderRadius: '14px',
      background: 'oklch(' + preset.l + '% ' + preset.c + ' ' + preset.h + ')',
      boxShadow: preset.id === app.accentId ? '0 0 0 3px var(--card), 0 0 0 6px var(--accent)' : 'inset 0 0 0 1px var(--hairline)'
    },
    onClick: () => app.setAccent(preset)
  });

  const hueSlider = h('input', {
    type: 'range', min: 0, max: 359, value: Math.round(accent.h), style: { width: '100%' },
    onInput: (e) => app.setAccent({ id: 'custom', label: 'Custom', l: accent.l, c: accent.c, h: Number(e.target.value) })
  });

  const schemaRows = app.schema.fields().map((f) => h('div', {
      class: 'row between',
      style: { gap: '10px', alignItems: 'center', minHeight: '44px', borderBottom: '1px solid var(--hairline)' }
    },
    h('span', { style: { minWidth: '0' } }, f.label),
    h('div', { class: 'row', style: { gap: '10px', alignItems: 'center', marginLeft: 'auto', flex: 'none' } },
      h('span', { class: 'muted', style: { fontSize: 'var(--t-small)' } }, f.type),
      h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)' } },
        app.schema.usage(app.tree, f.id) + ' ×'),
      h('button', { class: 'icon-button tiny', style: { color: 'var(--caution)' },
        title: t('action-delete'), 'aria-label': t('action-delete'),
        onClick: () => app.removeField(f.id) }, '×'))));

  const typePicker = picker({
    items: [{ id: 'text', label: 'Text', short: 'T' }, { id: 'number', label: 'Number', short: '#' },
      { id: 'boolean', label: 'Yes / no', short: '✓' }, { id: 'option', label: 'Option', short: '☰' }],
    value: 'text', ariaLabel: 'Field type', local: true, minWidth: 44, variant: 'raised glyph'
  });

  const exportPicker = picker({
    items: app.transfer.formats().map((f) => ({ id: f.id, label: f.label })),
    value: app.transfer.formats()[0]?.id, ariaLabel: t('action-export'), local: true, minWidth: 132
  });

  // Die Erklaerung steht am Anfang der Karte: sie sagt, was eigene Felder sind,
  // und gehoert damit vor die Liste, nicht zwischen Liste und Eingabe.
  const newFieldHint = h('div', { class: 'muted', style: {
    fontSize: 'var(--t-small)', textWrap: 'pretty', paddingBottom: '4px'
  } }, t('field-hint'));
  const newField = h('div', { class: 'row', style: { gap: '8px', paddingTop: '6px', alignItems: 'center' } },
    h('input', { id: 'new-field-label', placeholder: t('label-new-field'),
      style: { flex: '1', minWidth: '0', padding: '12px 14px', borderRadius: 'var(--r-control)', border: 0, background: 'var(--raised)' } }),
    typePicker,
    h('button', { class: 'icon-button', style: { flex: 'none', background: 'var(--accent)', color: 'var(--card)' },
      title: t('action-add'), 'aria-label': t('action-add'), onClick: () => {
        const label = document.getElementById('new-field-label').value.trim();
        if (label) app.addField({ label, type: typePicker.value });
      } }, icons.plus(20)));

  // Zwei feste Spalten statt Raster: im Raster richtet sich jede Zeile nach der
  // hoechsten Karte und hinterlaesst Luecken.
  const twoUp = (window.innerWidth || 1280) >= 760;
  const cards = [];
  const add = (c) => { cards.push(c); return c; };
  const pane = (...items) => {
    if (!twoUp) return h('div', { class: 'pane stack', style: { gap: '18px' } }, ...items);
    const left = [], right = [];
    let lh = 0, rh = 0;
    const weight = [1.6, 0.7, 1.1, 1.2, 1.3];
    items.filter(Boolean).forEach((it, i) => {
      if (lh <= rh) { left.push(it); lh += weight[i] ?? 1; } else { right.push(it); rh += weight[i] ?? 1; }
    });
    return h('div', { class: 'pane', style: { display: 'flex', gap: '18px', alignItems: 'flex-start' } },
      h('div', { class: 'stack', style: { gap: '18px', flex: '1', minWidth: '0' } }, ...left),
      h('div', { class: 'stack', style: { gap: '18px', flex: '1', minWidth: '0' } }, ...right));
  };
  return pane(
    h('div', { class: 'card stack' },
      h('div', { class: 'section-label' }, t('settings-appearance')),
      line(t('settings-accent'),
        h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)', flex: 'none' } },
          'oklch(' + accent.l.toFixed(0) + '% ' + accent.c.toFixed(3) + ' ' + accent.h.toFixed(0) + ')')),
      h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px' } }, ...PRESETS.map(swatch)),
      h('div', { class: 'stack', style: { gap: '6px' } }, h('label', { class: 'muted', style: { fontSize: 'var(--t-small)' } }, 'Hue'), hueSlider),
      app.accentAdjusted.length
        ? h('div', { class: 'caution' }, t('settings-adjusted', {
            what: app.accentAdjusted.map((a) => a.what + ' ' + a.from.toFixed(2) + ' → ' + a.to.toFixed(2)).join(', ') }))
        : null,
      line(t('settings-mode'),
        h('div', { class: 'segmented' },
          ...[['system', t('mode-system')], ['light', t('mode-light')], ['dark', t('mode-dark')]].map(([id, label]) =>
            h('button', { type: 'button', 'aria-pressed': String(app.mode === id), onClick: () => app.setMode(id) }, label)))),
      line(t('settings-language'), localePicker(app))
    ),

    // Import und Export stehen hier direkt — ein Zwischenschritt waere einer zu viel.
    h('div', { class: 'card stack' },
      h('div', { class: 'section-label' }, t('view-transfer')),
      line(t('action-import'),
        h('label', { class: 'icon-button', style: { cursor: 'pointer', flex: 'none' },
            title: t('transfer-choose'), 'aria-label': t('transfer-choose') },
          icons.folder(20),
          h('input', { type: 'file', style: { display: 'none' },
            onChange: (e) => { const file = e.target.files?.[0]; if (file) app.parseImport(file); } })),
        t('import-hint')),
      // Am Zeigergeraet nimmt die Karte auch eine hineingezogene Datei an; auf
      // dem Handy gibt es kein Ziehen, dort entfaellt die Flaeche.
      compact ? null : h('div', {
          style: { display: 'grid', placeItems: 'center', padding: '18px', borderRadius: 'var(--r-control)',
            border: '2px dashed var(--edge)', color: 'var(--secondary)', fontSize: 'var(--t-small)',
            textAlign: 'center' },
          onDragover: (e) => { e.preventDefault(); e.currentTarget.style.background = 'var(--raised)'; },
          onDragleave: (e) => { e.currentTarget.style.background = 'transparent'; },
          onDrop: (e) => {
            e.preventDefault();
            e.currentTarget.style.background = 'transparent';
            const file = e.dataTransfer?.files?.[0];
            if (file) app.parseImport(file);
          }
        }, t('transfer-drop'), t('import-hint')),
      app.importReport
        ? h('div', { class: 'stack', style: { gap: '8px' } },
            h('div', { class: 'row between' },
              h('span', {}, t('transfer-report', { people: app.importReport.people, families: app.importReport.families })),
              h('span', { class: 'chip small' }, app.importReport.formatLabel)),
            h('div', { class: 'row', style: { gap: '10px' } },
              h('button', { class: 'button-primary', onClick: () => app.applyImport('merge') }, t('transfer-apply')),
              h('button', { class: 'button-secondary', onClick: () => app.clearImport() }, t('action-cancel'))))
        : null,
      line(t('action-export'),
        h('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', justifyContent: 'flex-end', minWidth: '0' } },
          exportPicker,
          h('button', { class: 'icon-button', style: { flex: 'none' },
            title: t('action-export'), 'aria-label': t('action-export'), onClick: () => {
              const id = exportPicker.value;
              const fmt = app.transfer.formats().find((f) => f.id === id);
              if (fmt && fmt.caps.export) app.exportAs(id);
              else toast(t('transfer-unsupported', { format: fmt ? fmt.label : id }));
            } }, icons.data(20))), t('export-hint'))
    ),

    h('div', { class: 'card stack' },
      h('div', { class: 'section-label' }, t('settings-security')),
      // Reality: the tree is sealed with the passphrase. Biometrics/PIN aren't built yet, so
      // they're labelled "planned" rather than dressed up as working controls.
      line(t('security-encrypted'),
        h('span', { class: 'muted', style: { fontSize: 'var(--t-small)', flex: 'none' } }, t('security-on-device')),
        t('security-encrypted-hint')),
      line(t('security-passphrase'),
        h('button', { class: 'button-secondary', style: { flex: 'none' },
          onClick: () => app.startChangePassphrase() }, t('security-change')),
        t('security-change-hint')),
      line(t('security-autolock'), picker({
        items: [
          { id: 0, label: t('security-never') },
          { id: 5, label: t('security-minutes', { count: 5 }) },
          { id: 30, label: t('security-minutes', { count: 30 }) }
        ],
        value: app.autoLockMinutes, ariaLabel: t('security-autolock'), minWidth: 128,
        onPick: (v) => app.setAutoLock(v)
      }), t('security-autolock-hint')),
      app.sealer
        ? h('button', { class: 'button-secondary', style: { alignSelf: 'flex-start' },
            onClick: () => app.lockNow('manual') }, t('security-lock-now'))
        : null,
      // Planned, not built — labelled honestly rather than shown as a working control.
      line(t('security-biometrics'),
        h('span', { class: 'muted', style: { fontSize: 'var(--t-small)', flex: 'none' } }, t('security-planned')),
        t('security-biometrics-hint'))
    ),

    h('div', { class: 'card stack' },
      h('div', { class: 'section-label' }, t('settings-schema')),
      newFieldHint, ...schemaRows, newField),

    h('div', { class: 'card stack' },
      h('div', { class: 'section-label' }, t('settings-about')),
      line(t('settings-store'), h('span', { class: 'muted', style: { fontSize: 'var(--t-small)', flex: 'none' } }, app.storeKind)),
      line(t('label-people-count', { count: s.people }),
        h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)', flex: 'none' } },
          t('label-families', { count: s.families }) + ' · ' + t('label-generation-count', { count: s.generations }))),
      line(t('label-unsourced', { count: s.unsourced }),
        h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)', flex: 'none' } },
          Math.round((s.unsourced / Math.max(1, s.people)) * 100) + ' %')),
      line(t('settings-tree'), picker({
        items: DATASETS.map((d) => ({ id: d.id, label: d.label })),
        value: app.datasetId, ariaLabel: t('settings-tree'), minWidth: 132,
        onPick: (id) => app.setDataset(id)
      })),
      line(t('settings-sample'),
        h('button', { class: 'icon-button', style: { flex: 'none', color: 'var(--caution)' },
          title: t('action-reset-seed'), 'aria-label': t('action-reset-seed'),
          onClick: () => app.reseed() }, icons.trash(20)), t('sample-hint')),
      // Nur zum Ansehen am Rechner: dort meldet pointer:coarse immer falsch,
      // also laesst sich die Touch-Fassung von Hand einschalten.
      line(t('settings-touch'), h('button', {
        class: 'switch' + (isTouchForced() ? ' on' : ''), type: 'button', role: 'switch',
        'aria-checked': String(isTouchForced()), 'aria-label': t('settings-touch'),
        onClick: () => setTouchForced(!isTouchForced())
      }, h('span', { class: 'knob' })), t('touch-hint')),
      h('div', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } },
        h('span', {}, 'open'), h('span', { style: { color: 'var(--accent-on)' } }, 'om'), h('span', {}, ' 0.1.0 · local only'))
    )
  );
}


/** Eigenes Dropdown: das native select laesst sich nicht in die Kartensprache bringen. */
function picker({ items, value, onPick, ariaLabel, local = false, minWidth = 132, variant = '' }) {
  let current = value;
  const shortOf = (it) => (it ? (it.short ?? it.label) : '');
  const label = h('span', {}, shortOf(items.find((i) => i.id === current)));

  const trigger = h('button', {
    class: 'select-trigger' + (variant ? ' ' + variant : ''), type: 'button',
    'aria-haspopup': 'listbox', 'aria-expanded': 'false',
    style: { minWidth: minWidth + 'px' },
    onClick: (e) => { e.stopPropagation(); open ? close() : show(); }
  }, label, h('span', { class: 'select-caret' }));

  const rows = items.map((it) => {
    const tick = h('span', { class: 'menu-tick' }, it.id === current ? '✓' : '');
    const row = h('button', {
      class: 'menu-item' + (it.id === current ? ' current' : ''),
      type: 'button', role: 'option', 'aria-selected': String(it.id === current),
      onClick: () => {
        close();
        if (it.id === current) return;
        current = it.id;
        if (local) {
          label.textContent = shortOf(it);
          rows.forEach((r, i) => {
            const on = items[i].id === current;
            r.el.classList.toggle('current', on);
            r.el.setAttribute('aria-selected', String(on));
            r.tick.textContent = on ? '✓' : '';
          });
        }
        onPick?.(it.id);
      }
    }, h('span', {}, it.label), tick);
    return { el: row, tick };
  });

  const menu = h('div', {
    class: 'menu', role: 'listbox', 'aria-label': ariaLabel, style: { display: 'none' }
  }, ...rows.map((r) => r.el));

  let open = false;
  const onDoc = (e) => { if (!wrap.contains(e.target)) close(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  function show() {
    open = true;
    menu.style.display = 'grid';
    trigger.setAttribute('aria-expanded', 'true');
    requestAnimationFrame(() => menu.classList.add('is-open'));
    document.addEventListener('pointerdown', onDoc);
    document.addEventListener('keydown', onKey);
  }
  function close() {
    open = false;
    menu.classList.remove('is-open');
    trigger.setAttribute('aria-expanded', 'false');
    setTimeout(() => { if (!open) menu.style.display = 'none'; }, 130);
    document.removeEventListener('pointerdown', onDoc);
    document.removeEventListener('keydown', onKey);
  }

  const wrap = h('div', { class: 'select-wrap' }, trigger, menu);
  Object.defineProperty(wrap, 'value', { get: () => current });
  return wrap;
}

function localePicker(app) {
  return picker({
    items: LOCALES, value: currentLocale(), ariaLabel: t('settings-language'),
    minWidth: 176,   // Platz fuer lange Sprachnamen (Português, Nederlands …)
    onPick: (id) => app.setLocale(id)
  });
}
