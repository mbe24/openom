import { h, fullName, initials } from '../ui/dom.js';
import { isCompact, isTouchInput, isTouchForced } from '../ui/viewport.js';
import { pickPerson, alreadyChildIds } from '../ui/personPicker.js';
import { descendantIds } from '../core/queries.js';
import { addChoiceButton } from '../ui/menu.js';
import { faceOf } from '../ui/components.js';
import { icons } from '../ui/icons.js';
import { parseDate, lifeSpan } from '../core/dates.js';
import { t, dateSymbols } from '../core/i18n.js';

/**
 * Personen-Editor. Autosave: jede Aenderung geht als Op in den Store,
 * Undo/Redo laeuft ueber das Op-Log (Cmd/Ctrl+Z). Die Datumsfelder nehmen
 * an, was die Quelle sagt, und zeigen darunter, wie es gelesen wird.
 */
export function editorView(app) {
  const { tree, focusId } = app;
  const person = tree.person(focusId);
  if (!person) return h('div', { class: 'pane' }, t('label-unknown'));

  const field = (key, label, opts = {}) => {
    const input = h('input', {
      value: person[key] ?? '', placeholder: opts.placeholder ?? '',
      'aria-label': label,
      // Beim Tippen still schreiben, beim Verlassen einmal neu zeichnen
      // (die Datumszeile darunter liest dann mit).
      onInput: (e) => app.updatePerson({ [key]: e.target.value }, { silent: true }),
      onChange: (e) => app.updatePerson({ [key]: e.target.value })
    });
    const reading = opts.date ? h('div', { class: 'reading' }, readDate(person[key])) : null;
    if (opts.date) {
      input.addEventListener('input', (e) => {
        reading.textContent = readDate(e.target.value);
      });
    }
    return h('div', { class: 'field' }, h('label', {}, label), input, reading);
  };

  const customFields = app.schema.fields().map((def) => {
    const value = person.custom?.[def.id];
    let control;
    if (def.type === 'boolean') {
      control = h('button', {
        class: 'row', type: 'button', 'aria-pressed': String(!!value),
        onClick: () => app.updatePerson({ custom: { [def.id]: !value } })
      }, h('span', { style: {
        width: '48px', height: '28px', borderRadius: '14px', padding: '3px',
        background: value ? 'var(--accent)' : 'var(--edge)',
        display: 'flex', justifyContent: value ? 'flex-end' : 'flex-start'
      } }, h('span', { style: { width: '22px', height: '22px', borderRadius: '11px', background: '#fff' } })));
    } else if (def.type === 'option') {
      control = h('select', { onChange: (e) => app.updatePerson({ custom: { [def.id]: e.target.value } }) },
        h('option', { value: '' }, '—'),
        ...(def.options ?? []).map((o) => h('option', { value: o, selected: value === o }, o)));
    } else {
      control = h('input', {
        value: value ?? '', type: def.type === 'number' ? 'number' : 'text', size: 1,
        style: { width: '100%', minWidth: '0' },
        onInput: (e) => app.updatePerson({ custom: { [def.id]: e.target.value } }, { silent: true }),
        onChange: (e) => app.updatePerson({ custom: { [def.id]: e.target.value } })
      });
    }
    return h('div', { class: 'row between', style: { gap: '16px', padding: '10px 0', borderBottom: '1px solid var(--hairline)' } },
      h('div', { class: 'stack', style: { gap: '2px' } },
        h('span', {}, def.label),
        h('span', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } }, def.type)),
      // Schrumpft statt umzubrechen: auf schmalen Geraeten bleibt die
      // Bedienung in derselben Zeile und rechtsbuendig.
      h('div', { style: { flex: '1 1 auto', minWidth: '0', maxWidth: '260px',
        display: 'flex', justifyContent: 'flex-end' } }, control));
  });

  const sym = dateSymbols();
  const span = (p) => lifeSpan(p, sym) || t('label-no-year');

  /**
   * Loeschen sieht aus wie auf dem Handy: Papierkorb, im zweiten Schritt rot
   * gefuellt. Ein Kreuz war vom Plus daneben kaum zu unterscheiden — Form und
   * Farbe trennen die beiden jetzt.
   */
  const removeButton = (label, run) => {
    const btn = h('button', {
      class: 'rel-x', type: 'button', title: label, 'aria-label': label,
      onClick: (ev) => {
        ev.stopPropagation();
        if (btn.classList.contains('armed')) { run(); return; }
        for (const other of document.querySelectorAll('.rel-x.armed')) other.classList.remove('armed');
        btn.classList.add('armed');
        setTimeout(() => document.addEventListener('click', disarm, { once: true }), 0);
      }
    }, icons.trash(17));
    const disarm = () => btn.classList.remove('armed');
    return btn;
  };

  /**
   * Touch: Zeile nach links ziehen, roter Knopf erscheint, Druck loescht. Das
   * Ziehen ist schon die Bestaetigung, also kein Zwei-Schritt-Knopf. Am
   * Zeigergeraet bleibt das ✕ — dort gibt es keine Wischgeste.
   */
  // Die Eingabeart entscheidet, nicht die Fenstergroesse: ein verkleinertes
  // Desktop-Fenster ist "compact", hat aber keine Wischgeste — dort waere
  // Loeschen sonst unerreichbar.
  const touch = isTouchInput();
  // Am Rechner soll die Maus die Geste vorfuehren koennen.
  const mouseMaySwipe = isTouchForced();
  const swipeRow = (content, label, run) => {
    if (!touch) {
      return h('div', { class: 'row between', style: { gap: '10px' } }, content, removeButton(label, run));
    }
    const front = h('div', { class: 'swipe-front' }, content);
    const del = h('button', { class: 'swipe-del', type: 'button',
      title: label, 'aria-label': label,
      onClick: (ev) => { ev.stopPropagation(); run(); } }, icons.trash(18));
    const wrap = h('div', { class: 'swipe' }, del, front);

    // Die Zeile schiebt sich nach links weg und legt den Knopf frei.
    const WIDTH = 50;
    let x0 = null, off = 0, moved = 0;
    const set = (px, animate) => {
      off = px;
      front.style.transition = animate ? 'transform .18s ease' : 'none';
      front.style.transform = 'translateX(' + -px + 'px)';
    };
    const closeAll = () => {
      for (const other of document.querySelectorAll('.swipe.open')) other.__close?.();
    };
    wrap.__close = () => { wrap.classList.remove('open'); set(0, true); };
    front.addEventListener('pointerdown', (ev) => {
      if (ev.pointerType === 'mouse' && !mouseMaySwipe) return;
      if (ev.pointerType === 'mouse') front.setPointerCapture?.(ev.pointerId);
      x0 = ev.clientX; moved = 0;
      if (!wrap.classList.contains('open')) closeAll();
    });
    front.addEventListener('pointermove', (ev) => {
      if (x0 === null) return;
      const dx = ev.clientX - x0;
      moved = Math.max(moved, Math.abs(dx));
      set(Math.max(0, Math.min(WIDTH, (wrap.classList.contains('open') ? WIDTH : 0) - dx)), false);
    });
    const end = () => {
      if (x0 === null) return;
      const open = off > WIDTH / 2;
      wrap.classList.toggle('open', open);
      set(open ? WIDTH : 0, true);
      x0 = null;
    };
    front.addEventListener('pointerup', end);
    front.addEventListener('pointercancel', end);
    set(0, false);
    return wrap;
  };



  const { father, mother } = tree.parentsOf(person.id);
  const parentRows = [['M', father, t('action-add-father'), t('rel-link-father')],
                      ['F', mother, t('action-add-mother'), t('rel-link-mother')]]
    .map(([sex, p, add, linkLabel]) => p
      ? swipeRow(
          h('span', { class: 'row', style: { gap: '8px', minWidth: '0', alignItems: 'baseline' } },
            h('span', {}, fullName(p)),
            h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-tiny)' } }, span(p))),
          t(sex === 'M' ? 'rel-remove-father' : 'rel-remove-mother'),
          () => app.detachParent(person.id, p.id))
      : h('div', { class: 'row between', style: { gap: '10px', minHeight: '42px', alignItems: 'center' } },
          h('span', { class: 'muted' }, t(sex === 'M' ? 'label-father-unknown' : 'label-mother-unknown')),
          addChoiceButton({
            label: add, linkLabel,
            create: () => app.addParentFor(person.id, sex),
            link: (btn, title) => pickPerson(btn, { tree, title,
              // Nachkommen und die Person selbst wuerden einen Zyklus bauen.
              exclude: new Set([person.id, ...descendantIds(tree, person.id),
                ...(father ? [father.id] : []), ...(mother ? [mother.id] : [])]),
              onPick: (id) => app.linkParent(person.id, id, sex) })
          })));

  const families = tree.familiesOf(person.id);
  const relationships = h('div', { class: 'stack', style: { gap: '4px' } },
    h('div', { class: 'section-label' }, t('rel-title')),
    h('div', { class: 'muted', style: { fontSize: 'var(--t-small)', paddingBottom: '4px' } },
      t(isCompact() ? 'rel-hint-compact' : 'rel-hint')),
    h('div', { class: 'rel-group' }, t('label-parents')),
    h('div', { class: 'rel-block' }, ...parentRows),
    h('div', { class: 'row between', style: { alignItems: 'center', paddingTop: '6px' } },
      h('div', { class: 'rel-group' }, t('label-marriages')),
      addChoiceButton({
        label: t('action-add-marriage'), linkLabel: t('rel-link-partner'),
        create: () => app.addMarriage(),
        link: (btn, title) => pickPerson(btn, { tree, title,
          // Sich selbst und bestehende Partner nicht erneut — Verwandtenehen
          // bleiben erlaubt, die gibt es in echten Baeumen.
          exclude: new Set([person.id, ...families.flatMap((f) => f.spouses)]),
          onPick: (id) => app.linkPartner(id) })
      })),
    ...(families.length ? families.map((fam) => {
      const other = fam.spouses.filter((s) => s !== person.id).map((s) => tree.person(s)).filter(Boolean);
      const year = String(fam.facts?.marriage ?? '').match(/\d{4}/)?.[0];
      const kids = fam.children.map((c) => tree.person(c)).filter(Boolean);
      return h('div', { class: 'rel-block' },
        swipeRow(
          h('div', { class: 'row', style: { gap: '8px', minWidth: '0', alignItems: 'baseline' } },
            h('span', { style: { fontFamily: 'var(--font-name)' } },
              other.length ? other.map(fullName).join(', ') : t('rel-no-partner')),
            year ? h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-tiny)' } },
              sym.marriage + ' ' + year) : null),
          t('rel-remove-marriage'), () => app.removeMarriage(fam.id)),
        h('div', { class: 'rel-kids' },
          ...kids.map((k) => swipeRow(
            h('span', { class: 'row', style: { gap: '8px', minWidth: '0', alignItems: 'baseline' } },
              h('span', {}, fullName(k)),
              h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-tiny)' } }, span(k))),
            t('rel-remove-child'), () => app.detachChild(fam.id, k.id))),
          h('div', { class: 'row', style: { gap: '8px', alignItems: 'center', paddingTop: '2px' } },
            addChoiceButton({
              label: t('action-add-child'), linkLabel: t('rel-link-child'),
              create: () => app.addChild(fam.id),
              link: (btn, title) => pickPerson(btn, { tree, title,
                // Vorfahren und die Eltern selbst wuerden einen Zyklus bauen;
                // wer schon Eltern hat, kann nicht zweimal Kind sein.
                exclude: new Set([
                  ...fam.spouses,
                  ...fam.children,
                  ...fam.spouses.flatMap((s) => [...tree.ancestorIds(s)]),
                  ...alreadyChildIds(tree)
                ]),
                onPick: (id) => app.linkChildTo(fam.id, id) })
            }),
            h('span', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } }, t('action-add-child')))));
    }) : [h('div', { class: 'muted', style: { fontSize: 'var(--t-small)', paddingBottom: '6px' } },
      t('rel-none'))]));

  const portrait = isCompact();
  // Die Hoehe folgt dem Inhalt: mit flex:1 waere der Bereich auf Fensterhoehe
  // geklemmt, der Inhalt quillt heraus und der untere Innenabstand liegt
  // ueber statt unter den Knoepfen.
  return h('div', { class: 'pane', style: { display: 'flex', flex: '0 0 auto', minHeight: '100%', boxSizing: 'border-box' } },
    h('div', { class: 'stack', style: { gap: '18px', width: '100%' } },
      h('div', { class: 'row between' },
        h('div', { class: 'section-label' }, t('view-editor')),
        // Tastenkuerzel nur am Rechner.
        isCompact() ? null : h('span', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } }, 'autosave · ⌘Z')),

      // Portraet: Kachel ist Ablage- und Tippflaeche. Die Bytes gehen in den
      // BlobStore, ins Dokument wandert nur der Hash.
      h('div', { class: 'row', style: { gap: '14px', alignItems: 'center' } },
        (() => {
          const tile = h('label', {
            class: 'mono', title: t('media-portrait'),
            style: { width: '72px', height: '72px', borderRadius: '20px', display: 'grid',
              placeItems: 'center', fontSize: '24px', cursor: 'pointer', flex: 'none', overflow: 'hidden' },
            onDragover: (ev) => { ev.preventDefault(); },
            onDrop: (ev) => {
              ev.preventDefault();
              const file = ev.dataTransfer?.files?.[0];
              if (file) app.setPortraitFile(person.id, file);
            }
          }, initials(person),
            h('input', { type: 'file', accept: 'image/*', style: { display: 'none' },
              onChange: (ev) => { const file = ev.target.files?.[0]; if (file) app.setPortraitFile(person.id, file); } }));
          return faceOf(tree, person, tile);
        })(),
        h('div', { class: 'stack', style: { gap: '2px', flex: '1', minWidth: '0' } },
          h('span', {}, t('media-portrait')),
          h('span', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } }, t('media-hint'))),
        tree.portraitOf(person.id)
          ? h('button', { class: 'icon-button', style: { color: 'var(--caution)', flex: 'none' },
              title: t('media-remove'), 'aria-label': t('media-remove'),
              onClick: () => app.removePortrait(person.id) }, icons.trash(20))
          : null),

      h('div', { class: 'grid-3' },
        field('given', t('label-given')),
        field('surname', t('label-surname')),
        h('div', { class: 'field' },
          h('label', {}, t('label-sex')),
          h('select', { onChange: (e) => app.updatePerson({ sex: e.target.value }) },
            ...[['U', '—'], ['M', 'M'], ['F', 'F']].map(([v, l]) =>
              h('option', { value: v, selected: (person.sex ?? 'U') === v }, l))))),

      h('div', { class: 'grid-2' },
        field('birth', t('label-born'), { date: true, placeholder: t('hint-date-formats') }),
        field('death', t('label-died'), { date: true, placeholder: t('hint-date-formats') }),
        field('birthPlace', t('label-birthplace')),
        field('deathPlace', t('label-deathplace'))),

      h('div', { class: 'field' },
        h('label', {}, t('label-note')),
        h('textarea', { rows: 4,
          onInput: (e) => app.updatePerson({ note: e.target.value }, { silent: true }),
          onChange: (e) => app.updatePerson({ note: e.target.value }) }, person.note ?? '')),

      relationships,

      h('div', { class: 'stack', style: { gap: '4px' } },
        h('div', { class: 'row between' },
          h('div', { class: 'section-label' }, t('label-your-fields')),
          h('button', { class: 'button-quiet', onClick: () => app.setView('settings') }, t('settings-schema'))),
        ...customFields),

      // Alle drei Aktionen unten in einer Zeile: links das Loeschen (Symbol,
       // weil eindeutig), rechts Abbrechen und Speichern als Text — ✓ und ✕
       // nebeneinander lesen sich wie ein Schalter.
      h('div', { class: 'row', style: { gap: '10px', alignItems: 'center', paddingTop: '4px' } },
        app.pendingNewId ? null : h('button', { class: 'icon-button', style: { color: 'var(--caution)', flex: 'none' },
          title: t('action-delete'), 'aria-label': t('action-delete'),
          onClick: () => app.deletePerson() }, icons.trash(20)),
        h('div', { class: 'row', style: { gap: '10px', marginLeft: 'auto', flex: 'none' } },
          // Wie beim Speichern: der Zeigerdruck darf das Feld nicht verlassen,
          // sonst zeichnet das Schreiben neu und frisst den ersten Klick.
          h('button', { class: 'button-secondary',
            onPointerDown: (ev) => { ev.preventDefault(); setTimeout(() => app.cancelEditor(), 0); },
            onClick: (ev) => { if (ev.detail === 0) app.cancelEditor(); } }, t('action-cancel')),
          // Beim Zeigerdruck: Fokus behalten, Feldwert schreiben, dann erst
          // wechseln — sonst frisst das Neuzeichnen den ersten Klick.
          h('button', { class: 'button-primary',
            onPointerDown: (ev) => {
              ev.preventDefault();
              const el = document.activeElement;
              if (el && el !== ev.currentTarget && typeof el.blur === 'function') el.blur();
              setTimeout(() => app.commitEditor(), 0);
            },
            onClick: (ev) => { if (ev.detail === 0) app.commitEditor(); } }, t('action-save'))))
    )
  );
}

function readDate(raw) {
  const p = parseDate(raw);
  if (p.kind === 'empty') return '';
  const parts = { about: 'about ' + p.sortYear, before: 'before ' + (p.to ?? '?'), after: 'after ' + (p.from ?? '?'),
    range: p.from + '–' + p.to, exact: p.display, year: String(p.sortYear), text: 'kept as written' };
  return t('hint-read-as', { reading: parts[p.kind] ?? p.display });
}
