import { nameShortener } from '../core/queries.js';
import { h, svg, fullName, initials } from '../ui/dom.js';
import { personCard, monoNode, marriageNode } from '../ui/components.js';
import { t, dateSymbols, isRTL } from '../core/i18n.js';
import { lifeSpan } from '../core/dates.js';
import { isNarrow, isCompact } from '../ui/viewport.js';
import { placeCard } from '../ui/popover.js';
import { personMenu } from '../ui/menu.js';

// Zoom und Bildausschnitt der Handy-Ansicht ueberdauern das Neuzeichnen.
let treeZoom = 1;
let treeScroll = null;   // { cx, cy } — Mitte in Baumkoordinaten
let treeFocusSeen = null;
// Quer traegt die Tafel den Grundfaktor 0.72 — dieselben Grenzen wie hoch
// waeren dort viel zu klein. Grenzen daher je Ausrichtung.
const ZOOM = { portrait: [0.6, 1], landscape: [0.78, 1.75], desk: [0.8, 1.6] };
let deskZoom = 1;

/** Beim Verlassen der Ansicht vergessen — beim naechsten Besuch wird zentriert. */
export function resetTreeView() {
  treeScroll = null;
  treeFocusSeen = null;
}

// Zwei Geometrien, gleiche Bildsprache: quer wird der Baum auf die Breite
// skaliert, hoch bleibt er in Originalgroesse und wird waagerecht gewischt.
const WIDE = {
  W: 1010, HGT: 830,
  GP: [{ x: 128, y: 34 }, { x: 380, y: 34 }, { x: 630, y: 34 }, { x: 882, y: 34 }],
  GP_DIA: [{ x: 254, y: 112 }, { x: 756, y: 112 }],
  PARENTS: [{ x: 254, y: 196 }, { x: 756, y: 196 }],
  PARENT_DIA: { x: 505, y: 288 },
  FOCUS: { x: 505, y: 372 },
  UNION_Y: 486, CHILD_Y: 592,
  wGP: 236, wParent: 320, wFocus: 340, wSpouse: 250, spouseDX: 230, unionStep: 360
};
const TALL = {
  W: 1040, HGT: 860,
  GP: [{ x: 130, y: 40 }, { x: 390, y: 40 }, { x: 650, y: 40 }, { x: 910, y: 40 }],
  GP_DIA: [{ x: 260, y: 132 }, { x: 780, y: 132 }],
  PARENTS: [{ x: 260, y: 224 }, { x: 780, y: 224 }],
  PARENT_DIA: { x: 520, y: 322 },
  FOCUS: { x: 520, y: 412 },
  UNION_Y: 534, CHILD_Y: 646,
  wGP: 240, wParent: 280, wFocus: 320, wSpouse: 250, spouseDX: 220, unionStep: 340
};

/** Auf dem Label steht nur das Jahr — das genaue Datum zeigt die Detailansicht. */
function marriageYear(raw) {
  const m = String(raw ?? '').match(/\d{4}/);
  return m ? m[0] : '';
}

export function ancestorsView(app) {
  const { tree, focusId } = app;
  // Geometrie haengt an der Breite, die Bedienung an beidem: quer liegende
  // Handys sind breit genug fuer die Desktop-Tafel, aber viel zu flach.
  const portrait = isNarrow();
  const canvasMode = isCompact();
  const L = portrait ? TALL : WIDE;
  const { W, HGT, GP, GP_DIA, PARENTS, PARENT_DIA, FOCUS, UNION_Y, CHILD_Y } = L;
  const focus = tree.person(focusId);
  if (!focus) return h('div', { class: 'pane' }, t('label-unknown'));
  const sym = dateSymbols();

  const { family: parentFam, father, mother } = tree.parentsOf(focusId);
  const gpPairs = [father ? tree.parentsOf(father.id) : null, mother ? tree.parentsOf(mother.id) : null];
  const gp = [gpPairs[0]?.father ?? null, gpPairs[0]?.mother ?? null, gpPairs[1]?.father ?? null, gpPairs[1]?.mother ?? null];
  const marriages = tree.familiesOf(focusId);
  const siblings = tree.siblingsOf(focusId);
  const select = (p) => p && app.setFocus(p.id);

  /**
   * Kinderliste der Elternehe. An der Pille verankert, damit sie hoch wie quer
   * dasselbe Bauteil ist: hoch fast bildbreit, quer eine schwebende Karte.
   */
  const openPeople = (anchor, kids, title) => {
    const host = anchor.closest('.pane');
    if (!host) return;
    // Ohne eigene Positionierung liegt die Karte am naechsten positionierten
    // Vorfahren — auf dem Desktop war das nicht die Flaeche.
    if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
    host.querySelector('.pop-layer')?.remove();
    const list = h('div', { class: 'pop-list' },
      ...kids.map((k) => {
        const me = k.id === focusId;
        return h('button', {
          class: 'pop-row' + (me ? ' current' : ''), type: 'button', disabled: me,
          onClick: () => { layer.remove(); if (!me) app.setFocus(k.id); }
        },
          h('span', { class: 'mono' }, initials(k)),
          h('span', { class: 'who' },
            h('span', { class: 'name' }, fullName(k)),
            h('span', { class: 'dates' }, lifeSpan(k, dateSymbols()) || t('label-no-year'))));
      }));
    const card = h('div', { class: 'pop-card' },
      h('div', { class: 'section-label', style: { padding: '2px 4px 6px' } }, title),
      list);
    const layer = h('div', { class: 'pop-layer', onClick: () => layer.remove() }, card);
    host.appendChild(layer);

    placeCard(anchor, host, card, { maxHeight: Math.round(window.innerHeight * 0.55) });
  };
  // Namen werden nach Haeufigkeit gekuerzt, nie abgeschnitten (CLAUDE.md).
  // Budget in Zeichen: im Hochformat ist die Schrift groesser, also passt weniger.
  const fit = (w) => nameShortener(tree,
    Math.max(10, Math.floor((w - (portrait ? 86 : 66)) / (portrait ? 9.4 : 7.2))));
  const shortGP = fit(L.wGP);
  const shortParent = fit(L.wParent);
  const shortSpouse = fit(L.wSpouse);
  const shortFocus = fit(L.wFocus);

  const chart = h('div', { class: 'chart tree-chart', style: { width: W + 'px', height: HGT + 'px' } });
  // Rechtsklick oeffnet dasselbe Menue wie im Graphen — wer es dort gelernt hat,
  // erwartet es hier. Ueber Delegation, damit jede Karte es mitbekommt.
  if (!isCompact()) {
    chart.addEventListener('contextmenu', (ev) => {
      const el = ev.target.closest('[data-person]');
      const id = el && el.getAttribute('data-person');
      if (!id) return;
      ev.preventDefault();
      ev.stopPropagation();
      personMenu(app, id, ev.clientX, ev.clientY);
    });
  }
  const solid = [];
  const dashed = [];

  // Rechts nach links: gespiegelt wird in den Koordinaten, nicht per CSS —
  // sonst stuenden Schrift und Anker seitenverkehrt.
  const rtl = isRTL();
  const mx = (x) => (rtl ? W - x : x);

  const place = (node, x, y) => {
    // Wrapper traegt die Position, damit Klassen-Transforms (Raute) erhalten bleiben.
    chart.appendChild(h('div', { style: {
      position: 'absolute', left: mx(x) + 'px', top: y + 'px', transform: 'translate(-50%,-50%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center'
    } }, node));
    return node;
  };

  // ---------------------------------------------------------------- Grosseltern
  GP.forEach((pos, i) => {
    const person = gp[i];
    const pairIndex = i < 2 ? 0 : 1;
    const childOfPair = pairIndex === 0 ? father : mother;
    const label = i % 2 === 0 ? t('action-add-father') : t('action-add-mother');
    if (person) {
      // Ohne Monogramm: die 50 px Chrome sind hier der Unterschied zwischen
      // ausgeschriebenem Namen und Ellipse.
      place(h('button', {
        class: 'person-card compact', type: 'button', style: { width: L.wGP + 'px' },
        onClick: () => select(person)
      },
        h('span', { class: 'who' },
          h('span', { class: 'name' }, shortGP(person)),
          h('span', { class: 'dates' }, lifeSpan(person))),
        h('span', { class: 'anchor-bottom' })
      ), pos.x, pos.y);
    } else if (childOfPair && !portrait) {
      // Eltern lassen sich nur zu jemandem eintragen, den es gibt: fehlt schon das
      // Kind dieser Generation, bleibt der Platz leer statt ein totes Angebot zu zeigen.
      place(h('button', {
        class: 'person-card compact', type: 'button',
        style: { width: L.wGP + 'px', justifyContent: 'center', background: 'transparent',
          boxShadow: 'none', border: '2px dashed var(--edge)', color: 'var(--secondary)' },
        onClick: () => app.addParentFor(childOfPair.id, i % 2 === 0 ? 'M' : 'F')
      }, '+ ' + label), pos.x, pos.y);
    }
    const dia = GP_DIA[pairIndex];
    if (!childOfPair) return;
    const line = 'M' + pos.x + ' ' + (pos.y + 30) + ' Q' + (pos.x + (dia.x - pos.x) * 0.6) + ' ' + (dia.y - 24) +
      ' ' + (dia.x + (pos.x < dia.x ? -12 : 12)) + ' ' + (dia.y - 6);
    (person ? solid : dashed).push(line);
  });

  // Ehe-Knoten der Grosseltern nur, wenn es die Familie wirklich gibt.
  GP_DIA.forEach((pos, i) => {
    const parent = i === 0 ? father : mother;
    if (!parent) return;
    const fam = tree.childFamilyOf(parent.id);
    if (fam) place(marriageNode(fam, { soft: true, onSelect: () => select(parent) }), pos.x, pos.y);
    solid.push('M' + pos.x + ' ' + (pos.y + 13) + ' V' + (PARENTS[i].y - 34));
  });

  // ---------------------------------------------------------------- Eltern
  [[father, PARENTS[0], 'M'], [mother, PARENTS[1], 'F']].forEach(([p, pos, sex]) => {
    if (p) {
      place(h('div', { style: { width: L.wParent + 'px' } },
        personCard(p, { variant: 'compact', onSelect: select, anchors: ['top', 'bottom'], label: shortParent(p), tree })), pos.x, pos.y);
      solid.push('M' + pos.x + ' ' + (pos.y + 34) + ' Q' + ((pos.x + PARENT_DIA.x) / 2) + ' ' + (PARENT_DIA.y - 22) +
        ' ' + (PARENT_DIA.x + (pos.x < PARENT_DIA.x ? -12 : 12)) + ' ' + (PARENT_DIA.y - 5));
    } else {
      // Eltern des Fokus darf man hier anlegen — Grosseltern nicht: dort fehlt
      // die Zwischengeneration, an die sie gehoeren wuerden.
      place(h('button', {
        class: 'person-card compact', type: 'button',
        style: { width: L.wParent + 'px', justifyContent: 'center', background: 'transparent',
          boxShadow: 'none', border: '2px dashed var(--edge)', color: 'var(--secondary)' },
        onClick: () => app.addParents(sex)
      }, '+ ' + t(sex === 'M' ? 'action-add-father' : 'action-add-mother')), pos.x, pos.y);
    }
  });

  if (parentFam) {
    place(marriageNode(parentFam), PARENT_DIA.x, PARENT_DIA.y);
    solid.push('M' + PARENT_DIA.x + ' ' + (PARENT_DIA.y + 14) + ' V' + (FOCUS.y - 40));
    const py = marriageYear(parentFam.facts?.marriage);
    if (py) place(h('span', { class: 'pill' }, sym.marriage + ' ' + py), PARENT_DIA.x + 140, PARENT_DIA.y);
    // Geschwister haengen an der Elternehe — deshalb steht ihre Zahl dort und
    // nicht als unbeschriftete Knopfreihe am Bildrand.
    const kids = (parentFam.children || []).map((id) => tree.person(id)).filter(Boolean);
    if (kids.length > 1) {
      const pill = h('button', { class: 'pill pill-action', type: 'button',
        onClick: (e) => { e.stopPropagation(); openPeople(e.currentTarget, kids, t('label-siblings')); } },
        h('span', {}, t('label-children-count', { count: kids.length })),
        h('span', { class: 'caret' }));
      place(pill, PARENT_DIA.x, PARENT_DIA.y - 44);
    }
  }

  // Unterer Anker nur, wenn unten auch etwas haengt — sonst zeigt er ins Leere.
  const hasBelow = marriages.length > 0 || (!portrait);
  place(h('div', { style: { width: L.wFocus + 'px' } },
    personCard(focus, { variant: 'focus', onSelect: () => app.setView('detail'),
      anchors: hasBelow ? ['top', 'bottom'] : ['top'], label: shortFocus(focus), tree })),
    FOCUS.x, FOCUS.y);

  // ---------------------------------------------------------------- Ehen: jede
  // bekommt einen eigenen Knoten samt Partnerkarte. Kein Wischen auf Desktop.
  const unionXs = marriages.length === 1
    ? [W / 2]
    : marriages.map((_, i) => (i - (marriages.length - 1) / 2) * L.unionStep + W / 2);

  marriages.forEach((fam, i) => {
    const ux = unionXs[i];
    const spouse = tree.person(fam.spouses.find((s) => s !== focusId));
    const children = tree.childrenOf(focusId, fam.id);
    const isActive = (app.activeFamilyId ?? marriages[0]?.id) === fam.id;

    const dx = ux - FOCUS.x;
    // Dieselbe Form wie alle anderen Kanten: eine Gerade mit leichter Woelbung,
    // vom Anker der Karte zur Raute.
    const sy0 = FOCUS.y + 40;
    // Die Kante trifft die Raute nicht von Norden, sondern von Nordost bzw.
    // Nordwest — je nachdem, auf welcher Seite der Karte sie liegt.
    const side = Math.abs(dx) < 2 ? 0 : (dx < 0 ? 1 : -1);
    const ex = ux + side * 11, ey = UNION_Y - (side ? 11 : 14);
    solid.push(side === 0
      ? 'M' + FOCUS.x + ' ' + sy0 + ' V' + ey
      : 'M' + FOCUS.x + ' ' + sy0 +
        ' Q' + ((FOCUS.x + ex) / 2) + ' ' + (ey - 16) + ' ' + ex + ' ' + ey);
    place(marriageNode(fam, { soft: !isActive, onSelect: () => app.setActiveFamily(fam.id) }), ux, UNION_Y);

    // Partnerkarte nach aussen versetzt, damit sie keine Kinderkante schneidet.
    const sx = ux + (ux <= W / 2 ? -L.spouseDX : L.spouseDX);
    if (spouse) {
      const inner = ux <= W / 2 ? 'right' : 'left';
      const card = h('div', { style: { width: L.wSpouse + 'px', position: 'relative' } },
        personCard(spouse, { variant: 'compact', onSelect: select, label: shortSpouse(spouse), tree }),
        h('span', { style: {
          position: 'absolute', [inner]: '-5px', top: '50%', transform: 'translateY(-50%)',
          width: '10px', height: '10px', borderRadius: '5px', background: 'var(--anchor)'
        } }));
      place(card, sx, UNION_Y);
      solid.push('M' + (sx + (ux <= W / 2 ? L.wSpouse / 2 : -L.wSpouse / 2)) + ' ' + UNION_Y +
        ' H' + (ux + (ux <= W / 2 ? -13 : 13)));
    } else {
      if (!portrait) place(h('button', { class: 'person-card compact', type: 'button',
        style: { width: L.wSpouse + 'px', justifyContent: 'center', background: 'transparent',
          boxShadow: 'none', border: '2px dashed var(--edge)', color: 'var(--secondary)' },
        onClick: () => app.addMarriage() }, '+ ' + t('action-add-marriage')), sx, UNION_Y);
    }
    const uy = marriageYear(fam.facts?.marriage);
    if (uy) place(h('span', { class: 'pill' }, sym.marriage + ' ' + uy), ux, UNION_Y - 44);

    // Ein Band pro Ehe: eigene Zeile, damit sich die Kinder zweier Ehen nicht
    // ueberlagern. Der "+X"-Knoten ist das letzte Element derselben Zeile.
    const bandY = CHILD_Y + i * 96;
    const shown = children.slice(0, 5);
    const overflow = children.length - shown.length;
    const items = shown.map((c) => ({ kind: 'child', person: c }));
    if (overflow > 0) items.push({ kind: 'more', count: overflow });
    items.unshift({ kind: 'add' });
    const step = 76;
    items.forEach((item, k) => {
      const cx = ux + (k - (items.length - 1) / 2) * step;
      const spread = items.length > 1 ? (k - (items.length - 1) / 2) / ((items.length - 1) / 2) : 0;
      const angle = 90 - spread * 42;
      const rad = (angle * Math.PI) / 180;
      // Die Kante zum "+"-Knoten ist gestrichelt: dort ist noch kein Kind.
      // Endpunkt ist der Anker auf der Knoten-Oberkante (Knoten 44 px hoch,
      // per translate zentriert), nicht der Mittelpunkt.
      const edge = 'M' + (ux + 16 * Math.cos(rad)).toFixed(1) + ' ' + (UNION_Y + 16 * Math.sin(rad)).toFixed(1) +
        ' Q' + ((ux + cx) / 2).toFixed(1) + ' ' + (bandY - 52) + ' ' + cx.toFixed(1) + ' ' + (bandY - 34);
      (item.kind === 'add' ? dashed : solid).push(edge);
      let node;
      if (item.kind === 'child') node = monoNode(item.person, { onSelect: select, withYear: true, anchor: true, tree });
      else if (item.kind === 'more') {
        const all = (fam.children || []).map((id) => tree.person(id)).filter(Boolean);
        node = monoNode(null, { accentLabel: '+' + item.count, withYear: true, anchor: true,
          onSelect: (_p, ev) => {
            const el = ev && ev.currentTarget ? ev.currentTarget : node.querySelector('button') || node;
            openPeople(el, all, t('label-children'));
          } });
      }
      else node = h('span', { class: 'mono-stack' },
        h('button', { class: 'mono-node', type: 'button', title: t('action-add-child'),
          style: { background: 'transparent', boxShadow: 'none', border: '2px dashed var(--edge)', color: 'var(--secondary)' },
          onClick: () => app.addChild(fam.id) }, '+',
          h('span', { class: 'anchor-top', style: { background: 'var(--edge)' } })),
        h('span', { class: 'mono-year' }, '\u00A0'));
      place(node, cx, bandY);
    });

  });

  if (!marriages.length && !portrait) {
    place(h('button', { class: 'person-card compact', type: 'button',
      style: { width: L.wSpouse + 'px', justifyContent: 'center', background: 'transparent',
        boxShadow: 'inset 0 0 0 2px var(--edge)', color: 'var(--secondary)' },
      onClick: () => app.addMarriage() }, '+ ' + t('action-add-marriage')), W / 2, UNION_Y);
  }

  const edges = svg('svg', { class: 'edges', viewBox: '0 0 ' + W + ' ' + HGT, width: W, height: HGT });
  // Die Kanten spiegelt eine Gruppe — sie tragen keine Schrift.
  const ink = rtl ? svg('g', { transform: 'translate(' + W + ',0) scale(-1,1)' }) : edges;
  if (rtl) edges.appendChild(ink);
  if (solid.length) ink.appendChild(svg('path', { d: solid.join(' ') }));
  if (dashed.length) ink.appendChild(svg('path', { class: 'dashed', d: dashed.join(' ') }));
  chart.insertBefore(edges, chart.firstChild);

  // Fit auf beide Achsen: der Baum darf auch hochskalieren, sonst bleibt auf
  // grossen Bildschirmen die halbe Flaeche leer.
  const availW = Math.max(320, (window.innerWidth || W) - (portrait ? 32 : 190));
  // Auch die Hoehe einpassen: sonst reicht die Tafel unter den Rand, und die
  // erste Generation liegt hinter der schwebenden Titelzeile.
  const availH = Math.max(320, (window.innerHeight || HGT) - 110);
  const usedH = CHILD_Y + 74;
  // Hochformat: nicht kleinrechnen, sondern waagerecht wischen — sonst waere der
  // Baum bei 360 px auf ein Drittel geschrumpft und niemand koennte ihn lesen.
  // Hochformat: Originalgroesse. Der Baum ist Arbeitsflaeche — statt ihn klein
  // zu rechnen, verschiebt man ihn in beide Richtungen.
  const [zMin, zMax] = portrait ? ZOOM.portrait : ZOOM.landscape;
  // Nach dem Drehen kann der gemerkte Wert ausserhalb liegen.
  treeZoom = Math.min(zMax, Math.max(zMin, treeZoom));
  const scale = canvasMode
    ? treeZoom * (portrait ? 1 : 0.72)
    : Math.max(0.45, Math.min(1.6, Math.min(availW / W, availH / usedH))) * 0.96 * deskZoom;
  const stage = h('div', {
    style: { width: (W * scale) + 'px', height: (HGT * scale) + 'px',
      margin: portrait ? '8px 0 0' : '0', position: 'relative', flex: 'none' }
  }, h('div', { style: {
      // Rechts-nach-links: die ganze Tafel kippen, Karten kippen per CSS zurueck.
      transform: 'scale(' + scale + ')',
      transformOrigin: '0 0', position: 'absolute', left: 0, top: 0
    } }, chart));

  // Neue Person im Fokus: Ansicht neu ausrichten.
  if (treeFocusSeen !== focusId) { treeScroll = null; treeFocusSeen = focusId; }

  const padX = Math.round((window.innerWidth || 390) * 0.42);
  const padY = Math.round((window.innerHeight || 800) * 0.34);

  if (canvasMode) {
    // Einrasten an drei Stellen: linker Zweig, Fokus, rechter Zweig.
    // Ganze Flaeche: waagerecht wie senkrecht ziehbar, ohne Rasten — sonst
    // zerrt das Einrasten gegen das freie Verschieben.
    const track = h('div', { style: {
      overflow: 'auto', display: 'flex', WebkitOverflowScrolling: 'touch',
      flex: '1', minHeight: '0',
      scrollbarWidth: 'none', msOverflowStyle: 'none', touchAction: 'none', cursor: 'grab'
      // margin:auto zentriert, solange die Tafel kleiner als das Bild ist —
      // groesser geworden, faellt der Rand auf null und man scrollt normal.
    } }, h('div', { style: { padding: padY + 'px ' + padX + 'px', flex: 'none', margin: 'auto' } }, stage));
    track.classList.add('no-bar');
    // Ziehen statt Scrollbalken: mit Finger oder Maus direkt am Baum.
    let dragging = false, sx = 0, sy = 0, sl = 0, st = 0, moved = 0;
    track.addEventListener('pointerdown', (e) => {
      dragging = true; moved = 0;
      sx = e.clientX; sy = e.clientY;
      sl = track.scrollLeft; st = track.scrollTop;
      track.style.cursor = 'grabbing';
    });
    track.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      const dx = e.clientX - sx, dy = e.clientY - sy;
      moved = Math.max(moved, Math.abs(dx), Math.abs(dy));
      if (moved > 6) e.preventDefault();
      track.scrollLeft = sl - dx;
      track.scrollTop = st - dy;
    });
    const endDrag = () => {
      if (!dragging) return;
      dragging = false;
      track.style.cursor = 'grab';
    };
    track.addEventListener('pointerup', endDrag);
    track.addEventListener('pointercancel', endDrag);
    track.addEventListener('pointerleave', endDrag);
    // Ein Zug darf keinen Klick auf der Karte darunter ausloesen.
    track.addEventListener('click', (e) => { if (moved > 6) { e.stopPropagation(); e.preventDefault(); } }, true);
    // Bildmitte merken, damit Zoomen um die Mitte dreht statt zu springen.
    // Waehrend des Wiederherstellens nicht mitschreiben: ein frisch gebauter
    // Container meldet 0/0 und wuerde die gemerkte Mitte loeschen.
    let settling = true;
    const remember = () => {
      if (settling || !track.clientWidth) return;
      treeScroll = {
        cx: (track.scrollLeft + track.clientWidth / 2 - padX) / scale,
        cy: (track.scrollTop + track.clientHeight / 2 - padY) / scale
      };
    };
    track.addEventListener('scroll', remember, { passive: true });

    // Zwei Finger zoomen, Mausrad ebenso — zwischen 60 % und Originalgroesse.
    const setZoom = (next) => {
      const z = Math.min(zMax, Math.max(zMin, next));
      if (Math.abs(z - treeZoom) < 0.005) return;
      if (!settling) remember();
      treeZoom = z;
      app.render();
    };
    let pinch = null;
    const dist = (e) => Math.hypot(
      e.touches[0].clientX - e.touches[1].clientX,
      e.touches[0].clientY - e.touches[1].clientY);
    track.addEventListener('touchstart', (e) => {
      if (e.touches.length === 2) { pinch = { d: dist(e), z: treeZoom }; }
    }, { passive: true });
    track.addEventListener('touchmove', (e) => {
      if (pinch && e.touches.length === 2) {
        e.preventDefault();
        setZoom(pinch.z * (dist(e) / pinch.d));
      }
    }, { passive: false });
    track.addEventListener('touchend', () => { pinch = null; });
    track.addEventListener('wheel', (e) => {
      e.preventDefault();
      setZoom(treeZoom * (e.deltaY < 0 ? 1.08 : 1 / 1.08));
    }, { passive: false });

    // Statt Frames abzuzaehlen: der Beobachter meldet sich, sobald der
    // Container seine endgueltige Groesse hat — und wieder, wenn sie sich
    // aendert (Drehen, Fenstergroesse). Polling verlor bei flachen Fenstern.
    let lastBox = '';
    const apply = () => {
      const cw = track.clientWidth, ch = track.clientHeight;
      if (!cw || !ch) return;
      const maxX = track.scrollWidth - cw, maxY = track.scrollHeight - ch;
      const cx = treeScroll ? treeScroll.cx : W / 2;
      // Passt die Tafel ganz ins Bild, wird sie als Ganzes zentriert —
      // sonst der Fokus.
      const cy = treeScroll ? treeScroll.cy
        : (HGT * scale <= ch ? HGT / 2 : FOCUS.y);
      track.scrollLeft = Math.max(0, Math.min(maxX, cx * scale + padX - cw / 2));
      track.scrollTop = Math.max(0, Math.min(maxY, cy * scale + padY - ch / 2));
      requestAnimationFrame(() => { settling = false; });
    };
    const ro = new ResizeObserver(() => {
      const box = track.clientWidth + 'x' + track.clientHeight +
        ':' + track.scrollWidth + 'x' + track.scrollHeight;
      if (box === lastBox) return;
      lastBox = box;
      settling = true;
      apply();
    });
    ro.observe(track);
    ro.observe(track.firstElementChild);
    // Gedrosselte Fenster liefern keine Beobachtermeldung — Zeitgeber als Netz.
    setTimeout(apply, 60);
    // Die Geschwisterleiste schwebt ueber der Flaeche, statt ihr eine Zeile
    // wegzunehmen: quer oben rechts unter dem Schriftzug, hoch unten rechts
    // ueber den runden Knoepfen — dort ist sie mit dem Daumen erreichbar.
    // Geschwister stehen an der Elternraute, nicht als Reihe am Bildrand.
    const sibs = null;
    return h('div', { class: 'pane stack', style: {
      gap: '8px', height: '100%', padding: '0', position: 'relative'
    } }, sibs, track);
  }

  // Auch am Desktop ist die Tafel Arbeitsflaeche: gezogen wird an ihr selbst,
  // Balken braucht es dafuer nicht.
  const deskTrack = h('div', { class: 'no-bar', style: {
    overflow: 'auto', flex: '1', minHeight: '0', display: 'flex',
    cursor: 'grab', touchAction: 'none'
    // Oben mehr Rand als unten: die schwebende Titelzeile mit dem Umschalter
    // liegt sonst auf den Grosseltern. Unten wird der leere Rest der Tafel
    // weggeschnitten, sonst zentriert die Flaeche um Luft statt um den Baum.
  } }, h('div', { style: {
    margin: 'auto', padding: '40vh 30vw', flex: 'none'
  } }, stage));

  let dragging = false, sx = 0, sy = 0, sl = 0, st = 0, moved = 0;
  deskTrack.addEventListener('pointerdown', (e) => {
    dragging = true; moved = 0;
    sx = e.clientX; sy = e.clientY; sl = deskTrack.scrollLeft; st = deskTrack.scrollTop;
    deskTrack.style.cursor = 'grabbing';
  });
  deskTrack.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const dx = e.clientX - sx, dy = e.clientY - sy;
    moved = Math.max(moved, Math.abs(dx), Math.abs(dy));
    if (moved > 6) e.preventDefault();
    deskTrack.scrollLeft = sl - dx;
    deskTrack.scrollTop = st - dy;
  });
  const endDeskDrag = () => { dragging = false; deskTrack.style.cursor = 'grab'; };
  deskTrack.addEventListener('pointerup', endDeskDrag);
  deskTrack.addEventListener('pointercancel', endDeskDrag);
  deskTrack.addEventListener('pointerleave', endDeskDrag);
  deskTrack.addEventListener('click', (e) => { if (moved > 6) { e.stopPropagation(); e.preventDefault(); } }, true);

  // Sparsamer Zoom: die Tafel ist schon eingepasst, das hier ist Feinjustage.
  deskTrack.addEventListener('wheel', (e) => {
    e.preventDefault();
    const [lo, hi] = ZOOM.desk;
    const next = Math.min(hi, Math.max(lo, deskZoom * (e.deltaY < 0 ? 1.06 : 1 / 1.06)));
    if (Math.abs(next - deskZoom) < 0.004) return;
    deskZoom = next;
    app.render();
  }, { passive: false });

  // Nach dem Zeichnen auf die Mitte der Tafel stellen.
  const centreDesk = () => {
    const cw = deskTrack.clientWidth, ch = deskTrack.clientHeight;
    if (!cw || !ch) return;
    const nodes = deskTrack.querySelectorAll('.person-card, .mono-node, .diamond, .pill');
    if (!nodes.length) return;
    const tr = deskTrack.getBoundingClientRect();
    let top = Infinity, bottom = -Infinity, left = Infinity, right = -Infinity;
    for (const n of nodes) {
      const r = n.getBoundingClientRect();
      top = Math.min(top, r.top); bottom = Math.max(bottom, r.bottom);
      left = Math.min(left, r.left); right = Math.max(right, r.right);
    }
    // Von Bildschirm- in Scroll-Koordinaten: aktueller Stand plus Abstand
    // zwischen Inhaltsmitte und Bildmitte.
    deskTrack.scrollLeft = Math.max(0, Math.min(deskTrack.scrollWidth - cw,
      deskTrack.scrollLeft + ((left + right) / 2 - (tr.left + cw / 2))));
    deskTrack.scrollTop = Math.max(0, Math.min(deskTrack.scrollHeight - ch,
      deskTrack.scrollTop + ((top + bottom) / 2 - (tr.top + ch / 2)) - 14));
  };
  let lastDeskBox = '';
  const deskRo = new ResizeObserver(() => {
    const box = deskTrack.clientWidth + 'x' + deskTrack.scrollWidth + 'x' + deskTrack.scrollHeight;
    if (box === lastDeskBox) return;
    lastDeskBox = box;
    centreDesk();
  });
  deskRo.observe(deskTrack);
  deskRo.observe(deskTrack.firstElementChild);
  setTimeout(centreDesk, 60);

  // Geschwister haengen ueberall an der Elternraute — keine zweite Knopfreihe.
  // Ohne Innenabstand: die Flaeche laeuft bis unter die schwebende Titelzeile.
  return h('div', { class: 'pane stack', style: {
    gap: '4px', height: '100%', padding: '0', position: 'relative'
  } }, deskTrack);
}
