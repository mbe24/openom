import { h, svg, fullName, initials } from '../ui/dom.js';
import { icons } from '../ui/icons.js';
import { personMenu } from '../ui/menu.js';
import { isCompact } from '../ui/viewport.js';
import { faceOf } from '../ui/components.js';

// Pan-Position lebt im Modul, nicht am App-Objekt: die Sicht wird bei jedem
// Zeichnen neu gebaut, die Position soll das ueberdauern.
// Die Sichtmitte wird in Graph-Koordinaten gehalten, nicht als Pixel-Scroll:
// nur so ueberlebt sie einen Zoomwechsel, ohne vom DOM abzuhaengen.
let savedCentre = null;
let savedFocus = null;
let savedSig = null;      // Layout-Signatur: aendert sie sich, ist die gemerkte Mitte wertlos
let generation = 0;
let lastCentre = null;   // Ausgangspunkt fuer die Fahrt zum neuen Fokus
import { graphLayout, pathBetween, nameShortener, directLine } from '../core/queries.js';
import { t, isRTL } from '../core/i18n.js';
import { shortDate } from '../core/dates.js';

/** Gesamtgraph: deterministisches Generationen-Layout, Ehe-Knoten, Pan und Zoom. */
export function graphView(app) {
  const { tree, focusId } = app;
  // Auch quer liegende Handys bekommen die Arbeitsflaeche: das Seitenpanel
  // frisst dort die halbe Hoehe.
  const portrait = isCompact();
  // Seitenlinien aus: nur Vorfahren, Nachfahren und deren Ehepartner.
  const layout = graphLayout(tree, focusId,
    app.showCollateral ? {} : { only: directLine(tree, focusId) });
  const CARD_W = 240, CARD_H = 56;
  // Alle Karten sind gleich gross. Gekuerzt wird nach gemessener Breite, nicht
  // nach Zeichenzahl: "J. Sebastian Bach" ist schmaler als "Sebastian B." lang.
  // Die Namensspalte wird gemessen, nicht geschaetzt: Polster und Monogramm
  // sind je nach Fenster verschieden gross, und jede Konstante lief bisher
  // entweder zu knapp (abgeschnitten) oder zu grosszuegig (unnoetig gekuerzt).
  const NAME_PX = (() => {
    const probe = h('div', { class: 'chart', style: {
      position: 'absolute', left: '-9999px', top: '0', width: CARD_W + 'px'
    } }, h('div', { class: 'person-card graph-node compact', style: {
      width: CARD_W + 'px', boxSizing: 'border-box'
    } },
      h('span', { class: 'mono' }, 'AB'),
      h('span', { class: 'who' }, h('span', { class: 'name' }, 'x'))));
    document.body.appendChild(probe);
    const px = probe.querySelector('.name').clientWidth;
    probe.remove();
    return Math.max(80, px - 2);
  })();
  // Die Schriftfamilie kommt aus dem Token, nicht aus einem Literal: bei
  // Arabisch und Ge'ez ersetzt [data-script] sie, und ein fest verdrahteter
  // Name wuerde am Gemessenen vorbeirechnen.
  const family = (getComputedStyle(document.documentElement)
    .getPropertyValue('--font-name') || 'Georgia, serif').trim();
  const fitBy = (px, size) => {
    // Eigener Messkontext je Schrift: ein gemeinsamer wuerde sich ueberschreiben.
    const ruler = document.createElement('canvas').getContext('2d');
    ruler.font = size + 'px ' + family;
    const levels = [26, 22, 19, 17, 15, 13, 11, 9].map((b) => nameShortener(tree, b));
    return (person) => {
      let out = levels[0](person);
      for (const lvl of levels) {
        out = lvl(person);
        if (ruler.measureText(out).width <= px) return out;
      }
      return out;
    };
  };
  const shorten = fitBy(NAME_PX, 21);
  const shortPanel = fitBy(286 - 20 - 46 - 12 - 34, 19);
  const highlight = new Set((app.pathTargetId ? pathBetween(tree, app.pathTargetId, focusId) : []).map((p) => p?.id));

  const rtl = isRTL();
  const mx = (x) => (rtl ? layout.width - x : x);

  const edges = svg('svg', { class: 'edges', width: layout.width, height: layout.height,
    viewBox: '0 0 ' + layout.width + ' ' + layout.height, style: 'position:absolute;inset:0' });

  for (const m of layout.marriages) {
    for (const s of m.spouses) {
      const cls = highlight.has(s.id) ? 'accent' : '';
      edges.appendChild(svg('path', { class: cls, d: tie(s.x, s.y + 28, m.x, m.y) }));
    }
    // Geschwisterblock und Einzelkinder derselben Familie koennen nebeneinander
    // vorkommen: der Block bekommt die Schiene, der Rest die uebliche Kurve.
    const blocked = m.children.filter((c) => c.sib && c.sib.fam === m.family.id);
    const rest = m.children.filter((c) => !(c.sib && c.sib.fam === m.family.id));
    // Alle Abgaenge einer Ehe zusammen betrachten: Spaltenkoepfe eines
    // Geschwisterblocks und Einzelkinder. Sie starten nach Ziel-x sortiert auf
    // einem kleinen Faecher unter der Raute — sonst laufen mehrere Kanten am
    // Knoten uebereinander und beruehren sich (Design Spec, Slide 14/15).
    const departures = [];
    if (blocked.length) {
      const cols = new Map();
      for (const c of blocked) {
        if (!cols.has(c.sib.col)) cols.set(c.sib.col, []);
        cols.get(c.sib.col).push(c);
      }
      for (const list of cols.values()) {
        list.sort((a, b) => a.sib.row - b.sib.row);
        departures.push({ node: list[0], chain: list });
      }
    }
    for (const c of (blocked.length ? rest : m.children)) departures.push({ node: c, chain: null });
    departures.sort((p, q) => p.node.x - q.node.x);
    // Ein Geschwisterblock haengt an EINER Kante: von der Raute laeuft eine Linie
    // zu einem Verteilpunkt ueber dem Block, erst dort faechert sie kurz auf die
    // Spaltenkoepfe auf. Vier lange Parallelen von der Raute quer durchs Bild
    // kreuzen sonst alles, was dazwischen liegt. Bei ein bis zwei Abgaengen
    // braucht es den Umweg nicht — die gehen direkt an die Raute.
    if (departures.length && departures.length <= 2) {
      departures.forEach((d, i) => {
        const k = i - (departures.length - 1) / 2;
        const c = d.node;
        const cls = highlight.has(c.id) ? 'accent' : '';
        const far = Math.abs(c.x - m.x) / 900;
        const p = svg('path', { class: cls, d: drop(m.x + k * 20, m.y + 13, c.x, c.y - 28) });
        if (!cls && far > 0.4) p.setAttribute('opacity', String(Math.max(0.3, 1 - far * 0.6)));
        edges.appendChild(p);
        if (d.chain) {
          for (let j = 1; j < d.chain.length; j++) {
            const a2 = d.chain[j - 1], b2 = d.chain[j];
            const cl = highlight.has(b2.id) ? 'accent' : '';
            edges.appendChild(svg('path', { class: cl, d: swing(a2.x, a2.y + 26, b2.x, b2.y - 26, j % 2 ? -22 : 22) }));
          }
        }
      });
    } else if (departures.length) {
      const heads = departures.map((d) => d.node);
      const minX = Math.min(...heads.map((c) => c.x)), maxX = Math.max(...heads.map((c) => c.x));
      const hubX = (minX + maxX) / 2;
      const topY = Math.min(...heads.map((c) => c.y));
      // Der Verteilpunkt sitzt hoeher, wenn die Spaltenkoepfe weit auseinander
      // liegen — sonst laufen die kurzen Aeste flach auf die Karten zu (gleiche
      // Regel wie beim vertikalen Abstand der Generationen).
      const spanX = maxX - minX;
      // Je breiter der Block, desto hoeher das Gelenk — sonst laufen die Aeste
      // flach auf die Karten zu. Mindestens 60 px unter der Raute bleibt es.
      // Stamm und Aeste teilen sich die verfuegbare Hoehe im Verhaeltnis ihrer
      // Breiten — so haben beide dieselbe Steigung und keiner laeuft flach.
      const runY = Math.max(80, topY - 28 - m.y);
      const trunkDx = Math.abs(hubX - m.x), branchDx = Math.max(1, spanX / 2);
      const frac = Math.min(0.78, Math.max(0.3, trunkDx / (trunkDx + branchDx)));
      const hubY = m.y + runY * frac;
      const anyHot = heads.some((c) => highlight.has(c.id));
      const trunkFar = Math.abs(hubX - m.x) / 900;
      const trunk = svg('path', { class: anyHot ? 'accent' : '', d: drop(m.x, m.y + 13, hubX, hubY) });
      if (!anyHot && trunkFar > 0.4) trunk.setAttribute('opacity', String(Math.max(0.3, 1 - trunkFar * 0.6)));
      edges.appendChild(trunk);
      departures.forEach((d, i) => {
        const k = i - (departures.length - 1) / 2;
        const c = d.node;
        const cls = highlight.has(c.id) ? 'accent' : '';
        edges.appendChild(svg('path', { class: cls, d: drop(hubX + k * 10, hubY + 4, c.x, c.y - 28) }));
        if (d.chain) {
          for (let j = 1; j < d.chain.length; j++) {
            const a2 = d.chain[j - 1], b2 = d.chain[j];
            const cl = highlight.has(b2.id) ? 'accent' : '';
            edges.appendChild(svg('path', { class: cl, d: swing(a2.x, a2.y + 26, b2.x, b2.y - 26, j % 2 ? -22 : 22) }));
          }
        }
      });
    }
  }

  // "Fit" heisst nicht, 60 Personen auf einen Bildschirm zu quetschen — bei
  // grossen Baeumen oeffnet die Sicht auf Arbeits-Zoom am Fokus, kleine passen ganz.
  const fitScale = Math.min(
    ((window.innerWidth || 1280) - 460) / layout.width,
    ((window.innerHeight || 800) - 240) / layout.height);
  const zoom = app.graphZoom === 'fit' ? Math.max(0.62, Math.min(1, fitScale)) : app.graphZoom;
  // Freier Rand um den Graphen: ohne ihn endet das Scrollen am Inhalt und ein
  // Randknoten laesst sich nie in die Bildmitte ziehen.
  const padX = Math.round((window.innerWidth || 1280) * 0.42);
  const padY = Math.round((window.innerHeight || 800) * 0.42);
  if (rtl) {
    // Kanten tragen keine Schrift — sie spiegelt eine Gruppe um die Flaeche.
    const ink = svg('g', { transform: 'translate(' + layout.width + ',0) scale(-1,1)' });
    while (edges.firstChild) ink.appendChild(edges.firstChild);
    edges.appendChild(ink);
  }

  // Doppelklick oeffnet die Person — einfacher Klick zentriert nur.
  // Rechtsklick bringt das Kontextmenue; am Handy nicht, dort ist langes
  // Druecken schon fuer das Pfad-Ziel belegt.
  const openOnDouble = (el, id) => {
    el.addEventListener('dblclick', (e) => {
      e.preventDefault(); e.stopPropagation();
      app.setFocus(id); app.setView('detail');
    });
    if (!portrait) {
      el.addEventListener('contextmenu', (e) => {
        e.preventDefault(); e.stopPropagation();
        personMenu(app, id, e.clientX, e.clientY);
      });
    }
    return el;
  };

  const canvas = h('div', { class: 'chart', style: {
    width: layout.width + 'px', height: layout.height + 'px',
    transform: 'translate(' + padX + 'px,' + padY + 'px) scale(' + zoom + ')',
    transformOrigin: '0 0'
  } }, edges);

  const detailed = zoom >= 0.6;
  const dated = zoom >= 1.4;   // ab hier ist Platz fuer Lebensdaten
  const far = zoom < 0.42;

  for (const m of layout.marriages) {
    // Auf jeder Zoomstufe gleich gross auf dem Schirm — und wirklich quadratisch:
    // ohne die Nullwerte machen Button-Grundstile aus 5 px ein Rechteck.
    const ds = Math.max(6, Math.round((zoom < 0.42 ? 10 : 13) / Math.max(zoom, 0.34)));
    // Ab der Namensstufe traegt die Raute ihr Jahr — darunter waere es Gekrissel.
    const my = m.family?.facts?.marriage;
    const myYear = my ? String(my).match(/\d{4}/)?.[0] : null;
    if (detailed && myYear) {
      // Neben die Raute, nicht darueber: oberhalb laufen die beiden Partner-
      // kanten als Trichter zusammen, und dort schneidet jede Pille sie.
      // Seitlich ist frei — die Kinderkanten gehen nach unten.
      canvas.appendChild(h('div', { style: {
        position: 'absolute', left: (mx(m.x) + (rtl ? -20 : 20)) + 'px', top: m.y + 'px',
        transform: rtl ? 'translate(-100%,-50%)' : 'translate(0,-50%)'
      } }, h('span', { class: 'pill', style: { fontSize: '14px', whiteSpace: 'nowrap' } },
        t('symbol-marriage') + ' ' + myYear)));
    }
    canvas.appendChild(h('div', { style: { left: mx(m.x) + 'px', top: m.y + 'px', transform: 'translate(-50%,-50%)' } },
      h('button', { class: 'diamond' + (m.family.children.length ? '' : ' soft'), type: 'button',
        style: {
          width: ds + 'px', height: ds + 'px', minWidth: '0', minHeight: '0',
          padding: '0', border: 'none', boxSizing: 'border-box', display: 'block',
          lineHeight: '0', fontSize: '0', flex: 'none',
          borderRadius: Math.max(2, Math.round(ds * 0.3)) + 'px'
        },
        title: m.family.facts?.marriage ? t('symbol-marriage') + ' ' + m.family.facts.marriage : '' })));
  }

  // Semantischer Zoom wie in der Spec: weit draussen tragen die Knoten nur das
  // Monogramm, ab Arbeits-Zoom die ganze Karte. Ein 16-px-Name bei 27 % waere
  // vier Pixel hoch — und muesste abgeschnitten werden.
  // Tippen im Hochformat fuehrt direkt in die Detailansicht; langes Druecken
  // setzt stattdessen das Pfad-Ziel (am Desktop macht das Shift-Klick).
  let longPressed = null;
  const nodeActivate = (e, id) => {
    if (longPressed === id) { longPressed = null; return; }
    if (e.shiftKey) { app.setPathTarget(id); return; }
    // Auch auf dem Handy zentriert ein Tipp den Knoten — die Detailansicht
    // oeffnet der eigene Knopf unten rechts.
    app.setFocus(id);
  };
  const withLongPress = (el, id) => {
    let timer = null;
    const start = () => { timer = setTimeout(() => { longPressed = id; app.setPathTarget(id); }, 480); };
    const stop = () => { if (timer) clearTimeout(timer); timer = null; };
    el.addEventListener('pointerdown', start);
    el.addEventListener('pointerup', stop);
    el.addEventListener('pointercancel', stop);
    el.addEventListener('pointermove', stop);
    return el;
  };

  for (const node of layout.nodes.values()) {
    const isFocus = node.id === focusId;
    const hit = highlight.has(node.id);
    let el;
    if (detailed) {
      el = h('button', {
        class: 'person-card graph-node compact' + (isFocus ? ' focus' : ''), type: 'button',
        title: fullName(node.person),
        style: {
          left: mx(node.x) + 'px', top: node.y + 'px', transform: 'translate(-50%,-50%)',
          width: CARD_W + 'px', height: (dated ? CARD_H + 20 : CARD_H) + 'px',
          boxSizing: 'border-box', flex: 'none'
        },
        onClick: (e) => nodeActivate(e, node.id)
      },
        // Mit Jahreszeile spannt das Monogramm ueber beide Zeilen — Oberkante Name
        // bis Unterkante Jahre, also die vollen 38 px der zwei Zeilenboxen.
        faceOf(tree, node.person, h('span', { class: 'mono', style: dated
          ? { width: '38px', height: '38px', borderRadius: '12px', fontSize: '16px',
              transform: 'translateY(-0.9px)', flex: 'none', overflow: 'hidden' }
          : null }, initials(node.person))),
        // Ohne Jahreszeile steht die Schrift geometrisch mittig, wirkt aber hoch:
        // Newsreaders Unterlaenge zaehlt in der Zeilenbox mit. 1,5 px tiefer.
        h('span', { class: 'who', style: dated ? { gap: '0px' } : { transform: 'translateY(1.5px)' } },
          h('span', { class: 'name', style: {
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', lineHeight: '1.15',
            fontSize: '21px'
          } }, shorten(node.person)),
          dated ? h('span', { style: {
              whiteSpace: 'nowrap', fontSize: '16px', lineHeight: '1.2',
              fontVariantNumeric: 'tabular-nums',
              color: isFocus ? 'var(--accent-tint)' : 'var(--secondary)'
            } },
            [shortDate(node.person.birth), shortDate(node.person.death)].filter(Boolean).join(' – ') || '—') : null)
      );
      if (hit) el.style.boxShadow = 'var(--shadow-2), inset 0 0 0 2px var(--accent)';
    } else if (far) {
      // Weit draussen wie in der Spec: Punkte, Namen nur an Fokus und Pfad.
      // Punkte deutlich groesser als die Ehe-Rauten — sonst sind Personen und
      // Ehen auf dieser Stufe kaum zu unterscheiden.
      const d = Math.round(22 / zoom);
      el = h('button', {
        class: 'graph-dot', type: 'button', title: fullName(node.person),
        style: {
          left: mx(node.x) + 'px', top: node.y + 'px', transform: 'translate(-50%,-50%)',
          width: d + 'px', height: d + 'px', borderRadius: '50%', padding: '0',
          background: isFocus ? 'var(--accent)' : hit ? 'var(--accent)' : 'var(--edge)',
          boxShadow: isFocus || hit ? '0 0 0 ' + Math.round(5 / zoom) + 'px var(--card)' : 'none'
        },
        onClick: (e) => nodeActivate(e, node.id)
      });
    } else {
      // Monogramm-Knoten, gegen den Zoom hochskaliert damit er tappbar bleibt.
      const size = Math.round(46 / zoom);
      el = h('button', {
        class: 'mono-node', type: 'button', title: fullName(node.person),
        style: {
          left: mx(node.x) + 'px', top: node.y + 'px', transform: 'translate(-50%,-50%)',
          width: size + 'px', height: size + 'px', borderRadius: Math.round(size * 0.3) + 'px',
          fontSize: Math.round(size * 0.42) + 'px',
          background: isFocus ? 'var(--accent)' : hit ? 'var(--accent-tint)' : 'var(--mono-bg)',
          color: isFocus ? '#fff' : hit ? 'var(--accent-tint-text)' : 'var(--mono-text)',
          boxShadow: isFocus || hit ? '0 0 0 3px var(--card)' : 'inset 0 0 0 1px var(--hairline)'
        },
        onClick: (e) => nodeActivate(e, node.id)
      }, initials(node.person));
      faceOf(tree, node.person, el);
    }
    canvas.appendChild(openOnDouble(portrait ? withLongPress(el, node.id) : el, node.id));
  }

  // Der Scrollbereich muss die *skalierte* Groesse plus Rand haben — ein
  // transform aendert die Layoutbox nicht, sonst passen Sicht und Scrollweg nicht.
  const stage = h('div', { style: {
    position: 'relative',
    width: Math.round(layout.width * zoom) + padX * 2 + 'px',
    height: Math.round(layout.height * zoom) + padY * 2 + 'px'
  } }, canvas);
  stage.style.visibility = 'hidden';
  // Im Hochformat ist der ganze Bildschirm die Arbeitsflaeche: kein Papier,
  // keine Kante — der leicht akzentuierte Seitenhintergrund traegt den Graphen.
  const viewport = h('div', {
    class: 'no-bar',
    style: portrait
      ? { position: 'relative', flex: '1', minHeight: '0', overflow: 'auto', background: 'transparent' }
      // Randlos wie die Tafel: der leichte Akzent der Flaeche, keine Karte.
      : { position: 'relative', flex: '1', minHeight: '0', overflow: 'auto', background: 'transparent' }
  }, stage);

  // Der Fokus-Knoten liegt bei 60 Personen weit ausserhalb des Sichtfelds —
  // nach dem Mounten dorthin scrollen.
  // --- Pan: Ziehen mit der Maus, Cursor zeigt den Zustand
  let dragging = false, sx = 0, sy = 0, sl = 0, st = 0;
  viewport.style.cursor = 'grab';
  viewport.addEventListener('dragstart', (e) => e.preventDefault());
  viewport.addEventListener('pointerdown', (e) => {
    if (e.target.closest('button')) return;
    dragging = true;
    sx = e.clientX; sy = e.clientY; sl = viewport.scrollLeft; st = viewport.scrollTop;
    viewport.style.cursor = 'grabbing';
    viewport.setPointerCapture(e.pointerId);
  });
  viewport.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    viewport.scrollLeft = sl - (e.clientX - sx);
    viewport.scrollTop = st - (e.clientY - sy);
  });
  const endDrag = () => { dragging = false; viewport.style.cursor = 'grab'; remember(); };
  viewport.addEventListener('pointerup', endDrag);
  viewport.addEventListener('pointercancel', endDrag);

  // --- Zwei Finger: zusammenziehen zoomt, Doppeltippen zentriert auf den Knoten
  if (portrait) {
    let pinch = null, lastTap = 0;
    viewport.addEventListener('touchstart', (e) => {
      if (e.touches.length === 2) {
        const [a, b] = e.touches;
        pinch = { d: Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY), z: zoom };
      } else if (e.touches.length === 1) {
        const now = Date.now();
        if (now - lastTap < 300) {
          const el = e.target.closest('button');
          if (el) { savedCentre = null; savedFocus = null; app.forceUpdateGraph?.(); }
        }
        lastTap = now;
      }
    }, { passive: true });
    viewport.addEventListener('touchmove', (e) => {
      if (!pinch || e.touches.length !== 2) return;
      e.preventDefault();
      const [a, b] = e.touches;
      const d = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      const next = Math.min(2.5, Math.max(0.2, pinch.z * (d / pinch.d)));
      if (Math.abs(next - zoom) > 0.02) app.setZoom(next);
    }, { passive: false });
    viewport.addEventListener('touchend', () => { pinch = null; }, { passive: true });
  }

  // --- Zoom: Mausrad, verankert am Punkt unter dem Zeiger
  viewport.addEventListener('wheel', (e) => {
    e.preventDefault();
    const rect = viewport.getBoundingClientRect();
    const px = (viewport.scrollLeft + e.clientX - rect.left - padX) / zoom;
    const py = (viewport.scrollTop + e.clientY - rect.top - padY) / zoom;
    const next = Math.min(2.5, Math.max(0.2, zoom * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
    app.graphAnchor = { px, py, cx: e.clientX - rect.left, cy: e.clientY - rect.top };
    app.setZoom(next);
  }, { passive: false });

  // Pan ueberlebt das Neuzeichnen: ein Filter-Umschalten darf die Ansicht nicht
  // verschieben. Neu zentriert wird nur, wenn der Fokus wirklich wechselt.
  const mine = ++generation;
  const centreFromScroll = () => ({
    px: (viewport.scrollLeft + viewport.clientWidth / 2 - padX) / zoom,
    py: (viewport.scrollTop + viewport.clientHeight / 2 - padY) / zoom
  });
  const remember = () => {
    if (settling || mine !== generation || !viewport.isConnected || viewport.clientWidth === 0) return;
    savedCentre = centreFromScroll();
    lastCentre = savedCentre;
  };
  viewport.addEventListener('scroll', remember, { passive: true });

  const focusNode = layout.nodes.get(focusId);
  const anchor = app.graphAnchor;
  // Ein Filterwechsel verschiebt jeden Knoten — dieselbe Graph-Koordinate zeigt
  // dann woanders hin. Also merken, aus welchem Layout die Mitte stammt.
  const sig = (app.showCollateral ? 'c' : 'd') + ':' + layout.nodes.size +
    ':' + Math.round(layout.width) + 'x' + Math.round(layout.height);
  const sameLayout = savedSig === sig;
  const keep = sameLayout && savedFocus === focusId ? savedCentre : null;
  const from = sameLayout && savedFocus && savedFocus !== focusId ? lastCentre : null;
  savedSig = sig;
  app.graphAnchor = null;
  savedFocus = focusId;

  let settling = true;
  let applied = { left: 0, top: 0 };
  // Ziel immer als Punkt im Graphen — Pixelwerte gelten nur fuer einen Zoomwert.
  const target = anchor ? { anchor } : keep ? { centre: keep } : focusNode ? { focus: true } : null;

  // Zuweisungen auf einen noch nicht eingehaengten Scroll-Container werden auf 0
  // geklemmt — daher warten, bis er wirklich vermessen ist.
  let tries = 0;
  const reveal = () => { stage.style.visibility = 'visible'; };
  const settle = () => {
    if (!target) { settling = false; reveal(); return; }
    // Erst wenn wirklich Spielraum da ist, greift die Klemmung richtig — auf
    // dem ersten Durchgang ist scrollWidth === clientWidth.
    const room = viewport.scrollWidth > viewport.clientWidth || viewport.scrollHeight > viewport.clientHeight;
    if (!viewport.isConnected || viewport.clientWidth === 0 || !room) {
      // Kein Abzaehlen von Frames: der Beobachter weckt uns, sobald die Buehne
      // vermessen ist. Bei flachen Fenstern kam das Polling zu frueh ans Ende.
      return;
    }
    // Hat der Nutzer waehrend der Wartezeit schon selbst gescrollt, gehoert ihm die Sicht.
    if (viewport.scrollLeft !== applied.left || viewport.scrollTop !== applied.top) {
      settling = false;
      savedCentre = centreFromScroll();
      savedFocus = focusId;
      reveal();
      return;
    }
    // Der Container klemmt jede Zuweisung auf seinen aktuellen Scrollweg. Ist die
    // Buehne noch nicht vermessen, ist der Weg 0 und das Ziel ginge verloren.
    const maxL = viewport.scrollWidth - viewport.clientWidth;
    const maxT = viewport.scrollHeight - viewport.clientHeight;
    const wanted = Math.round(Math.round(layout.width * zoom) + padX * 2 - viewport.clientWidth);
    if (maxL < wanted - 2) return;

    let centre;
    if (target.anchor) {
      // Punkt unter dem Zeiger bleibt stehen — als Mitte ausgedrueckt.
      centre = {
        px: target.anchor.px + (viewport.clientWidth / 2 - target.anchor.cx) / zoom,
        py: target.anchor.py + (viewport.clientHeight / 2 - target.anchor.cy) / zoom
      };
    } else if (target.centre) {
      centre = target.centre;
    } else {
      centre = { px: mx(focusNode.x), py: focusNode.y };
    }
    // Sicherheitsnetz: die Mitte bleibt im Graphen, nie in der leeren Randflaeche.
    centre = {
      px: Math.max(0, Math.min(centre.px, layout.width)),
      py: Math.max(0, Math.min(centre.py, layout.height))
    };
    const toLeft = Math.max(0, Math.min(centre.px * zoom + padX - viewport.clientWidth / 2, maxL));
    const toTop = Math.max(0, Math.min(centre.py * zoom + padY - viewport.clientHeight / 2, maxT));
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const glide = from && !still && target.focus;

    const land = () => {
      applied = { left: viewport.scrollLeft, top: viewport.scrollTop };
      savedCentre = centreFromScroll();
      lastCentre = savedCentre;
      reveal();
      requestAnimationFrame(() => { settling = false; });
    };

    if (!glide) {
      viewport.scrollLeft = toLeft;
      viewport.scrollTop = toTop;
      return land();
    }
    // Der neue Fokus wird angefahren, nicht angesprungen: Start ist die zuletzt
    // gezeigte Mitte, damit die Bewegung dort ansetzt, wo der Blick war.
    const fromLeft = Math.max(0, Math.min(from.px * zoom + padX - viewport.clientWidth / 2, maxL));
    const fromTop = Math.max(0, Math.min(from.py * zoom + padY - viewport.clientHeight / 2, maxT));
    viewport.scrollLeft = fromLeft;
    viewport.scrollTop = fromTop;
    reveal();
    const dist = Math.hypot(toLeft - fromLeft, toTop - fromTop);
    const dur = Math.max(220, Math.min(620, 220 + dist * 0.35));
    const t0 = performance.now();
    const mineNow = mine;
    const step = (now) => {
      if (mineNow !== generation || !viewport.isConnected) { settling = false; return; }
      const k = Math.min(1, (now - t0) / dur);
      const e = k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
      viewport.scrollLeft = fromLeft + (toLeft - fromLeft) * e;
      viewport.scrollTop = fromTop + (toTop - fromTop) * e;
      if (k < 1) return requestAnimationFrame(step);
      land();
    };
    requestAnimationFrame(step);
  };
  // Der Beobachter meldet die endgueltige Groesse — und jede spaetere Aenderung
  // (Drehen, Fenstergroesse), sodass die Mitte erhalten bleibt.
  let lastBox = '';
  const ro = new ResizeObserver(() => {
    const box = viewport.clientWidth + 'x' + viewport.clientHeight +
      ':' + stage.scrollWidth + 'x' + stage.scrollHeight;
    if (box === lastBox) return;
    lastBox = box;
    settle();
  });
  ro.observe(viewport);
  ro.observe(stage);
  requestAnimationFrame(settle);
  // Gedrosselte Fenster (Hintergrundtab, unsichtbarer Rahmen) liefern keine
  // Frames — dann uebernimmt der Zeitgeber, damit die Buehne nicht verborgen bleibt.
  setTimeout(settle, 60);

  const filters = h('div', { class: 'card stack', style: { gap: '10px', flex: 'none' } },
    h('div', { class: 'section-label' }, t('graph-filters')),
    toggle(t('graph-collateral'), app.showCollateral, () => app.toggleCollateral()),
    app.pathTargetId
      ? h('div', { class: 'chip accent' }, t('graph-path') + ': ' + fullName(tree.person(app.pathTargetId)))
      : null,
    h('div', { class: 'muted', style: { fontSize: 'var(--t-tiny)', whiteSpace: 'nowrap' } },
      dated ? 'Names and dates'
        : detailed ? 'Names · 140 % for dates'
        : far ? 'Dots · 42 % for monograms' : 'Monograms · 60 % for names'),
    // Gezoomt wird mit dem Rad. Die Zahl steht unter dem Hinweis, im Akzent —
    // ein Klick stellt die Ansicht zurueck.
    h('button', { class: 'zoom-stat', type: 'button', title: t('action-fit'),
      'aria-label': t('action-fit'),
      onClick: () => { savedCentre = null; savedFocus = null; app.setZoom('fit'); } },
      Math.round(zoom * 100) + ' %')
  );

  const who = tree.person(focusId);
  const years = [shortDate(who?.birth), shortDate(who?.death)].filter(Boolean).join(' – ');
  const focusCard = h('div', { class: 'card stack', style: { gap: '10px', flex: 'none' } },
    // In der Ecke verankert, damit der Name die ganze Zeile behaelt.
    h('button', { class: 'icon-button corner', type: 'button',
      title: t('action-open-detail'), 'aria-label': t('action-open-detail'),
      onClick: () => app.setView('detail') }, icons.expand(11)),
    h('div', { class: 'row', style: { gap: '12px', alignItems: 'center' } },
      faceOf(tree, who, h('span', { class: 'mono-node', style: { width: '46px', height: '46px', fontSize: '18px', flex: 'none' } },
        initials(who))),
      h('span', { class: 'stack', style: { gap: '2px', minWidth: '0', flex: '1 1 0' } },
        // Eine Zeile: der Name wird gekuerzt wie ueberall, nie abgeschnitten.
        h('span', { style: {
          fontFamily: 'var(--font-name)', fontSize: '19px', lineHeight: '1.2', whiteSpace: 'nowrap'
        } }, shortPanel(who)),
        h('span', { class: 'muted', style: { fontSize: 'var(--t-small)', fontVariantNumeric: 'tabular-nums' } },
          years || t('label-no-year'))),
),
    (who?.birthPlace || who?.custom?.occupation)
      ? h('div', { class: 'muted', style: { fontSize: 'var(--t-small)', minHeight: '0', overflow: 'hidden' } },
          [who.birthPlace, who.custom?.occupation].filter(Boolean).join(' · '))
      : null,
  );

  if (portrait) {
    // Kein Panel: auf 360 px gehoert die Flaeche dem Graphen. Tippen oeffnet die
    // Detailansicht, langes Druecken setzt das Pfad-Ziel.
    // Gezoomt wird mit zwei Fingern, darum keine Zoomleiste: zwei runde Knoepfe
    // schweben ueber dem Graphen und kosten keine Flaeche.
    const round = (on, label, icon, onClick) => h('button', {
      class: 'fab' + (on ? ' on' : ''), type: 'button', title: label, 'aria-label': label,
      'aria-pressed': String(!!on), onClick
    }, icon);
    // Rechts die Aktionen der Ansicht, links das Navigieren — "ganzen Baum
    // zeigen" gehoert zum Navigieren und sitzt daher ueber der Lupe.
    const overlay = h('div', { class: 'graph-fabs' },
      h('button', { class: 'fab primary', type: 'button', title: t('view-detail'),
        'aria-label': t('view-detail'), onClick: () => app.setView('detail') }, icons.person(22)),
      round(app.showCollateral, t('graph-collateral'), icons.people(22), () => app.toggleCollateral()));
    const navOverlay = h('div', { class: 'graph-fabs left fit' },
      round(false, t('action-fit'), icons.fit(22), () => { savedCentre = null; savedFocus = null; app.setZoom('fit'); }));
    return h('div', { class: 'pane', style: { position: 'relative', height: '100%', display: 'flex', padding: '0' } },
      viewport, overlay, navOverlay);
  }

  return h('div', { class: 'pane', style: {
      display: 'flex', height: '100%', position: 'relative', padding: '0'
    } },
    app.graphPanel === false ? null : h('div', { class: 'stack graph-panel', style: {
      gap: '18px', width: '286px', minHeight: '0', overflowY: 'auto'
    } }, filters, focusCard),
    viewport);
}

function bow(x1, y1, x2, y2) {
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  const off = Math.min(28, len * 0.1);
  const cx2 = mx - (dy / len) * off, cy2 = my + (dx / len) * off;
  return 'M' + x1 + ' ' + y1 + ' Q' + cx2 + ' ' + cy2 + ' ' + x2 + ' ' + y2;
}

// Bogen zwischen zwei senkrecht stehenden Punkten: ohne Ausschwung waere das
// eine Gerade — die Seite wechselt von Geschwister zu Geschwister.
// Raute zum Kind: die Linie zielt von der Raute aus auf die Spalte des Kindes und
// laeuft dann senkrecht in dessen Oberkante — fast gerade, nur leicht geschwungen.
function drop(mx, my, cx, cy) {
  const dx = cx - mx, dy = Math.max(1, cy - my);
  if (Math.abs(dx) <= dy * 0.55) {
    return 'M' + mx + ' ' + my + ' Q' + cx + ' ' + (my + dy * 0.52) + ' ' + cx + ' ' + cy;
  }
  // Weit seitlich: eine im Wesentlichen gerade Diagonale, die erst kurz vor dem
  // Kind in die Senkrechte einbiegt — kein Bogen ueber die halbe Generation.
  const c1x = mx + dx * 0.55, c1y = my + dy * 0.62;
  const c2x = cx, c2y = cy - Math.min(34, dy * 0.3);
  return 'M' + mx + ' ' + my + ' C' + c1x + ' ' + c1y + ' ' + c2x + ' ' + c2y + ' ' + cx + ' ' + cy;
}

// Ehepartner an ihre Raute: der Strich verlaesst die Karte schon in Richtung
// Raute und kommt von der Seite an. Beide Partner symmetrisch von der Kartenmitte
// nach unten zu fuehren ergibt sonst eine Klammer.
function tie(x, y, mx, my) {
  const dx = mx - x;
  if (Math.abs(dx) < 6) return 'M' + mx + ' ' + y + ' Q' + mx + ' ' + ((y + my) / 2) + ' ' + mx + ' ' + (my - 13);
  // Wie bei den Kindern: fast gerade Diagonale, die erst kurz vor der Raute
  // einbiegt. Ein tief liegender Kontrollpunkt ergaebe zu zweit eine Klammer.
  const sx = x + Math.max(-110, Math.min(110, dx * 0.34));
  const end = mx + (dx > 0 ? -12 : 12), ey = my - 5;
  const ddx = end - sx, ddy = Math.max(1, ey - y);
  const c1x = sx + ddx * 0.5, c1y = y + ddy * 0.5;
  const c2x = end - Math.sign(ddx) * Math.min(22, Math.abs(ddx) * 0.16), c2y = ey - Math.min(18, ddy * 0.22);
  return 'M' + sx + ' ' + y + ' C' + c1x + ' ' + c1y + ' ' + c2x + ' ' + c2y + ' ' + end + ' ' + ey;
}

// Weit seitlich liegende Kinder: eine S-Kurve mit senkrechten Tangenten bleibt
// im Band zwischen den Generationen und laeuft nicht durch fremde Karten.
// Nah: der vertraute Bogen. Weit seitlich: die S-Kurve.
function link(x1, y1, x2, y2) {
  return Math.abs(x2 - x1) > Math.abs(y2 - y1) * 1.1 ? hook(x1, y1, x2, y2) : bow(x1, y1, x2, y2);
}

function hook(x1, y1, x2, y2) {
  const dy = Math.max(40, (y2 - y1) * 0.62);
  return 'M' + x1 + ' ' + y1 + ' C' + x1 + ' ' + (y1 + dy) + ' ' + x2 + ' ' + (y2 - dy) + ' ' + x2 + ' ' + y2;
}

function swing(x1, y1, x2, y2, off) {
  const my = (y1 + y2) / 2;
  return 'M' + x1 + ' ' + y1 + ' C' + (x1 + off) + ' ' + my + ' ' + (x2 + off) + ' ' + my + ' ' + x2 + ' ' + y2;
}

function toggle(label, on, onClick) {
  return h('button', { class: 'row between', type: 'button', style: { width: '100%' }, onClick },
    h('span', {}, label),
    h('span', { style: {
      width: '44px', height: '26px', borderRadius: '13px', flex: 'none',
      background: on ? 'var(--accent)' : 'var(--edge)', padding: '3px',
      display: 'flex', justifyContent: on ? 'flex-end' : 'flex-start'
    } }, h('span', { style: { width: '20px', height: '20px', borderRadius: '10px', background: '#fff' } })));
}
