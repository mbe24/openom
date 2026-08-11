import { compareSiblings, comparePeople, compareNames } from './sort.js';
import { parseDate } from './dates.js';

/** Ahnentafel: Fokus, Eltern, Grosseltern als verschachtelte Struktur. */
export function ancestors(tree, id, generations = 2) {
  const build = (pid, depth) => {
    const person = tree.person(pid);
    if (!person) return null;
    const node = { person, father: null, mother: null, family: null, depth };
    if (depth < generations) {
      const { family, father, mother } = tree.parentsOf(pid);
      node.family = family;
      node.father = father ? build(father.id, depth + 1) : null;
      node.mother = mother ? build(mother.id, depth + 1) : null;
    }
    return node;
  };
  return build(id, 0);
}

/** Flache Liste je Generation - fuer Faecher und Landscape-Layout. */
export function ancestorRings(tree, id, generations = 4) {
  const rings = [];
  let level = [id];
  for (let g = 0; g < generations; g++) {
    const next = [];
    for (const pid of level) {
      const { father, mother } = pid ? tree.parentsOf(pid) : { father: null, mother: null };
      next.push(father ? father.id : null, mother ? mother.id : null);
    }
    rings.push(next.map((pid) => (pid ? tree.person(pid) : null)));
    level = next;
  }
  return rings;
}

export function familiesOf(tree, id) {
  return tree.familiesOf(id).map((f) => ({
    family: f,
    spouse: tree.person(f.spouses.find((s) => s !== id)) ?? null,
    children: f.children.map((c) => tree.person(c)).filter(Boolean).sort(compareSiblings)
  }));
}

export function search(tree, query, limit = 20) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return tree.allPeople()
    .filter((p) => ((p.given ?? '') + ' ' + (p.surname ?? '')).toLowerCase().includes(needle))
    .sort((a, b) => comparePeople(a, b))
    .slice(0, limit);
}

export function list(tree, sort = 'surname') {
  return tree.allPeople().sort((a, b) => comparePeople(a, b, sort));
}

export function stats(tree) {
  const people = tree.allPeople();
  const unsourced = people.filter((p) => !(p.sources && p.sources.length)).length;
  const depth = (id, seen) => {
    if (seen.has(id)) return 0;
    seen.add(id);
    const { father, mother } = tree.parentsOf(id);
    return 1 + Math.max(father ? depth(father.id, seen) : 0, mother ? depth(mother.id, seen) : 0);
  };
  let generations = 0;
  for (const p of people) generations = Math.max(generations, depth(p.id, new Set()));
  return { people: people.length, families: tree.allFamilies().length, generations, unsourced };
}

/** Kuerzester Pfad zwischen zwei Personen ueber Familien. */
export function pathBetween(tree, aId, bId) {
  const queue = [[aId]];
  const seen = new Set([aId]);
  while (queue.length) {
    const path = queue.shift();
    const last = path[path.length - 1];
    if (last === bId) return path.map((id) => tree.person(id));
    const neighbours = new Set();
    const { father, mother } = tree.parentsOf(last);
    if (father) neighbours.add(father.id);
    if (mother) neighbours.add(mother.id);
    for (const f of tree.familiesOf(last)) {
      for (const s of f.spouses) if (s !== last) neighbours.add(s);
      for (const c of f.children) neighbours.add(c);
    }
    const childFam = tree.childFamilyOf(last);
    if (childFam) for (const c of childFam.children) if (c !== last) neighbours.add(c);
    for (const n of neighbours) {
      if (seen.has(n)) continue;
      seen.add(n);
      queue.push(path.concat([n]));
    }
  }
  return [];
}

/**
 * Deterministisches Generationen-Layout fuer den Gesamtgraphen: Reihe pro
 * Generation, Ehe-Knoten zwischen den Partnern, Kinder haengen daran.
 */
/**
 * Direkte Linie: Vorfahren und Nachfahren der Person, dazu deren Ehepartner —
 * ohne Geschwister, Cousins und deren Familien.
 */
export function directLine(tree, focusId) {
  const keep = new Set([focusId]);
  const up = [focusId];
  while (up.length) {
    const { father, mother } = tree.parentsOf(up.pop());
    for (const p of [father, mother]) if (p && !keep.has(p.id)) { keep.add(p.id); up.push(p.id); }
  }
  const down = [focusId];
  while (down.length) {
    const id = down.pop();
    for (const f of tree.familiesOf(id)) for (const c of f.children) if (!keep.has(c)) { keep.add(c); down.push(c); }
  }
  // Ehepartner der Linie gehoeren dazu, sonst haengen die Ehe-Rauten in der Luft.
  for (const id of [...keep]) for (const f of tree.familiesOf(id)) for (const s of f.spouses) keep.add(s);
  return keep;
}

export function graphLayout(tree, focusId, opts = {}) {
  const only = opts.only ?? null;
  const allowed = (id) => !only || only.has(id);
  const gapX = opts.gapX ?? 300;
  const gapY = opts.gapY ?? 250;
  const gen = new Map([[focusId, 0]]);
  const queue = [focusId];
  while (queue.length) {
    const id = queue.shift();
    const g = gen.get(id);
    const { father, mother } = tree.parentsOf(id);
    for (const p of [father, mother]) {
      if (p && allowed(p.id) && !gen.has(p.id)) { gen.set(p.id, g - 1); queue.push(p.id); }
    }
    for (const f of tree.familiesOf(id)) {
      for (const s of f.spouses) if (allowed(s) && !gen.has(s)) { gen.set(s, g); queue.push(s); }
      for (const c of f.children) if (allowed(c) && !gen.has(c)) { gen.set(c, g + 1); queue.push(c); }
    }
    const cf = tree.childFamilyOf(id);
    if (cf) for (const c of cf.children) if (allowed(c) && !gen.has(c)) { gen.set(c, g); queue.push(c); }
  }
  const rows = new Map();
  for (const [id, g] of gen) {
    if (!rows.has(g)) rows.set(g, []);
    rows.get(g).push(id);
  }
  const levels = [...rows.keys()].sort((a, b) => a - b);

  // Kinder stehen unter ihren Eltern: pro Generation von oben nach unten
  // platzieren, Wunschposition ist der Mittelwert der Elternpositionen. Ehepaare
  // bleiben als Einheit zusammen. Ohne das kreuzen die Kanten die halbe Flaeche.
  const nodes = new Map();
  const placed = new Map();
  // Grosse Geschwisterreihen werden zu einem Block gefaltet: zwanzig Kinder in
  // einer Zeile sind 6000 px breit und erzeugen einen Kantenfaecher quer ueber
  // das Bild. Als Spaltenblock stehen sie kompakt unter ihrer Familie.
  const BLOCK_MIN = 5;
  const blockX = gapX;
  const blockY = 108;
  const avg = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
  const unitWidth = (u) => u.kind === 'block' ? (u.cols - 1) * blockX : (u.ids.length - 1) * gapX;
  const unitsByLevel = new Map();
  // Wunschposition aus den Eltern (Vorfahrenrichtung) …
  const wantFromParents = (u) => {
    const xs = [];
    for (const id of u.ids) {
      const cf = tree.childFamilyOf(id);
      if (cf) for (const sp of cf.spouses) { const px = placed.get(sp); if (px != null) xs.push(px); }
    }
    return xs.length ? avg(xs) : null;
  };
  // … und aus den Kindern. Angeheiratete Eltern haengen nur hieran.
  const wantFromChildren = (u) => {
    const xs = [];
    for (const id of u.ids) for (const f of tree.familiesOf(id)) for (const c of f.children) {
      const n = nodes.get(c); if (n) xs.push(n.x);
    }
    return xs.length ? avg(xs) : null;
  };
  const writeUnit = (u, cx, rowY, level) => {
    const half = unitWidth(u) / 2;
    u.cx = cx; u.half = half;
    if (u.kind === 'block') {
      const perCol = Math.ceil(u.ids.length / u.cols);
      u.ids.forEach((id, i) => {
        const col = Math.floor(i / perCol), row = i % perCol;
        const x = cx - half + col * blockX;
        nodes.set(id, {
          id, person: tree.person(id), x, y: rowY + row * blockY, generation: level,
          sib: { fam: u.fam, col, row, last: row === perCol - 1 || i === u.ids.length - 1 }
        });
        placed.set(id, x);
      });
      return perCol - 1;
    }
    u.ids.forEach((id, i) => {
      const x = cx - half + i * gapX;
      nodes.set(id, { id, person: tree.person(id), x, y: rowY, generation: level });
      placed.set(id, x);
    });
    return 0;
  };
  // Nachruecken nach Prioritaet: wer am weitesten von seiner Wunschposition
  // entfernt ist, darf zuerst in den freien Raum zwischen seinen Nachbarn.
  const relax = (units, want, rowY, level) => {
    const gapOf = (a, b) => Math.max(a.kind === 'block' ? blockX : gapX, b.kind === 'block' ? blockX : gapX);
    const order = units.map((u, i) => i).sort((a, b) =>
      Math.abs(want.get(units[b]) - units[b].cx) - Math.abs(want.get(units[a]) - units[a].cx));
    for (const i of order) {
      const u = units[i], prev = units[i - 1], next = units[i + 1];
      const lo = prev ? prev.cx + prev.half + gapOf(prev, u) + u.half : -Infinity;
      const hi = next ? next.cx - next.half - gapOf(u, next) - u.half : Infinity;
      const cx = Math.min(Math.max(want.get(u), lo), hi);
      if (Math.abs(cx - u.cx) > 0.5) writeUnit(u, cx, rowY, level);
    }
  };
  const packInto = (units, want, rowY, level) => {
    units.sort((a, b) => want.get(a) - want.get(b));
    const halfs = units.map((u) => unitWidth(u) / 2);
    const seps = units.map((u) => (u.kind === 'block' ? blockX : gapX));
    const gapAt = (i) => Math.max(seps[i], seps[Math.max(0, i - 1)]);
    // Ein einziger Durchgang von links schiebt Kollisionen immer nur nach rechts;
    // deshalb zweimal packen — von links und von rechts — und mitteln.
    const L = [], R = [];
    let cur = -Infinity;
    units.forEach((u, i) => { const x = Math.max(want.get(u), cur + gapAt(i) + halfs[i]); L[i] = x; cur = x + halfs[i]; });
    cur = Infinity;
    for (let i = units.length - 1; i >= 0; i--) {
      const x = Math.min(want.get(units[i]), cur - gapAt(Math.min(i + 1, units.length - 1)) - halfs[i]);
      R[i] = x; cur = x - halfs[i];
    }
    const xs = units.map((u, i) => (L[i] + R[i]) / 2);
    for (let i = 1; i < units.length; i++) {
      const need = xs[i - 1] + halfs[i - 1] + gapAt(i) + halfs[i];
      if (xs[i] < need) xs[i] = need;
    }
    let extraRows = 0;
    units.forEach((u, ui) => { extraRows = Math.max(extraRows, writeUnit(u, xs[ui], rowY, level)); });
    return extraRows;
  };
  let y = 140;
  levels.forEach((level) => {
    const ids = rows.get(level).slice().sort((a, b) => {
      const pa = tree.person(a) ?? {}, pb = tree.person(b) ?? {};
      return compareNames(pa.surname, pb.surname) || compareSiblings(pa, pb);
    });
    const seen = new Set();
    const singles = [];
    let units = [];
    for (const id of ids) {
      if (seen.has(id)) continue;
      seen.add(id);
      const sps = [];
      for (const f of tree.familiesOf(id)) {
        for (const sp of f.spouses) {
          if (sp !== id && !seen.has(sp) && gen.get(sp) === level) { sps.push(sp); seen.add(sp); }
        }
      }
      // Bei mehreren Ehen steht die gemeinsame Person in der Mitte: sonst faellt
      // die zweite Ehe-Raute auf den ersten Ehepartner und die Kinderkanten der
      // beiden Ehen kreuzen sich (Design Spec, Slide 14/15).
      const unit = sps.length >= 2 ? [sps[0], id, ...sps.slice(1)] : [id, ...sps];
      // Nur kinderlose Einzelpersonen duerfen in einen Block — an allen anderen
      // haengt Struktur, die unter ihnen Platz braucht.
      const hangs = tree.familiesOf(id).some((f) => f.children.length > 0);
      if (unit.length === 1 && !hangs) singles.push(id); else units.push({ ids: unit, kind: 'row' });
    }
    // Geschwister nach ihrer Herkunftsfamilie sammeln.
    const bySib = new Map();
    for (const id of singles) {
      const cf = tree.childFamilyOf(id);
      const key = cf ? cf.id : 'loose:' + id;
      if (!bySib.has(key)) bySib.set(key, []);
      bySib.get(key).push(id);
    }
    for (const [key, group] of bySib) {
      if (group.length >= BLOCK_MIN) {
        const cols = Math.max(2, Math.min(4, Math.ceil(group.length / 5)));
        units.push({ ids: group, kind: 'block', cols, rows: Math.ceil(group.length / cols), fam: key });
      } else {
        for (const id of group) units.push({ ids: [id], kind: 'row' });
      }
    }
    const want = new Map();
    for (const u of units) want.set(u, wantFromParents(u));
    const rooted = units.filter((u) => want.get(u) != null);
    const loose = units.filter((u) => want.get(u) == null);
    const mid = rooted.length ? rooted.reduce((a, u) => a + want.get(u), 0) / rooted.length : 0;
    loose.forEach((u, i) => want.set(u, mid + (i - (loose.length - 1) / 2) * gapX));
    const extraRows = packInto(units, want, y, level);
    unitsByLevel.set(level, { units, y: y });
    y += gapY + extraRows * blockY;
  });

  // Zwei Ausgleichsdurchgaenge nach Barycenter-Art: beim ersten Lauf von oben
  // kennen angeheiratete Eltern noch keine Position — sie haengen nicht an
  // Vorfahren, sondern an ihrem Kind. Von unten nach oben und zurueck ruecken
  // sie ueber ihre Nachkommen statt in einen fremden Familienstrang.
  for (let pass = 0; pass < 4; pass++) {
    const order = pass === 0 ? [...levels].reverse() : levels;
    for (const level of order) {
      const info = unitsByLevel.get(level);
      const w = new Map();
      for (const u of info.units) {
        const par = wantFromParents(u), kid = wantFromChildren(u);
        const here = avg(u.ids.map((id) => nodes.get(id).x));
        const v = pass === 0
          ? (kid != null ? (par != null ? kid * 0.7 + par * 0.3 : kid) : par)
          : (par != null ? (kid != null ? par * 0.55 + kid * 0.45 : par) : kid);
        w.set(u, v ?? here);
      }
      packInto(info.units, w, info.y, level);
      relax(info.units, w, info.y, level);
    }
  }
  const xsAll = [...nodes.values()].map((n) => n.x);
  const shift = 260 - Math.min(...xsAll);
  for (const n of nodes.values()) n.x += shift;
  const width = Math.max(...xsAll) + shift + 260;

  // Flache Kinderkanten vermeiden: stehen die Kinder eines Paares weit seitlich,
  // bekommt alles darunter mehr vertikalen Abstand, statt die Kante flach ueber
  // die halbe Generation zu ziehen.
  const extraByLevel = new Map();
  for (const f of tree.allFamilies()) {
    const pts = f.spouses.map((s) => nodes.get(s)).filter(Boolean);
    const kids = f.children.map((c) => nodes.get(c)).filter(Boolean);
    if (!pts.length || !kids.length) continue;
    const mx = pts.reduce((s, p) => s + p.x, 0) / pts.length;
    const my = pts.reduce((s, p) => s + p.y, 0) / pts.length + gapY / 2;
    const level = Math.min(...pts.map((p) => p.generation));
    for (const k of kids) {
      const need = (Math.abs(k.x - mx) * 0.5 - (k.y - my)) * 0.75;
      if (need > 0) extraByLevel.set(level, Math.min(330, Math.max(extraByLevel.get(level) ?? 0, need)));
    }
  }
  if (extraByLevel.size) {
    const offset = new Map();
    let cum = 0;
    for (const level of levels) {
      offset.set(level, cum);
      cum += extraByLevel.get(level) ?? 0;
    }
    for (const n of nodes.values()) n.y += offset.get(n.generation) ?? 0;
  }

  const marriages = tree.allFamilies().map((f) => {
    const pts = f.spouses.map((s) => nodes.get(s)).filter(Boolean);
    if (!pts.length) return null;
    const x = pts.reduce((a, p) => a + p.x, 0) / pts.length;
    const y = pts.reduce((a, p) => a + p.y, 0) / pts.length + gapY / 2;
    return {
      family: f, x, y,
      spouses: pts,
      children: f.children.map((c) => nodes.get(c)).filter(Boolean)
    };
  }).filter(Boolean);
  const maxY = Math.max(...[...nodes.values()].map((n) => n.y), 200);
  return { nodes, marriages, width, height: maxY + 160 };
}

/** Deterministischer Pseudo-Versatz aus der ID, damit Layouts reproduzierbar bleiben. */
function jitter(id) {
  let hash = 2166136261;
  for (let i = 0; i < id.length; i++) { hash ^= id.charCodeAt(i); hash = Math.imul(hash, 16777619); }
  const a = ((hash >>> 8) & 255) / 255, b = ((hash >>> 16) & 255) / 255;
  return { dx: a * 2 - 1, dy: b * 2 - 1 };
}

export { parseDate };


/**
 * Namen fuer Graphknoten kuerzen. Alle Karten sind gleich breit, also muss der
 * Name in ein festes Budget passen. Wichtig ist der seltene Ruf- oder Vorname —
 * haeufige Vornamen (in dieser Familie: Johann) werden zum Initial. Ein seltener
 * Nachname (eingeheiratet) bleibt stehen, ein haeufiger weicht als Erstes.
 */
export function nameShortener(tree, budget = 20) {
  const givenFreq = new Map();
  const surFreq = new Map();
  const people = tree.allPeople();
  for (const p of people) {
    for (const g of String(p.given ?? '').split(/\s+/).filter(Boolean)) {
      givenFreq.set(g, (givenFreq.get(g) ?? 0) + 1);
    }
    const s = String(p.surname ?? '').trim();
    if (s) surFreq.set(s, (surFreq.get(s) ?? 0) + 1);
  }
  const many = Math.max(3, Math.round(people.length * 0.06));
  const commonGiven = (n) => (givenFreq.get(n) ?? 0) >= many;
  const commonSur = (n) => (surFreq.get(n) ?? 0) >= many;

  return function shorten(person) {
    if (!person) return '—';
    const given = String(person.given ?? '').split(/\s+/).filter(Boolean);
    const sur = String(person.surname ?? '').trim();
    if (!given.length && !sur) return '—';
    // Der Kernname: der erste seltene Vorname, sonst der letzte.
    let keep = given.findIndex((g) => !commonGiven(g));
    if (keep < 0) keep = given.length - 1;
    const short = (g) => g.slice(0, 1) + '.';
    const join = (ps, s) => [...ps, s].filter(Boolean).join(' ');
    // Erst der volle Name — gekuerzt wird nur, wenn der Platz nicht reicht.
    let parts = [...given];
    let out = join(parts, sur);
    if (out.length > budget) {
      parts = given.map((g, i) => (i === keep || !commonGiven(g) ? g : short(g)));
      out = join(parts, sur);
    }
    if (out.length > budget && sur && commonSur(sur)) out = join(parts, short(sur));
    if (out.length > budget) { parts = given.map((g, i) => (i === keep ? g : short(g))); out = join(parts, commonSur(sur) ? short(sur) : sur); }
    // Abkuerzen geht vor Weglassen: "A. M. Wilcke" behaelt beide Vornamen,
    // "Magdalena Wilcke" wirft einen weg.
    if (out.length > budget) out = join(given.map(short), commonSur(sur) ? short(sur) : sur);
    if (out.length > budget) out = join([parts[keep]], commonSur(sur) ? short(sur) : sur);
    // Nie abschneiden: notfalls beide Teile auf Initialen kuerzen (CLAUDE.md).
    if (out.length > budget) out = join([short(parts[keep] ?? '')], sur);
    if (out.length > budget) out = join([short(parts[keep] ?? '')], short(sur));
    return out;
  };
}

/** Alle Nachkommen — Zyklusschutz beim Verknuepfen von Eltern. */
export function descendantIds(tree, id, seen = new Set()) {
  for (const fam of tree.familiesOf(id)) {
    for (const cid of fam.children) {
      if (seen.has(cid)) continue;
      seen.add(cid);
      descendantIds(tree, cid, seen);
    }
  }
  return seen;
}
