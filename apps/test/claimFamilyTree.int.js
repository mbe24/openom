// OPE-201 stage 1: the claim engine driven through the FamilyTree READ adapter. Asserts a small
// claim set via the low-level shim, feeds the resulting op batches into a FamilyTree, and checks
// the projection maps back to the v2 view shapes the UI reads (person.given/.surname/.sex/.birth,
// family.spouses/.children/.facts, the citation → sources mapping). Needs the built tree wasm
// (node scripts/build-tree.mjs); skips cleanly when absent so a fresh checkout stays green.
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTree } from '../app/src/core/tree/index.js';
import { FamilyTree, seedAppId, V } from '../app/src/core/familyTree.js';
import { tabSync } from '../app/src/core/tabSync.js';

const wasmUrl = new URL('../app/src/vendor/tree/openom_tree_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;

// A minimal in-memory DocStore (append-only log + one snapshot slot) — enough to drive hydrate/merge.
function fakeStore() {
  const logs = new Map();
  const snaps = new Map();
  return {
    async list() { return [...logs.keys()]; },
    async readSnapshot(doc) { return snaps.get(doc) ?? null; },
    async readUpdates(doc, from = 0) { const l = logs.get(doc) ?? []; return { updates: l.slice(from), cursor: l.length }; },
    async append(doc, deltas) { const l = logs.get(doc) ?? []; l.push(...deltas); logs.set(doc, l); },
    async putSnapshot(doc, bytes, _v) { snaps.set(doc, { bytes, version: 1 }); },
    async delete(doc) { logs.delete(doc); snaps.delete(doc); },
  };
}

// Build the fixture claim set once, as a flat list of op-batch bytes, via the low-level shim.
async function fixtureBatches() {
  const eng = await createTree({ initInput, createdBy: 'did:key:zAuthor' });
  const out = [];
  let clock = 1_700_000_000_000;
  const at = () => clock++;
  const anchor = (id, type) => out.push(eng.assertAnchor(id, type, at()));
  const claim = (target, pred, value) => out.push(eng.assertClaim(target, pred, value, at()));

  // Ada Lovelace — a person with a name, sex, and a birth event; her name claim carries a citation.
  anchor('per_ada', V.TYPE_PERSON);
  claim('per_ada', V.P_NAME, { parts: { given: 'Ada', family: 'Lovelace' }, convention: 'western', type: 'birth' });
  claim('per_ada', V.P_SEX, { sex: 'F' });
  claim('per_ada', V.P_BIOGRAPHY, { text: 'A mathematician.' });
  anchor('evt_ada_birth', V.TYPE_EVENT);
  claim('evt_ada_birth', V.P_EVENT_TYPE, { type: 'birth' });
  claim('evt_ada_birth', V.P_DATE, { edtf: '1815' });
  claim('evt_ada_birth', V.P_PARTICIPANT, { personId: 'per_ada', role: 'principal' });

  // A partner and a child, so a union (family) with children projects.
  anchor('per_byron', V.TYPE_PERSON);
  claim('per_byron', V.P_NAME, { parts: { given: 'George', family: 'Byron' }, convention: 'western', type: 'birth' });
  claim('per_byron', V.P_SEX, { sex: 'M' });
  claim('per_ada', V.P_PARTNERSHIP, { pair: ['per_ada', 'per_byron'], role: 'spouse' });

  anchor('per_kid', V.TYPE_PERSON);
  claim('per_kid', V.P_NAME, { parts: { given: 'Byron', family: 'King' }, convention: 'western', type: 'birth' });
  claim('per_kid', V.P_PARENT, { parentPersonId: 'per_ada', kind: 'biological' });
  claim('per_kid', V.P_PARENT, { parentPersonId: 'per_byron', kind: 'biological' });

  // The engine now accumulates mints and emits one batch at flush (one settled intention = one entry);
  // the per-call returns above are empty. Take the whole fixture as a single batch to feed via merge.
  return [eng.flush()];
}

describe.skipIf(!built)('FamilyTree read adapter (projection → v2 views)', () => {
  // Prime the wasm init with the .wasm bytes before any FamilyTree is constructed (in node there
  // is no fetch to load it lazily; the module-level init caches the first call's input).
  beforeAll(async () => { await createTree({ initInput }); });

  async function loaded() {
    const batches = await fixtureBatches();
    const cft = new FamilyTree(fakeStore(), 'tree-1', null, 'did:key:zLocal');
    for (const batch of batches) await cft.mergeRemote(batch);
    return cft;
  }

  it('maps a person: name parts, sex, biography→note, and the birth event', async () => {
    const cft = await loaded();
    const ada = cft.person('per_ada');
    expect(ada).toBeTruthy();
    expect(ada.given).toBe('Ada');
    expect(ada.surname).toBe('Lovelace');
    expect(ada.sex).toBe('F');
    expect(ada.note).toBe('A mathematician.');
    expect(ada.birth).toBe('1815');
    expect(ada.names[0].parts.given).toEqual(['Ada']);
  });

  it('maps a union to a family with spouses + children', async () => {
    const cft = await loaded();
    const fams = cft.allFamilies();
    expect(fams.length).toBe(1);
    const fam = fams[0];
    expect(fam.spouses.sort()).toEqual(['per_ada', 'per_byron']);
    expect(fam.children).toEqual(['per_kid']);

    // …and the read helpers over that model resolve relationships.
    expect(cft.childrenOf('per_ada').map((p) => p.id)).toEqual(['per_kid']);
    const { father, mother } = cft.parentsOf('per_kid');
    expect(father.id).toBe('per_byron');
    expect(mother.id).toBe('per_ada');
  });

  it('surfaces a person-owned event only under its principal, not partners', async () => {
    const cft = await loaded();
    // The birth event is Ada's; George (a spouse in the partnership, not a participant) has no events.
    expect(cft.person('per_ada').events.map((e) => e.type)).toEqual(['birth']);
    expect(cft.person('per_byron').events).toEqual([]);
  });

  it('createPerson mints a person the projection surfaces (name/sex/birth)', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-w', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada', surname: 'Lovelace', sex: 'F', birth: '1815' });
    expect(p.given).toBe('Ada');
    expect(p.surname).toBe('Lovelace');
    expect(p.sex).toBe('F');
    expect(p.birth).toBe('1815');
    expect(cft.allPeople().length).toBe(1);
  });

  it('updatePerson supersedes in place — no duplicate claims, other parts preserved', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-w2', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada', surname: 'Lovelace' });
    await cft.updatePerson(p.id, { surname: 'Byron' });
    const u = cft.person(p.id);
    expect(u.surname).toBe('Byron');
    expect(u.given).toBe('Ada');
    expect(u.names.length).toBe(1);
  });

  it('supersedes an event date + sets its place', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-w3', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'A', birth: '1800' });
    await cft.updatePerson(p.id, { birth: '1815', birthPlace: 'London' });
    const u = cft.person(p.id);
    expect(u.birth).toBe('1815');
    expect(u.birthPlace).toBe('London');
    expect(u.events.filter((e) => e.type === 'birth').length).toBe(1);
  });

  it('persists ops to the store and replays them on hydrate', async () => {
    const store = fakeStore();
    const cft = new FamilyTree(store, 'tree-p', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada', sex: 'F' });
    const restored = new FamilyTree(store, 'tree-p', null, 'did:key:zLocal');
    await restored.hydrate();
    expect(restored.person(p.id)?.given).toBe('Ada');
    expect(restored.person(p.id)?.sex).toBe('F');
  });

  it('addMarriage + addChild build a family (union) with spouses, children, marriage facts', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-b1', null, 'did:key:zLocal');
    const a = await cft.createPerson({ given: 'Ada', sex: 'F' });
    const fam = await cft.addMarriage(a.id, { given: 'George', sex: 'M' }, { marriage: '1835' });
    expect(fam.spouses.length).toBe(2);
    expect(fam.spouses).toContain(a.id);
    expect(fam.facts.marriage).toBe('1835');
    const kid = await cft.addChild(fam.id, { given: 'Byron' });
    expect(cft.family(fam.id).children).toContain(kid.id);
    expect(cft.childrenOf(a.id).map((p) => p.id)).toContain(kid.id);
  });

  it('addParents attaches a father and mother to a child', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-b2', null, 'did:key:zLocal');
    const child = await cft.createPerson({ given: 'Kid' });
    const fam = await cft.addParents(child.id, { given: 'Dad' }, { given: 'Mom' });
    expect(fam.spouses.length).toBe(2);
    const { father, mother } = cft.parentsOf(child.id);
    expect(father.given).toBe('Dad');
    expect(mother.given).toBe('Mom');
  });

  it('deletePerson removes the person and drops their dangling relationships', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-b3', null, 'did:key:zLocal');
    const a = await cft.createPerson({ given: 'Ada' });
    const fam = await cft.addMarriage(a.id, { given: 'George' });
    const other = fam.spouses.find((s) => s !== a.id);
    await cft.deletePerson(a.id);
    expect(cft.person(a.id)).toBeUndefined();
    expect(cft.allPeople().map((p) => p.id)).toEqual([other]);
    expect(cft.familiesOf(other).length).toBe(0);
  });

  it('attachMedia sets a portrait the view surfaces', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-b4', null, 'did:key:zLocal');
    const a = await cft.createPerson({ given: 'Ada' });
    const { linkId } = await cft.attachMedia(a.id, { hash: 'sha256:img1', mime: 'image/png', role: 'portrait' });
    expect(linkId).toBeTruthy();
    expect(cft.portraitOf(a.id)?.media?.hash).toBe('sha256:img1');
    expect(cft.mediaOf(a.id).length).toBe(1);
  });

  it('undo/redo a field edit (supersede)', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-u1', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada', surname: 'Lovelace' });
    await cft.updatePerson(p.id, { surname: 'Byron' });
    expect(cft.person(p.id).surname).toBe('Byron');
    expect(cft.canUndo).toBe(true);
    await cft.undo();
    expect(cft.person(p.id).surname).toBe('Lovelace');
    expect(cft.person(p.id).given).toBe('Ada');
    expect(cft.canRedo).toBe(true);
    await cft.redo();
    expect(cft.person(p.id).surname).toBe('Byron');
  });

  it('undo createPerson removes the person; redo restores it', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-u2', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada', sex: 'F' });
    expect(cft.allPeople().length).toBe(1);
    await cft.undo();
    expect(cft.allPeople().length).toBe(0);
    await cft.redo();
    expect(cft.allPeople().length).toBe(1);
    expect(cft.person(p.id)?.given).toBe('Ada');
    expect(cft.person(p.id)?.sex).toBe('F');
  });

  it('undo a delete restores the person', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-u3', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada', sex: 'F' });
    await cft.deletePerson(p.id);
    expect(cft.person(p.id)).toBeUndefined();
    await cft.undo();
    expect(cft.person(p.id)?.given).toBe('Ada');
    expect(cft.person(p.id)?.sex).toBe('F');
  });

  it('settle overlay: silent edits show but do not mint (undo hits the create, not a keystroke)', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-s1', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'A' });
    await cft.updatePerson(p.id, { given: 'Ad' }, { silent: true });
    await cft.updatePerson(p.id, { given: 'Ada' }, { silent: true });
    expect(cft.person(p.id).given).toBe('Ada'); // overlay shows the in-progress value
    await cft.undo();
    expect(cft.person(p.id)).toBeUndefined(); // the burst minted nothing, so undo removes the person
  });

  it('settle mints once and is a single undo step', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-s2', null, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'A' });
    await cft.updatePerson(p.id, { given: 'Ad' }, { silent: true });
    await cft.updatePerson(p.id, { given: 'Ada' }); // settle
    expect(cft.person(p.id).given).toBe('Ada');
    await cft.undo();
    expect(cft.person(p.id).given).toBe('A');
  });

  it('seed() translates v2 upsert ops into a claim-backed tree', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-seed', null, 'did:key:zLocal');
    await cft.seed([
      { type: 'upsertPerson', id: 'p_dad', fields: { given: 'John', sex: 'M', birth: '1900' } },
      { type: 'upsertPerson', id: 'p_mom', fields: { given: 'Jane', sex: 'F' } },
      { type: 'upsertPerson', id: 'p_kid', fields: { given: 'Kid' } },
      { type: 'upsertFamily', id: 'f_1', fields: { spouses: ['p_dad', 'p_mom'], children: ['p_kid'], facts: { marriage: '1925' } } },
    ]);
    expect(cft.allPeople().length).toBe(3);
    expect(cft.person('p_dad').given).toBe('John');
    expect(cft.person('p_dad').birth).toBe('1900');
    const fam = cft.allFamilies()[0];
    expect(fam.spouses.slice().sort()).toEqual(['p_dad', 'p_mom']);
    expect(fam.children).toEqual(['p_kid']);
    expect(fam.facts.marriage).toBe('1925');
    expect(cft.canUndo).toBe(false); // seeding is not undoable
    expect(seedAppId('p_dad')).toBe('p_dad'); // the symbolic id is the anchor id
  });

  it('syncTail merges another writer\'s tail from the shared store (no re-append)', async () => {
    const store = fakeStore();
    const a = new FamilyTree(store, 'shared', null, 'did:key:zA');
    await a.hydrate();
    const b = new FamilyTree(store, 'shared', null, 'did:key:zB');
    await b.hydrate();

    const p = await a.createPerson({ given: 'Ada', sex: 'F' });
    expect(b.person(p.id)).toBeUndefined(); // b hasn't caught up
    expect(await b.syncTail()).toBe(true);
    expect(b.person(p.id)?.given).toBe('Ada');

    // Bidirectional: b writes, a catches up; both converge, and the shared log isn't double-appended.
    const q = await b.createPerson({ given: 'Grace', sex: 'F' });
    await a.syncTail();
    expect(a.person(q.id)?.given).toBe('Grace');
    const strip = (m) => ({ ...m, families: m.families.map(({ createdAt, updatedAt, ...f }) => f) });
    expect(strip(a.toJSON())).toEqual(strip(b.toJSON()));
    expect(await a.syncTail()).toBe(false); // fully caught up — nothing new in the shared tail
  });

  it.skipIf(typeof BroadcastChannel === 'undefined')('tabSync converges the other tab on a ping', async () => {
    const store = fakeStore();
    const a = new FamilyTree(store, 'bc-doc', null, 'did:key:zA');
    await a.hydrate();
    const b = new FamilyTree(store, 'bc-doc', null, 'did:key:zB');
    await b.hydrate();
    const offA = tabSync(a, 'bc-doc');
    const offB = tabSync(b, 'bc-doc');
    try {
      const p = await a.createPerson({ given: 'Ada', sex: 'F' });
      await new Promise((r) => setTimeout(r, 80)); // let the BroadcastChannel ping + syncTail land
      expect(b.person(p.id)?.given).toBe('Ada');
    } finally {
      offA(); offB();
    }
  });

  it('reset clears the tree', async () => {
    const cft = new FamilyTree(fakeStore(), 'tree-r', null, 'did:key:zLocal');
    await cft.createPerson({ given: 'A' });
    expect(cft.allPeople().length).toBe(1);
    await cft.reset();
    expect(cft.allPeople().length).toBe(0);
  });

  it('round-trips through a snapshot with an identical read model', async () => {
    // mergeFamilyFields stamps a wall-clock createdAt/updatedAt on each family (part of the v2 view
    // shape, as in the legacy engine); drop those volatile fields before comparing the two projections.
    const strip = (m) => ({
      ...m,
      families: m.families.map(({ createdAt, updatedAt, ...f }) => f),
    });
    const cft = await loaded();
    const before = strip(cft.toJSON());

    const store = fakeStore();
    await store.putSnapshot('tree-2', cft.snapshotBytes(), null);
    const restored = new FamilyTree(store, 'tree-2', null, 'did:key:zLocal');
    await restored.hydrate();
    expect(strip(restored.toJSON())).toEqual(before);
  });
});

// Coverage the retired treelog suites (familyTreeEngine.int.js) uniquely had, reproduced on the claim
// engine (OPE-240): typed custom booleans, cross-session field clearing, compaction-with-tail hydrate,
// and deterministic resolution of a concurrent same-author edit to one field.
describe.skipIf(!built)('FamilyTree — custom fields, clearing, compaction, concurrent edits', () => {
  beforeAll(async () => { await createTree({ initInput }); });

  // A minimal schema that declares one field's type, so #coerceCustom can read it back typed.
  const boolSchema = { field: (id) => (id === 'living' ? { type: 'boolean' } : undefined) };

  it('stores a custom boolean as an explicit value and reads it back typed (false is a value, not a clear)', async () => {
    const store = fakeStore();
    const cft = new FamilyTree(store, 'tree-cb', boolSchema, 'did:key:zLocal');
    const p = await cft.createPerson({ given: 'Ada' });

    await cft.updatePerson(p.id, { custom: { living: true } });
    expect(cft.person(p.id).custom.living).toBe(true); // typed boolean, not the string 'true'

    // `false` is an explicit stored value — it must NOT be treated as clearing the field.
    await cft.updatePerson(p.id, { custom: { living: false } });
    expect(cft.person(p.id).custom.living).toBe(false);

    // …and it survives a reload with its type intact (needs the same schema on the fresh instance).
    const restored = new FamilyTree(store, 'tree-cb', boolSchema, 'did:key:zLocal');
    await restored.hydrate();
    expect(restored.person(p.id).custom.living).toBe(false);
  });

  it('clears a field set in a PREVIOUS session, and it stays cleared across a further reload', async () => {
    const store = fakeStore();
    const a = new FamilyTree(store, 'tree-clr', null, 'did:key:zLocal');
    const p = await a.createPerson({ given: 'Ada', note: 'a note' });

    // A fresh session reloads, then clears the value that a prior session minted (same author, so the
    // retract legitimately supersedes the earlier-session claim).
    const b = new FamilyTree(store, 'tree-clr', null, 'did:key:zLocal');
    await b.hydrate();
    expect(b.person(p.id).note).toBe('a note');
    await b.updatePerson(p.id, { note: '' });
    expect(b.person(p.id).note).toBe('');

    // The clear is durable: another reload still sees it gone (no resurrection of the prior claim).
    const c = new FamilyTree(store, 'tree-clr', null, 'did:key:zLocal');
    await c.hydrate();
    expect(c.person(p.id).note).toBe('');
  });

  it('hydrate loads a snapshot plus only the tail appended after it (compaction)', async () => {
    const store = fakeStore();
    const a = new FamilyTree(store, 'tree-cmp', null, 'did:key:zLocal');
    const p1 = await a.createPerson({ given: 'Ada' });
    await a.compact();                                   // snapshot covers p1
    const p2 = await a.createPerson({ given: 'Grace' }); // a tail op after the snapshot

    const b = new FamilyTree(store, 'tree-cmp', null, 'did:key:zLocal');
    await b.hydrate();                                   // snapshot (p1) + only the tail (p2)
    expect(b.person(p1.id)?.given).toBe('Ada');
    expect(b.person(p2.id)?.given).toBe('Grace');
    expect(b.allPeople().length).toBe(2);
  });

  it('a concurrent same-author edit to the SAME field converges to one deterministic value on both replicas', async () => {
    // Both replicas start from the same person, then each supersedes `note` differently and concurrently.
    // Same-author supersede forks into two live claims under one (target, predicate); the projection must
    // resolve to ONE value, and both replicas must agree (deterministic, order-independent) — the property
    // that keeps two devices of one user from diverging.
    const seedStore = fakeStore();
    const a = new FamilyTree(seedStore, 'doc', null, 'did:key:zLocal');
    const seed = [];
    let off = a.onDelta((d) => seed.push(d));
    const p = await a.createPerson({ given: 'Ada', note: 'original' });
    off();

    const b = new FamilyTree(fakeStore(), 'doc', null, 'did:key:zLocal');
    for (const d of seed) await b.mergeRemote(d);
    expect(b.person(p.id).note).toBe('original');

    const da = [];
    off = a.onDelta((d) => da.push(d));
    await a.updatePerson(p.id, { note: 'from A' });
    off();
    const db = [];
    off = b.onDelta((d) => db.push(d));
    await b.updatePerson(p.id, { note: 'from B' });
    off();

    for (const d of db) await a.mergeRemote(d);
    for (const d of da) await b.mergeRemote(d);

    // Convergence is the invariant — both replicas show the same resolved note (which of the two wins is
    // the projection's deterministic tiebreak, not asserted here).
    expect(a.person(p.id).note).toBe(b.person(p.id).note);
    expect(['from A', 'from B']).toContain(a.person(p.id).note);
  });
});
