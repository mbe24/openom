// OPE-198 — app-level acceptance for the claim engine:
//   1. two ClaimFamilyTree replicas exchanging deltas (onDelta → mergeRemote) converge to an identical
//      read model under shuffled interleavings (the set-union CRDT's order-independence);
//   2. shadow-parity — seeded from the same v2 ops, the claim engine reproduces the legacy treelog
//      engine's read model (person fields + family structure), modulo id representation;
//   3. per-surface round-trips (create/update/addChild/addMarriage/attachMedia/delete/undo/redo).
// Needs both built wasms (node scripts/build-tree.mjs, node scripts/build-treelog.mjs); skips cleanly
// when either is absent.
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createClaimTree } from '../app/src/core/tree/index.js';
import { createTree } from '../app/src/core/treelog/index.js';
import { ClaimFamilyTree } from '../app/src/core/claimFamilyTree.js';
import { FamilyTree } from '../app/src/core/familyTree.js';
import { seedOps } from '../app/src/core/seed.js';
import { khaldunOps } from '../app/src/core/seedKhaldun.js';

const treeWasm = new URL('../app/src/vendor/tree/openom_tree_bg.wasm', import.meta.url);
const treelogWasm = new URL('../app/src/vendor/treelog/openom_treelog_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(treeWasm)) && fs.existsSync(fileURLToPath(treelogWasm));
const treeInit = built ? { module_or_path: fs.readFileSync(fileURLToPath(treeWasm)) } : undefined;
const treelogInit = built ? { module_or_path: fs.readFileSync(fileURLToPath(treelogWasm)) } : undefined;

function fakeStore() {
  const logs = new Map();
  const snaps = new Map();
  return {
    async list() { return [...logs.keys()]; },
    async readSnapshot(doc) { return snaps.get(doc) ?? null; },
    async readUpdates(doc, from = 0) { const l = logs.get(doc) ?? []; return { updates: l.slice(from), cursor: l.length }; },
    async append(doc, deltas) { const l = logs.get(doc) ?? []; l.push(...deltas); logs.set(doc, l); },
    async putSnapshot(doc, bytes) { snaps.set(doc, { bytes, version: 1 }); },
    async delete(doc) { logs.delete(doc); snaps.delete(doc); },
  };
}

// A treelog seed id is `hex(utf8(symbolic))`; recover the symbolic id so the two engines' entities line
// up (the claim engine uses the symbolic id directly as the anchor id).
const symOf = (hexId) => new TextDecoder().decode(Uint8Array.from(hexId.match(/../g).map((h) => parseInt(h, 16))));

// Drop the wall-clock createdAt/updatedAt the family view stamps (not part of the read-model contract).
const strip = (m) => ({ ...m, families: m.families.map(({ createdAt, updatedAt, ...f }) => f) });

const rotate = (a, k) => a.slice(k).concat(a.slice(0, k));
const interleave = (a) => {
  const half = Math.ceil(a.length / 2);
  const out = [];
  for (let i = 0; i < half; i++) { out.push(a[i]); if (a[i + half]) out.push(a[i + half]); }
  return out;
};

describe.skipIf(!built)('claim engine — convergence + treelog shadow-parity (OPE-198)', () => {
  beforeAll(async () => {
    await createClaimTree({ initInput: treeInit });
    await createTree({ initInput: treelogInit });
  });

  async function authored(build) {
    const batches = [];
    const a = new ClaimFamilyTree(fakeStore(), 'a', null, 'did:key:zA');
    const off = a.onDelta((d) => batches.push(d));
    await build(a);
    off();
    return { a, batches };
  }

  it('two replicas converge to an identical read model under shuffled interleavings', async () => {
    const { a, batches } = await authored(async (t) => {
      const dad = await t.createPerson({ given: 'John', sex: 'M', birth: '1900' });
      const fam = await t.addMarriage(dad.id, { given: 'Jane', sex: 'F' }, { marriage: '1925' });
      const kid = await t.addChild(fam.id, { given: 'Kid', sex: 'M' });
      await t.updatePerson(kid.id, { birth: '1926', birthPlace: 'Leipzig' });
      const gone = await t.createPerson({ given: 'Ghost' });
      await t.deletePerson(gone.id);
    });
    const orders = [batches, [...batches].reverse(), rotate(batches, 3), interleave(batches)];
    for (const order of orders) {
      const b = new ClaimFamilyTree(fakeStore(), 'b', null, 'did:key:zB');
      for (const d of order) await b.mergeRemote(d);
      expect(strip(b.toJSON())).toEqual(strip(a.toJSON()));
    }
  });

  it('two authors editing disjoint people converge after a shuffled exchange', async () => {
    const { a, batches: ba } = await authored(async (t) => {
      await t.createPerson({ given: 'Ada', sex: 'F' });
      await t.createPerson({ given: 'Alan', sex: 'M' });
    });
    const bBatches = [];
    const b = new ClaimFamilyTree(fakeStore(), 'b2', null, 'did:key:zB');
    const off = b.onDelta((d) => bBatches.push(d));
    await b.createPerson({ given: 'Grace', sex: 'F' });
    off();
    for (const d of [...bBatches].reverse()) await a.mergeRemote(d);
    for (const d of interleave(ba)) await b.mergeRemote(d);
    expect(a.allPeople().length).toBe(3);
    expect(strip(a.toJSON())).toEqual(strip(b.toJSON()));
  });

  it.each([
    ['Bach', seedOps],
    ['Khaldun', khaldunOps],
  ])('shadow-parity: the claim engine reproduces the treelog view on the %s seed', async (_name, ops) => {
    const tl = new FamilyTree(fakeStore(), 'tl', null);
    await tl.seed(ops());
    const cl = new ClaimFamilyTree(fakeStore(), 'cl', null, 'did:key:zLocal');
    await cl.seed(ops());

    const normPeople = (tree, mapId) =>
      tree.allPeople().map((p) => ({
        id: mapId(p.id), given: p.given, surname: p.surname, sex: p.sex,
        birth: p.birth, death: p.death, birthPlace: p.birthPlace, deathPlace: p.deathPlace,
      })).sort((x, y) => x.id.localeCompare(y.id));
    const normFamilies = (tree, mapId) =>
      tree.allFamilies().map((f) => ({
        spouses: f.spouses.map(mapId).sort(),
        children: f.children.map(mapId).sort(),
        marriage: f.facts?.marriage ?? '',
        place: f.facts?.place ?? '',
      })).sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));

    expect(cl.allPeople().length).toBe(tl.allPeople().length);
    expect(normPeople(cl, (x) => x)).toEqual(normPeople(tl, symOf));
    expect(normFamilies(cl, (x) => x)).toEqual(normFamilies(tl, symOf));
  });

  it('per-surface round-trips: create/update/addMarriage/addChild/attachMedia/delete/undo/redo', async () => {
    const cft = new ClaimFamilyTree(fakeStore(), 'rt', null, 'did:key:zLocal');
    const a = await cft.createPerson({ given: 'Ada', surname: 'Lovelace', sex: 'F', birth: '1815' });
    expect(cft.person(a.id).birth).toBe('1815');

    await cft.updatePerson(a.id, { death: '1852', note: 'mathematician' });
    expect(cft.person(a.id).death).toBe('1852');
    expect(cft.person(a.id).note).toBe('mathematician');

    const fam = await cft.addMarriage(a.id, { given: 'William', sex: 'M' }, { marriage: '1835' });
    expect(cft.family(fam.id).facts.marriage).toBe('1835');
    const kid = await cft.addChild(fam.id, { given: 'Byron', sex: 'M' });
    expect(cft.childrenOf(a.id).map((p) => p.id)).toContain(kid.id);

    const { linkId } = await cft.attachMedia(a.id, { hash: 'sha256:portrait', mime: 'image/png', role: 'portrait' });
    expect(cft.portraitOf(a.id)?.media?.hash).toBe('sha256:portrait');

    await cft.detachMedia(linkId);
    expect(cft.portraitOf(a.id)).toBeNull();

    await cft.deletePerson(kid.id);
    expect(cft.person(kid.id)).toBeUndefined();
    await cft.undo();
    expect(cft.person(kid.id)?.given).toBe('Byron');
    await cft.redo();
    expect(cft.person(kid.id)).toBeUndefined();
  });
});
