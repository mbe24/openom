// App-level acceptance for the claim engine:
//   1. two FamilyTree replicas exchanging deltas (onDelta → mergeRemote) converge to an identical
//      read model under shuffled interleavings (the set-union CRDT's order-independence);
//   2. per-surface round-trips (create/update/addChild/addMarriage/attachMedia/delete/undo/redo).
// Needs the built claim-engine wasm (node scripts/build-tree.mjs); skips cleanly when it's absent.
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTree } from '../app/src/core/tree/index.js';
import { FamilyTree } from '../app/src/core/familyTree.js';

const treeWasm = new URL('../app/src/vendor/tree/openom_tree_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(treeWasm));
const treeInit = built ? { module_or_path: fs.readFileSync(fileURLToPath(treeWasm)) } : undefined;

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

// Drop the wall-clock createdAt/updatedAt the family view stamps (not part of the read-model contract).
const strip = (m) => ({ ...m, families: m.families.map(({ createdAt, updatedAt, ...f }) => f) });

const rotate = (a, k) => a.slice(k).concat(a.slice(0, k));
const interleave = (a) => {
  const half = Math.ceil(a.length / 2);
  const out = [];
  for (let i = 0; i < half; i++) { out.push(a[i]); if (a[i + half]) out.push(a[i + half]); }
  return out;
};

describe.skipIf(!built)('claim engine — convergence + round-trips', () => {
  beforeAll(async () => {
    await createTree({ initInput: treeInit });
  });

  async function authored(build) {
    const batches = [];
    const a = new FamilyTree(fakeStore(), 'a', null, 'did:key:zA');
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
      const b = new FamilyTree(fakeStore(), 'b', null, 'did:key:zB');
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
    const b = new FamilyTree(fakeStore(), 'b2', null, 'did:key:zB');
    const off = b.onDelta((d) => bBatches.push(d));
    await b.createPerson({ given: 'Grace', sex: 'F' });
    off();
    for (const d of [...bBatches].reverse()) await a.mergeRemote(d);
    for (const d of interleave(ba)) await b.mergeRemote(d);
    expect(a.allPeople().length).toBe(3);
    expect(strip(a.toJSON())).toEqual(strip(b.toJSON()));
  });

  it('per-surface round-trips: create/update/addMarriage/addChild/attachMedia/delete/undo/redo', async () => {
    const cft = new FamilyTree(fakeStore(), 'rt', null, 'did:key:zLocal');
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
