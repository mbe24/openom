// OPE-201 stage 1: the claim engine driven through the ClaimFamilyTree READ adapter. Asserts a small
// claim set via the low-level shim, feeds the resulting op batches into a ClaimFamilyTree, and checks
// the projection maps back to the v2 view shapes the UI reads (person.given/.surname/.sex/.birth,
// family.spouses/.children/.facts, the citation → sources mapping). Needs the built tree wasm
// (node scripts/build-tree.mjs); skips cleanly when absent so a fresh checkout stays green.
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createClaimTree } from '../app/src/core/tree/index.js';
import { ClaimFamilyTree, V } from '../app/src/core/claimFamilyTree.js';

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
  const eng = await createClaimTree({ initInput, createdBy: 'did:key:zAuthor' });
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

  return out;
}

describe.skipIf(!built)('ClaimFamilyTree read adapter (projection → v2 views)', () => {
  // Prime the wasm init with the .wasm bytes before any ClaimFamilyTree is constructed (in node there
  // is no fetch to load it lazily; the module-level init caches the first call's input).
  beforeAll(async () => { await createClaimTree({ initInput }); });

  async function loaded() {
    const batches = await fixtureBatches();
    const cft = new ClaimFamilyTree(fakeStore(), 'tree-1', null, 'did:key:zLocal');
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
    const restored = new ClaimFamilyTree(store, 'tree-2', null, 'did:key:zLocal');
    await restored.hydrate();
    expect(strip(restored.toJSON())).toEqual(before);
  });
});
