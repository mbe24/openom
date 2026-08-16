// The treelog-backed FamilyTree facade, driven over a MemoryStore exactly as the app drives it: seed
// the Bach fixture, read the v2 model the views consume, make an edit, and rehydrate from the same
// store. Verifies the facade reproduces FamilyTree's public surface. Needs the built wasm; skips if
// absent.
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTree } from '../app/src/core/treelog/index.js';
import { FamilyTree } from '../app/src/core/familyTree.js';
import { MemoryStore } from '../app/src/core/store.js';
import { seedOps } from '../app/src/core/seed.js';

const wasmUrl = new URL('../app/src/vendor/treelog/openom_treelog_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;

// Prime the wasm init once (in the browser createTree fetches the .wasm itself; in node we feed bytes).
beforeAll(async () => { if (built) await createTree({ initInput }); });

describe.skipIf(!built)('FamilyTree (treelog-backed)', () => {
  it('seeds, reads the v2 model, edits in place, and rehydrates', async () => {
    const store = new MemoryStore();
    const tree = new FamilyTree(store, 'tree-test');
    await tree.hydrate();
    await tree.seed(seedOps());

    // counts + a representative person read through the v2 getters
    expect(tree.allPeople().length).toBe(59);
    expect(tree.allFamilies().length).toBe(14);
    const jsb = tree.allPeople().find((p) => p.given === 'Johann Sebastian' && p.surname === 'Bach');
    expect(jsb).toBeTruthy();
    expect(jsb.birth).toBe('21.03.1685');
    expect(jsb.death).toBe('28.07.1750');
    expect(jsb.birthPlace).toBe('Eisenach');
    expect(jsb.sex).toBe('M');
    expect(jsb.custom.occupation).toBe('Thomaskantor in Leipzig');
    expect(jsb.sources?.length).toBe(4);

    // relationships
    expect(tree.familiesOf(jsb.id).length).toBeGreaterThan(0);
    expect(tree.childrenOf(jsb.id).length).toBeGreaterThan(0);
    const { father } = tree.parentsOf(jsb.id);
    expect(father?.surname).toBe('Bach');

    // family facts
    const marriage = tree.familiesOf(jsb.id).find((f) => f.facts.marriage);
    expect(marriage).toBeTruthy();

    // an in-place edit updates the read model and does not create a duplicate person
    await tree.updatePerson(jsb.id, { given: 'J. S.' });
    expect(tree.person(jsb.id).given).toBe('J. S.');
    expect(tree.allPeople().length).toBe(59);

    // rehydrate from the same store: the engine rebuilds from the persisted deltas
    const reopened = new FamilyTree(store, 'tree-test');
    await reopened.hydrate();
    expect(reopened.allPeople().length).toBe(59);
    expect(reopened.allFamilies().length).toBe(14);
    expect(reopened.person(jsb.id).given).toBe('J. S.');
    expect(reopened.person(jsb.id).custom.occupation).toBe('Thomaskantor in Leipzig');
  });

  it('creates, links, and deletes with the same API the views call', async () => {
    const store = new MemoryStore();
    const tree = new FamilyTree(store, 'tree-crud');
    await tree.hydrate();
    const a = await tree.createPerson({ given: 'Ada', surname: 'Lovelace', sex: 'F', birth: '1815' });
    expect(a.given).toBe('Ada');
    expect(a.birth).toBe('1815');
    const fam = await tree.addMarriage(a.id, { given: 'Charles', surname: 'Babbage', sex: 'M' });
    expect(tree.family(fam.id).spouses.length).toBe(2);
    const kid = await tree.addChild(fam.id, { given: 'Byron', surname: 'Lovelace' });
    expect(tree.childrenOf(a.id).map((p) => p.given)).toContain('Byron');
    await tree.deletePerson(kid.id);
    expect(tree.person(kid.id)).toBeUndefined();
    expect(tree.childrenOf(a.id).length).toBe(0);
  });

  it('clears a field that was set in a previous session (retract reconciles all live claims)', async () => {
    const store = new MemoryStore();
    const a = new FamilyTree(store, 'doc');
    await a.hydrate();
    const p = await a.createPerson({ given: 'Ada', birth: '1815' });

    // A fresh instance = a new session/tab (fresh replica id where storage is absent).
    const b = new FamilyTree(store, 'doc');
    await b.hydrate();
    expect(b.person(p.id).birth).toBe('1815');
    await b.updatePerson(p.id, { birth: '' }); // clear a prior-session field
    expect(b.person(p.id).birth).toBe('');

    // Stays cleared after another reload (the retract really landed, not a view artifact).
    const c = new FamilyTree(store, 'doc');
    await c.hydrate();
    expect(c.person(p.id).birth).toBe('');
    // And a re-set from the new session takes effect without piling up a stale competing claim.
    await c.updatePerson(p.id, { birth: '1820' });
    expect(c.person(p.id).birth).toBe('1820');
  });

  it('addParents assigns father=M and mother=F (sex not clobbered by the default)', async () => {
    const store = new MemoryStore();
    const tree = new FamilyTree(store, 'doc');
    await tree.hydrate();
    const kid = await tree.createPerson({ given: 'Kid' });
    await tree.addParents(kid.id, { given: 'Dad' }, { given: 'Mom' });
    const { father, mother } = tree.parentsOf(kid.id);
    expect(father?.given).toBe('Dad');
    expect(father?.sex).toBe('M');
    expect(mother?.given).toBe('Mom');
    expect(mother?.sex).toBe('F');
  });

  it('stores custom booleans as explicit values and reads them back typed', async () => {
    const schema = { field: (id) => ({ id, type: id === 'emigrated' ? 'boolean' : 'text' }) };
    const store = new MemoryStore();
    const tree = new FamilyTree(store, 'doc', schema);
    await tree.hydrate();
    const p = await tree.createPerson({ given: 'Ada', custom: { emigrated: true, occupation: 'Analyst' } });
    expect(tree.person(p.id).custom.emigrated).toBe(true); // a real boolean, not the string 'true'
    expect(tree.person(p.id).custom.occupation).toBe('Analyst');

    // Unchecking stores an explicit false (a last-writer-wins write, not a retract) and reads false.
    await tree.updatePerson(p.id, { custom: { emigrated: false } });
    expect(tree.person(p.id).custom.emigrated).toBe(false);
    const reopened = new FamilyTree(store, 'doc', schema);
    await reopened.hydrate();
    expect(reopened.person(p.id).custom.emigrated).toBe(false);
    expect(reopened.person(p.id).custom.occupation).toBe('Analyst');
  });

  it('an undo on one replica does not corrupt another replica sharing the store (convergence)', async () => {
    // Two FamilyTree instances over ONE store = two tabs of the same doc (two replicas), which is real
    // today via shared IndexedDB. This is the case that would silently corrupt convergence once B1
    // delta-sync connects: an undo that rewinds the Lamport clock or truncates the shared log destroys a
    // concurrent replica's work. With forward inverse-op undo it must converge.
    const store = new MemoryStore();
    const A = new FamilyTree(store, 'doc');
    await A.hydrate();
    const p = await A.createPerson({ given: 'Ada' });
    await A.updatePerson(p.id, { given: 'Bea' }); // A: a settled, undoable rename

    const B = new FamilyTree(store, 'doc'); // second tab
    await B.hydrate();
    expect(B.person(p.id).given).toBe('Bea');
    await B.updatePerson(p.id, { note: 'hi' }); // B's concurrent edit to a different field

    await A.undo(); // A reverts its rename
    expect(A.person(p.id).given).toBe('Ada');
    await A.updatePerson(p.id, { given: 'Cleo' }); // A re-edits after the undo

    // A fresh reader merges the entire shared log; both edits must survive and converge.
    const C = new FamilyTree(store, 'doc');
    await C.hydrate();
    const person = C.person(p.id);
    expect(person).toBeTruthy();
    expect(person.note).toBe('hi'); // B's concurrent edit survived A's undo (no log truncation)
    expect(person.given).toBe('Cleo'); // A's post-undo re-edit propagated (no clock rewind / stamp reuse)
  });

  it('undoes and redoes settled edits along a timeline', async () => {
    const store = new MemoryStore();
    const tree = new FamilyTree(store, 'tree-undo');
    await tree.hydrate();
    expect(tree.canUndo).toBe(false);

    const a = await tree.createPerson({ given: 'Ada', surname: 'Lovelace' });
    expect(tree.canUndo).toBe(true);
    await tree.updatePerson(a.id, { surname: 'Byron' });
    expect(tree.person(a.id).surname).toBe('Byron');

    await tree.undo(); // revert the surname edit
    expect(tree.person(a.id).surname).toBe('Lovelace');
    await tree.redo(); // reapply it
    expect(tree.person(a.id).surname).toBe('Byron');

    await tree.undo(); // back to just-created
    await tree.undo(); // back before the create → person gone
    expect(tree.person(a.id)).toBeUndefined();
    expect(tree.canUndo).toBe(false);
    expect(tree.canRedo).toBe(true);
    await tree.redo(); // the person returns
    expect(tree.person(a.id)?.given).toBe('Ada');
  });
});
