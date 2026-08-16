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
