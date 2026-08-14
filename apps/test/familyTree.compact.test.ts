import { describe, it, expect } from 'vitest';
import { FamilyTree } from '../app/src/core/familyTree.js';
import { MemoryStore } from '../app/src/core/store.js';

// compact() writes a snapshot and records how many log entries it covers. The
// hazard: if the snapshot body is built from only this replica's in-memory state
// while claiming coverage of the store's whole log, a concurrent replica's
// interleaved entries are marked "covered" but never enter the snapshot — and the
// next load skips them. fold-before-cover applies the unfolded tail first.
describe('FamilyTree.compact — fold-before-cover', () => {
  it("folds a concurrent replica's ops into the snapshot before covering them", async () => {
    const store = new MemoryStore();
    const doc = 'tree-x';

    // Two replicas (think: two browser tabs) sharing one store. Neither observes
    // the other's writes live.
    const a = new FamilyTree(store, doc);
    const b = new FamilyTree(store, doc);
    await a.hydrate();
    await b.hydrate();

    const bea = await b.createPerson({ given: 'Bea' }); // store entry 1 (unseen by a)
    const ada = await a.createPerson({ given: 'Ada' }); // store entry 2

    // a compacts. Pre-fix it would cover entry 1 without its content in the body.
    await a.compact();

    // A fresh replica loads only the snapshot (+ any tail). It must see BOTH.
    const c = new FamilyTree(store, doc);
    await c.hydrate();

    expect(c.person(bea.id)?.given).toBe('Bea');
    expect(c.person(ada.id)?.given).toBe('Ada');
    expect(c.allPeople().length).toBe(2);
  });

  it('single-replica compaction round-trips through a snapshot', async () => {
    const store = new MemoryStore();
    const doc = 'tree-s';

    const a = new FamilyTree(store, doc);
    await a.hydrate();
    const solo = await a.createPerson({ given: 'Solo' });
    await a.compact();

    const b = new FamilyTree(store, doc);
    await b.hydrate();

    expect(b.person(solo.id)?.given).toBe('Solo');
    expect(b.allPeople().length).toBe(1);
  });
});
