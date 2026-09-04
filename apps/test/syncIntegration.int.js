// Integration: two devices converge through the reworked reconcile composition (reconcileTree over real
// channels). This is the piece the unit tests don't cover — that buildSyncSession's channel wiring, run
// against a shared server, actually creates the tree row and converges two real FamilyTrees. The keyring
// channel is stubbed here (its crypto round-trip needs the wasm and is covered by keyringSync.int + the
// reconcileKeyring unit test); this exercises the SNAPSHOT (row-creation) + DELTA channels + the ordering.
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTree } from '../app/src/core/tree/index.js';
import { FamilyTree } from '../app/src/core/familyTree.js';
import { createSyncedDeltaSync } from '../app/src/core/syncedDeltaSync.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { MemoryStore, ConflictError } from '../app/src/core/store.js';
import { reconcileTree, reconcileSnapshot, reconcileDeltas } from '../app/src/core/syncReconcilers.js';
import { Ok } from '../app/src/core/syncOutcome.js';

const wasmUrl = new URL('../app/src/vendor/tree/openom_tree_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;
beforeAll(async () => { if (built) await createTree({ initInput }); });

const identity = async (b) => b;

// A minimal shared server: one tree's snapshot row (create-once CAS) + delta log. Mirrors the RemoteStore
// methods the snapshot + delta channels call. No keyring here (that channel is stubbed in the test).
class FakeServer {
  #row = null; // { bytes, version } | null
  #log = [];
  #v = 0;
  remote() {
    return {
      readSnapshot: async () => this.#row,
      putSnapshot: async (_id, bytes, expected) => {
        if (expected === null && this.#row) throw new ConflictError(null, null); // create-only: row exists
        this.#row = { bytes, version: `v${++this.#v}` };
        return this.#row.version;
      },
      appendLog: async (_id, sealed) => {
        const seq = this.#log.length;
        this.#log.push({ seq, member: null, replica: null, counter: 0, time: '', payload: sealed });
        return seq;
      },
      readLog: async (_id, since = -1) => {
        const entries = this.#log.filter((e) => e.seq > since);
        return { entries, nextCursor: entries.length ? entries[entries.length - 1].seq : since, oldestRetainedSeq: 0, headSeq: this.#log.length - 1 };
      },
    };
  }
  get hasRow() { return this.#row != null; }
  get logLength() { return this.#log.length; }
}

async function makeDevice(server, uuid, label) {
  const remote = server.remote();
  const tree = new FamilyTree(new MemoryStore(), uuid, null, `did:key:z${label}`);
  await tree.hydrate();
  const keyringStore = memoryKeyringStore();
  // Unattributed V1 entries (keyringRevision 0) → the verifier accepts without a governing keyring, so no
  // real keyring/wasm is needed to exercise the delta channel.
  const worker = { entryAttribution: async () => ({ keyringRevision: 0, keyId: new Uint8Array() }) };
  const controller = createSyncedDeltaSync({ version: 1, tree, remote, docId: uuid, seal: identity, open: identity, worker, keyringStore });

  const snapshot = () => reconcileSnapshot({ tree, uuid, remote, sealSnapshot: identity });
  const deltas = () => reconcileDeltas({ controller });
  const reconcile = () => reconcileTree({
    pullKeyring: async () => {}, // keyring channel stubbed (covered elsewhere)
    snapshot,
    publishKeyring: async () => {},
    deltas,
  });
  return { tree, reconcile };
}

describe.skipIf(!built)('sync integration — two devices converge through reconcileTree', () => {
  it('device A creates the tree row + a person; device B pulls, converges, and edits flow back', async () => {
    const server = new FakeServer();
    const uuid = 'tree-uuid-1';
    const A = await makeDevice(server, uuid, 'A');
    const B = await makeDevice(server, uuid, 'B');

    // A edits, then reconciles: the snapshot channel CREATES the row, the delta channel pushes the edit.
    const p = await A.tree.createPerson({ given: 'Ada' });
    const r1 = await A.reconcile();
    expect(r1).toEqual(Ok()); // whole tick converged
    expect(server.hasRow).toBe(true); // row created by the snapshot channel
    expect(server.logLength).toBeGreaterThan(0); // the create delta was pushed

    // B reconciles: the row already exists (no double-create), and B pulls A's delta → converges.
    const r2 = await B.reconcile();
    expect(r2).toEqual(Ok());
    expect(B.tree.person(p.id)?.given).toBe('Ada');

    // B edits; both reconcile; A sees B's change (bidirectional convergence).
    await B.tree.updatePerson(p.id, { surname: 'Lovelace' });
    await B.reconcile();
    await A.reconcile();
    expect(A.tree.person(p.id)?.surname).toBe('Lovelace');
  });

  it('a second device that starts empty reconstructs the whole tree from the log (no snapshot adopt needed)', async () => {
    const server = new FakeServer();
    const uuid = 'tree-uuid-2';
    const A = await makeDevice(server, uuid, 'A');
    await A.tree.createPerson({ given: 'Grace' });
    await A.tree.createPerson({ given: 'Hopper' });
    await A.reconcile();

    // C joins fresh AFTER the edits — it pulls the full log and reconstructs (V1: full-log replay).
    const C = await makeDevice(server, uuid, 'C');
    await C.reconcile();
    expect(C.tree.allPeople().map((x) => x.given).sort()).toEqual(['Grace', 'Hopper']);
  });

  it('concurrent creators: both reconcile against an empty server; the row is created once and both converge', async () => {
    const server = new FakeServer();
    const uuid = 'tree-uuid-3';
    const A = await makeDevice(server, uuid, 'A');
    const B = await makeDevice(server, uuid, 'B');
    await A.tree.createPerson({ given: 'Ada' });
    await B.tree.createPerson({ given: 'Babbage' });

    // Both reconcile (A first creates the row; B's create sees the row exists via the 409 → Ok('exists')).
    await A.reconcile();
    await B.reconcile();
    await A.reconcile(); // exchange
    await B.reconcile();

    for (const D of [A, B]) {
      const names = D.tree.allPeople().map((x) => x.given).sort();
      expect(names).toEqual(['Ada', 'Babbage']); // set-union convergence
    }
    expect(server.hasRow).toBe(true);
  });
});
