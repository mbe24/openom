// SyncController end-to-end: two claim-engine replicas converge through a shared delta log. Uses a fake
// remote (an in-memory log matching RemoteStore's append/read shape) and identity seal/open, so the
// orchestration + the engine merge are exercised without a running server. The real server contract is
// covered by openom/tests/api.rs (delta_log_lifecycle).
import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTree } from '../app/src/core/tree/index.js';
import { FamilyTree } from '../app/src/core/familyTree.js';
import { SyncController } from '../app/src/core/sync.js';
import { createSyncedDeltaSync } from '../app/src/core/syncedDeltaSync.js';
import { RetryableVerifyError } from '../app/src/core/sealer/entryVerifier.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { MemoryStore } from '../app/src/core/store.js';

const wasmUrl = new URL('../app/src/vendor/tree/openom_tree_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;
beforeAll(async () => { if (built) await createTree({ initInput }); });

// An in-memory stand-in for the server's delta log, matching the RemoteStore methods the controller uses.
class FakeRemote {
  #log = [];
  async appendLog(_id, sealed) {
    const seq = this.#log.length;
    this.#log.push({ seq, payload: sealed });
    return seq;
  }
  async readLog(_id, since = -1) {
    const entries = this.#log
      .filter((e) => e.seq > since)
      .map((e) => ({ seq: e.seq, member: null, replica: null, counter: 0, time: '', payload: e.payload }));
    return {
      entries,
      nextCursor: entries.length ? entries[entries.length - 1].seq : since,
      oldestRetainedSeq: 0,
      headSeq: this.#log.length - 1,
    };
  }
  async readSnapshot() {
    return null;
  }
  async activity(id, since = -1) {
    const { entries, headSeq } = await this.readLog(id, since);
    return { changes: entries.map(({ seq, member, replica, counter, time }) => ({ seq, member, replica, counter, time })), headSeq };
  }
}

const identity = async (b) => b;

describe.skipIf(!built)('SyncController — two replicas converge through the delta log', () => {
  it('propagates creates, edits, and concurrent field edits, converging', async () => {
    const remote = new FakeRemote();
    const a = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    const b = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await a.hydrate();
    await b.hydrate();
    const sa = new SyncController({ tree: a, remote, docId: 'doc', seal: identity, open: identity });
    const sb = new SyncController({ tree: b, remote, docId: 'doc', seal: identity, open: identity });

    // A creates a person; push; B pulls it.
    const p = await a.createPerson({ given: 'Ada', surname: 'Lovelace' });
    await sa.push();
    await sb.pull();
    expect(b.person(p.id)?.given).toBe('Ada');
    expect(b.person(p.id)?.surname).toBe('Lovelace');

    // B renames; both sync; A sees it.
    await b.updatePerson(p.id, { surname: 'Byron' });
    await sb.sync();
    await sa.sync();
    expect(a.person(p.id)?.surname).toBe('Byron');

    // Concurrent edits to DIFFERENT fields on each side, then exchange → both survive, converge.
    await a.updatePerson(p.id, { birth: '1815' });
    await b.updatePerson(p.id, { note: 'hi' });
    await sa.push();
    await sb.push();
    await sa.pull();
    await sb.pull();
    for (const tree of [a, b]) {
      expect(tree.person(p.id)?.birth).toBe('1815');
      expect(tree.person(p.id)?.note).toBe('hi');
      expect(tree.person(p.id)?.surname).toBe('Byron');
    }
    // The activity feed reports every appended change.
    const feed = await sa.activity(-1);
    expect(feed.changes.length).toBeGreaterThan(0);
  });

  it('a second device catches up from the log via bootstrap()', async () => {
    const remote = new FakeRemote();
    const a = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await a.hydrate();
    const sa = new SyncController({ tree: a, remote, docId: 'doc', seal: identity, open: identity });
    await a.createPerson({ given: 'Grace' });
    await a.createPerson({ given: 'Hopper' });
    await sa.push();

    // A brand-new device with an empty store catches up purely from the log.
    const c = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await c.hydrate();
    const sc = new SyncController({ tree: c, remote, docId: 'doc', seal: identity, open: identity });
    await sc.bootstrap();
    expect(c.allPeople().length).toBe(2);
    expect(c.allPeople().map((x) => x.given).sort()).toEqual(['Grace', 'Hopper']);
  });

  it('drops an entry that fails verification and merges the rest (order-insensitive)', async () => {
    const remote = new FakeRemote();
    const a = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    const b = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await a.hydrate();
    await b.hydrate();
    const sa = new SyncController({ tree: a, remote, docId: 'doc', seal: identity, open: identity });
    // B's verifier rejects the FIRST entry it's asked about (stands in for an unauthorized author /
    // bad signature the sealer's verifyEntry would throw on); the rest must still merge.
    let seen = 0;
    const verify = async () => {
      seen += 1;
      if (seen === 1) throw new Error('unauthorized author');
    };
    const sb = new SyncController({ tree: b, remote, docId: 'doc', seal: identity, open: identity, verify });

    await a.createPerson({ given: 'Ada' });
    await a.createPerson({ given: 'Grace' });
    await sa.push();
    const r = await sb.pull();

    expect(r.rejected.length).toBe(1); // exactly the refused entry
    expect(r.merged).toBeGreaterThanOrEqual(1); // the rest still merged — one bad entry doesn't stall the log
    // Nothing verified-bad reached the tree without also blocking the good entries.
    expect(seen).toBeGreaterThanOrEqual(2);
  });

  it('createSyncedDeltaSync wires the verifier: a forged entry is dropped, the rest merge', async () => {
    const remote = new FakeRemote();
    const a = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    const b = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await a.hydrate();
    await b.hydrate();
    const sa = new SyncController({ tree: a, remote, docId: 'doc', seal: identity, open: identity });
    // A fake worker (the composer's primitives) + a keyring retained at the governing revision, so the
    // composer runs the real decision flow (attributed epoch → verifyEntry). verifyEntry rejects the first.
    let seen = 0;
    const worker = {
      entryAttribution: async () => ({ keyringRevision: 2, keyId: new Uint8Array([1]) }),
      epochIsAttributed: async () => true,
      verifyEntry: async () => {
        seen += 1;
        if (seen === 1) throw new Error('unauthorized author');
      },
    };
    const keyringStore = memoryKeyringStore();
    await keyringStore.save('doc', 2, new Uint8Array([9])); // the governing keyring the composer fetches
    const sb = createSyncedDeltaSync({ version: 1, tree: b, remote, docId: 'doc', seal: identity, open: identity, worker, keyringStore });

    await a.createPerson({ given: 'Ada' });
    await a.createPerson({ given: 'Grace' });
    await sa.push();
    const r = await sb.pull();
    expect(r.rejected.length).toBe(1);
    expect(r.merged).toBeGreaterThanOrEqual(1);
  });

  it('HOLDS a retryable entry (keyring not retained yet) without advancing the cursor, then merges it after a keyring sync', async () => {
    const remote = new FakeRemote();
    const a = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    const b = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await a.hydrate();
    await b.hydrate();
    const sa = new SyncController({ tree: a, remote, docId: 'doc', seal: identity, open: identity });
    // The composer asks for governing keyring revision 2. The store starts EMPTY → keyringAt(2) is null →
    // the verifier throws a RetryableVerifyError (transient, NOT a rejection). With the epoch unattributed,
    // a RETAINED keyring later accepts the entry unsigned.
    const worker = {
      entryAttribution: async () => ({ keyringRevision: 2, keyId: new Uint8Array([1]) }),
      epochIsAttributed: async () => false, // epoch not shared → accept once the governing keyring is present
      verifyEntry: async () => {},
    };
    const keyringStore = memoryKeyringStore();
    const sb = createSyncedDeltaSync({ version: 1, tree: b, remote, docId: 'doc', seal: identity, open: identity, worker, keyringStore });

    const p = await a.createPerson({ given: 'Ada' });
    await sa.push();

    // First pull: rev 2 not retained → the entry is HELD, the cursor is NOT advanced, nothing merges.
    const r1 = await sb.pull();
    expect(r1.merged).toBe(0);
    expect(r1.rejected.length).toBe(0); // a hold is NOT a rejection — the entry must never be dropped
    expect(r1.held).not.toBeNull();
    expect(b.person(p.id)).toBeFalsy();

    // Retain the governing keyring and pull again: because the cursor never advanced, the SAME entry is
    // re-served and now merges — the edit was held, not lost forever.
    await keyringStore.save('doc', 2, new Uint8Array([9]));
    const r2 = await sb.pull();
    expect(r2.merged).toBe(1);
    expect(b.person(p.id)?.given).toBe('Ada');
  });

  it('bootstrap DEFERS (no throw, no adopt) on a retryable snapshot verify', async () => {
    const snapshot = new Uint8Array([0xbe, 0xef]);
    const remote = {
      readSnapshot: async () => ({ bytes: snapshot }),
      readLog: async () => ({ entries: [], nextCursor: -1, oldestRetainedSeq: 0, headSeq: -1 }),
    };
    const b = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await b.hydrate();
    const verify = async () => { throw new RetryableVerifyError('governing keyring not retained yet'); };
    const sb = new SyncController({ tree: b, remote, docId: 'doc', seal: identity, open: identity, verify });
    // A transient failure must not abort bootstrap (that would strand an invited device forever) — it
    // defers, unlike the genuine forged-snapshot case below which still throws.
    const r = await sb.bootstrap();
    expect(r.deferred).toBe(true);
    expect(b.allPeople().length).toBe(0); // nothing adopted, but no throw either
  });

  it('bootstrap refuses a snapshot that fails verification (never adopts it)', async () => {
    const forged = new Uint8Array([0xde, 0xad]);
    const remote = {
      readSnapshot: async () => ({ bytes: forged }),
      readLog: async () => ({ entries: [], nextCursor: -1, oldestRetainedSeq: 0, headSeq: -1 }),
    };
    const b = new FamilyTree(new MemoryStore(), 'doc', null, 'did:key:zLocal');
    await b.hydrate();
    const verify = async () => {
      throw new Error('forged snapshot');
    };
    const sb = new SyncController({ tree: b, remote, docId: 'doc', seal: identity, open: identity, verify });
    await expect(sb.bootstrap()).rejects.toThrow(/forged snapshot/);
    expect(b.allPeople().length).toBe(0); // nothing adopted from the unverified snapshot
  });
});
