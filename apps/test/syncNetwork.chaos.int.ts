import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { SealedStore } from '../app/src/core/sealedStore.js';
import { SyncStore } from '../app/src/core/syncStore.js';
import { MemoryStore } from '../app/src/core/store.js';
import { SealerSession } from '../app/src/core/sealer/session.js';

// Network-drop simulation — the sibling of crashRetry.chaos: the process does NOT crash, the
// REMOTE just fails intermittently (a plain network error, distinct from a CAS conflict). The
// "flaky wifi mid-sync" case. The local write is the durable commit point and never touches the
// network, so no committed edit may ever be lost; SyncStore must swallow the network error
// (→ offline), keep the doc dirty, and converge on retry with no dup — including the lost-ack
// case (the put LANDED but the ack was dropped) and a drop while fetching the remote of a
// conflict. Invariant: every completed commit survives on every device, no phantom, all
// devices converge to one set.
//
// Note the layering under test: reconcile() is ONE tick that returns `offline` and stops — it
// never loops. The convergeAll() loop here is the TEST driving to convergence (modelling "the
// user eventually got online and synced"), not the app; the retry *policy* lives in a future
// SyncController, not in SyncStore.

const TREE = 'tree';
const enc = new TextEncoder();
const dec = new TextDecoder();
const serialize = (s: Set<number>) => enc.encode(JSON.stringify([...s].sort((a, b) => a - b)));
const deserialize = (b: Uint8Array): Set<number> => new Set<number>(JSON.parse(dec.decode(b)));

function fakeCore(replicaTag: number) {
  return {
    treeId: new Uint8Array([replicaTag & 0xff]),
    sealEntry(kind: string, _f: string, _c: string, counter: number, prev: Uint8Array, _cov: number, _b: Uint8Array, pt: Uint8Array) {
      const envelope = enc.encode(JSON.stringify({ r: replicaTag, n: counter, k: kind, prev: Array.from(prev), pt: Array.from(pt) }));
      return { envelope, ciphertextHash: new Uint8Array([replicaTag & 0xff, counter & 0xff, pt.length & 0xff]) };
    },
    openEntry(kind: string, bytes: Uint8Array) {
      const rec = JSON.parse(dec.decode(bytes));
      if (rec.k !== kind) throw new Error('unexpected kind');
      return new Uint8Array(rec.pt);
    },
  };
}

class NetworkDown extends Error {}

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Fires a network drop at a named remote seam: once at `armedSeam` (deterministic) or randomly
// per a seeded probability (chaos).
class Net {
  armedSeam: string | null = null;
  rand: (() => number) | null = null;
  p = 0;
  drop(seam: string) {
    if (this.armedSeam === seam) {
      this.armedSeam = null;
      throw new NetworkDown(seam);
    }
    if (this.rand && this.rand() < this.p) throw new NetworkDown('chaos@' + seam);
  }
}

// A flaky remote: the read can drop; the put can drop BEFORE it lands (retry the same bytes) or
// AFTER it lands but before the ack is seen (the lost-ack case). A CAS conflict still surfaces
// as a real ConflictError from the inner store — never as a NetworkDown.
function flakyRemote(inner: any, net: Net) {
  return {
    caps: () => inner.caps?.() ?? {},
    async readSnapshot(id: string) {
      net.drop('read');
      return inner.readSnapshot(id);
    },
    async putSnapshot(id: string, bytes: Uint8Array, expected: any) {
      net.drop('put.before');
      const v = await inner.putSnapshot(id, bytes, expected);
      net.drop('put.after'); // applied, ack lost
      return v;
    },
  };
}

let replicaSeq = 0;

class Dev {
  local = new MemoryStore();
  persist = new Map<string, string>();
  sync: SyncStore;
  session: SealerSession;
  sealed: SealedStore;
  tree = new Set<number>();

  constructor(remote: any) {
    const persist = {
      getItem: (k: string) => (this.persist.has(k) ? this.persist.get(k)! : null),
      setItem: (k: string, v: string) => void this.persist.set(k, v),
      removeItem: (k: string) => void this.persist.delete(k),
    };
    this.session = new SealerSession(fakeCore(replicaSeq++));
    this.sync = new SyncStore(this.local, remote, { persist });
    this.sealed = new SealedStore(this.sync, this.session);
  }

  // Local commit — never hits the network, so it always succeeds.
  async commit(id: number) {
    this.tree.add(id);
    const cur = await this.sealed.readSnapshot(TREE);
    await this.sealed.putSnapshot(TREE, serialize(this.tree), cur ? cur.version : null);
  }

  // One sync tick, union-merging conflicts. A network drop must arrive as an `offline` status
  // (or a handled conflict), NEVER as a thrown NetworkDown escaping SyncStore — if one escapes,
  // this throws and the test fails, which is the point of leaving it uncaught.
  async sync_() {
    let r: any = await this.sync.reconcile(TREE);
    let guard = 0;
    while (r.status === 'conflict' && guard++ < 50) {
      const remotePlain = deserialize(await this.session.open(r.remote.bytes, TREE, { kind: 'snapshot' }));
      for (const x of remotePlain) this.tree.add(x);
      const merged = await this.session.seal(serialize(this.tree), TREE, { kind: 'snapshot' });
      await this.sync.resolveWith(TREE, merged, r.remote.version);
      r = await this.sync.reconcile(TREE);
    }
    const snap = await this.sealed.readSnapshot(TREE);
    if (snap) this.tree = deserialize(snap.bytes);
    return r;
  }
}

// Drive everyone to convergence with the network UP: repeat until a full pass is quiet. Models
// "the user is online and a sync tick runs to completion" — NOT the app auto-looping.
async function convergeAll(devices: Dev[], net: Net) {
  net.armedSeam = null;
  net.rand = null;
  for (let pass = 0; pass < 60; pass++) {
    let quiet = true;
    for (const d of devices) {
      const r = await d.sync_();
      if (['conflict', 'offline', 'synced', 'fastForward'].includes(r.status)) quiet = false;
    }
    if (quiet) break;
  }
}

describe('network-drop simulation', () => {
  const seams = ['read', 'put.before', 'put.after'];
  for (const seam of seams) {
    it(`a drop at ${seam} loses nothing and still converges`, async () => {
      replicaSeq = 0;
      const net = new Net();
      const remote = flakyRemote(new MemoryStore(), net);
      const a = new Dev(remote);
      const b = new Dev(remote);

      await a.commit(1);
      await convergeAll([a, b], net); // both hold {1}

      await a.commit(2);
      net.armedSeam = seam; // the next matching remote touch drops once
      await a.sync_(); // may go offline mid-tick
      await convergeAll([a, b], net);

      for (const d of [a, b]) {
        expect(d.tree.has(1)).toBe(true);
        expect(d.tree.has(2)).toBe(true);
        for (const x of d.tree) expect([1, 2]).toContain(x);
      }
      expect([...a.tree].sort()).toEqual([...b.tree].sort());
    });
  }

  it('a drop while fetching a conflict comes back offline, not a thrown error', async () => {
    // Force the narrow path the random seeds rarely hit: push() gets a CAS conflict, then the
    // fetch of the remote-to-merge drops. A sync tick must resolve to `offline` (retry later),
    // never throw a raw network error up to the app. Without the harden this rejects.
    replicaSeq = 0;
    const net = new Net();
    const remote = flakyRemote(new MemoryStore(), net);
    const rival = new Dev(remote);
    await rival.commit(9);
    await convergeAll([rival], net); // the remote now holds a real sealed snapshot {9}

    const a = new Dev(remote);
    await a.commit(7); // local {7}, dirty, remoteVersion=null → a stale push will CAS-conflict
    net.armedSeam = 'read'; // the conflict-branch fetch drops once
    const r = await a.sync.pushSnapshot(TREE);
    expect(r.status).toBe('offline');

    // …and it still converges once the network is back.
    await convergeAll([a, rival], net);
    for (const d of [a, rival]) {
      expect(d.tree.has(7)).toBe(true);
      expect(d.tree.has(9)).toBe(true);
    }
  });

  it('never loses a commit under seeded random network drops (property)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 1_000_000 }),
        fc.array(fc.record({ dev: fc.integer({ min: 0, max: 1 }), id: fc.integer({ min: 1, max: 6 }) }), { minLength: 1, maxLength: 24 }),
        async (seed, ops) => {
          replicaSeq = 0;
          const net = new Net();
          net.rand = rng(seed);
          net.p = 0.3; // 30% of remote touches drop
          const remote = flakyRemote(new MemoryStore(), net);
          const devices = [new Dev(remote), new Dev(remote)];

          // Local commits never touch the network, so every attempted id is committed.
          for (const op of ops) {
            await devices[op.dev].commit(op.id);
            await devices[op.dev].sync_(); // may go offline; retried during convergeAll
          }
          await convergeAll(devices, net);

          const attempted = new Set(ops.map((o) => o.id));
          for (const d of devices) {
            for (const id of attempted) expect(d.tree.has(id)).toBe(true); // no loss
            for (const x of d.tree) expect(attempted.has(x)).toBe(true); // no phantom
          }
          expect([...devices[0].tree].sort()).toEqual([...devices[1].tree].sort()); // converged
        },
      ),
      { numRuns: 200 },
    );
  });
});
