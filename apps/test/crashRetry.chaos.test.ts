import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { SealedStore } from '../app/src/core/sealedStore.js';
import { SyncStore } from '../app/src/core/syncStore.js';
import { MemoryStore, ConflictError } from '../app/src/core/store.js';
import { SealerSession } from '../app/src/core/sealer/session.js';

// Crash-retry simulation. The write path — SealedStore → SyncStore → {durable local, shared
// remote}, sealed by a SealerSession — is driven through injected faults at every seam a
// crash can strike, then recovered and run to convergence. A "crash" discards all volatile
// objects and rebuilds them over the SURVIVING durable stores (the local MemoryStore and
// the persisted sync bookkeeping) with a FRESH replica — the modelled reality that the
// replica id is minted per JS context. The invariant: no committed edit is ever lost and no
// phantom edit ever appears, no matter where the crash lands.
//
// The tree is modelled as a growing set of integer ids; merge = set union (idempotent under
// re-application, so a double-apply is invisible in the result — which is exactly how the
// "no double-apply" invariant is checked: the converged set equals the union oracle).

const TREE = 'tree';
const enc = new TextEncoder();
const dec = new TextDecoder();

const serialize = (s: Set<number>) => enc.encode(JSON.stringify([...s].sort((a, b) => a - b)));
const deserialize = (b: Uint8Array): Set<number> => new Set(JSON.parse(dec.decode(b)));

// A deterministic reversible sealer core: embeds a per-session replica tag + the chain
// coordinates so the "envelope" round-trips and distinct content yields distinct bytes
// (so the lost-ack bytesEqual path behaves like the real one).
function fakeCore(replicaTag: number) {
  return {
    treeId: new Uint8Array([replicaTag & 0xff]),
    sealEntry(
      kind: string,
      _f: string,
      _c: string,
      counter: number,
      prev: Uint8Array,
      _cov: number,
      _b: Uint8Array,
      plaintext: Uint8Array,
    ) {
      const rec = { r: replicaTag, n: counter, k: kind, prev: Array.from(prev), pt: Array.from(plaintext) };
      const envelope = enc.encode(JSON.stringify(rec));
      const ciphertextHash = new Uint8Array([replicaTag & 0xff, counter & 0xff, plaintext.length & 0xff]);
      return { envelope, ciphertextHash };
    },
    openEntry(kind: string, bytes: Uint8Array) {
      const rec = JSON.parse(dec.decode(bytes));
      if (rec.k !== kind) throw new Error('unexpected kind');
      return new Uint8Array(rec.pt);
    },
  };
}

class SimulatedCrash extends Error {}

// A seeded PRNG (mulberry32) — a failing property replays exactly from its seed.
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

// The fault controller: either fire at one named seam exactly once (deterministic tests) or
// fire randomly per a probability + seeded PRNG (chaos). `point(name)` throws SimulatedCrash
// when armed.
class Faults {
  armedSeam: string | null = null; // fire once at this seam, then disarm
  rand: (() => number) | null = null;
  p = 0;

  point(name: string) {
    if (this.armedSeam === name) {
      this.armedSeam = null;
      throw new SimulatedCrash(name);
    }
    if (this.rand && this.rand() < this.p) {
      throw new SimulatedCrash('chaos@' + name);
    }
  }
}

// Wrap a DocStore so putSnapshot can crash before applying (…before) or after the durable
// write but before returning (…after — models a crash before SyncStore marks dirty).
function faultLocal(inner: any, faults: Faults) {
  return {
    caps: () => inner.caps(),
    list: (...a: any[]) => inner.list(...a),
    readSnapshot: (...a: any[]) => inner.readSnapshot(...a),
    readUpdates: (...a: any[]) => inner.readUpdates(...a),
    append: (...a: any[]) => inner.append(...a),
    delete: (...a: any[]) => inner.delete(...a),
    async putSnapshot(id: string, bytes: Uint8Array, expected: any) {
      faults.point('local.before'); // seam A: after seal, before durable persist
      const v = await inner.putSnapshot(id, bytes, expected);
      faults.point('local.after'); // seam B: durable, before dirty is recorded
      return v;
    },
  };
}

// Wrap the shared remote so a push can crash before applying (S3a — never lands) or after
// applying but before the ack is seen (S3b — the lost-ack case).
function faultRemote(inner: any, faults: Faults) {
  return {
    caps: () => inner.caps?.() ?? {},
    readSnapshot: (...a: any[]) => inner.readSnapshot(...a),
    async putSnapshot(id: string, bytes: Uint8Array, expected: any) {
      faults.point('remote.before'); // seam C / S3a
      const v = await inner.putSnapshot(id, bytes, expected);
      faults.point('remote.after'); // seam D / S3b: applied, ack lost
      return v;
    },
  };
}

let replicaSeq = 0;

// One device: its own durable local store + persisted sync bookkeeping, a shared remote, and
// a fresh SealerSession per (re)build. `reload()` is the crash-recovery — volatile layers are
// thrown away and rebuilt over the survivors, with a brand-new replica.
class Device {
  local = new MemoryStore();
  persist = new Map<string, string>();
  remote: any;
  faults: Faults;
  sync!: SyncStore;
  session!: SealerSession;
  sealed!: SealedStore;
  tree = new Set<number>();

  constructor(remote: any, faults: Faults) {
    this.remote = remote;
    this.faults = faults;
    this.build();
  }

  build() {
    const persist = {
      getItem: (k: string) => (this.persist.has(k) ? this.persist.get(k)! : null),
      setItem: (k: string, v: string) => void this.persist.set(k, v),
      removeItem: (k: string) => void this.persist.delete(k),
    };
    this.session = new SealerSession(fakeCore(replicaSeq++));
    this.sync = new SyncStore(faultLocal(this.local, this.faults), this.remote, { persist });
    this.sealed = new SealedStore(this.sync, this.session);
  }

  async reload() {
    this.build();
    const snap = await this.sealed.readSnapshot(TREE); // opens the durable local snapshot
    this.tree = snap ? deserialize(snap.bytes) : new Set();
  }

  async commit(id: number) {
    this.tree.add(id);
    const cur = await this.sealed.readSnapshot(TREE);
    await this.sealed.putSnapshot(TREE, serialize(this.tree), cur ? cur.version : null);
  }

  // Reconcile, resolving conflicts by union-merging the remote plaintext, until settled.
  async sync_() {
    let r: any = await this.sync.reconcile(TREE);
    let guard = 0;
    while (r.status === 'conflict' && guard++ < 50) {
      const remotePlain = deserialize(await this.session.open(r.remote.bytes, TREE, { kind: 'snapshot' }));
      for (const x of remotePlain) this.tree.add(x);
      const mergedSealed = await this.session.seal(serialize(this.tree), TREE, { kind: 'snapshot' });
      await this.sync.resolveWith(TREE, mergedSealed, r.remote.version);
      r = await this.sync.reconcile(TREE);
    }
    // Adopt whatever we now hold locally (a fast-forward may have replaced it).
    const snap = await this.sealed.readSnapshot(TREE);
    if (snap) this.tree = deserialize(snap.bytes);
    return r;
  }
}

// Run an action; on a simulated crash, reload the device (recover) and report it crashed.
async function attempt(dev: Device, action: () => Promise<void>): Promise<boolean> {
  try {
    await action();
    return false;
  } catch (e) {
    if (e instanceof SimulatedCrash) {
      await dev.reload();
      return true;
    }
    if (e instanceof ConflictError) return false; // a real CAS conflict is not a crash
    throw e;
  }
}

// Drive all devices to convergence with faults OFF: repeat sync passes until a full pass is
// quiet (everyone synced/upToDate/clean/fastForward, nobody in conflict).
async function convergeAll(devices: Device[], faults: Faults) {
  faults.armedSeam = null;
  faults.rand = null;
  for (let pass = 0; pass < 50; pass++) {
    let quiet = true;
    for (const d of devices) {
      const r = await d.sync_();
      if (r.status === 'conflict' || r.status === 'offline') quiet = false;
      if (r.status === 'synced' || r.status === 'fastForward') quiet = false; // something moved
    }
    if (quiet) break;
  }
}

describe('crash-retry simulation', () => {
  // Deterministic per-seam tests: a single crash at each named seam must never lose a
  // committed edit or corrupt convergence.
  const seams = ['local.before', 'local.after', 'remote.before', 'remote.after'];
  for (const seam of seams) {
    it(`recovers from a crash at ${seam}`, async () => {
      replicaSeq = 0;
      const faults = new Faults();
      const remoteInner = new MemoryStore();
      const remote = faultRemote(remoteInner, faults);
      const a = new Device(remote, faults);
      const b = new Device(remote, faults);

      await attempt(a, () => a.commit(1)); // lands cleanly (no fault armed yet)
      await a.sync_();
      await b.sync_(); // b picks up {1}

      faults.armedSeam = seam;
      const crashed = await attempt(a, () => a.commit(2)); // may crash at the seam
      // Whether or not it crashed, drive everyone to convergence and check no loss.
      await convergeAll([a, b], faults);

      // '1' was durably committed and pushed before the crash → must survive everywhere.
      expect(a.tree.has(1)).toBe(true);
      expect(b.tree.has(1)).toBe(true);
      // If the commit of '2' completed (didn't crash), it must have converged to both.
      if (!crashed) {
        expect(a.tree.has(2)).toBe(true);
        expect(b.tree.has(2)).toBe(true);
      }
      // No phantom ids anywhere.
      for (const d of [a, b]) for (const x of d.tree) expect([1, 2]).toContain(x);
    });
  }

  it('never loses a completed commit under seeded random crashes (property)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 1_000_000 }), // seed
        fc.array(fc.record({ dev: fc.integer({ min: 0, max: 1 }), id: fc.integer({ min: 1, max: 6 }) }), {
          minLength: 1,
          maxLength: 24,
        }),
        async (seed, ops) => {
          replicaSeq = 0;
          const faults = new Faults();
          faults.rand = rng(seed);
          faults.p = 0.15; // 15% chance of a crash at each seam
          const remote = faultRemote(new MemoryStore(), faults);
          const devices = [new Device(remote, faults), new Device(remote, faults)];

          const committed = new Set<number>(); // oracle: ids whose commit returned successfully
          for (const op of ops) {
            const d = devices[op.dev];
            const crashed = await attempt(d, () => d.commit(op.id));
            if (!crashed) committed.add(op.id);
            // A sync tick, which may also crash — recovered inside attempt().
            await attempt(d, async () => {
              await d.sync_();
            });
          }

          await convergeAll(devices, faults);

          const attempted = new Set(ops.map((o) => o.id));
          for (const d of devices) {
            // No lost update: every completed commit is present.
            for (const id of committed) expect(d.tree.has(id)).toBe(true);
            // No phantom: nothing beyond what was attempted ever appears.
            for (const x of d.tree) expect(attempted.has(x)).toBe(true);
          }
          // Both devices converged to the same set.
          expect([...devices[0].tree].sort()).toEqual([...devices[1].tree].sort());
        },
      ),
      { numRuns: 200 },
    );
  });
});
