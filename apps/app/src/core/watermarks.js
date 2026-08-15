// Watermarks: refuse-on-regression (§10). A signature proves authorship, never
// *currency* — an old-but-valid keyring or snapshot is a fully coherent view of the
// PAST, so a partly-untrusted server could serve a pre-revocation keyring or a stale
// snapshot undetectably. The client persists, per tree, the highest keyring `revision`
// and snapshot coordinate it has verified, and refuses anything lower. Every second
// device thereby becomes a rollback detector.

const PREFIX = 'openom.wm.';

export class RegressionError extends Error {
  constructor(kind, have, got) {
    super(`${kind} regression: have ${have}, refused ${got}`);
    this.name = 'RegressionError';
    this.kind = kind;
    this.have = have;
    this.got = got;
  }
}

// Persistence shim: real localStorage when usable, else an in-memory map (Node, tests,
// private-mode browsers where localStorage exists but throws on access).
function defaultStore() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem('__wm_probe__');
      return localStorage;
    }
  } catch {
    /* fall through to memory */
  }
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, v),
  };
}

const ZERO = { keyringRevision: 0, coversThroughSeq: 0, snapshots: [] };

// How many recent snapshot hashes to remember per tree for replay detection. A rollback to
// a snapshot older than this window can't be caught — a bounded, honest degradation (memory
// vs. depth). The common attack (re-serving a recently-superseded snapshot) is well inside it.
const MAX_SNAPSHOTS = 64;

// Snapshot hashes are the envelope's `ciphertext_hash` (non-secret header metadata). Accept
// a hex string as-is, or bytes to hexify, so callers can pass either.
function toHex(x) {
  if (typeof x === 'string') return x;
  const arr = x instanceof Uint8Array ? x : new Uint8Array(x);
  let s = '';
  for (const b of arr) s += b.toString(16).padStart(2, '0');
  return s;
}

export class Watermarks {
  #store;

  constructor(store = defaultStore()) {
    this.#store = store;
  }

  #load(treeId) {
    try {
      const raw = this.#store.getItem(PREFIX + treeId);
      if (raw) return { ...ZERO, ...JSON.parse(raw) };
    } catch {
      /* corrupt/absent → zero watermark */
    }
    return { ...ZERO };
  }

  #save(treeId, wm) {
    try {
      this.#store.setItem(PREFIX + treeId, JSON.stringify(wm));
    } catch {
      /* ephemeral — best effort */
    }
  }

  /** The highest watermark seen for a tree (zeros if none). */
  current(treeId) {
    return this.#load(treeId);
  }

  /**
   * Record a freshly-verified keyring/snapshot for a tree. Throws RegressionError on a
   * rollback/replay; equal is fine (idempotent). Otherwise advances and returns the
   * watermark. The coordinates are independent:
   *   - `keyringRevision` / `coversThroughSeq` are monotonic ordinals — refuse anything
   *     below the stored value. (`coversThroughSeq` is server-assigned and 0 throughout V1,
   *     so it is inert until the V2 delta log exists.)
   *   - `snapshotHash` (the snapshot's `ciphertext_hash`) has no order, so it is guarded by
   *     memory instead: re-serving a snapshot the client already moved PAST is a rollback,
   *     while a genuinely new hash is legitimate progress. This is the live snapshot
   *     anti-rollback signal in V1. Its limits are honest: the first snapshot a client ever
   *     sees can't be verified (no prior state to anchor against), and a rollback older than
   *     the remembered window (`MAX_SNAPSHOTS`) escapes detection.
   */
  observe(treeId, { keyringRevision = 0, coversThroughSeq = 0, snapshotHash } = {}) {
    const wm = this.#load(treeId);
    if (keyringRevision < wm.keyringRevision) {
      throw new RegressionError('keyring', wm.keyringRevision, keyringRevision);
    }
    if (coversThroughSeq < wm.coversThroughSeq) {
      throw new RegressionError('coverage', wm.coversThroughSeq, coversThroughSeq);
    }
    const next = {
      keyringRevision: Math.max(wm.keyringRevision, keyringRevision),
      coversThroughSeq: Math.max(wm.coversThroughSeq, coversThroughSeq),
      snapshots: this.#observeSnapshot(wm.snapshots ?? [], snapshotHash),
    };
    this.#save(treeId, next);
    return next;
  }

  // Fold a freshly-accepted snapshot hash into the remembered window, or reject a replay.
  #observeSnapshot(list, snapshotHash) {
    if (snapshotHash == null) return list; // caller didn't supply one — nothing to check
    const h = toHex(snapshotHash);
    const idx = list.indexOf(h);
    if (idx === -1) return [...list, h].slice(-MAX_SNAPSHOTS); // new snapshot → progress
    if (idx === list.length - 1) return list; // the current head, re-observed → idempotent
    // Seen before, but not the head: the client already superseded it, so serving it again
    // is a rollback to an older-but-valid snapshot.
    throw new RegressionError('snapshot-rollback', list[list.length - 1], h);
  }
}
