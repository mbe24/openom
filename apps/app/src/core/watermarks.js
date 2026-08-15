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

const ZERO = { keyringRevision: 0, coversThroughSeq: 0 };

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
   * Record a freshly-verified keyring/snapshot for a tree. Throws RegressionError if
   * either coordinate is BELOW the stored watermark (a rollback/replay). Equal is fine
   * (idempotent — re-observing the same state). Otherwise advances and returns the
   * watermark. Each coordinate is independent: the snapshot can advance while the
   * keyring holds, and vice versa.
   */
  observe(treeId, { keyringRevision = 0, coversThroughSeq = 0 } = {}) {
    const wm = this.#load(treeId);
    if (keyringRevision < wm.keyringRevision) {
      throw new RegressionError('keyring', wm.keyringRevision, keyringRevision);
    }
    if (coversThroughSeq < wm.coversThroughSeq) {
      throw new RegressionError('snapshot', wm.coversThroughSeq, coversThroughSeq);
    }
    const next = {
      keyringRevision: Math.max(wm.keyringRevision, keyringRevision),
      coversThroughSeq: Math.max(wm.coversThroughSeq, coversThroughSeq),
    };
    this.#save(treeId, next);
    return next;
  }
}
