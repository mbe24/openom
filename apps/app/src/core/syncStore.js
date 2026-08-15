// SyncStore: layers remote sync over a durable LOCAL DocStore. It sits BELOW
// SealedStore, so it only ever handles OPAQUE (already-sealed) bytes — it can't merge
// conflicts (only plaintext can), it *surfaces* them for the layer above to resolve.
//
// Design (per the client-sealing review):
//   * The LOCAL write is the synchronous commit point (§1). putSnapshot commits to the
//     local cache and returns immediately; the remote push is a separate step, so a
//     flaky network never blocks or loses a local edit.
//   * A ConflictError (the remote CAS lost — someone else wrote) is NOT a retry: the
//     caller must pull the remote, merge (fold-before-cover, §10), re-seal, and try
//     again. A network error IS a retry, with the same bytes. Conflating them dups on
//     every disconnect — so RemoteStore/MemoryStore raise ConflictError only for a true
//     version conflict, and SyncStore branches on it.
//   * The local DocStore version ('v'+counter) and the remote version (server ETag) are
//     DIFFERENT namespaces. `#synced` tracks, per doc, the remote version we last
//     agreed with; it is remote-namespaced.
//
// Anti-rollback (refuse-on-regression, §10) lives ABOVE this layer: it needs the
// plaintext keyring `revision` and snapshot coordinates, which SyncStore can't see.
//
// DURABILITY (§8a crash-retry): the per-doc sync bookkeeping — the remote version we last
// agreed with, and whether the doc has unpushed local changes — is PERSISTED, not just
// in-memory. In-memory maps lose the `dirty` flag on reload, and a fresh instance would
// then treat a locally-committed-but-unpushed snapshot as clean and let `pull()`
// fast-forward an older remote over it — a silent loss of a durable local edit. Two guards
// close that: (1) the flags survive a reload; (2) `pull()` only fast-forwards with POSITIVE
// evidence the local was clean (a known synced remote version + not dirty), or when there
// is no local snapshot to lose — anything else is surfaced as a conflict for the caller to
// merge, never overwritten.

import { ConflictError } from './store.js';

const bytesEqual = (a, b) =>
  a === b || (!!a && !!b && a.length === b.length && a.every((x, i) => x === b[i]));

const PREFIX = 'openom.sync.';

// Durable KV for the sync bookkeeping: real localStorage when usable, else an in-memory
// map (Node, tests, private-mode browsers). Mirrors watermarks.js's persistence shim.
function defaultPersist() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem('__sync_probe__');
      return localStorage;
    }
  } catch {
    /* fall through to memory */
  }
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, v),
    removeItem: (k) => m.delete(k),
  };
}

export class SyncStore {
  #local;
  #remote;
  #persist;
  #cache = new Map(); // id -> {remoteVersion, dirty}; in-memory mirror of #persist

  constructor(local, remote, { persist } = {}) {
    if (!local || !remote) throw new Error('SyncStore needs a local and a remote store');
    this.#local = local;
    this.#remote = remote;
    this.#persist = persist ?? defaultPersist();
  }

  // Per-doc sync state, loaded from the durable store on first touch and cached.
  #state(id) {
    if (this.#cache.has(id)) return this.#cache.get(id);
    let s = { remoteVersion: null, dirty: false };
    try {
      const raw = this.#persist.getItem(PREFIX + id);
      if (raw) s = { ...s, ...JSON.parse(raw) };
    } catch {
      /* corrupt/absent → defaults (dirty:false, but pull() still won't clobber, see below) */
    }
    this.#cache.set(id, s);
    return s;
  }

  #save(id, patch) {
    const s = { ...this.#state(id), ...patch };
    this.#cache.set(id, s);
    try {
      this.#persist.setItem(PREFIX + id, JSON.stringify(s));
    } catch {
      /* best effort — the in-memory cache still holds it for this session */
    }
    return s;
  }

  #clear(id) {
    this.#cache.delete(id);
    try {
      this.#persist.removeItem?.(PREFIX + id);
    } catch {
      /* ignore */
    }
  }

  caps() {
    return { ...this.#local.caps(), remote: true };
  }
  async list() {
    return this.#local.list();
  }
  async readSnapshot(id) {
    return this.#local.readSnapshot(id); // reads come from the local cache
  }
  async readUpdates(id, since) {
    return this.#local.readUpdates(id, since);
  }
  async append(id, updates) {
    const result = await this.#local.append(id, updates);
    this.#save(id, { dirty: true });
    return result;
  }
  async delete(id) {
    this.#clear(id);
    return this.#local.delete(id);
  }

  /** Local commit — the synchronous durability point. Marks the doc for later push. */
  async putSnapshot(id, bytes, expected = null) {
    const version = await this.#local.putSnapshot(id, bytes, expected);
    this.#save(id, { dirty: true });
    return version;
  }

  /** Whether the doc has local changes not yet confirmed on the remote. */
  isDirty(id) {
    return this.#state(id).dirty;
  }

  /**
   * Push the local snapshot to the remote.
   *  - `synced`   — accepted; `version` is the new remote version.
   *  - `clean`    — nothing to push.
   *  - `conflict` — the remote moved on; `remote` is its current (sealed) snapshot for
   *                 the caller to open + merge + re-put.
   *  - `offline`  — network/other error; still dirty, retry later with the same bytes.
   */
  async pushSnapshot(id) {
    if (!this.#state(id).dirty) return { status: 'clean' };
    const snap = await this.#local.readSnapshot(id);
    if (!snap) return { status: 'clean' };
    try {
      const version = await this.#remote.putSnapshot(id, snap.bytes, this.#state(id).remoteVersion);
      this.#save(id, { remoteVersion: version, dirty: false });
      return { status: 'synced', version };
    } catch (e) {
      if (e instanceof ConflictError) {
        return { status: 'conflict', remote: await this.#remote.readSnapshot(id) };
      }
      return { status: 'offline', error: e };
    }
  }

  /**
   * Pull the remote snapshot.
   *  - `upToDate`    — already in sync (incl. confirming our own write that landed
   *                    despite a lost ack — the idempotency case).
   *  - `fastForward` — local was in sync with the old remote; adopted the new one.
   *  - `conflict`    — both sides changed; `remote` (sealed) for the caller to merge.
   *  - `noRemote`    — the remote has no snapshot yet.
   *  - `offline`     — network/other error.
   */
  async pull(id) {
    let remote;
    try {
      remote = await this.#remote.readSnapshot(id);
    } catch (e) {
      return { status: 'offline', error: e };
    }
    if (!remote) return { status: 'noRemote' };
    const st = this.#state(id);
    if (remote.version === st.remoteVersion) return { status: 'upToDate' };

    const local = await this.#local.readSnapshot(id);
    // Idempotency: if the remote already equals our local bytes, our own push landed
    // (a lost ack) — confirm it rather than mistaking it for a conflict.
    if (local && bytesEqual(local.bytes, remote.bytes)) {
      this.#save(id, { remoteVersion: remote.version, dirty: false });
      return { status: 'upToDate' };
    }
    // Fast-forward (overwrite local with remote) is only safe with POSITIVE evidence the
    // local is disposable: either there is no local snapshot to lose, or we were provably
    // in sync with a known remote version and have no unpushed changes. A dirty doc — OR a
    // doc with local content but no sync record at all (e.g. the dirty flag was lost) —
    // must NOT be clobbered; surface it as a conflict for the caller to merge (§8a).
    const provablyClean = !st.dirty && st.remoteVersion != null;
    if (local && !provablyClean) {
      return { status: 'conflict', remote };
    }
    // No local to lose, or provably clean: adopt the new remote.
    await this.#local.putSnapshot(id, remote.bytes, local ? local.version : null);
    this.#save(id, { remoteVersion: remote.version, dirty: false });
    return { status: 'fastForward', remote };
  }

  /**
   * Record a conflict resolution: store the merged snapshot locally and mark that we've
   * now incorporated remote version `remoteVersion`, so the next push's If-Match matches
   * the server (its current version) and the CAS succeeds. Used by the Replicator after
   * it merges the remote plaintext into the local tree.
   */
  async resolveWith(id, mergedBytes, remoteVersion) {
    const local = await this.#local.readSnapshot(id);
    const version = await this.#local.putSnapshot(id, mergedBytes, local ? local.version : null);
    this.#save(id, { remoteVersion, dirty: true });
    return version;
  }

  /**
   * One sync tick: pull, then (if clear) push. Returns the final status. A `conflict`
   * means the caller must open the remote plaintext, merge, re-put, and reconcile again.
   */
  async reconcile(id) {
    const pulled = await this.pull(id);
    if (pulled.status === 'conflict' || pulled.status === 'offline') return pulled;
    // A fast-forward adopted the remote and (by construction) had no local changes —
    // nothing to push. Surface it rather than masking it with a no-op 'clean' push.
    if (pulled.status === 'fastForward') return pulled;
    return this.pushSnapshot(id);
  }
}
