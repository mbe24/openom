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

import { ConflictError } from './store.js';

const bytesEqual = (a, b) =>
  a === b || (!!a && !!b && a.length === b.length && a.every((x, i) => x === b[i]));

export class SyncStore {
  #local;
  #remote;
  #synced = new Map(); // id -> remote version we're in sync with
  #dirty = new Set(); // ids with local changes not yet confirmed on the remote

  constructor(local, remote) {
    if (!local || !remote) throw new Error('SyncStore needs a local and a remote store');
    this.#local = local;
    this.#remote = remote;
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
    this.#dirty.add(id);
    return this.#local.append(id, updates);
  }
  async delete(id) {
    this.#dirty.delete(id);
    this.#synced.delete(id);
    return this.#local.delete(id);
  }

  /** Local commit — the synchronous durability point. Marks the doc for later push. */
  async putSnapshot(id, bytes, expected = null) {
    const version = await this.#local.putSnapshot(id, bytes, expected);
    this.#dirty.add(id);
    return version;
  }

  /** Whether the doc has local changes not yet confirmed on the remote. */
  isDirty(id) {
    return this.#dirty.has(id);
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
    if (!this.#dirty.has(id)) return { status: 'clean' };
    const snap = await this.#local.readSnapshot(id);
    if (!snap) return { status: 'clean' };
    try {
      const version = await this.#remote.putSnapshot(id, snap.bytes, this.#synced.get(id) ?? null);
      this.#synced.set(id, version);
      this.#dirty.delete(id);
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
    if (remote.version === this.#synced.get(id)) return { status: 'upToDate' };

    const local = await this.#local.readSnapshot(id);
    // Idempotency: if the remote already equals our local bytes, our own push landed
    // (a lost ack) — confirm it rather than mistaking it for a conflict.
    if (local && bytesEqual(local.bytes, remote.bytes)) {
      this.#synced.set(id, remote.version);
      this.#dirty.delete(id);
      return { status: 'upToDate' };
    }
    if (this.#dirty.has(id)) {
      return { status: 'conflict', remote };
    }
    // Local matched the old remote; fast-forward the cache to the new remote.
    await this.#local.putSnapshot(id, remote.bytes, local ? local.version : null);
    this.#synced.set(id, remote.version);
    return { status: 'fastForward', remote };
  }

  /**
   * One sync tick: pull, then (if clear) push. Returns the final status. A `conflict`
   * means the caller must open the remote plaintext, merge, re-put, and reconcile again.
   */
  async reconcile(id) {
    const pulled = await this.pull(id);
    if (pulled.status === 'conflict' || pulled.status === 'offline') return pulled;
    return this.pushSnapshot(id);
  }
}
