// SyncSession — everything for ONE open tree's sync, owned as a single object with a single lifetime.
//
// This is the ownership boundary that replaces the old scattered epoch/ref-race dance: a SyncSession
// holds its own AbortController and a SyncDriver, and NOTHING else references its moving parts. The
// composition root builds one, swaps it in with a single `this.sync = session` assignment, and
// `session.start()`; teardown is just `this.sync?.abort()`. A stale/half-built session that lost the
// race is inert — its signal is aborted, so its reconcile tick no-ops and touches nothing.
//
// It is deliberately thin: the WIRING (building the delta controller, the snapshot replicator, and the
// keyring pull/publish thunks from a tree + vault + remote) lives in buildSyncSession; here we only own
// the abort signal, drive the injected reconcile tick, and expose start / syncNow / abort / status. Per
// [[tree-backend-cardinality]] there is one SyncSession per OPEN tree; multi-tree is then just a set of
// these, one alive at a time.

import { SyncDriver } from './syncDriver.js';
import { reconcileTree, reconcileSnapshot, reconcileDeltas } from './syncReconcilers.js';

export class SyncSession {
  #driver;
  #abort;
  #onDispose;
  #started = false;

  /**
   * @param {object} o
   * @param {(signal: AbortSignal) => Promise<import('./syncOutcome.js')>} o.reconcile  one full tick
   * @param {((cb: () => void) => () => void)|null} [o.subscribeEdits]  local-edit trigger (tree.onDelta)
   * @param {(s: object) => void} [o.onStatus]
   * @param {(e?: any) => void} [o.onAuthError]  dead session → re-gate
   * @param {(e?: any) => void} [o.onSecurity]   rollback / keyring fork → surface
   * @param {object} [o.driverOptions]  timer/tuning injection passed through to SyncDriver (tests)
   */
  constructor({ reconcile, subscribeEdits = null, onStatus = () => {}, onAuthError = () => {}, onSecurity = () => {}, onDispose = null, driverOptions = {} }) {
    if (typeof reconcile !== 'function') throw new Error('SyncSession needs a reconcile(signal) => Outcome');
    this.#onDispose = onDispose;
    this.#abort = new AbortController();
    this.#driver = new SyncDriver({
      tick: (signal) => reconcile(signal),
      subscribeEdits,
      onStatus,
      onAuthError,
      onSecurity,
      signal: this.#abort.signal,
      ...driverOptions,
    });
  }

  /** The session's abort signal — passed to the reconcile tick and every channel op it drives. */
  get signal() {
    return this.#abort.signal;
  }

  /** The driver's status snapshot ({ state, lastSyncedAt, pending }) — for a sync indicator. */
  get status() {
    return this.#driver.status;
  }

  /** Begin syncing. Idempotent; a no-op once aborted. */
  start() {
    if (this.#started || this.#abort.signal.aborted) return;
    this.#started = true;
    this.#driver.start();
  }

  /** Force a tick now ("Sync now"). */
  syncNow() {
    if (!this.#abort.signal.aborted) this.#driver.syncNow();
  }

  /** Tear the session down: abort the signal (in-flight reconciles no-op), stop the driver, and dispose
   *  the channels (e.g. the delta controller's onDelta subscription). Idempotent. */
  abort() {
    if (this.#abort.signal.aborted) return;
    this.#abort.abort();
    this.#driver.stop();
    try { this.#onDispose?.(); } catch { /* best effort — teardown must not throw */ }
  }
}

/**
 * Wire a SyncSession for one open tree from its real channel objects. The tree's DATA syncs over three
 * channels — the keyring (vault pull + publish), the snapshot (row-creation in V1), and the delta log
 * (the SyncController the vault assembles) — composed into one dependency-ordered reconcile tick.
 *
 * @param {object} o
 * @param {object} o.tree      a FamilyTree (onDelta / snapshotBytes)
 * @param {string} o.uuid      the server tree id (== the local keyring/doc key after the identity collapse)
 * @param {Uint8Array} o.treeId  the 16 seam id bytes (vault.syncKeyring's treeId argument)
 * @param {object} o.session   the passphrase SealerSession (seal/open) for this tree
 * @param {object} o.vault     the vault (syncKeyring / reconcileKeyring / makeDeltaSync)
 * @param {object} o.remote    a RemoteStore
 * @param {{onStatus?:Function,onAuthError?:Function,onSecurity?:Function}} [o.callbacks]
 * @param {object} [o.driverOptions]  timer/tuning injection (tests)
 * @returns {SyncSession}
 */
export function buildSyncSession({ tree, uuid, treeId, session, vault, remote, callbacks = {}, driverOptions = {} }) {
  const controller = vault.makeDeltaSync({ tree, remote, docId: uuid, session });
  const sealSnapshot = (bytes) => session.seal(bytes, uuid, { kind: 'snapshot' });

  const pullKeyring = () =>
    vault.syncKeyring(uuid, treeId, async (since) => (await remote.readKeyring(uuid, since + 1)).revisions);

  const publishKeyring = () =>
    vault.reconcileKeyring(uuid, {
      getServerHead: async (localHead) => (await remote.readKeyring(uuid, localHead + 1)).head,
      putUpdate: (bytes) => remote.putKeyring(uuid, bytes),
      serverBytesAt: async (rev) => (await remote.readKeyring(uuid, rev)).revisions.find((r) => r.revision === rev)?.bytes ?? null,
    });

  const snapshot = () => reconcileSnapshot({ tree, uuid, remote, sealSnapshot });
  const deltas = () => reconcileDeltas({ controller });
  const reconcile = (signal) => reconcileTree({ pullKeyring, snapshot, publishKeyring, deltas, signal });

  return new SyncSession({
    reconcile,
    subscribeEdits: (cb) => tree.onDelta(cb),
    onStatus: callbacks.onStatus,
    onAuthError: callbacks.onAuthError,
    onSecurity: callbacks.onSecurity,
    onDispose: () => controller.stop(), // release the controller's onDelta subscription on teardown
    driverOptions,
  });
}
