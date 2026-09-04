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

export class SyncSession {
  #driver;
  #abort;
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
  constructor({ reconcile, subscribeEdits = null, onStatus = () => {}, onAuthError = () => {}, onSecurity = () => {}, driverOptions = {} }) {
    if (typeof reconcile !== 'function') throw new Error('SyncSession needs a reconcile(signal) => Outcome');
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

  /** Tear the session down: abort the signal (in-flight reconciles no-op) then stop the driver. Idempotent. */
  abort() {
    if (this.#abort.signal.aborted) return;
    this.#abort.abort();
    this.#driver.stop();
  }
}
