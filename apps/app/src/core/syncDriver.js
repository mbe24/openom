// SyncDriver — a generic scheduler for ONE tree's sync tick.
//
// It knows nothing about keyrings, snapshots, or deltas: it is handed a single
//   tick(signal) => Promise<Outcome>
// (the whole per-tree reconcile, composed by the SyncSession) and owns only WHEN to run it and what
// to do with the outcome. It triggers a tick on a debounced local edit, a jittered periodic poll, a
// reconnect, or an explicit "Sync now"; makes ticks single-flight (a trigger mid-tick folds into one
// more pass); and dispatches the returned Outcome:
//
//   Ok           → converged: reset backoff, stamp last-synced, schedule the next poll
//   Deferred     → a precondition isn't ready yet (row/keyring pending): retry soon, don't stamp synced
//   Conflict     → a conflict bubbled past the reconcilers: retry soon (they resolve it in-loop)
//   Offline      → transient: exponential backoff, silent (the local commit is durable)
//   Rejected     → permanent refusal (quota/forbidden): surface + STOP (retrying can't help)
//   Unauthorized → dead session: surface + STOP (never a silent backoff behind a green UI)
//
// The scheduler machinery (debounce / single-flight / backoff / status) is timer-injectable for tests;
// the tick is opaque, so the driver has no error taxonomy of its own — the Outcome IS the taxonomy.

import { OK, OFFLINE, CONFLICT, REJECTED, DEFERRED, UNAUTHORIZED, Offline } from './syncOutcome.js';

export class SyncDriver {
  #tick;
  #subscribeEdits;
  #onStatus;
  #onAuthError;
  #onSecurity;
  #signal;
  #now;
  #setTimer;
  #clearTimer;
  #random;
  #onOnline;
  #debounceMs;
  #pollMs;
  #deferredMs;
  #backoffMinMs;
  #backoffCapMs;

  #unsubEdits = null;
  #unsubOnline = null;
  #timer = null;
  #debounceTimer = null;
  #ticking = false;
  #dirty = false;
  #stopped = false;
  #backoff = 0;
  #pending = false;
  #lastSyncedAt = null;

  constructor({
    tick,
    subscribeEdits = null, // (cb) => unsubscribe — fires on each local edit (tree.onDelta)
    onStatus = () => {},
    onAuthError = () => {},
    onSecurity = () => {},
    signal = null, // the SyncSession's AbortSignal — passed to tick + checked before scheduling
    now = () => Date.now(),
    setTimer = (fn, ms) => setTimeout(fn, ms),
    clearTimer = (h) => clearTimeout(h),
    onOnline = defaultOnOnline,
    random = () => Math.random(),
    debounceMs = 800,
    pollMs = 30_000,
    deferredMs = 2_000,
    backoffMinMs = 1_000,
    backoffCapMs = 60_000,
  }) {
    if (typeof tick !== 'function') throw new Error('SyncDriver needs a tick(signal) => Outcome');
    this.#tick = tick;
    this.#subscribeEdits = subscribeEdits;
    this.#onStatus = onStatus;
    this.#onAuthError = onAuthError;
    this.#onSecurity = onSecurity;
    this.#signal = signal;
    this.#now = now;
    this.#setTimer = setTimer;
    this.#clearTimer = clearTimer;
    this.#onOnline = onOnline;
    this.#random = random;
    this.#debounceMs = debounceMs;
    this.#pollMs = pollMs;
    this.#deferredMs = deferredMs;
    this.#backoffMinMs = backoffMinMs;
    this.#backoffCapMs = backoffCapMs;
  }

  /** Begin: subscribe to edits + reconnect, kick one tick now, then schedule the poll. */
  start() {
    if (this.#stopped) throw new Error('SyncDriver: start() after stop()');
    if (this.#subscribeEdits) this.#unsubEdits = this.#subscribeEdits(() => this.#onEdit());
    if (this.#onOnline) this.#unsubOnline = this.#onOnline(() => this.#onReconnect());
    this.#kick();
  }

  /** Force a tick now ("Sync now"): reset backoff and run. */
  syncNow() {
    this.#backoff = 0;
    this.#kick();
  }

  /** Stop all timers + subscriptions. An in-flight tick's result is discarded (guarded by #stopped). */
  stop() {
    this.#stopped = true;
    this.#clear(this.#timer);
    this.#clear(this.#debounceTimer);
    this.#timer = this.#debounceTimer = null;
    try { this.#unsubEdits?.(); } catch { /* best effort */ }
    try { this.#unsubOnline?.(); } catch { /* best effort */ }
    this.#unsubEdits = this.#unsubOnline = null;
  }

  get status() {
    return {
      state: this.#ticking ? 'syncing' : this.#backoff ? 'offline' : 'idle',
      lastSyncedAt: this.#lastSyncedAt,
      pending: this.#pending,
    };
  }

  #onEdit() {
    this.#pending = true;
    this.#clear(this.#debounceTimer);
    this.#debounceTimer = this.#setTimer(() => { this.#debounceTimer = null; this.#kick(); }, this.#debounceMs);
  }

  #onReconnect() {
    this.#backoff = 0; // a fresh network — retry now rather than waiting out the backoff
    this.#kick();
  }

  #kick() {
    if (this.#stopped || this.#signal?.aborted) return;
    if (this.#ticking) { this.#dirty = true; return; } // single-flight — fold into the running tick
    void this.#runTick();
  }

  async #runTick() {
    this.#ticking = true;
    this.#clear(this.#timer);
    this.#timer = null;
    this.#emit('syncing');
    let outcome;
    try {
      do {
        this.#dirty = false;
        outcome = await this.#tick(this.#signal);
      } while (this.#dirty && !this.#stopped && !this.#signal?.aborted);
    } catch (e) {
      // A tick should return an Outcome, not throw — but if a reconciler leaks, treat it as offline
      // rather than crash the loop or leak an unhandled rejection.
      outcome = Offline(e);
    } finally {
      this.#ticking = false;
    }
    if (this.#stopped || this.#signal?.aborted) return;
    this.#dispatch(outcome);
  }

  #dispatch(outcome) {
    switch (outcome?.tag) {
      case OK:
        this.#backoff = 0;
        this.#lastSyncedAt = this.#now();
        this.#pending = false;
        this.#emit('idle');
        this.#schedulePoll();
        return;
      case DEFERRED:
        // a precondition isn't ready (row/keyring pending) — come back soon, stay 'pending', don't
        // claim we synced. A fixed short retry (not exponential) so bootstrap converges promptly.
        this.#emit('syncing');
        this.#scheduleTimer(this.#deferredMs);
        return;
      case CONFLICT:
        // conflicts are resolved inside the reconcilers' merge loop; one that bubbles here just retries
        this.#scheduleTimer(this.#deferredMs);
        return;
      case UNAUTHORIZED:
        this.#emit('offline');
        this.#surface(this.#onAuthError, outcome);
        this.stop(); // a dead session must not spin behind a green UI
        return;
      case REJECTED:
        this.#emit('offline');
        this.#surface(this.#onSecurity, outcome.reason ?? outcome);
        this.stop(); // permanent refusal — retrying can't help
        return;
      case OFFLINE:
      default:
        this.#backoff = Math.min(this.#backoff ? this.#backoff * 2 : this.#backoffMinMs, this.#backoffCapMs);
        this.#emit('offline');
        this.#scheduleTimer(this.#backoff);
        return;
    }
  }

  #schedulePoll() {
    const jittered = Math.round(this.#pollMs * (0.85 + 0.3 * this.#random())); // ±15% so peers don't align
    this.#scheduleTimer(jittered);
  }

  #scheduleTimer(ms) {
    if (this.#stopped || this.#signal?.aborted) return;
    this.#clear(this.#timer);
    this.#timer = this.#setTimer(() => { this.#timer = null; this.#kick(); }, ms);
  }

  #emit(state) {
    try {
      this.#onStatus({ state, lastSyncedAt: this.#lastSyncedAt, pending: this.#pending });
    } catch { /* a status listener must never break the sync loop */ }
  }

  #surface(cb, arg) {
    try { cb(arg); } catch { /* a surface callback must never become an unhandled rejection */ }
  }

  #clear(h) {
    if (h != null) this.#clearTimer(h);
  }
}

function defaultOnOnline(cb) {
  if (typeof window === 'undefined' || !window.addEventListener) return null;
  const handler = () => cb();
  window.addEventListener('online', handler);
  return () => window.removeEventListener('online', handler);
}
