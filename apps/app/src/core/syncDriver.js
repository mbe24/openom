// SyncDriver — schedules a SyncController toward convergence. The controller does exactly ONE
// tick (push then pull) and THROWS on a network failure; it has no notion of "when" or "retry".
// The driver owns that: it triggers a tick on a debounced local edit, a periodic poll, a
// reconnect, or an explicit "Sync now", makes ticks single-flight, and translates the thrown
// outcomes into a small state machine —
//   transient (offline / 5xx)      → exponential backoff, retry (offline is silent + normal)
//   AuthError (dead session)       → surface + stop (never spin a dead session behind a green UI)
//   RegressionError / rollback     → surface as a security signal (partly-trusted server replay)
//   410 bootstrap-required         → re-run controller.bootstrap()
//
// Two ordering rules matter: the keyring is synced BEFORE the pull each tick, so a landed delta
// can be verified at its governing revision (SyncController.pull holds, not drops, an entry whose
// keyring revision isn't retained yet); and the snapshot baseline is re-cut on a THROTTLE (edits
// or time), not every tick — compact() otherwise only runs at hydrate, and SyncStore.isDirty is
// set by every append so it can't gate a snapshot push. All merge/verify live in the controller;
// this stays a pure scheduler, fully timer-injectable for tests.

import { AuthError } from './store.js';

const isRollback = (e) =>
  e?.name === 'RegressionError' || e?.code === 'revision_rollback' || /roll(?:ed)? ?back/i.test(e?.message ?? '');
const isBootstrapRequired = (e) => e?.status === 410 || e?.code === 'bootstrap_required';

export class SyncDriver {
  #controller;
  #syncKeyring;
  #recut;
  #onStatus;
  #onAuthError;
  #onSecurity;
  #now;
  #setTimer;
  #clearTimer;
  #random;
  #debounceMs;
  #pollMs;
  #backoffMinMs;
  #backoffCapMs;
  #recutEveryDeltas;
  #recutEveryMs;

  #subscribeEdits;
  #onOnline;
  #unsubEdits = null;
  #unsubOnline = null;

  #timer = null; // the poll / backoff timer
  #debounceTimer = null;
  #ticking = false;
  #dirty = false; // a trigger arrived mid-tick → run once more
  #stopped = false;
  #backoff = 0;
  #pending = false;
  #lastSyncedAt = null;
  #editsSinceRecut = 0;
  #lastRecutAt = 0;

  constructor({
    controller,
    subscribeEdits = null, // (cb) => unsubscribe — fires on each local edit (tree.onDelta)
    syncKeyring = null, // async () => void — pull+verify keyring successors before the pull
    recut = null, // async () => void — force a snapshot cut + push (bounded staleness)
    onStatus = () => {},
    onAuthError = () => {},
    onSecurity = () => {},
    now = () => Date.now(),
    setTimer = (fn, ms) => setTimeout(fn, ms),
    clearTimer = (h) => clearTimeout(h),
    onOnline = defaultOnOnline,
    random = () => Math.random(),
    debounceMs = 800,
    pollMs = 30_000,
    backoffMinMs = 1_000,
    backoffCapMs = 60_000,
    recutEveryDeltas = 50,
    recutEveryMs = 5 * 60_000,
  }) {
    if (!controller) throw new Error('SyncDriver needs a controller');
    this.#controller = controller;
    this.#subscribeEdits = subscribeEdits;
    this.#syncKeyring = syncKeyring;
    this.#recut = recut;
    this.#onStatus = onStatus;
    this.#onAuthError = onAuthError;
    this.#onSecurity = onSecurity;
    this.#now = now;
    this.#setTimer = setTimer;
    this.#clearTimer = clearTimer;
    this.#onOnline = onOnline;
    this.#random = random;
    this.#debounceMs = debounceMs;
    this.#pollMs = pollMs;
    this.#backoffMinMs = backoffMinMs;
    this.#backoffCapMs = backoffCapMs;
    this.#recutEveryDeltas = recutEveryDeltas;
    this.#recutEveryMs = recutEveryMs;
    this.#lastRecutAt = now();
  }

  /** Begin syncing: subscribe to edits + reconnect, kick one tick now, and schedule the poll. */
  start() {
    if (this.#stopped) throw new Error('SyncDriver: start() after stop()');
    if (this.#subscribeEdits) this.#unsubEdits = this.#subscribeEdits(() => this.#onEdit());
    if (this.#onOnline) this.#unsubOnline = this.#onOnline(() => this.#onReconnect());
    this.#kick();
  }

  /** Force a tick now (a "Sync now" control): reset backoff and run. */
  syncNow() {
    this.#backoff = 0;
    this.#kick();
  }

  /** Stop all timers + subscriptions. An in-flight tick's result is discarded (guarded by #stopped). */
  stop() {
    this.#stopped = true;
    this.#clear(this.#timer);
    this.#clear(this.#debounceTimer);
    this.#timer = null;
    this.#debounceTimer = null;
    try { this.#unsubEdits?.(); } catch { /* best effort */ }
    try { this.#unsubOnline?.(); } catch { /* best effort */ }
    this.#unsubEdits = null;
    this.#unsubOnline = null;
  }

  get status() {
    return { state: this.#ticking ? 'syncing' : this.#backoff ? 'offline' : 'idle', lastSyncedAt: this.#lastSyncedAt, pending: this.#pending };
  }

  #onEdit() {
    this.#pending = true;
    this.#editsSinceRecut += 1;
    this.#clear(this.#debounceTimer);
    this.#debounceTimer = this.#setTimer(() => { this.#debounceTimer = null; this.#kick(); }, this.#debounceMs);
  }

  #onReconnect() {
    this.#backoff = 0; // a fresh network — retry immediately rather than waiting out the backoff
    this.#kick();
  }

  #kick() {
    if (this.#stopped) return;
    if (this.#ticking) { this.#dirty = true; return; } // single-flight — fold into the running tick
    void this.#runTick();
  }

  async #runTick() {
    this.#ticking = true;
    this.#clear(this.#timer);
    this.#timer = null;
    this.#emit('syncing');
    try {
      do {
        this.#dirty = false;
        await this.#oneTick();
      } while (this.#dirty && !this.#stopped); // a trigger during the tick runs one more pass
      this.#backoff = 0;
      this.#lastSyncedAt = this.#now();
      this.#pending = false;
      if (!this.#stopped) { this.#emit('idle'); this.#schedulePoll(); }
    } catch (e) {
      await this.#handleError(e);
    } finally {
      this.#ticking = false;
    }
  }

  async #oneTick() {
    if (this.#syncKeyring) await this.#syncKeyring(); // keyring first: landed deltas verify at their revision
    await this.#controller.sync(); // push then pull (may throw → caught in #runTick)
    await this.#maybeRecut();
  }

  async #maybeRecut() {
    if (!this.#recut) return;
    const byCount = this.#editsSinceRecut >= this.#recutEveryDeltas;
    const byTime = this.#editsSinceRecut > 0 && this.#now() - this.#lastRecutAt >= this.#recutEveryMs;
    if (!byCount && !byTime) return;
    await this.#recut(); // caller guards on "only if the local snapshot version changed"
    this.#editsSinceRecut = 0;
    this.#lastRecutAt = this.#now();
  }

  async #handleError(e) {
    if (e instanceof AuthError || e?.name === 'AuthError') {
      // A dead session must never hide behind a silent-offline backoff — surface it and stop.
      this.#emit('offline');
      this.#onAuthError(e);
      this.stop();
      return;
    }
    if (isRollback(e)) {
      this.#onSecurity(e); // a partly-trusted server replayed a superseded snapshot — surface, keep polling
      if (!this.#stopped) { this.#emit('idle'); this.#schedulePoll(); }
      return;
    }
    if (isBootstrapRequired(e)) {
      try {
        await this.#controller.bootstrap();
        if (!this.#stopped) { this.#emit('idle'); this.#schedulePoll(); }
        return;
      } catch (be) {
        e = be; // re-bootstrap itself failed → fall through to backoff
      }
    }
    // Transient (offline / 5xx / network): back off and retry. Offline is normal + silent.
    if (this.#stopped) return;
    this.#backoff = Math.min(this.#backoff ? this.#backoff * 2 : this.#backoffMinMs, this.#backoffCapMs);
    this.#emit('offline');
    this.#scheduleTimer(this.#backoff);
  }

  #schedulePoll() {
    const jittered = Math.round(this.#pollMs * (0.85 + 0.3 * this.#random())); // ±15% so peers don't align
    this.#scheduleTimer(jittered);
  }

  #scheduleTimer(ms) {
    if (this.#stopped) return;
    this.#clear(this.#timer);
    this.#timer = this.#setTimer(() => { this.#timer = null; this.#kick(); }, ms);
  }

  #emit(state) {
    try {
      this.#onStatus({ state, lastSyncedAt: this.#lastSyncedAt, pending: this.#pending });
    } catch { /* a status listener must never break the sync loop */ }
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
