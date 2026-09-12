// The sync driver's cadence scheduler (OPE-410): every trigger (edit/poll/online/initial/manual) routes
// through one rate-limited scheduler so ticks are never started closer than the cadence floor — R2 rejects
// more than one write per second to the same object key (heads/{replica}, snapshot), so the driver must not
// drive pointer rewrites faster than that. Uses fake timers; the worker.syncNow tick is stubbed.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startSyncDriver, DEFAULT_SYNC_CADENCE_MS } from '../app/src/core/appCoreClient.js';
import { makeError } from '../app/src/core/errorModel.js';

// A worker stub whose syncNow resolves on the microtask queue, recording the fake-clock time of each call.
function fakeWorker(result = { state: 'ok' }) {
  const callsAt = [];
  return {
    callsAt,
    syncNow: vi.fn(async () => {
      callsAt.push(Date.now());
      return typeof result === 'function' ? result() : result;
    }),
  };
}

// Advance the fake clock in small steps so queued microtasks (the async tick body) run between timer fires.
async function advance(ms, step = 50) {
  if (ms <= 0) { await vi.advanceTimersByTimeAsync(0); return; } // fire 0-delay timers + flush microtasks
  for (let elapsed = 0; elapsed < ms; elapsed += step) {
    await vi.advanceTimersByTimeAsync(Math.min(step, ms - elapsed));
  }
}

describe('sync driver cadence', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('never starts two ticks closer than the default floor, however fast edits arrive', async () => {
    const w = fakeWorker();
    let fireEdit = () => {};
    const driver = startSyncDriver(w, 'doc', { subscribeEdits: (fn) => { fireEdit = fn; return () => {}; } });

    // Hammer edits every 100ms for 5s — far faster than the ~1.1s floor.
    for (let t = 0; t < 5000; t += 100) {
      fireEdit();
      await advance(100);
    }
    driver.stop();

    // With a ≥1s floor, 5s of continuous editing yields only a handful of ticks — never one per edit.
    expect(w.syncNow.mock.calls.length).toBeLessThanOrEqual(6);
    // And consecutive ticks are spaced at least the floor apart (allow a small scheduling epsilon).
    for (let i = 1; i < w.callsAt.length; i += 1) {
      expect(w.callsAt[i] - w.callsAt[i - 1]).toBeGreaterThanOrEqual(DEFAULT_SYNC_CADENCE_MS - 60);
    }
  });

  it('a poll landing right after an edit tick is deferred to the floor, not run immediately', async () => {
    const w = fakeWorker();
    let fireEdit = () => {};
    const driver = startSyncDriver(w, 'doc', { subscribeEdits: (fn) => { fireEdit = fn; return () => {}; } });

    await advance(0);          // initial catch-up tick fires at t≈0
    expect(w.syncNow).toHaveBeenCalledTimes(1);
    fireEdit();                // an edit right after
    await advance(500);        // still inside the floor window
    expect(w.syncNow).toHaveBeenCalledTimes(1);
    await advance(700);        // now past the floor (~1.1s total)
    expect(w.syncNow).toHaveBeenCalledTimes(2);
    driver.stop();
  });

  it('honors a configurable cadence, clamped to a 1s minimum', async () => {
    // A generous cadence stretches the floor…
    const slow = fakeWorker();
    let slowEdit = () => {};
    const d1 = startSyncDriver(slow, 'doc', { cadenceMs: 3000, subscribeEdits: (fn) => { slowEdit = fn; return () => {}; } });
    await advance(0);
    expect(slow.syncNow).toHaveBeenCalledTimes(1);
    slowEdit();
    await advance(2500);
    expect(slow.syncNow).toHaveBeenCalledTimes(1); // still within the 3s floor
    await advance(700);
    expect(slow.syncNow).toHaveBeenCalledTimes(2);
    d1.stop();

    // …but a sub-second cadence is clamped up to 1s (never below R2's per-key ceiling).
    const fast = fakeWorker();
    let fastEdit = () => {};
    const d2 = startSyncDriver(fast, 'doc', { cadenceMs: 200, subscribeEdits: (fn) => { fastEdit = fn; return () => {}; } });
    await advance(0);
    fastEdit();
    await advance(400);
    expect(fast.syncNow).toHaveBeenCalledTimes(1); // 200ms request was clamped to ≥1s
    await advance(700);
    expect(fast.syncNow).toHaveBeenCalledTimes(2);
    d2.stop();
  });

  it('backs off by Retry-After on a rate-limited tick instead of waiting the full poll', async () => {
    const statuses = [];
    // First tick 429s with Retry-After 3s; subsequent ticks succeed.
    let first = true;
    const w = fakeWorker(() => {
      if (first) { first = false; return { state: 'error', error: makeError('rate_limited', { retryAfter: 3 }) }; }
      return { state: 'ok' };
    });
    const driver = startSyncDriver(w, 'doc', { onStatus: (s) => statuses.push(s) });

    await advance(0);
    expect(w.syncNow).toHaveBeenCalledTimes(1);
    expect(statuses.at(-1).state).toBe('offline'); // retriable → offline, not a hard error
    await advance(2000);
    expect(w.syncNow).toHaveBeenCalledTimes(1);     // still backing off (Retry-After was 3s)
    await advance(1200);
    expect(w.syncNow).toHaveBeenCalledTimes(2);     // re-armed at ~3s, well before the 30s poll
    expect(statuses.at(-1).state).toBe('synced');
    driver.stop();
  });
});
