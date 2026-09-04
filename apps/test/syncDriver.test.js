import { describe, it, expect } from 'vitest';
import { SyncDriver } from '../app/src/core/syncDriver.js';
import { Ok, Offline, Deferred, Rejected, Unauthorized } from '../app/src/core/syncOutcome.js';

// Deterministic clock: the driver's timers are injected, fired by hand. Timer callbacks are synchronous
// (they start the async runTick fire-and-forget); the test flushes microtasks after.
function fakeClock() {
  let t = 0;
  let seq = 1;
  const timers = new Map();
  return {
    now: () => t,
    setTimer: (fn, ms) => { const id = seq++; timers.set(id, { at: t + ms, fn }); return id; },
    clearTimer: (id) => timers.delete(id),
    advance(ms) {
      const target = t + ms;
      let guard = 0;
      while (guard++ < 10_000) {
        let nextId = null;
        let nextAt = Infinity;
        for (const [id, tm] of timers) if (tm.at <= target && tm.at < nextAt) { nextAt = tm.at; nextId = id; }
        if (nextId == null) break;
        t = nextAt;
        const { fn } = timers.get(nextId);
        timers.delete(nextId);
        fn();
      }
      t = target;
    },
    pending: () => timers.size,
  };
}
const flush = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

// A tick that returns a scripted Outcome, optionally blocking (for the single-flight test).
function fakeTick() {
  let outcome = Ok();
  let gate = null;
  let open = null;
  const calls = { n: 0 };
  return {
    calls,
    set(o) { outcome = o; },
    block() { gate = new Promise((r) => { open = r; }); },
    unblock() { const r = open; gate = null; open = null; r?.(); },
    fn: async () => {
      calls.n += 1;
      if (gate) await gate;
      return typeof outcome === 'function' ? outcome(calls.n) : outcome;
    },
  };
}

function makeDriver(tick, clock, extra = {}) {
  let edit = null;
  const driver = new SyncDriver({
    tick: tick.fn,
    subscribeEdits: (cb) => { edit = cb; return () => { edit = null; }; },
    onOnline: null,
    now: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    random: () => 0.5,
    ...extra,
  });
  return { driver, fireEdit: () => edit?.() };
}

describe('SyncDriver', () => {
  it('kicks one tick on start (Ok) then schedules a poll', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const { driver } = makeDriver(tick, clock);
    driver.start();
    await flush();
    expect(tick.calls.n).toBe(1);
    expect(driver.status.state).toBe('idle');
    expect(driver.status.lastSyncedAt).not.toBeNull();
    expect(clock.pending()).toBe(1); // the poll timer
    driver.stop();
  });

  it('debounces a burst of edits into a single tick', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const { driver, fireEdit } = makeDriver(tick, clock, { debounceMs: 800 });
    driver.start();
    await flush(); // start tick (#1)
    fireEdit(); fireEdit(); fireEdit();
    clock.advance(500); await flush();
    expect(tick.calls.n).toBe(1); // still debouncing
    clock.advance(400); await flush(); // crosses 800ms since the last edit
    expect(tick.calls.n).toBe(2); // three edits coalesced into ONE tick
    driver.stop();
  });

  it('is single-flight: a trigger during a tick runs exactly one more pass', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const { driver, fireEdit } = makeDriver(tick, clock, { debounceMs: 0 });
    tick.block();
    driver.start();
    await flush();
    expect(tick.calls.n).toBe(1); // blocked in-flight
    fireEdit(); fireEdit(); // two triggers while blocked → one dirty re-run
    clock.advance(1); await flush();
    expect(tick.calls.n).toBe(1);
    tick.unblock(); await flush();
    expect(tick.calls.n).toBe(2); // exactly ONE follow-up pass
    driver.stop();
  });

  it('backs off on Offline (growing) then resets on Ok', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const { driver } = makeDriver(tick, clock, { backoffMinMs: 1000, backoffCapMs: 60_000 });
    tick.set(Offline());
    driver.start();
    await flush();
    expect(tick.calls.n).toBe(1);
    expect(driver.status.state).toBe('offline');
    clock.advance(1000); await flush(); // first retry
    expect(tick.calls.n).toBe(2);
    clock.advance(1000); await flush(); // too soon for the doubled 2000ms backoff
    expect(tick.calls.n).toBe(2);
    clock.advance(1000); await flush(); // 2000ms elapsed → second retry
    expect(tick.calls.n).toBe(3);
    tick.set(Ok());
    clock.advance(4000); await flush(); // 4000ms backoff → success
    expect(tick.calls.n).toBe(4);
    expect(driver.status.state).toBe('idle');
    driver.stop();
  });

  it('Deferred retries at the fixed short delay and does not stamp last-synced', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const { driver } = makeDriver(tick, clock, { deferredMs: 2000 });
    tick.set(Deferred('row not created yet'));
    driver.start();
    await flush();
    expect(tick.calls.n).toBe(1);
    expect(driver.status.lastSyncedAt).toBeNull(); // deferred is not a sync — nothing converged
    clock.advance(1999); await flush();
    expect(tick.calls.n).toBe(1); // not yet
    clock.advance(1); await flush(); // deferredMs elapsed → retry (a fixed short delay, not the 30s poll)
    expect(tick.calls.n).toBe(2);
    driver.stop();
  });

  it('surfaces Unauthorized and stops (never a silent backoff)', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    let authed = 0;
    const { driver } = makeDriver(tick, clock, { onAuthError: () => { authed += 1; } });
    tick.set(Unauthorized());
    driver.start();
    await flush();
    expect(authed).toBe(1);
    expect(clock.pending()).toBe(0); // stopped — no retry armed
    clock.advance(600_000); await flush();
    expect(tick.calls.n).toBe(1);
  });

  it('surfaces a Rejected (permanent) as a security signal and stops', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    let sec = 0;
    const { driver } = makeDriver(tick, clock, { onSecurity: () => { sec += 1; } });
    tick.set(Rejected({ status: 403 }));
    driver.start();
    await flush();
    expect(sec).toBe(1);
    expect(clock.pending()).toBe(0); // permanent — stopped, not backoff-spinning
  });

  it('stop() cancels every timer and prevents further ticks', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const { driver } = makeDriver(tick, clock);
    driver.start();
    await flush();
    driver.stop();
    expect(clock.pending()).toBe(0);
    clock.advance(60_000); await flush();
    expect(tick.calls.n).toBe(1); // never ticked again
  });

  it('an aborted signal short-circuits ticks (no work on a torn-down session)', async () => {
    const tick = fakeTick();
    const clock = fakeClock();
    const ac = new AbortController();
    const { driver } = makeDriver(tick, clock, { signal: ac.signal });
    ac.abort();
    driver.start();
    await flush();
    expect(tick.calls.n).toBe(0); // aborted before the first kick ran
    expect(clock.pending()).toBe(0);
  });
});
