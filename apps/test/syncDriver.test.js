import { describe, it, expect } from 'vitest';
import { SyncDriver } from '../app/src/core/syncDriver.js';
import { AuthError } from '../app/src/core/store.js';

// A deterministic clock: the driver's timers are injected, so we fire them by hand. Timer callbacks
// are synchronous (they start the async runTick fire-and-forget); the test flushes microtasks after.
function fakeClock() {
  let t = 0;
  let seq = 1;
  const timers = new Map();
  return {
    now: () => t,
    setTimer: (fn, ms) => {
      const id = seq++;
      timers.set(id, { at: t + ms, fn });
      return id;
    },
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
// Drain the microtask + macrotask queue (real timers) so a fire-and-forget runTick settles.
const flush = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

function fakeController() {
  const calls = { sync: 0, bootstrap: 0 };
  let mode = 'ok';
  let gate = null; // while set, sync() awaits it (a one-shot block for the single-flight test)
  let openGate = null;
  return {
    calls,
    set(m) { mode = m; },
    block() { gate = new Promise((r) => { openGate = r; }); }, // call BEFORE the tick you want to stall
    unblock() { const r = openGate; gate = null; openGate = null; r?.(); },
    async sync() {
      calls.sync += 1;
      if (gate) await gate;
      if (mode === 'auth') throw new AuthError('401');
      if (mode === 'offline') throw new Error('network down');
      if (mode === 'rollback') throw new Error('the server rolled back');
      if (mode === 'gone') { const e = new Error('history stripped'); e.status = 410; throw e; }
    },
    async bootstrap() { calls.bootstrap += 1; },
  };
}

function makeDriver(controller, clock, extra = {}) {
  let edit = null;
  const driver = new SyncDriver({
    controller,
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
  it('kicks one tick on start, then schedules a poll', async () => {
    const c = fakeController();
    const clock = fakeClock();
    const { driver } = makeDriver(c, clock);
    driver.start();
    await flush();
    expect(c.calls.sync).toBe(1);
    expect(clock.pending()).toBe(1); // the poll timer
    driver.stop();
  });

  it('debounces a burst of edits into a single tick', async () => {
    const c = fakeController();
    const clock = fakeClock();
    const { driver, fireEdit } = makeDriver(c, clock, { debounceMs: 800 });
    driver.start();
    await flush(); // start's tick (sync #1)
    fireEdit(); fireEdit(); fireEdit();
    clock.advance(500); await flush();
    expect(c.calls.sync).toBe(1); // still debouncing — no extra tick yet
    clock.advance(400); await flush(); // crosses 800ms since the last edit
    expect(c.calls.sync).toBe(2); // the three edits coalesced into ONE tick
    driver.stop();
  });

  it('is single-flight: a trigger during a tick runs exactly one more pass', async () => {
    const c = fakeController();
    const clock = fakeClock();
    const { driver, fireEdit } = makeDriver(c, clock, { debounceMs: 0 });
    c.block(); // the start tick will block inside sync()
    driver.start();
    await flush();
    expect(c.calls.sync).toBe(1); // in-flight, blocked

    fireEdit(); fireEdit(); // two triggers while blocked → collapse to a single dirty re-run
    clock.advance(1); await flush();
    expect(c.calls.sync).toBe(1); // nothing new started — single-flight held

    c.unblock(); await flush();
    expect(c.calls.sync).toBe(2); // exactly ONE follow-up pass, not two
    driver.stop();
  });

  it('backs off on offline (growing), then resets on success', async () => {
    const c = fakeController();
    const clock = fakeClock();
    const { driver } = makeDriver(c, clock, { backoffMinMs: 1000, backoffCapMs: 60_000 });
    c.set('offline');
    driver.start();
    await flush();
    expect(c.calls.sync).toBe(1);
    expect(driver.status.state).toBe('offline');

    clock.advance(1000); await flush(); // first backoff retry
    expect(c.calls.sync).toBe(2);
    clock.advance(1000); await flush(); // too soon for the doubled (2000ms) backoff
    expect(c.calls.sync).toBe(2);
    clock.advance(1000); await flush(); // now 2000ms elapsed → second retry
    expect(c.calls.sync).toBe(3);

    c.set('ok');
    clock.advance(4000); await flush(); // 4000ms backoff → success
    expect(c.calls.sync).toBe(4);
    expect(driver.status.state).toBe('idle');
    expect(driver.status.lastSyncedAt).not.toBeNull();
    driver.stop();
  });

  it('surfaces AuthError and stops (never a silent backoff)', async () => {
    const c = fakeController();
    const clock = fakeClock();
    let authed = 0;
    const { driver } = makeDriver(c, clock, { onAuthError: () => { authed += 1; } });
    c.set('auth');
    driver.start();
    await flush();
    expect(authed).toBe(1);
    expect(clock.pending()).toBe(0); // stopped — no retry timer armed
    clock.advance(600_000); await flush();
    expect(c.calls.sync).toBe(1); // never ticked again
  });

  it('surfaces a rollback as a security signal and keeps polling', async () => {
    const c = fakeController();
    const clock = fakeClock();
    let security = 0;
    const { driver } = makeDriver(c, clock, { onSecurity: () => { security += 1; } });
    c.set('rollback');
    driver.start();
    await flush();
    expect(security).toBe(1);
    expect(clock.pending()).toBe(1); // a poll is scheduled — not stopped, not backoff-spinning
    driver.stop();
  });

  it('re-bootstraps on a 410 (history stripped)', async () => {
    const c = fakeController();
    const clock = fakeClock();
    const { driver } = makeDriver(c, clock);
    c.set('gone');
    driver.start();
    await flush();
    expect(c.calls.bootstrap).toBe(1);
    driver.stop();
  });

  it('runs syncKeyring BEFORE the pull each tick, and stop() cancels everything', async () => {
    const c = fakeController();
    const clock = fakeClock();
    const order = [];
    const { driver } = makeDriver(c, clock, {
      syncKeyring: async () => { order.push('keyring'); },
    });
    const origSync = c.sync.bind(c);
    c.sync = async () => { order.push('sync'); return origSync(); };
    driver.start();
    await flush();
    expect(order).toEqual(['keyring', 'sync']);
    driver.stop();
    expect(clock.pending()).toBe(0); // all timers cleared
  });

  it('re-cuts the snapshot after the delta threshold', async () => {
    const c = fakeController();
    const clock = fakeClock();
    let recuts = 0;
    const { driver, fireEdit } = makeDriver(c, clock, {
      recut: async () => { recuts += 1; },
      recutEveryDeltas: 3,
      debounceMs: 0,
    });
    driver.start();
    await flush();
    expect(recuts).toBe(0);
    fireEdit(); fireEdit(); // 2 edits < threshold
    clock.advance(1); await flush();
    expect(recuts).toBe(0);
    fireEdit(); // 3rd edit crosses the threshold; the tick after it re-cuts
    clock.advance(1); await flush();
    expect(recuts).toBe(1);
    driver.stop();
  });
});
