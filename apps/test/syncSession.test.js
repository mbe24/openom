import { describe, it, expect } from 'vitest';
import { SyncSession, buildSyncSession } from '../app/src/core/syncSession.js';
import { Ok } from '../app/src/core/syncOutcome.js';

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

function makeSession(reconcile, clock, extra = {}) {
  return new SyncSession({
    reconcile,
    subscribeEdits: null,
    driverOptions: { now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer, onOnline: null, random: () => 0.5 },
    ...extra,
  });
}

describe('SyncSession', () => {
  it('start() drives the reconcile tick with a live (un-aborted) signal', async () => {
    const clock = fakeClock();
    const seen = [];
    const session = makeSession(async (signal) => { seen.push(signal.aborted); return Ok(); }, clock);
    session.start();
    await flush();
    expect(seen).toEqual([false]);
    expect(session.status.lastSyncedAt).not.toBeNull();
    session.abort();
  });

  it('abort() aborts the signal and stops the driver — no further ticks', async () => {
    const clock = fakeClock();
    const calls = { n: 0 };
    const session = makeSession(async () => { calls.n += 1; return Ok(); }, clock);
    session.start();
    await flush();
    expect(calls.n).toBe(1);
    session.abort();
    expect(session.signal.aborted).toBe(true);
    expect(clock.pending()).toBe(0); // the poll timer was cancelled
    clock.advance(120_000); await flush();
    expect(calls.n).toBe(1); // never ticked again
  });

  it('abort() is idempotent and start() after abort is a no-op', async () => {
    const clock = fakeClock();
    const calls = { n: 0 };
    const session = makeSession(async () => { calls.n += 1; return Ok(); }, clock);
    session.abort();
    session.abort(); // no throw
    session.start(); // inert once aborted
    await flush();
    expect(calls.n).toBe(0);
    expect(session.signal.aborted).toBe(true);
  });

  it('buildSyncSession drives keyring-pull → snapshot → keyring-publish → deltas, and disposes the controller on abort', async () => {
    const clock = fakeClock();
    const calls = [];
    const controller = {
      sync: async () => { calls.push('deltas'); return { merged: 0, held: null }; },
      stop: () => calls.push('dispose'),
    };
    const tree = { onDelta: () => () => {}, snapshotBytes: () => new Uint8Array([7]) };
    const sealer = { seal: async (b, _id, { kind }) => new Uint8Array([kind === 'snapshot' ? 0x5 : 0xd, ...b]) };
    const remote = {
      readSnapshot: async () => { calls.push('snap'); return { bytes: new Uint8Array([1]) }; }, // row exists → no create
      readKeyring: async () => ({ revisions: [], head: 0 }),
      putKeyring: async () => {},
    };
    const vault = {
      makeDeltaSync: () => controller,
      syncKeyring: async (_uuid, _treeId, fetch) => { calls.push('kpull'); await fetch(0); return { revision: 0, changed: false }; },
      reconcileKeyring: async (_uuid, { getServerHead }) => { calls.push('kpub'); await getServerHead(0); return { head: 0 }; },
    };
    const sync = buildSyncSession({
      tree, uuid: 'u', treeId: new Uint8Array(16), session: sealer, vault, remote,
      driverOptions: { now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer, onOnline: null, random: () => 0.5 },
    });
    sync.start();
    await flush();
    expect(calls).toEqual(['kpull', 'snap', 'kpub', 'deltas']); // dependency order
    expect(sync.status.lastSyncedAt).not.toBeNull();
    sync.abort();
    expect(calls).toContain('dispose'); // controller.stop() ran on teardown
  });

  it('a reconcile in flight when abort() fires sees the aborted signal', async () => {
    const clock = fakeClock();
    let release;
    const gate = new Promise((r) => { release = r; });
    let abortedDuringTick = null;
    const session = makeSession(async (signal) => {
      await gate; // hold the tick open
      abortedDuringTick = signal.aborted;
      return Ok();
    }, clock);
    session.start();
    await flush(); // tick started, blocked on the gate
    session.abort(); // abort while the tick is in flight
    release();
    await flush();
    expect(abortedDuringTick).toBe(true); // the in-flight reconcile observed the abort
  });
});
