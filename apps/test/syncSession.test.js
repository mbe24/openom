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
      // The snapshot channel now reconciles the base via controller.adopt() (row exists → nothing to adopt).
      adopt: async () => { calls.push('snap'); return { rowExists: true, adopted: false }; },
      sync: async () => { calls.push('deltas'); return { merged: 0, held: null }; },
      stop: () => calls.push('dispose'),
    };
    const tree = { onDelta: () => () => {}, snapshotBytes: () => new Uint8Array([7]) };
    const sealer = { seal: async (b, _id, { kind }) => new Uint8Array([kind === 'snapshot' ? 0x5 : 0xd, ...b]) };
    const remote = {
      readKeyring: async () => ({ revisions: [], head: 0 }),
      putKeyring: async () => {},
    };
    const vault = {
      makeDeltaSync: () => controller,
      syncKeyring: async (_uuid, _treeId, fetch) => { calls.push('kpull'); await fetch(0); return { revision: 0, changed: false }; },
      reconcileKeyring: async (_uuid, { getServerHead }) => { calls.push('kpub'); await getServerHead(0); return { head: 0 }; },
      // No keyring loaded in this mock → the advisory membership channel is a clean no-op (tested on its own).
      membershipSummary: async () => null,
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
});

describe('buildSyncSession — writer base self-heal (A7)', () => {
  function makeShareSession({ adopt, hasBeenShared = async () => true, canCommit = async () => true, pulledSeq = 4 } = {}) {
    const clock = fakeClock();
    const puts = [];
    const controller = {
      adopt,
      pulledSeq: () => pulledSeq,
      sync: async () => ({ merged: 0, held: null }),
      stop: () => {},
    };
    const tree = { onDelta: () => () => {}, snapshotBytes: () => new Uint8Array([0x7, 0x7]) };
    const sealer = { seal: async (b, _id, opts) => ({ kind: opts.kind, covers: opts.coversThroughSeq, body: b }) };
    const remote = {
      readKeyring: async () => ({ revisions: [], head: 0 }),
      putKeyring: async () => {},
      putSnapshot: async (id, sealed, expected) => { puts.push({ id, sealed, expected }); },
    };
    const vault = {
      makeDeltaSync: () => controller,
      syncKeyring: async (_u, _t, fetch) => { await fetch(0); return { revision: 0, changed: false }; },
      reconcileKeyring: async (_u, { getServerHead }) => { await getServerHead(0); return { head: 0 }; },
      hasBeenShared,
      canCommit,
    };
    const sync = buildSyncSession({
      tree, uuid: 'u', treeId: new Uint8Array(16), session: sealer, vault, remote, memberId: 'me',
      driverOptions: { now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer, onOnline: null, random: () => 0.5 },
    });
    return { sync, puts };
  }
  const staleBase = async () => ({ rowExists: true, adopted: false, coversThroughSeq: 0, version: 'etag-1' });

  it('a committer publishes a signed base covering pulledSeq+1 when the shared base still subsumes nothing', async () => {
    const { sync, puts } = makeShareSession({ adopt: staleBase, pulledSeq: 4 });
    sync.start();
    await flush();
    expect(puts).toHaveLength(1);
    expect(puts[0].expected).toBe('etag-1'); // CAS-UPDATE against the base etag
    expect(puts[0].sealed.kind).toBe('snapshot');
    expect(puts[0].sealed.covers).toBe(5); // pulledSeq(4) + 1 (exclusive)
    sync.abort();
  });

  it('a non-committer (editor) does not publish a base', async () => {
    const { sync, puts } = makeShareSession({ adopt: staleBase, canCommit: async () => false });
    sync.start();
    await flush();
    expect(puts).toHaveLength(0);
    sync.abort();
  });

  it('a never-shared tree does not publish a base', async () => {
    const { sync, puts } = makeShareSession({ adopt: staleBase, hasBeenShared: async () => false });
    sync.start();
    await flush();
    expect(puts).toHaveLength(0);
    sync.abort();
  });

  it('a base that already covers the history (covers > 0) is not re-published', async () => {
    const { sync, puts } = makeShareSession({ adopt: async () => ({ rowExists: true, adopted: false, coversThroughSeq: 3, version: 'e' }) });
    sync.start();
    await flush();
    expect(puts).toHaveLength(0);
    sync.abort();
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
