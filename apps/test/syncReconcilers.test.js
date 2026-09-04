import { describe, it, expect } from 'vitest';
import {
  attempt, mapReplicatorStatus, reconcileSnapshot, reconcileDeltas, reconcileTree,
} from '../app/src/core/syncReconcilers.js';
import { Ok, Offline, isOk, OK, OFFLINE, CONFLICT, REJECTED, DEFERRED } from '../app/src/core/syncOutcome.js';

const forkError = () => { const e = new Error('fork'); e.name = 'KeyringForkError'; e.revision = 2; return e; };

describe('syncReconcilers — channel mappings', () => {
  it('attempt: Ok on success, fork→Rejected, network→Offline, 403→Rejected', async () => {
    expect((await attempt(async () => 5))).toEqual(Ok(5));
    expect((await attempt(async () => { throw forkError(); })).tag).toBe(REJECTED);
    expect((await attempt(async () => { throw forkError(); })).reason.fork).toBe(true);
    expect((await attempt(async () => { throw new TypeError('fetch failed'); })).tag).toBe(OFFLINE);
    expect((await attempt(async () => { throw Object.assign(new Error('x'), { status: 403 }); })).tag).toBe(REJECTED);
  });

  it('mapReplicatorStatus maps each status', () => {
    for (const s of ['synced', 'clean', 'upToDate', 'fastForward', 'noRemote']) expect(mapReplicatorStatus(s).tag).toBe(OK);
    expect(mapReplicatorStatus('offline').tag).toBe(OFFLINE);
    expect(mapReplicatorStatus('rollback').tag).toBe(REJECTED);
    expect(mapReplicatorStatus('rollback').reason.security).toBe(true);
    expect(mapReplicatorStatus('unresolved').tag).toBe(CONFLICT);
  });

  it('reconcileSnapshot compacts (idempotent row-cut) then maps the replicator status', async () => {
    let compacted = false;
    const tree = { compact: async () => { compacted = true; } };
    const replicator = { sync: async (id) => { expect(id).toBe('u'); return 'synced'; } };
    expect(isOk(await reconcileSnapshot({ tree, uuid: 'u', replicator }))).toBe(true);
    expect(compacted).toBe(true);
  });

  it('reconcileDeltas: Ok normally, Deferred when an entry is held, classified on throw', async () => {
    expect((await reconcileDeltas({ controller: { sync: async () => ({ merged: 1, held: null }) } })).tag).toBe(OK);
    expect((await reconcileDeltas({ controller: { sync: async () => ({ held: 7 }) } })).tag).toBe(DEFERRED);
    expect((await reconcileDeltas({ controller: { sync: async () => { throw new TypeError('net'); } } })).tag).toBe(OFFLINE);
  });
});

describe('syncReconcilers — reconcileTree (dependency order + short-circuits)', () => {
  const okThunks = (order) => ({
    pullKeyring: async () => order.push('pull'),
    snapshot: async () => { order.push('snap'); return Ok(); },
    publishKeyring: async () => order.push('pub'),
    deltas: async () => { order.push('delta'); return Ok(); },
  });

  it('runs the channels in dependency order and returns Ok when all converge', async () => {
    const order = [];
    const r = await reconcileTree(okThunks(order));
    expect(order).toEqual(['pull', 'snap', 'pub', 'delta']);
    expect(isOk(r)).toBe(true);
  });

  it('stops at a keyring-pull failure — nothing row-dependent runs', async () => {
    const order = [];
    const r = await reconcileTree({
      ...okThunks(order),
      pullKeyring: async () => { order.push('pull'); throw new TypeError('net'); },
    });
    expect(order).toEqual(['pull']);
    expect(r.tag).toBe(OFFLINE);
  });

  it('skips publish + deltas when the snapshot did not establish the row', async () => {
    const order = [];
    const r = await reconcileTree({
      ...okThunks(order),
      snapshot: async () => { order.push('snap'); return Offline(); },
    });
    expect(order).toEqual(['pull', 'snap']); // publish + deltas skipped
    expect(r.tag).toBe(OFFLINE);
  });

  it('surfaces a keyring fork from the publish step as Rejected (worst of the channels)', async () => {
    const r = await reconcileTree({
      pullKeyring: async () => {},
      snapshot: async () => Ok(),
      publishKeyring: async () => { throw forkError(); },
      deltas: async () => Ok(),
    });
    expect(r.tag).toBe(REJECTED);
    expect(r.reason.fork).toBe(true);
  });

  it('aborts cooperatively: a mid-tick abort stops the remaining steps and returns Ok (no-op)', async () => {
    const ac = new AbortController();
    const order = [];
    const r = await reconcileTree({
      signal: ac.signal,
      pullKeyring: async () => { order.push('pull'); ac.abort(); },
      snapshot: async () => { order.push('snap'); return Ok(); },
      publishKeyring: async () => order.push('pub'),
      deltas: async () => Ok(),
    });
    expect(order).toEqual(['pull']); // aborted right after the pull
    expect(isOk(r)).toBe(true); // abort is a no-op, not an error
  });
});
