import { describe, it, expect } from 'vitest';
import {
  attempt, reconcileSnapshot, reconcileDeltas, reconcileTree,
} from '../app/src/core/syncReconcilers.js';
import { Ok, Offline, isOk, OK, OFFLINE, REJECTED, DEFERRED } from '../app/src/core/syncOutcome.js';

const forkError = () => { const e = new Error('fork'); e.name = 'KeyringForkError'; e.revision = 2; return e; };

describe('syncReconcilers — channel mappings', () => {
  it('attempt: Ok on success, fork→Rejected, network→Offline, 403→Rejected', async () => {
    expect((await attempt(async () => 5))).toEqual(Ok(5));
    expect((await attempt(async () => { throw forkError(); })).tag).toBe(REJECTED);
    expect((await attempt(async () => { throw forkError(); })).reason.fork).toBe(true);
    expect((await attempt(async () => { throw new TypeError('fetch failed'); })).tag).toBe(OFFLINE);
    expect((await attempt(async () => { throw Object.assign(new Error('x'), { status: 403 }); })).tag).toBe(REJECTED);
  });

  it('reconcileSnapshot: no-op when the row already exists', async () => {
    const remote = {
      readSnapshot: async () => ({ bytes: new Uint8Array([1]), version: 'v1' }),
      putSnapshot: async () => { throw new Error('must not create when the row exists'); },
    };
    const r = await reconcileSnapshot({ tree: {}, uuid: 'u', remote, sealSnapshot: async () => new Uint8Array() });
    expect(r).toEqual(Ok('exists'));
  });

  it('reconcileSnapshot: creates the row (expected=null) when absent, sealing the current state', async () => {
    let put = null;
    const remote = {
      readSnapshot: async () => null,
      putSnapshot: async (id, bytes, expected) => { put = { id, bytes: Array.from(bytes), expected }; },
    };
    const tree = { snapshotBytes: () => new Uint8Array([9]) };
    const r = await reconcileSnapshot({ tree, uuid: 'u', remote, sealSnapshot: async (b) => new Uint8Array([0xaa, ...b]) });
    expect(r).toEqual(Ok('created'));
    expect(put).toEqual({ id: 'u', bytes: [0xaa, 9], expected: null });
  });

  it('reconcileSnapshot: a concurrent creator (409) resolves to exists', async () => {
    const remote = {
      readSnapshot: async () => null,
      putSnapshot: async () => { const e = new Error('conflict'); e.name = 'ConflictError'; throw e; },
    };
    const tree = { snapshotBytes: () => new Uint8Array([9]) };
    expect(await reconcileSnapshot({ tree, uuid: 'u', remote, sealSnapshot: async (b) => b })).toEqual(Ok('exists'));
  });

  it('reconcileSnapshot: a network failure defers (Offline)', async () => {
    const remote = { readSnapshot: async () => { throw new TypeError('fetch failed'); } };
    const r = await reconcileSnapshot({ tree: {}, uuid: 'u', remote, sealSnapshot: async () => new Uint8Array() });
    expect(r.tag).toBe(OFFLINE);
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
