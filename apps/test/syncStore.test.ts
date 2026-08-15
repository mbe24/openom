import { describe, it, expect } from 'vitest';
import { SyncStore } from '../app/src/core/syncStore.js';
import { MemoryStore, ConflictError } from '../app/src/core/store.js';

const bytes = (...xs: number[]) => new Uint8Array(xs);

// A device: its own local cache, sharing a remote. Two devices share one `remote`.
const device = (remote: any) => new SyncStore(new MemoryStore(), remote);

// Mimic the FamilyTree caller: read the current local version, put with it as `expected`.
async function put(store: any, id: string, b: Uint8Array) {
  const cur = await store.readSnapshot(id);
  return store.putSnapshot(id, b, cur ? cur.version : null);
}

describe('SyncStore', () => {
  it('putSnapshot commits locally (sync commit point) and marks dirty', async () => {
    const s = device(new MemoryStore());
    const v = await put(s, 't', bytes(1, 2, 3));
    expect(v).toBeTruthy();
    expect(s.isDirty('t')).toBe(true);
    expect(Array.from((await s.readSnapshot('t'))!.bytes)).toEqual([1, 2, 3]);
  });

  it('pushSnapshot uploads and clears dirty', async () => {
    const remote = new MemoryStore();
    const s = device(remote);
    await put(s, 't', bytes(1));
    expect((await s.pushSnapshot('t')).status).toBe('synced');
    expect(s.isDirty('t')).toBe(false);
    expect(Array.from((await remote.readSnapshot('t'))!.bytes)).toEqual([1]);
  });

  it('pushSnapshot with nothing dirty is a no-op', async () => {
    const s = device(new MemoryStore());
    expect((await s.pushSnapshot('t')).status).toBe('clean');
  });

  it('pull fast-forwards a clean local to a newer remote (second device)', async () => {
    const remote = new MemoryStore();
    const a = device(remote);
    const b = device(remote);
    await put(a, 't', bytes(9));
    await a.pushSnapshot('t');
    const r = await b.pull('t');
    expect(r.status).toBe('fastForward');
    expect(Array.from((await b.readSnapshot('t'))!.bytes)).toEqual([9]);
  });

  it('surfaces a conflict (with remote bytes) when both sides changed', async () => {
    const remote = new MemoryStore();
    const a = device(remote);
    const b = device(remote);
    await put(a, 't', bytes(1));
    await a.pushSnapshot('t');
    await b.pull('t'); // b now in sync
    await put(a, 't', bytes(2));
    await a.pushSnapshot('t'); // remote advances to A's latest
    await put(b, 't', bytes(3)); // b edits locally
    const r = await b.pushSnapshot('t');
    expect(r.status).toBe('conflict');
    expect(Array.from(r.remote!.bytes)).toEqual([2]); // the remote the caller must merge
    expect(b.isDirty('t')).toBe(true); // still unpushed — retry after merge
  });

  it('pull confirms our own write that landed despite a lost ack (idempotency)', async () => {
    const remote = new MemoryStore();
    const s = device(remote);
    await put(s, 't', bytes(5)); // local, dirty, no recorded ack
    await remote.putSnapshot('t', bytes(5), null); // the push actually landed
    const r = await s.pull('t');
    expect(r.status).toBe('upToDate');
    expect(s.isDirty('t')).toBe(false); // confirmed, not a conflict
  });

  it('pushSnapshot reports offline and stays dirty on a network error', async () => {
    const remote = {
      caps: () => ({}),
      putSnapshot: async () => {
        throw new Error('network down');
      },
      readSnapshot: async () => null,
    };
    const s = new SyncStore(new MemoryStore(), remote);
    await put(s, 't', bytes(1));
    const r = await s.pushSnapshot('t');
    expect(r.status).toBe('offline');
    expect(s.isDirty('t')).toBe(true);
  });

  it('reconcile syncs a clean tick (pull noRemote → push synced)', async () => {
    const s = device(new MemoryStore());
    await put(s, 't', bytes(7));
    expect((await s.reconcile('t')).status).toBe('synced');
  });

  it('reconcile surfaces a conflict for the caller to merge', async () => {
    const remote = new MemoryStore();
    const a = device(remote);
    const b = device(remote);
    await put(a, 't', bytes(1));
    await a.pushSnapshot('t');
    await b.pull('t');
    await put(a, 't', bytes(2));
    await a.pushSnapshot('t');
    await put(b, 't', bytes(3));
    expect((await b.reconcile('t')).status).toBe('conflict');
  });

  it('ConflictError from the local commit propagates (stale expected)', async () => {
    const s = device(new MemoryStore());
    await put(s, 't', bytes(1));
    await expect(s.putSnapshot('t', bytes(2), 'stale-version')).rejects.toBeInstanceOf(ConflictError);
  });
});
