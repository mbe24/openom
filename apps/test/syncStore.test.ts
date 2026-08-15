import { describe, it, expect } from 'vitest';
import { SyncStore } from '../app/src/core/syncStore.js';
import { MemoryStore, ConflictError } from '../app/src/core/store.js';
import { Watermarks } from '../app/src/core/watermarks.js';

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

  // §8a durability: the sync bookkeeping survives a reload, and pull() never clobbers a
  // committed-but-unpushed local edit. A "reload" = a new SyncStore over the SAME durable
  // local store and the SAME persisted bookkeeping (localStorage in the browser).
  const memKV = () => {
    const m = new Map<string, string>();
    return {
      getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
      setItem: (k: string, v: string) => void m.set(k, v),
      removeItem: (k: string) => void m.delete(k),
    };
  };

  it('does NOT fast-forward over an unpushed local edit after a reload (persisted dirty)', async () => {
    const remote = new MemoryStore();
    const local = new MemoryStore(); // durable — survives the "reload"
    const persist = memKV(); // durable — survives the "reload"

    const s1 = new SyncStore(local, remote, { persist });
    await put(s1, 't', bytes(1, 1, 1)); // committed locally, never pushed

    // Meanwhile another device advances the remote.
    const other = device(remote);
    await put(other, 't', bytes(9, 9));
    await other.pushSnapshot('t');

    // Reload: a fresh instance over the same durable local + persisted bookkeeping.
    const s2 = new SyncStore(local, remote, { persist });
    expect(s2.isDirty('t')).toBe(true); // the dirty flag survived
    const r = await s2.pull('t');
    expect(r.status).toBe('conflict'); // surfaced for merge, NOT fast-forwarded
    expect(Array.from((await s2.readSnapshot('t'))!.bytes)).toEqual([1, 1, 1]); // local intact
  });

  it('DOES fast-forward after a reload when the local was cleanly synced', async () => {
    const remote = new MemoryStore();
    const local = new MemoryStore();
    const persist = memKV();

    const s1 = new SyncStore(local, remote, { persist });
    await put(s1, 't', bytes(1));
    await s1.pushSnapshot('t'); // synced — remoteVersion recorded, dirty cleared (persisted)

    const other = device(remote);
    await other.pull('t');
    await put(other, 't', bytes(2));
    await other.pushSnapshot('t'); // remote advances

    const s2 = new SyncStore(local, remote, { persist }); // reload
    const r = await s2.pull('t');
    expect(r.status).toBe('fastForward'); // provably clean → safe to adopt
    expect(Array.from((await s2.readSnapshot('t'))!.bytes)).toEqual([2]);
  });

  // §10 anti-rollback: with a Watermarks injected, SyncStore observes every accepted snapshot
  // (own writes and fast-forwards) and refuses a fast-forward onto a snapshot the client
  // already moved past — a partly-trusted server re-serving stale-but-valid data.
  const wmStore = () => new Watermarks(memKV());
  const rollbackRemoteTo = async (remote: any, id: string, b: Uint8Array) => {
    const cur = await remote.readSnapshot(id);
    await remote.putSnapshot(id, b, cur ? cur.version : null); // serve old bytes at a fresh version
  };

  it('advances on genuine progress but catches a later rollback (multi-device)', async () => {
    const remote = new MemoryStore();
    const writer = device(remote); // pushes new snapshots
    const b = new SyncStore(new MemoryStore(), remote, { persist: memKV(), watermarks: wmStore() });

    await put(writer, 't', bytes(1));
    await writer.pushSnapshot('t');
    expect((await b.pull('t')).status).toBe('fastForward'); // b accepts S1

    await put(writer, 't', bytes(2));
    await writer.pushSnapshot('t');
    expect((await b.pull('t')).status).toBe('fastForward'); // b accepts S2 — genuine progress

    await rollbackRemoteTo(remote, 't', bytes(1)); // server rolls back to S1
    const r = await b.pull('t');
    expect(r.status).toBe('rollback');
    expect(Array.from((await b.readSnapshot('t'))!.bytes)).toEqual([2]); // stale S1 not adopted
  });

  it('own writes advance the head, so a rollback of them is caught on the next pull', async () => {
    // This is why observing only the pull path would be unsound: a single device that never
    // pulls must still remember its own snapshots to detect the server reverting them.
    const remote = new MemoryStore();
    const s = new SyncStore(new MemoryStore(), remote, { persist: memKV(), watermarks: wmStore() });
    await put(s, 't', bytes(1));
    await s.pushSnapshot('t'); // head S1 (via own write)
    await put(s, 't', bytes(2));
    await s.pushSnapshot('t'); // head S2 (via own write)

    await rollbackRemoteTo(remote, 't', bytes(1));
    expect((await s.pull('t')).status).toBe('rollback');
  });

  it('reconcile surfaces a rollback rather than pushing over it', async () => {
    const remote = new MemoryStore();
    const s = new SyncStore(new MemoryStore(), remote, { persist: memKV(), watermarks: wmStore() });
    await put(s, 't', bytes(1));
    await s.pushSnapshot('t');
    await put(s, 't', bytes(2));
    await s.pushSnapshot('t');
    await rollbackRemoteTo(remote, 't', bytes(1));
    expect((await s.reconcile('t')).status).toBe('rollback');
  });

  it('does NOT clobber local content that differs from remote when the sync record is missing', async () => {
    // Belt-and-suspenders: even if the dirty flag were lost (persist cleared but the
    // durable local survived), a differing local snapshot is surfaced as a conflict, not
    // overwritten — fast-forward requires POSITIVE evidence the local was disposable.
    const remote = new MemoryStore();
    const local = new MemoryStore();
    await local.putSnapshot('t', bytes(1, 2, 3), null); // local content, no sync record at all

    const other = device(remote);
    await put(other, 't', bytes(7, 7));
    await other.pushSnapshot('t');

    const s = new SyncStore(local, remote, { persist: memKV() });
    const r = await s.pull('t');
    expect(r.status).toBe('conflict');
    expect(Array.from((await s.readSnapshot('t'))!.bytes)).toEqual([1, 2, 3]);
  });
});
