import { describe, it, expect } from 'vitest';
import { Replicator } from '../app/src/core/replicator.js';
import { SyncStore } from '../app/src/core/syncStore.js';
import { MemoryStore } from '../app/src/core/store.js';

const bytes = (...xs: number[]) => new Uint8Array(xs);
const MARK = 0xee;

// Reversible fake sealer; a fake merge that concatenates local+remote plaintext (order
// deterministic) so we can assert the merged content.
const open = async (b: Uint8Array) => b.slice(1);
const seal = async (b: Uint8Array) => new Uint8Array([MARK, ...b]);
const merge = async (local: Uint8Array | null, remote: Uint8Array) =>
  new Uint8Array([...(local ?? []), ...remote]);

const device = (remote: any) => new SyncStore(new MemoryStore(), remote);
const repl = (sync: any, over: object = {}) => new Replicator(sync, { open, seal, merge, ...over });

async function put(store: any, id: string, b: Uint8Array) {
  const cur = await store.readSnapshot(id);
  return store.putSnapshot(id, b, cur ? cur.version : null);
}

describe('Replicator', () => {
  it('pushes a fresh local doc to a clean remote', async () => {
    const remote = new MemoryStore();
    const s = device(remote);
    await put(s, 't', bytes(MARK, 1)); // already "sealed" for the store below
    expect(await repl(s).sync('t')).toBe('synced');
    expect(Array.from((await remote.readSnapshot('t'))!.bytes)).toEqual([MARK, 1]);
  });

  it('fast-forwards a second device with no local changes', async () => {
    const remote = new MemoryStore();
    const a = device(remote);
    const b = device(remote);
    await put(a, 't', bytes(MARK, 9));
    await a.pushSnapshot('t');
    expect(await repl(b).sync('t')).toBe('fastForward');
    expect(Array.from((await b.readSnapshot('t'))!.bytes)).toEqual([MARK, 9]);
  });

  it('resolves a conflict by merging remote into local, then converges', async () => {
    const remote = new MemoryStore();
    const a = device(remote);
    const b = device(remote);
    await put(a, 't', await seal(bytes(1))); // A: plaintext [1]
    await a.pushSnapshot('t');
    await b.pull('t'); // B in sync with A's [1]
    await put(a, 't', await seal(bytes(2))); // A advances remote to [2]
    await a.pushSnapshot('t');
    await put(b, 't', await seal(bytes(3))); // B edits locally to [3]

    // B's replicator: conflict → merge(local [3], remote [2]) = [3,2] → converges.
    expect(await repl(b).sync('t')).toBe('synced');
    const onRemote = await remote.readSnapshot('t');
    expect(Array.from(await open(onRemote!.bytes))).toEqual([3, 2]); // merged plaintext
    // and B's local matches
    const bLocal = await b.readSnapshot('t');
    expect(Array.from(await open(bLocal!.bytes))).toEqual([3, 2]);
  });

  it('returns offline on a network error (state stays dirty for retry)', async () => {
    const remote = {
      caps: () => ({}),
      putSnapshot: async () => {
        throw new Error('network down');
      },
      readSnapshot: async () => null,
    };
    const s = new SyncStore(new MemoryStore(), remote);
    await put(s, 't', bytes(MARK, 1));
    expect(await repl(s).sync('t')).toBe('offline');
    expect(s.isDirty('t')).toBe(true);
  });

  it('gives up as unresolved when the remote never stops changing', async () => {
    // A remote whose version changes on every read → every push conflicts forever.
    const { ConflictError } = await import('../app/src/core/store.js');
    let n = 0;
    const remote = {
      caps: () => ({}),
      // Always a different snapshot than local (so it's a real conflict, not the
      // lost-ack confirm), and a fresh version each read (so it never converges).
      readSnapshot: async () => ({ bytes: new Uint8Array([MARK, 200, ++n]), version: 'v' + n }),
      putSnapshot: async () => {
        throw new ConflictError('x', 'y');
      },
    };
    const s = new SyncStore(new MemoryStore(), remote);
    await put(s, 't', await seal(bytes(1)));
    expect(await repl(s, { maxRounds: 3 }).sync('t')).toBe('unresolved');
  });
});
