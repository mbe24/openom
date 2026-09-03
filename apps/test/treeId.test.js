import { describe, it, expect } from 'vitest';
import { readTreeIdentity, ensureTreeIdentity } from '../app/src/core/treeId.js';
import { treeIdToUuid } from '../app/src/core/keyringPublish.js';

function fakeStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), _m: m };
}

// A lock that runs every request serially (the property navigator.locks gives us): enough to force
// two concurrent mints through one at a time.
function serialLocks() {
  let chain = Promise.resolve();
  return {
    request(_name, fn) {
      const run = chain.then(() => fn());
      chain = run.catch(() => {});
      return run;
    },
  };
}

// Distinct 16 bytes each call, so a second mint would produce a DIFFERENT id (making a split visible).
function counterBytes() {
  let n = 0;
  return () => {
    n += 1;
    const b = new Uint8Array(16);
    b[0] = n;
    return { fn: () => b, count: () => n };
  };
}

describe('treeId — per-member tree identity', () => {
  it('readTreeIdentity is null before anything is minted', () => {
    expect(readTreeIdentity('m1', { storage: fakeStorage() })).toBeNull();
    expect(readTreeIdentity(null, { storage: fakeStorage() })).toBeNull();
  });

  it('mints once, caches, and the uuid is treeIdToUuid(bytes)', async () => {
    const storage = fakeStorage();
    const bytes = new Uint8Array(16).fill(7);
    const id = await ensureTreeIdentity('m1', { storage, makeBytes: () => bytes });
    expect(id.bytes).toEqual(bytes);
    expect(id.uuid).toBe(treeIdToUuid(bytes));
    // Cached: a later read (sync) and a later ensure both return the same identity, no re-mint.
    expect(readTreeIdentity('m1', { storage })).toEqual(id);
    const again = await ensureTreeIdentity('m1', { storage, makeBytes: () => new Uint8Array(16).fill(9) });
    expect(again.uuid).toBe(id.uuid);
  });

  it('two concurrent first-provisions converge on ONE identity (no split)', async () => {
    const storage = fakeStorage();
    const locks = serialLocks();
    const mk = counterBytes()();
    const [a, b] = await Promise.all([
      ensureTreeIdentity('m1', { storage, makeBytes: mk.fn, locks }),
      ensureTreeIdentity('m1', { storage, makeBytes: mk.fn, locks }),
    ]);
    expect(a.uuid).toBe(b.uuid);
    expect(mk.count()).toBe(1); // minted exactly once despite two racing calls
  });

  it('different members get different trees', async () => {
    const storage = fakeStorage();
    const a = await ensureTreeIdentity('m1', { storage, makeBytes: () => new Uint8Array(16).fill(1) });
    const b = await ensureTreeIdentity('m2', { storage, makeBytes: () => new Uint8Array(16).fill(2) });
    expect(a.uuid).not.toBe(b.uuid);
  });

  it('works without navigator.locks (single-tab fallback)', async () => {
    const storage = fakeStorage();
    const id = await ensureTreeIdentity('m1', { storage, makeBytes: () => new Uint8Array(16).fill(3), locks: null });
    expect(id.uuid).toBe(treeIdToUuid(new Uint8Array(16).fill(3)));
  });
});
