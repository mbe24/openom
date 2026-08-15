import { describe, it, expect } from 'vitest';
import { SealedStore } from '../app/src/core/sealedStore.js';
import { MemoryStore, ConflictError } from '../app/src/core/store.js';

// A reversible stand-in for the real crypto sealer: prefix a marker byte on seal,
// require + strip it on open (so "unsealed" bytes are detectably rejected).
const MARK = 0xee;
const fakeSealer = {
  seal: async (b: Uint8Array) => new Uint8Array([MARK, ...b]),
  open: async (b: Uint8Array) => {
    if (b[0] !== MARK) throw new Error('not sealed');
    return b.slice(1);
  },
};

describe('SealedStore', () => {
  it('round-trips through seal/open', async () => {
    const inner = new MemoryStore();
    const store = new SealedStore(inner, fakeSealer);
    const v = await store.putSnapshot('t', new Uint8Array([1, 2, 3]));
    const snap = await store.readSnapshot('t');
    expect(Array.from(snap!.bytes)).toEqual([1, 2, 3]);
    expect(snap!.version).toBe(v);
  });

  it('the inner store only ever holds ciphertext', async () => {
    const inner = new MemoryStore();
    const store = new SealedStore(inner, fakeSealer);
    await store.putSnapshot('t', new Uint8Array([1, 2, 3]));
    const raw = await inner.readSnapshot('t'); // reach past the seal
    expect(raw!.bytes[0]).toBe(MARK); // sealed
    expect(Array.from(raw!.bytes)).not.toEqual([1, 2, 3]); // never plaintext
  });

  it('propagates ConflictError unchanged (ciphertext cannot merge)', async () => {
    const inner = new MemoryStore();
    const store = new SealedStore(inner, fakeSealer);
    await store.putSnapshot('t', new Uint8Array([1])); // version now v1
    await expect(store.putSnapshot('t', new Uint8Array([2]), 'stale')).rejects.toBeInstanceOf(
      ConflictError,
    );
  });

  it('readSnapshot returns null when absent', async () => {
    const store = new SealedStore(new MemoryStore(), fakeSealer);
    expect(await store.readSnapshot('missing')).toBeNull();
  });

  it('caps passes through the inner store and flags encrypted', async () => {
    const store = new SealedStore(new MemoryStore(), fakeSealer);
    expect(store.caps()).toEqual({ remote: false, conditionalWrites: true, durable: false, encrypted: true });
  });

  it('seals/opens the delta log too', async () => {
    const inner = new MemoryStore();
    const store = new SealedStore(inner, fakeSealer);
    await store.append('t', [new Uint8Array([7]), new Uint8Array([8])]);
    const raw = await inner.readUpdates('t', 0);
    expect(raw.updates.every((u: Uint8Array) => u[0] === MARK)).toBe(true); // stored sealed
    const opened = await store.readUpdates('t', 0);
    expect(opened.updates.map((u: Uint8Array) => Array.from(u))).toEqual([[7], [8]]);
  });
});
