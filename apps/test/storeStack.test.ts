import { describe, it, expect } from 'vitest';
import { composeStore } from '../app/src/core/storeStack.js';
import { MemoryStore } from '../app/src/core/store.js';

const MARK = 0xee;
const sealer = {
  seal: async (b: Uint8Array) => new Uint8Array([MARK, ...b]),
  open: async (b: Uint8Array) => b.slice(1),
};

describe('composeStore (composition root, §16 fail-closed)', () => {
  it('demo mode is plaintext MemoryStore, no crypto/sync', async () => {
    const { store, encrypted } = await composeStore({ mode: 'demo' });
    expect(encrypted).toBe(false);
    await store.putSnapshot('t', new Uint8Array([1, 2, 3]));
    // Stored plaintext (demo only) — and it's a MemoryStore (ephemeral).
    expect(store).toBeInstanceOf(MemoryStore);
  });

  it("refuses a durable store in demo mode (can't smuggle real data through)", async () => {
    const durable = { caps: () => ({ durable: true }) };
    await expect(composeStore({ mode: 'demo', local: durable as any })).rejects.toThrow(/MemoryStore/);
  });

  it('local/synced without a sealer is refused (no plaintext path for real data)', async () => {
    await expect(composeStore({ mode: 'local', local: new MemoryStore() })).rejects.toThrow(/sealer/);
    await expect(composeStore({ mode: 'synced', local: new MemoryStore() })).rejects.toThrow(/sealer/);
  });

  it('local mode seals over the durable store (encrypted at rest)', async () => {
    const local = new MemoryStore();
    const { store, encrypted } = await composeStore({ mode: 'local', sealer, local });
    expect(encrypted).toBe(true);
    await store.putSnapshot('t', new Uint8Array([1, 2, 3]));
    expect(Array.from((await store.readSnapshot('t'))!.bytes)).toEqual([1, 2, 3]); // opens
    expect((await local.readSnapshot('t'))!.bytes[0]).toBe(MARK); // sealed underneath
  });

  it('synced mode = Sealed over Sync, exposes sync for the Replicator', async () => {
    const local = new MemoryStore();
    const remote = new MemoryStore(); // stand-in server
    const { store, encrypted, sync } = await composeStore({ mode: 'synced', sealer, local, remote });
    expect(encrypted).toBe(true);
    expect(sync).toBeTruthy();
    await store.putSnapshot('t', new Uint8Array([7]));
    const r = await sync.reconcile('t'); // pull(noRemote) → push
    expect(r.status).toBe('synced');
    expect((await remote.readSnapshot('t'))!.bytes[0]).toBe(MARK); // server holds ciphertext
  });

  it('rejects an unknown mode', async () => {
    await expect(composeStore({ mode: 'nonsense' as any })).rejects.toThrow(/unknown store mode/);
  });
});
