import { describe, it, expect } from 'vitest';
import { SealerSession } from '../app/src/core/sealer/session.js';

// A reversible, deterministic stand-in for the real WasmSealer core: it records every seal
// (so tests can inspect the chain) and encodes the whole entry into the "envelope" so
// openEntry can recover the plaintext and verify the kind — the same surface the real core
// exposes (sealEntry → {envelope, ciphertextHash}; openEntry → plaintext).
function fakeCore(opts: { failOn?: (pt: Uint8Array) => boolean } = {}) {
  const seals: any[] = [];
  const core = {
    treeId: new Uint8Array([1, 2, 3]),
    sealEntry(
      kind: string,
      _format: string,
      _compression: string,
      counter: number,
      prev: Uint8Array,
      covers: number,
      _blobId: Uint8Array,
      plaintext: Uint8Array,
    ) {
      if (opts.failOn?.(plaintext)) throw new Error('simulated seal failure');
      // A distinct hash per (counter, content) so chain links are checkable.
      const ciphertextHash = new Uint8Array([counter & 0xff, plaintext.length & 0xff, kind.charCodeAt(0)]);
      const record = {
        kind,
        counter,
        prev: Array.from(prev),
        covers,
        plaintext: Array.from(plaintext),
        ciphertextHash: Array.from(ciphertextHash),
      };
      seals.push(record);
      const envelope = new TextEncoder().encode(JSON.stringify(record));
      return { envelope, ciphertextHash };
    },
    openEntry(expectKind: string, bytes: Uint8Array) {
      const record = JSON.parse(new TextDecoder().decode(bytes));
      if (record.kind !== expectKind) throw new Error('unexpected kind');
      return new Uint8Array(record.plaintext);
    },
    seals,
  };
  return core;
}

const b = (...xs: number[]) => new Uint8Array(xs);

describe('SealerSession (§8a chain state)', () => {
  it('rejects a bad core', () => {
    expect(() => new SealerSession({} as any)).toThrow(/sealer core/);
  });

  it('round-trips a snapshot', async () => {
    const s = new SealerSession(fakeCore());
    const sealed = await s.seal(b(1, 2, 3), 'tree', { kind: 'snapshot' });
    expect(Array.from(await s.open(sealed, 'tree', { kind: 'snapshot' }))).toEqual([1, 2, 3]);
  });

  it('counts from 0, increments per seal, and seals covers_through_seq = 0 (V1)', async () => {
    const core = fakeCore();
    const s = new SealerSession(core);
    await s.seal(b(1), 'tree');
    await s.seal(b(2), 'tree');
    expect(core.seals.map((r) => r.counter)).toEqual([0, 1]);
    expect(core.seals.every((r) => r.covers === 0)).toBe(true);
  });

  it('chains prev across snapshot AND delta (one shared chain)', async () => {
    const core = fakeCore();
    const s = new SealerSession(core);
    await s.seal(b(1), 'tree', { kind: 'snapshot' });
    await s.seal(b(2), 'tree', { kind: 'delta' });
    await s.seal(b(3), 'tree', { kind: 'snapshot' });
    // First entry has an empty prev; each later prev equals the prior ciphertextHash.
    expect(core.seals[0].prev).toEqual([]);
    expect(core.seals[1].prev).toEqual(core.seals[0].ciphertextHash);
    expect(core.seals[2].prev).toEqual(core.seals[1].ciphertextHash);
    // Counter is shared across kinds, not per-kind.
    expect(core.seals.map((r) => r.counter)).toEqual([0, 1, 2]);
  });

  it('verifies kind on open', async () => {
    const s = new SealerSession(fakeCore());
    const sealed = await s.seal(b(9), 'tree', { kind: 'snapshot' });
    await expect(s.open(sealed, 'tree', { kind: 'delta' })).rejects.toThrow(/unexpected kind/);
  });

  it('serializes concurrent seals into one linear chain', async () => {
    const core = fakeCore();
    const s = new SealerSession(core);
    // Fire a batch WITHOUT awaiting between them (as SealedStore.append would).
    await Promise.all([1, 2, 3, 4, 5].map((n) => s.seal(b(n), 'tree', { kind: 'delta' })));
    // No duplicate or skipped counters, and a fully linked chain in issue order.
    expect(core.seals.map((r) => r.counter)).toEqual([0, 1, 2, 3, 4]);
    for (let i = 1; i < core.seals.length; i++) {
      expect(core.seals[i].prev).toEqual(core.seals[i - 1].ciphertextHash);
    }
  });

  it('a failed seal neither advances the chain nor poisons the queue', async () => {
    const core = fakeCore({ failOn: (pt) => pt.length === 2 }); // fail the 2-byte payload
    const s = new SealerSession(core);
    await s.seal(b(1), 'tree'); // ok → counter 0
    await expect(s.seal(b(7, 7), 'tree')).rejects.toThrow(/simulated seal failure/);
    await s.seal(b(3), 'tree'); // still works → counter 1, not 2 (no wasted counter)
    expect(core.seals.map((r) => r.counter)).toEqual([0, 1]);
    expect(core.seals[1].prev).toEqual(core.seals[0].ciphertextHash);
  });
});

// A core whose sealEntry blocks on a gate the test releases, plus a lock() spy — so we can
// interleave a lock() with an in-flight seal and assert the ordering.
function gatedCore() {
  const order: string[] = [];
  let open: () => void = () => {};
  const gate = new Promise<void>((r) => { open = r; });
  const core = {
    treeId: b(1),
    async sealEntry(_k: string, _f: string, _c: string, counter: number) {
      order.push('seal:start:' + counter);
      await gate;
      order.push('seal:end:' + counter);
      return { envelope: b(counter), ciphertextHash: b(counter) };
    },
    openEntry: () => b(),
    lock() { order.push('core:lock'); },
    order,
    release: () => open(),
  };
  return core;
}

describe('SealerSession lock (drain-then-free)', () => {
  it('waits for an in-flight seal to finish before freeing the core', async () => {
    const core = gatedCore();
    const s = new SealerSession(core);
    const sealP = s.seal(b(1), 'tree');   // starts, blocks on the gate
    await Promise.resolve();               // let it reach the gate
    const lockP = s.lock();                // must not free until the seal completes
    await new Promise((r) => setTimeout(r, 0));
    expect(core.order).toEqual(['seal:start:0']); // core NOT locked yet
    core.release();
    await sealP;
    await lockP;
    expect(core.order).toEqual(['seal:start:0', 'seal:end:0', 'core:lock']);
  });

  it('rejects seal and open once locked, instead of hitting a freed core', async () => {
    const core = gatedCore();
    core.release();                        // don't block
    const s = new SealerSession(core);
    await s.seal(b(1), 'tree');
    await s.lock();
    expect(s.locked).toBe(true);
    await expect(s.seal(b(2), 'tree')).rejects.toThrow(/locked/);
    await expect(s.open(b(), 'tree')).rejects.toThrow(/locked/);
  });

  it('is idempotent — a second lock frees nothing more', async () => {
    const core = gatedCore();
    core.release();
    const s = new SealerSession(core);
    await s.lock();
    await s.lock();
    expect(core.order.filter((e) => e === 'core:lock')).toHaveLength(1);
  });
});
