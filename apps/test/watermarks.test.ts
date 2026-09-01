import { describe, it, expect } from 'vitest';
import { Watermarks, RegressionError } from '../app/src/core/watermarks.js';

function memStore() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => {
      m.set(k, v);
    },
  };
}

// The keyring cursor is opaque bytes now (OPE-278); a chain cursor happens to be the 4-byte revision.
const cur = (n: number) => new Uint8Array([0, 0, 0, n]);
const asArr = (u: Uint8Array) => Array.from(u);

describe('Watermarks (§10 refuse-on-regression)', () => {
  it('advances the coverage watermark forward', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringCursor: cur(3), coversThroughSeq: 10 });
    const c = wm.current('t');
    expect(asArr(c.keyringCursor)).toEqual(asArr(cur(3)));
    expect(c.coversThroughSeq).toBe(10);
    expect(c.snapshots).toEqual([]);
  });

  it('stores the keyring cursor opaquely + write-through (order check is engine-owned, not JS)', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringCursor: cur(5) });
    // JS can't order opaque bytes and mustn't try — the engine refuses a rollback. A "lower" cursor just
    // overwrites; nothing throws.
    expect(() => wm.observe('t', { keyringCursor: cur(4) })).not.toThrow();
    expect(asArr(wm.current('t').keyringCursor)).toEqual(asArr(cur(4)));
  });

  it('refuses a snapshot coordinate regression', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { coversThroughSeq: 10 });
    expect(() => wm.observe('t', { coversThroughSeq: 9 })).toThrow(RegressionError);
  });

  it('treats an equal coverage observation as idempotent', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringCursor: cur(2), coversThroughSeq: 4 });
    expect(() => wm.observe('t', { keyringCursor: cur(2), coversThroughSeq: 4 })).not.toThrow();
  });

  it('keeps the keyring cursor when observing only another coordinate', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringCursor: cur(3) });
    wm.observe('t', { coversThroughSeq: 5 }); // no keyringCursor supplied → cursor preserved
    expect(asArr(wm.current('t').keyringCursor)).toEqual(asArr(cur(3)));
    expect(wm.current('t').coversThroughSeq).toBe(5);
  });

  it('persists the keyring cursor across instances sharing a store', () => {
    const store = memStore();
    new Watermarks(store).observe('t', { keyringCursor: cur(7) });
    const b = new Watermarks(store);
    expect(asArr(b.current('t').keyringCursor)).toEqual(asArr(cur(7)));
  });

  it('is per-tree', () => {
    const wm = new Watermarks(memStore());
    wm.observe('tree-a', { coversThroughSeq: 5 });
    expect(() => wm.observe('tree-b', { coversThroughSeq: 1 })).not.toThrow();
  });

  describe('snapshot-hash replay detection (V1 anti-rollback)', () => {
    it('advances through a sequence of new snapshot hashes', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { snapshotHash: 'aa' });
      wm.observe('t', { snapshotHash: 'bb' });
      const next = wm.observe('t', { snapshotHash: 'cc' });
      expect(next.snapshots).toEqual(['aa', 'bb', 'cc']);
    });

    it('re-observing the current head is idempotent', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { snapshotHash: 'aa' });
      wm.observe('t', { snapshotHash: 'bb' });
      expect(() => wm.observe('t', { snapshotHash: 'bb' })).not.toThrow();
    });

    it('refuses a snapshot the client already moved past (rollback)', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { snapshotHash: 'aa' });
      wm.observe('t', { snapshotHash: 'bb' }); // now past 'aa'
      expect(() => wm.observe('t', { snapshotHash: 'aa' })).toThrow(RegressionError);
    });

    it('still accepts a genuinely new snapshot after progressing', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { snapshotHash: 'aa' });
      wm.observe('t', { snapshotHash: 'bb' });
      expect(() => wm.observe('t', { snapshotHash: 'cc' })).not.toThrow();
    });

    it('accepts hashes given as bytes, matching the hex form', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { snapshotHash: new Uint8Array([0x01, 0x02, 0x03]) }); // -> '010203'
      wm.observe('t', { snapshotHash: 'aabb' });
      // Replaying the byte form (now superseded) is caught, proving it normalized to hex.
      expect(() => wm.observe('t', { snapshotHash: new Uint8Array([0x01, 0x02, 0x03]) })).toThrow(RegressionError);
    });

    it('persists across instances (a second device detects the replay)', () => {
      const store = memStore();
      new Watermarks(store).observe('t', { snapshotHash: 'aa' });
      const b = new Watermarks(store);
      b.observe('t', { snapshotHash: 'bb' });
      expect(() => b.observe('t', { snapshotHash: 'aa' })).toThrow(RegressionError);
    });

    it('bounds the remembered window (a rollback older than the window escapes)', () => {
      const wm = new Watermarks(memStore());
      // 65 distinct hashes; the window holds the last 64, so the very first is evicted.
      for (let i = 0; i <= 64; i++) wm.observe('t', { snapshotHash: 'h' + i });
      // 'h0' is no longer remembered, so it reads as new — documented, honest degradation.
      expect(() => wm.observe('t', { snapshotHash: 'h0' })).not.toThrow();
      // But a recently-superseded one is still caught.
      expect(() => wm.observe('t', { snapshotHash: 'h60' })).toThrow(RegressionError);
    });

    it('coexists with the keyring cursor and coverage coordinates', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { keyringCursor: cur(2), coversThroughSeq: 0, snapshotHash: 'aa' });
      wm.observe('t', { keyringCursor: cur(3), coversThroughSeq: 0, snapshotHash: 'bb' });
      // The keyring cursor is write-through (engine-owned order — no throw); the snapshot dimension still
      // catches a replay independently.
      expect(() => wm.observe('t', { keyringCursor: cur(1) })).not.toThrow();
      expect(() => wm.observe('t', { snapshotHash: 'aa' })).toThrow(RegressionError);
    });
  });
});
