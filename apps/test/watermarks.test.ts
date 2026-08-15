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

describe('Watermarks (§10 refuse-on-regression)', () => {
  it('advances the watermark forward', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringRevision: 3, coversThroughSeq: 10 });
    expect(wm.current('t')).toEqual({ keyringRevision: 3, coversThroughSeq: 10, snapshots: [] });
  });

  it('refuses a keyring revision below the watermark (rollback)', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringRevision: 5 });
    expect(() => wm.observe('t', { keyringRevision: 4 })).toThrow(RegressionError);
    expect(wm.current('t').keyringRevision).toBe(5); // unchanged
  });

  it('refuses a snapshot coordinate regression', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { coversThroughSeq: 10 });
    expect(() => wm.observe('t', { coversThroughSeq: 9 })).toThrow(RegressionError);
  });

  it('treats an equal observation as idempotent', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringRevision: 2, coversThroughSeq: 4 });
    expect(() => wm.observe('t', { keyringRevision: 2, coversThroughSeq: 4 })).not.toThrow();
  });

  it('advances one coordinate while the other holds', () => {
    const wm = new Watermarks(memStore());
    wm.observe('t', { keyringRevision: 3, coversThroughSeq: 3 });
    const next = wm.observe('t', { keyringRevision: 3, coversThroughSeq: 5 });
    expect(next).toEqual({ keyringRevision: 3, coversThroughSeq: 5, snapshots: [] });
  });

  it('persists across instances sharing a store (second device detects rollback)', () => {
    const store = memStore();
    new Watermarks(store).observe('t', { keyringRevision: 7 });
    const b = new Watermarks(store);
    expect(b.current('t').keyringRevision).toBe(7);
    expect(() => b.observe('t', { keyringRevision: 6 })).toThrow(RegressionError);
  });

  it('is per-tree', () => {
    const wm = new Watermarks(memStore());
    wm.observe('tree-a', { keyringRevision: 5 });
    expect(() => wm.observe('tree-b', { keyringRevision: 1 })).not.toThrow();
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

    it('coexists with the keyring and coverage coordinates', () => {
      const wm = new Watermarks(memStore());
      wm.observe('t', { keyringRevision: 2, coversThroughSeq: 0, snapshotHash: 'aa' });
      wm.observe('t', { keyringRevision: 3, coversThroughSeq: 0, snapshotHash: 'bb' });
      // keyring rollback is still refused independently of the snapshot dimension.
      expect(() => wm.observe('t', { keyringRevision: 1, snapshotHash: 'bb' })).toThrow(RegressionError);
    });
  });
});
