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
    expect(wm.current('t')).toEqual({ keyringRevision: 3, coversThroughSeq: 10 });
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
    expect(next).toEqual({ keyringRevision: 3, coversThroughSeq: 5 });
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
});
