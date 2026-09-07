import { describe, it, expect } from 'vitest';
import { MembershipAsserts, sameSummary } from '../app/src/core/membershipAsserts.js';

const A = { view: [{ memberId: 'owner', role: 1 }, { memberId: 'bob', role: 4 }], basis: ['op:aa'] };

describe('sameSummary', () => {
  it('is order-independent in the member list', () => {
    const reordered = { view: [A.view[1], A.view[0]], basis: ['op:aa'] };
    expect(sameSummary(A, reordered)).toBe(true);
  });
  it('distinguishes a role change, a membership change, and a basis change', () => {
    expect(sameSummary(A, { ...A, view: [{ memberId: 'owner', role: 2 }, A.view[1]] })).toBe(false);
    expect(sameSummary(A, { ...A, view: [A.view[0]] })).toBe(false);
    expect(sameSummary(A, { ...A, basis: ['op:bb'] })).toBe(false);
  });
  it('null only equals null', () => {
    expect(sameSummary(null, null)).toBe(true);
    expect(sameSummary(A, null)).toBe(false);
    expect(sameSummary(null, A)).toBe(false);
  });
});

describe('MembershipAsserts', () => {
  it('mark records the desired intent without confirming it', () => {
    const m = new MembershipAsserts(); // in-memory in Node
    m.mark('t', A);
    expect(m.desired('t')).toEqual(A);
    expect(m.isConfirmed('t', A)).toBe(false);
  });

  it('confirm advances the de-dup baseline (order-independent)', () => {
    const m = new MembershipAsserts();
    m.confirm('t', A);
    expect(m.isConfirmed('t', A)).toBe(true);
    const reordered = { view: [A.view[1], A.view[0]], basis: ['op:aa'] };
    expect(m.isConfirmed('t', reordered)).toBe(true); // same view, different array order
    expect(m.isConfirmed('t', { ...A, basis: ['op:bb'] })).toBe(false);
  });

  it('confirm keeps the recorded desired, and trees are independent', () => {
    const m = new MembershipAsserts();
    m.mark('t1', A);
    m.confirm('t1', A);
    expect(m.desired('t1')).toEqual(A); // confirm did not clobber desired
    expect(m.isConfirmed('t2', A)).toBe(false); // a different tree is untouched
  });

  it('persists across instances that share a store (durable-queue survival)', () => {
    const store = new Map();
    const shim = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v) };
    new MembershipAsserts(shim).mark('t', A); // "before the network push", then a crash…
    expect(new MembershipAsserts(shim).desired('t')).toEqual(A); // …a fresh instance still has the intent
  });
});
