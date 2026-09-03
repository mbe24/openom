import { describe, it, expect, vi } from 'vitest';
import { DevAuth, SessionController } from '../app/src/core/session.js';

// A localStorage-like fake (shared between "tabs" to model cross-origin-tab sharing).
class FakeStorage {
  #m = new Map();
  getItem(k) { return this.#m.has(k) ? this.#m.get(k) : null; }
  setItem(k, v) { this.#m.set(k, String(v)); }
  removeItem(k) { this.#m.delete(k); }
}

// A deterministic uuid factory so account ids are predictable in assertions.
function seqIds() {
  let n = 0;
  return () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`;
}

// Fire a synthetic cross-tab `storage` event on a broadcast target (what a real browser does to
// OTHER tabs when localStorage changes).
function fireStorage(broadcast, key) {
  const e = new Event('storage');
  e.key = key;
  broadcast.dispatchEvent(e);
}

const mk = (over = {}) =>
  new DevAuth({ storage: new FakeStorage(), broadcast: new EventTarget(), makeId: seqIds(), ...over });

describe('DevAuth — multi-account', () => {
  it('starts signed out: no accounts, null memberId, getAccessToken throws', async () => {
    const auth = mk();
    expect(auth.list()).toEqual([]);
    expect(auth.memberId()).toBeNull();
    expect(auth.activeAccount()).toBeNull();
    await expect(auth.getAccessToken()).rejects.toThrow(/no active account/);
  });

  it('signIn creates a local account, activates it, and makes memberId its uuid', async () => {
    const auth = mk();
    const acc = await auth.signIn({ label: 'Alice' });
    expect(acc.label).toBe('Alice');
    expect(acc.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(auth.memberId()).toBe(acc.id);
    expect(auth.list()).toEqual([acc]);
  });

  it('holds MULTIPLE accounts and switches the active one', async () => {
    const auth = mk();
    const alice = await auth.createAccount('Alice');
    const bob = await auth.createAccount('Bob'); // creating also activates
    expect(auth.list().map((a) => a.label)).toEqual(['Alice', 'Bob']);
    expect(auth.memberId()).toBe(bob.id);
    auth.switchTo(alice.id);
    expect(auth.memberId()).toBe(alice.id);
    expect(auth.switchTo('unknown-id')).toBeNull(); // no-op
    expect(auth.memberId()).toBe(alice.id);
  });

  it('getAccessToken returns the active uuid as the bearer (option A) and accepts forceRefresh', async () => {
    const auth = mk();
    const acc = await auth.signIn({ label: 'Alice' });
    expect(await auth.getAccessToken()).toBe(acc.id); // token == memberId == sub
    expect(await auth.getAccessToken({ forceRefresh: true })).toBe(acc.id); // seam accepts it (no-op today)
    expect(await auth.getAccessToken()).toBe(auth.memberId());
  });

  it('signOut clears the active account but keeps the list for switching back', async () => {
    const auth = mk();
    const alice = await auth.signIn({ label: 'Alice' });
    await auth.signOut();
    expect(auth.memberId()).toBeNull();
    expect(auth.list()).toEqual([alice]); // preserved
    auth.switchTo(alice.id);
    expect(auth.memberId()).toBe(alice.id);
  });

  it('capabilities: local accounts are self-serve (register/login/sync all true)', () => {
    expect(mk().capabilities()).toEqual({ canRegister: true, canLogin: true, sync: true });
  });
});

describe('DevAuth — onChange', () => {
  it('fires on create, switch, and sign-out; unsubscribe stops it', async () => {
    const auth = mk();
    const cb = vi.fn();
    const off = auth.onChange(cb);
    const a = await auth.createAccount('Alice');
    const b = await auth.createAccount('Bob');
    auth.switchTo(a.id);
    await auth.signOut();
    expect(cb).toHaveBeenCalledTimes(4); // create, create, switch, signOut
    off();
    await auth.createAccount('Carol');
    expect(cb).toHaveBeenCalledTimes(4); // no more after unsubscribe
  });

  it('cross-tab: a storage event from another tab re-reads state and notifies (two tabs, two users)', async () => {
    const storage = new FakeStorage();
    const broadcast = new EventTarget();
    const ids = seqIds();
    const tabA = new DevAuth({ storage, broadcast, makeId: ids });
    const tabB = new DevAuth({ storage, broadcast, makeId: ids });
    const onB = vi.fn();
    tabB.onChange(onB);

    // tabA creates + activates an account (writes shared storage). The browser then fires a
    // `storage` event on the OTHER tab (tabB) — simulate it.
    const acc = await tabA.createAccount('Alice');
    fireStorage(broadcast, DevAuth.ACTIVE_KEY);

    expect(onB).toHaveBeenCalled();
    expect(tabB.memberId()).toBe(acc.id); // tabB now sees the shared active account
    expect(tabB.memberId()).toBe(tabA.memberId());
  });

  it('ignores storage events for unrelated keys', async () => {
    const storage = new FakeStorage();
    const broadcast = new EventTarget();
    const auth = new DevAuth({ storage, broadcast, makeId: seqIds() });
    const cb = vi.fn();
    auth.onChange(cb);
    fireStorage(broadcast, 'some.other.key');
    expect(cb).not.toHaveBeenCalled();
  });
});

describe('SessionController — delegates the AuthSession seam', () => {
  it('forwards memberId / getAccessToken / capabilities / onChange to the backend', async () => {
    const backend = mk();
    const ctrl = new SessionController(backend);
    const acc = await ctrl.signIn({ label: 'Alice' });
    expect(ctrl.memberId()).toBe(acc.id);
    expect(await ctrl.getAccessToken()).toBe(acc.id);
    expect(ctrl.capabilities()).toEqual({ canRegister: true, canLogin: true, sync: true });
    expect(ctrl.backend).toBe(backend);

    const cb = vi.fn();
    ctrl.onChange(cb);
    await ctrl.signIn({ label: 'Bob' });
    expect(cb).toHaveBeenCalledTimes(1);
  });

  it('requires a backend', () => {
    expect(() => new SessionController(null)).toThrow();
  });
});
