import { describe, it, expect } from 'vitest';
import { createVault } from '../app/src/core/sealer/vault.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { Watermarks, RegressionError } from '../app/src/core/watermarks.js';

// A fake WASM vault that models the real veneer's CONTRACT (not its crypto): keyrings carry a
// passphrase + recovery code + an opaque "dek" + revision; recover/changePassphrase bump the
// revision (respecting min_revision) and rotate the code; takeSealer() yields a reversible
// core keyed by the dek, so two sessions with the same dek round-trip (cross-device). This
// lets us test the orchestration — storage, watermarking, min_revision passing — without
// Argon2id.
const enc = new TextEncoder();
const dec = new TextDecoder();

function fakeCore(dek: number) {
  return {
    treeId: new Uint8Array(),
    sealEntry: (kind: string, _f: string, _c: string, counter: number, _p: Uint8Array, _cov: number, _b: Uint8Array, pt: Uint8Array) => ({
      envelope: enc.encode(JSON.stringify({ dek, kind, pt: Array.from(pt) })),
      ciphertextHash: new Uint8Array([counter & 0xff]),
    }),
    openEntry: (kind: string, bytes: Uint8Array) => {
      const r = JSON.parse(dec.decode(bytes));
      if (r.dek !== dek) throw new Error('wrong dek');
      if (r.kind !== kind) throw new Error('wrong kind');
      return new Uint8Array(r.pt);
    },
  };
}

function vaultResult(kr: any, recoveryCode: string, revision: number, dek: number | null) {
  let taken = false;
  return {
    keyring: enc.encode(JSON.stringify(kr)),
    recoveryCode,
    revision,
    takeSealer() {
      if (taken || dek == null) return undefined;
      taken = true;
      return fakeCore(dek);
    },
  };
}

function fakeWasm() {
  const decode = (b: Uint8Array) => JSON.parse(dec.decode(b));
  let dekSeq = 0;
  return {
    provision(passphrase: string) {
      const dek = ++dekSeq;
      const kr = { passphrase, revision: 1, dek, recoveryCode: 'CODE-1' };
      return vaultResult(kr, 'CODE-1', 1, dek);
    },
    unlock(keyring: Uint8Array, passphrase: string) {
      const kr = decode(keyring);
      if (kr.passphrase !== passphrase) throw new Error('wrong passphrase');
      return vaultResult(kr, '', kr.revision, kr.dek);
    },
    recover(keyring: Uint8Array, code: string, newPass: string, _t: any, _m: any, _r: any, minRev: number) {
      const kr = decode(keyring);
      if (code !== kr.recoveryCode) throw new Error('wrong code');
      if (kr.revision < minRev) throw new Error('revision rollback');
      const revision = Math.max(minRev, kr.revision) + 1;
      const nk = { passphrase: newPass, revision, dek: kr.dek, recoveryCode: 'CODE-' + revision };
      return vaultResult(nk, nk.recoveryCode, revision, kr.dek);
    },
    changePassphrase(keyring: Uint8Array, oldPass: string, newPass: string, _t: any, _m: any, minRev: number) {
      const kr = decode(keyring);
      if (oldPass !== kr.passphrase) throw new Error('wrong passphrase');
      const revision = Math.max(minRev, kr.revision) + 1;
      const nk = { passphrase: newPass, revision, dek: kr.dek, recoveryCode: 'CODE-' + revision };
      return vaultResult(nk, nk.recoveryCode, revision, null); // no new sealer
    },
  };
}

function memKV() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
  };
}

function newVault(keyringStore = memoryKeyringStore(), watermarks = new Watermarks(memKV())) {
  return { vault: createVault({ wasm: fakeWasm(), keyringStore, watermarks }), keyringStore, watermarks };
}

const TREE = 'tree-1';
const TID = new Uint8Array(16).fill(3);
const MEMBER = 'local-owner';
const REPLICA = new Uint8Array(16).fill(1);

async function sealOpen(session: any, text: string) {
  const sealed = await session.seal(enc.encode(text), TREE, { kind: 'snapshot' });
  return { sealed };
}

describe('createVault (passphrase lifecycle orchestration)', () => {
  it('provisions, stores the keyring, watermarks revision 1, and returns a working session', async () => {
    const { vault, keyringStore, watermarks } = newVault();
    const { session, recoveryCode } = await vault.provision(TREE, TID, 'pass', MEMBER, REPLICA);
    expect(recoveryCode).toBe('CODE-1');
    expect(await keyringStore.load(TREE)).not.toBeNull();
    expect(watermarks.current(TREE).keyringRevision).toBe(1);
    const { sealed } = await sealOpen(session, 'hi');
    expect(new TextDecoder().decode(await session.open(sealed, TREE, { kind: 'snapshot' }))).toBe('hi');
  });

  it('unlocks on another "device" and opens data sealed by the first (same DEK)', async () => {
    const store = memoryKeyringStore();
    const a = newVault(store);
    const { session: sa } = await a.vault.provision(TREE, TID, 'pass', MEMBER, REPLICA);
    const { sealed } = await sealOpen(sa, 'secret');

    const b = newVault(store); // fresh vault + watermarks, same keyring store
    const { session: sb } = await b.vault.unlock(TREE, TID, 'pass', MEMBER, REPLICA);
    expect(new TextDecoder().decode(await sb.open(sealed, TREE, { kind: 'snapshot' }))).toBe('secret');
  });

  it('rejects a wrong passphrase', async () => {
    const { vault } = newVault();
    await vault.provision(TREE, TID, 'right', MEMBER, REPLICA);
    await expect(vault.unlock(TREE, TID, 'wrong', MEMBER, REPLICA)).rejects.toThrow(/wrong passphrase/);
  });

  it('refuses to unlock a keyring rolled back below the watermark', async () => {
    const store = memoryKeyringStore();
    const { vault, watermarks } = newVault(store);
    await vault.provision(TREE, TID, 'old', MEMBER, REPLICA); // rev 1
    const stale = await store.load(TREE); // capture the rev-1 keyring
    await vault.changePassphrase(TREE, TID, 'old', 'new', MEMBER); // rev 2 → watermark 2

    await store.save(TREE, stale!); // a server serves the old rev-1 keyring back
    await expect(vault.unlock(TREE, TID, 'old', MEMBER, REPLICA)).rejects.toThrow(RegressionError);
    expect(watermarks.current(TREE).keyringRevision).toBe(2); // watermark held
  });

  it('recovers with the code, opens old data, bumps revision, rotates the code', async () => {
    const store = memoryKeyringStore();
    const a = newVault(store);
    const { session: sa } = await a.vault.provision(TREE, TID, 'old', MEMBER, REPLICA);
    const { sealed } = await sealOpen(sa, 'data');

    const b = newVault(store);
    const { session: sb, recoveryCode } = await b.vault.recover(TREE, TID, 'CODE-1', 'new', MEMBER, REPLICA);
    expect(recoveryCode).toBe('CODE-2');
    expect(b.watermarks.current(TREE).keyringRevision).toBe(2);
    expect(new TextDecoder().decode(await sb.open(sealed, TREE, { kind: 'snapshot' }))).toBe('data');
    // new passphrase unlocks; old does not
    await expect(b.vault.unlock(TREE, TID, 'new', MEMBER, REPLICA)).resolves.toBeTruthy();
    await expect(b.vault.unlock(TREE, TID, 'old', MEMBER, REPLICA)).rejects.toThrow();
  });

  it('change-passphrase rotates the code and bumps revision; old passphrase then fails', async () => {
    const { vault, watermarks } = newVault();
    await vault.provision(TREE, TID, 'old', MEMBER, REPLICA);
    const { recoveryCode } = await vault.changePassphrase(TREE, TID, 'old', 'new', MEMBER);
    expect(recoveryCode).toBe('CODE-2');
    expect(watermarks.current(TREE).keyringRevision).toBe(2);
    await expect(vault.unlock(TREE, TID, 'new', MEMBER, REPLICA)).resolves.toBeTruthy();
    await expect(vault.unlock(TREE, TID, 'old', MEMBER, REPLICA)).rejects.toThrow();
  });

  it('passes the watermark as min_revision so a stale keyring is refused on recover', async () => {
    const store = memoryKeyringStore();
    const { vault } = newVault(store);
    await vault.provision(TREE, TID, 'old', MEMBER, REPLICA); // rev 1
    const stale = await store.load(TREE);
    await vault.changePassphrase(TREE, TID, 'old', 'new', MEMBER); // watermark → 2
    await store.save(TREE, stale!); // roll the stored keyring back to rev 1
    // recover feeds min_revision = 2; the (fake) core refuses rev 1 < 2.
    await expect(vault.recover(TREE, TID, 'CODE-1', 'x', MEMBER, REPLICA)).rejects.toThrow(/rollback/);
  });

  it('hasKeyring reflects provisioning', async () => {
    const { vault } = newVault();
    expect(await vault.hasKeyring(TREE)).toBe(false);
    await vault.provision(TREE, TID, 'pass', MEMBER, REPLICA);
    expect(await vault.hasKeyring(TREE)).toBe(true);
  });

  it('unlock requires a provisioned keyring', async () => {
    const { vault } = newVault();
    await expect(vault.unlock(TREE, TID, 'pass', MEMBER, REPLICA)).rejects.toThrow(/no keyring/);
  });
});
