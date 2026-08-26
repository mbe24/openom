import { describe, it, expect } from 'vitest';
import { createVault } from '../app/src/core/sealer/vault.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { Watermarks } from '../app/src/core/watermarks.js';

// A fake crypto WORKER modelling the real worker's flat contract (values + sealerId handles),
// not its crypto: keyrings carry a passphrase + recovery code + an opaque "dek" + revision;
// recover/changePassphrase bump the revision (respecting min_revision) and rotate the code;
// sealEntry/openEntry are keyed by sealerId to a dek, so two sessions over the same dek
// round-trip (cross-device). Lets us test orchestration — storage, watermarking, min_revision,
// session wiring — without a real Worker or Argon2id.
const enc = new TextEncoder();
const dec = new TextDecoder();

function fakeWorker() {
  const decode = (b: Uint8Array) => JSON.parse(dec.decode(b));
  const encode = (o: any) => enc.encode(JSON.stringify(o));
  const sealers = new Map<string, number>(); // sealerId -> dek
  let seq = 0;
  let dekSeq = 0;
  const reg = (dek: number) => {
    const id = 's' + ++seq;
    sealers.set(id, dek);
    return id;
  };
  return {
    async provision(passphrase: string) {
      const dek = ++dekSeq;
      const kr = { passphrase, revision: 1, dek, recoveryCode: 'CODE-1' };
      return { keyring: encode(kr), recoveryCode: 'CODE-1', revision: 1, didKey: 'did:key:z6Mk' + passphrase, sealerId: reg(dek) };
    },
    async unlock(keyring: Uint8Array, passphrase: string, _t: any, _m: any, _r: any, minRev: number) {
      const kr = decode(keyring);
      if (kr.passphrase !== passphrase) throw new Error('wrong passphrase');
      if (kr.revision < minRev) throw new Error('keyring revision rollback');
      return { revision: kr.revision, didKey: 'did:key:z6Mk' + kr.passphrase, sealerId: reg(kr.dek) };
    },
    async recover(keyring: Uint8Array, code: string, newPass: string, _t: any, _m: any, _r: any, minRev: number) {
      const kr = decode(keyring);
      if (code !== kr.recoveryCode) throw new Error('wrong code');
      if (kr.revision < minRev) throw new Error('revision rollback');
      const revision = Math.max(minRev, kr.revision) + 1;
      const nk = { passphrase: newPass, revision, dek: kr.dek, recoveryCode: 'CODE-' + revision };
      return { keyring: encode(nk), recoveryCode: nk.recoveryCode, revision, didKey: 'did:key:z6Mk' + newPass, sealerId: reg(kr.dek) };
    },
    async changePassphrase(keyring: Uint8Array, oldPass: string, newPass: string, _t: any, _m: any, minRev: number) {
      const kr = decode(keyring);
      if (oldPass !== kr.passphrase) throw new Error('wrong passphrase');
      const revision = Math.max(minRev, kr.revision) + 1;
      const nk = { passphrase: newPass, revision, dek: kr.dek, recoveryCode: 'CODE-' + revision };
      return { keyring: encode(nk), recoveryCode: nk.recoveryCode, revision };
    },
    async sealEntry(id: string, kind: string, _f: string, _c: string, counter: number) {
      const dek = sealers.get(id);
      return { envelope: encode({ dek, kind }), ciphertextHash: new Uint8Array([counter & 0xff]) };
    },
    async openEntry(id: string, kind: string, bytes: Uint8Array) {
      const dek = sealers.get(id);
      const r = decode(bytes);
      if (r.dek !== dek) throw new Error('wrong dek');
      if (r.kind !== kind) throw new Error('wrong kind');
      return new Uint8Array();
    },
    lock(id: string) {
      sealers.delete(id);
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
  const worker = fakeWorker();
  const vault = createVault({ worker, keyringStore, watermarks, makeReplicaId: () => new Uint8Array(16) });
  return { vault, keyringStore, watermarks, worker };
}

const TREE = 'tree-1';
const TID = new Uint8Array(16).fill(3);
const MEMBER = 'local-owner';

// Prove a session actually seals+opens through its worker core (kind carried through).
async function roundTrips(session: any) {
  const sealed = await session.seal(enc.encode('x'), TREE, { kind: 'snapshot' });
  await session.open(sealed, TREE, { kind: 'snapshot' }); // throws if the dek/kind mismatch
  return true;
}

describe('createVault (worker orchestration)', () => {
  it('provisions, stores the keyring, watermarks revision 1, returns a working session', async () => {
    const { vault, keyringStore, watermarks } = newVault();
    const { session, recoveryCode } = await vault.provision(TREE, TID, 'pass', MEMBER);
    expect(recoveryCode).toBe('CODE-1');
    expect(await keyringStore.load(TREE)).not.toBeNull();
    expect(watermarks.current(TREE).keyringRevision).toBe(1);
    expect(await roundTrips(session)).toBe(true);
  });

  it('unlocks on another "device" and opens data sealed by the first (same DEK)', async () => {
    const store = memoryKeyringStore();
    const a = newVault(store);
    const { session: sa } = await a.vault.provision(TREE, TID, 'pass', MEMBER);
    const sealed = await sa.seal(enc.encode('secret'), TREE, { kind: 'snapshot' });

    const b = newVault(store); // fresh vault + watermarks + worker, same keyring store
    const { session: sb } = await b.vault.unlock(TREE, TID, 'pass', MEMBER);
    // b's worker registered the same dek from the keyring, so it opens a's sealed bytes.
    await expect(sb.open(sealed, TREE, { kind: 'snapshot' })).resolves.toBeInstanceOf(Uint8Array);
  });

  it('surfaces a stable did:key author id across devices', async () => {
    const store = memoryKeyringStore();
    const a = newVault(store);
    const { didKey: da } = await a.vault.provision(TREE, TID, 'pass', MEMBER);

    const b = newVault(store); // a second "device", same keyring store
    const { didKey: db } = await b.vault.unlock(TREE, TID, 'pass', MEMBER);

    expect(da).toMatch(/^did:key:/);
    // Same passphrase → same identity → same did:key across devices, unlike the per-context replicaId.
    expect(db).toBe(da);
  });

  it('rejects a wrong passphrase', async () => {
    const { vault } = newVault();
    await vault.provision(TREE, TID, 'right', MEMBER);
    await expect(vault.unlock(TREE, TID, 'wrong', MEMBER)).rejects.toThrow(/wrong passphrase/);
  });

  it('refuses to unlock a keyring below the watermark (min_revision backstop)', async () => {
    const store = memoryKeyringStore();
    const { vault, watermarks } = newVault(store);
    await vault.provision(TREE, TID, 'old', MEMBER); // rev 1, stored head = 1
    // The watermark has advanced past the stored head (e.g. a keyring sync saw a newer revision) — the
    // worker refuses unlocking a below-watermark keyring BEFORE exposing a sealer. (The store now retains
    // every revision + always unlocks with its head, so a server can't roll the head back by serving an
    // old keyring; this min_revision check is the deeper backstop.)
    watermarks.observe(TREE, { keyringRevision: 2 });
    await expect(vault.unlock(TREE, TID, 'old', MEMBER)).rejects.toThrow(/rollback/i);
    expect(watermarks.current(TREE).keyringRevision).toBe(2);
  });

  it('recovers with the code, bumps revision, rotates the code, opens old data', async () => {
    const store = memoryKeyringStore();
    const a = newVault(store);
    const { session: sa } = await a.vault.provision(TREE, TID, 'old', MEMBER);
    const sealed = await sa.seal(enc.encode('data'), TREE, { kind: 'snapshot' });

    const b = newVault(store);
    const { session: sb, recoveryCode } = await b.vault.recover(TREE, TID, 'CODE-1', 'new', MEMBER);
    expect(recoveryCode).toBe('CODE-2');
    expect(b.watermarks.current(TREE).keyringRevision).toBe(2);
    await expect(sb.open(sealed, TREE, { kind: 'snapshot' })).resolves.toBeInstanceOf(Uint8Array);
    await expect(b.vault.unlock(TREE, TID, 'new', MEMBER)).resolves.toBeTruthy();
    await expect(b.vault.unlock(TREE, TID, 'old', MEMBER)).rejects.toThrow();
  });

  it('change-passphrase rotates the code and bumps revision; old passphrase then fails', async () => {
    const { vault, watermarks } = newVault();
    await vault.provision(TREE, TID, 'old', MEMBER);
    const { recoveryCode } = await vault.changePassphrase(TREE, TID, 'old', 'new', MEMBER);
    expect(recoveryCode).toBe('CODE-2');
    expect(watermarks.current(TREE).keyringRevision).toBe(2);
    await expect(vault.unlock(TREE, TID, 'new', MEMBER)).resolves.toBeTruthy();
    await expect(vault.unlock(TREE, TID, 'old', MEMBER)).rejects.toThrow();
  });

  it('passes the watermark as min_revision so a below-watermark keyring is refused on recover', async () => {
    const store = memoryKeyringStore();
    const { vault, watermarks } = newVault(store);
    await vault.provision(TREE, TID, 'old', MEMBER); // rev 1, stored head = 1
    watermarks.observe(TREE, { keyringRevision: 2 }); // watermark advanced past the stored head
    await expect(vault.recover(TREE, TID, 'CODE-1', 'x', MEMBER)).rejects.toThrow(/rollback/);
  });

  it('hasKeyring reflects provisioning', async () => {
    const { vault } = newVault();
    expect(await vault.hasKeyring(TREE)).toBe(false);
    await vault.provision(TREE, TID, 'pass', MEMBER);
    expect(await vault.hasKeyring(TREE)).toBe(true);
  });

  it('unlock requires a provisioned keyring', async () => {
    const { vault } = newVault();
    await expect(vault.unlock(TREE, TID, 'pass', MEMBER)).rejects.toThrow(/no keyring/);
  });
});
