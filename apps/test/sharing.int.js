// core/sharing.js joinAsMember — the member-join JS WIRING (the wasm trust decisions are stubbed; they are
// proven in Rust: openom_vault::sharing::chain_genesis_walk_join_end_to_end + the app-core share→verify e2es).
// Adversarially covers: walk-derived retention (never the server's label), fail-closed ordering (a walk / pin
// / passphrase failure persists NOTHING), handle-free on a post-unlock store failure, the already-present
// guard, and the fingerprint cross-check.
import { describe, it, expect } from 'vitest';
import { joinAsMember, publishKeyring, frameHops, unframe, JoinError, KeyringForkError } from '../app/src/core/sharing.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';

const treeId = new Uint8Array(16).fill(0xaa);
const OWNER_KEY = new Uint8Array(32).fill(0x11);
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const signersJson = JSON.stringify([{ memberId: 'owner', authorPublicKey: hex(OWNER_KEY) }]);

// Two RAW per-revision bodies the walk "returns" (genesis + the shared head).
const REV1 = new Uint8Array([1, 1, 1]);
const REV2 = new Uint8Array([2, 2, 2, 2]);

// A fake wasm: verifyKeyringWalk + unlockAsMember return controlled values, recording handle frees.
function fakeWasm({ walkThrows = false, unlockThrows = false, revision = 2 } = {}) {
  const calls = { freed: 0, unlocked: 0 };
  return {
    calls,
    verifyKeyringWalk() {
      if (walkThrows) throw new Error('bad walk');
      return {
        revision,
        headKeyring: REV2,
        signersJson,
        bodiesFramed: frameHops([REV1, REV2]),
      };
    },
    unlockAsMember() {
      if (unlockThrows) throw new Error('wrong passphrase');
      calls.unlocked += 1;
      return {
        takeHandle: () => ({ free: () => { calls.freed += 1; } }),
        didKey: 'did:key:z6MkBob',
        watermark: new Uint8Array(52),
      };
    },
  };
}

const transport = (revisions) => ({ readKeyring: async () => ({ revisions, head: revisions.length }) });
const revs = [{ revision: 1, bytes: REV1 }, { revision: 2, bytes: REV2 }];

const baseOpts = {
  treeId,
  treeUuid: 'uuid-1',
  docId: 'k1',
  passphrase: 'pw',
  memberId: 'acct-bob',
  memberKdfParams: new Uint8Array(8),
  pinnedRevision: 1,
  pinnedHash: new Uint8Array(32).fill(0xcd),
};

describe('joinAsMember wiring', () => {
  it('frame/unframe round-trips the hop buffer', () => {
    const back = unframe(frameHops([REV1, REV2]));
    expect(back).toHaveLength(2);
    expect([...back[0]]).toEqual([...REV1]);
    expect([...back[1]]).toEqual([...REV2]);
  });

  it('verifies, retains every revision by walk-derived number, and unlocks', async () => {
    const wasm = fakeWasm();
    const keyringStore = memoryKeyringStore();
    const res = await joinAsMember({ wasm, transport: transport(revs), keyringStore }, baseOpts);
    expect(res.didKey).toBe('did:key:z6MkBob');
    expect(wasm.calls.unlocked).toBe(1);
    // Retained under WALK-DERIVED revisions 1 and 2 (not the server's label).
    expect([...(await keyringStore.at('k1', 1))]).toEqual([...REV1]);
    expect([...(await keyringStore.at('k1', 2))]).toEqual([...REV2]);
    expect((await keyringStore.loadHead('k1')).engine).toBe('chain');
  });

  it('refuses a re-join when the tree is already present (no rollback)', async () => {
    const keyringStore = memoryKeyringStore();
    await keyringStore.saveHead('k1', 'chain', REV2);
    await expect(
      joinAsMember({ wasm: fakeWasm(), transport: transport(revs), keyringStore }, baseOpts),
    ).rejects.toBeInstanceOf(JoinError);
  });

  it('fails closed on a bad walk — nothing persisted', async () => {
    const keyringStore = memoryKeyringStore();
    await expect(
      joinAsMember({ wasm: fakeWasm({ walkThrows: true }), transport: transport(revs), keyringStore }, baseOpts),
    ).rejects.toBeInstanceOf(JoinError);
    expect(await keyringStore.load('k1')).toBeNull();
  });

  it('fails closed on a mismatched revision count', async () => {
    const keyringStore = memoryKeyringStore();
    // walk claims revision 3 but only returns 2 bodies.
    await expect(
      joinAsMember({ wasm: fakeWasm({ revision: 3 }), transport: transport(revs), keyringStore }, baseOpts),
    ).rejects.toThrow(/mismatched revision count/);
    expect(await keyringStore.load('k1')).toBeNull();
  });

  it('fails closed on a wrong passphrase (unlock throws) — nothing persisted', async () => {
    const keyringStore = memoryKeyringStore();
    await expect(
      joinAsMember({ wasm: fakeWasm({ unlockThrows: true }), transport: transport(revs), keyringStore }, baseOpts),
    ).rejects.toBeInstanceOf(JoinError);
    expect(await keyringStore.load('k1')).toBeNull();
  });

  it('frees the handle if persistence fails after unlock (no leaked DEK-holder)', async () => {
    const wasm = fakeWasm();
    const keyringStore = memoryKeyringStore();
    keyringStore.save = async () => { throw new Error('store down'); };
    await expect(
      joinAsMember({ wasm, transport: transport(revs), keyringStore }, baseOpts),
    ).rejects.toThrow(/store down/);
    expect(wasm.calls.freed).toBe(1);
  });

  it('rejects a fingerprint mismatch when a verifier is supplied', async () => {
    const keyringStore = memoryKeyringStore();
    const verifyFingerprint = async () => false;
    await expect(
      joinAsMember(
        { wasm: fakeWasm(), transport: transport(revs), keyringStore, verifyFingerprint },
        { ...baseOpts, fp: 'expected-fp' },
      ),
    ).rejects.toThrow(/fingerprint/);
    expect(await keyringStore.load('k1')).toBeNull();
  });
});

// A publish transport that records PUTs and reports a server head; putKeyring throws a ConflictError when the
// revision is already present, mimicking the server's 409.
function publishTransport(serverHead = 0, presentBytes = {}) {
  const puts = [];
  return {
    puts,
    async readKeyring(_id, rev) {
      const bytes = presentBytes[rev];
      return { revisions: bytes ? [{ revision: rev, bytes }] : [], head: serverHead };
    },
    async putKeyring(_id, update) {
      puts.push(update);
    },
  };
}

// A wasm double whose wrapChainKeyringUpdate just tags the bytes (the real wrap is Rust-tested).
const wrapWasm = { wrapChainKeyringUpdate: (b) => new Uint8Array([0xff, ...b]) };

describe('publishKeyring wiring', () => {
  it('publishes every retained revision the server is missing, ascending', async () => {
    const keyringStore = memoryKeyringStore();
    await keyringStore.save('k1', 1, REV1);
    await keyringStore.save('k1', 2, REV2);
    const transport = publishTransport(0);
    const res = await publishKeyring({ wasm: wrapWasm, transport, keyringStore }, { docId: 'k1' });
    expect(res.head).toBe(2);
    expect(transport.puts).toHaveLength(2); // rev 1 and rev 2
    expect([...transport.puts[0]]).toEqual([0xff, ...REV1]);
  });

  it('is a no-op when the server is already at the local head', async () => {
    const keyringStore = memoryKeyringStore();
    await keyringStore.save('k1', 1, REV1);
    const transport = publishTransport(1);
    const res = await publishKeyring({ wasm: wrapWasm, transport, keyringStore }, { docId: 'k1' });
    expect(res.head).toBe(1);
    expect(transport.puts).toHaveLength(0);
  });

  it('treats a 409 with identical served bytes as benign', async () => {
    const keyringStore = memoryKeyringStore();
    await keyringStore.save('k1', 1, REV1);
    const transport = publishTransport(0, { 1: REV1 });
    const conflict = Object.assign(new Error('409'), { name: 'ConflictError' });
    transport.putKeyring = async () => { throw conflict; };
    const res = await publishKeyring({ wasm: wrapWasm, transport, keyringStore }, { docId: 'k1' });
    expect(res.head).toBe(1); // advanced past the already-admitted revision
  });

  it('raises a fork when a 409 serves DIFFERENT bytes', async () => {
    const keyringStore = memoryKeyringStore();
    await keyringStore.save('k1', 1, REV1);
    const transport = publishTransport(0, { 1: REV2 }); // server has different bytes at rev 1
    const conflict = Object.assign(new Error('409'), { name: 'ConflictError' });
    transport.putKeyring = async () => { throw conflict; };
    await expect(
      publishKeyring({ wasm: wrapWasm, transport, keyringStore }, { docId: 'k1' }),
    ).rejects.toBeInstanceOf(KeyringForkError);
  });
});
