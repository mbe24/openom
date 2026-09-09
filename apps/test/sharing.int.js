// core/sharing.js joinAsMember — the member-join JS WIRING (the wasm trust decisions are stubbed; they are
// proven in Rust: openom_vault::sharing::chain_genesis_walk_join_end_to_end + the app-core share→verify e2es).
// Adversarially covers: walk-derived retention (never the server's label), fail-closed ordering (a walk / pin
// / passphrase failure persists NOTHING), handle-free on a post-unlock store failure, the already-present
// guard, and the fingerprint cross-check.
import { describe, it, expect } from 'vitest';
import { joinAsMember, frameHops, unframe, JoinError } from '../app/src/core/sharing.js';
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
