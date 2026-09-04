// vault.joinAsMember orchestration (Mode A member sharing, read-side). The trust decision (genesis-walk,
// prefix-pin, founder extraction) lives in the wasm verifyKeyringWalk (Rust, tested there + end-to-end in
// the read e2e); here we cover the JS WIRING adversarially, per the design review:
//   - retention is keyed by the WALK-DERIVED revision (i+1), never the server's unverified label;
//   - fail-closed ordering: fp mismatch / wrong passphrase persist NOTHING;
//   - a persistence failure after unlock FREES the sealer (no leaked DEK-holder);
//   - a repeat join (a stale link) is refused rather than rolling the member back;
//   - the chain-only guard.
import { describe, it, expect } from 'vitest';
import { createVault, frameHops, KeyringJoinError } from '../app/src/core/sealer/vault.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { Watermarks } from '../app/src/core/watermarks.js';
import { fingerprintSigners } from '../app/src/core/invite.js';

const bytesFill = (fill, len = 8) => new Uint8Array(len).fill(fill);
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const treeKey = 'k1';
const treeId = new Uint8Array(16).fill(0xaa);

// The signer set the walk "returns"; the invite fp is computed over the SAME set (the real fingerprint).
const SIGNERS = [
  { memberId: 'owner', authorPublic: new Uint8Array(32).fill(0x11) },
  { memberId: 'co', authorPublic: new Uint8Array(32).fill(0x22) },
];
const signersJson = JSON.stringify(SIGNERS.map((s) => ({ memberId: s.memberId, authorPublic: hex(s.authorPublic) })));

// A 52-byte pinned watermark (revision(4) ‖ pin(48)) as unlockAsMember returns.
const pinnedWm = (rev) => {
  const b = new Uint8Array(4 + 48).fill(0xcd);
  new DataView(b.buffer).setUint32(0, rev, false);
  return b;
};

// A fake crypto worker: verifyKeyringWalk + unlockAsMember are stubbed to return controlled values (the
// real trust decision is the wasm's, tested there), and it records lock() so we can assert sealer freeing.
function joinWorker({ bodies, revision, unlockThrows = false } = {}) {
  const calls = { lock: [], unlock: 0 };
  return {
    calls,
    async verifyKeyringWalk() {
      return { revision, headKeyring: bodies[bodies.length - 1], signersJson, bodiesFramed: frameHops(bodies) };
    },
    async unlockAsMember() {
      calls.unlock++;
      if (unlockThrows) throw new Error('bad passphrase');
      return { watermark: pinnedWm(revision), didKey: 'did:key:zTest', needsReseal: false, sealerId: 's1' };
    },
    lock(id) {
      calls.lock.push(id);
    },
  };
}

async function makeInvite(overrides = {}) {
  return { fp: await fingerprintSigners(SIGNERS), pinnedRevision: 1, pinnedHash: new Uint8Array(32).fill(0x01), ...overrides };
}

describe('vault.joinAsMember', () => {
  it('retains every RAW body under its WALK-DERIVED revision (i+1), NOT the server label, and unlocks at the head', async () => {
    const bodies = [bytesFill(0xa1), bytesFill(0xa2), bytesFill(0xa3)];
    const worker = joinWorker({ bodies, revision: 3 });
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    const vault = createVault({ worker, keyringStore, watermarks });
    // The server LABELS are deliberately wrong/permuted — retention must ignore them.
    const revisions = [
      { revision: 50, bytes: bytesFill(0xf0) },
      { revision: 9, bytes: bytesFill(0xf1) },
      { revision: 2, bytes: bytesFill(0xf2) },
    ];
    const out = await vault.joinAsMember(treeKey, treeId, 'pw', 'me', bytesFill(0x77), revisions, await makeInvite());
    expect(out.didKey).toBe('did:key:zTest');
    // Stored under 1,2,3 (walk-derived) — never 50/9.
    expect(Array.from(await keyringStore.at(treeKey, 1))).toEqual(Array.from(bodies[0]));
    expect(Array.from(await keyringStore.at(treeKey, 2))).toEqual(Array.from(bodies[1]));
    expect(Array.from(await keyringStore.at(treeKey, 3))).toEqual(Array.from(bodies[2]));
    expect(await keyringStore.at(treeKey, 50)).toBeFalsy();
    expect(await keyringStore.at(treeKey, 9)).toBeFalsy();
    // Head = the walk's head body; watermark = the pinned form the wasm returned.
    expect(Array.from(await keyringStore.load(treeKey))).toEqual(Array.from(bodies[2]));
    expect(watermarks.current(treeKey).keyringCursor.length).toBe(4 + 48);
  });

  it('refuses a repeat join when the tree is already present locally (a stale link cannot roll the member back)', async () => {
    const bodies = [bytesFill(0xa1)];
    const worker = joinWorker({ bodies, revision: 1 });
    const keyringStore = memoryKeyringStore();
    await keyringStore.saveHead(treeKey, 'chain', bytesFill(0x07)); // already joined earlier
    const vault = createVault({ worker, keyringStore, watermarks: new Watermarks() });
    await expect(
      vault.joinAsMember(treeKey, treeId, 'pw', 'me', bytesFill(0x77), [{ revision: 1, bytes: bytesFill(0xf0) }], await makeInvite()),
    ).rejects.toThrow(KeyringJoinError);
    expect(worker.calls.unlock).toBe(0); // never even walked/unlocked
  });

  it('fail-closed on a fingerprint mismatch: rejects and persists NOTHING (unlock never runs)', async () => {
    const bodies = [bytesFill(0xa1), bytesFill(0xa2)];
    const worker = joinWorker({ bodies, revision: 2 });
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    const vault = createVault({ worker, keyringStore, watermarks });
    const invite = await makeInvite({ fp: 'not-the-real-fingerprint' });
    await expect(
      vault.joinAsMember(treeKey, treeId, 'pw', 'me', bytesFill(0x77), [{ revision: 1, bytes: bytesFill(0xf0) }, { revision: 2, bytes: bytesFill(0xf1) }], invite),
    ).rejects.toThrow(/fingerprint/);
    expect(worker.calls.unlock).toBe(0);
    expect(await keyringStore.at(treeKey, 1)).toBeFalsy();
    expect(await keyringStore.load(treeKey)).toBeFalsy();
    expect(watermarks.current(treeKey).keyringCursor.length).toBe(0); // never advanced
  });

  it('fail-closed on a wrong passphrase: unlock throws AFTER the walk, and nothing is persisted', async () => {
    const bodies = [bytesFill(0xa1), bytesFill(0xa2)];
    const worker = joinWorker({ bodies, revision: 2, unlockThrows: true });
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    const vault = createVault({ worker, keyringStore, watermarks });
    await expect(
      vault.joinAsMember(treeKey, treeId, 'pw', 'me', bytesFill(0x77), [{ revision: 1, bytes: bytesFill(0xf0) }, { revision: 2, bytes: bytesFill(0xf1) }], await makeInvite()),
    ).rejects.toThrow(/passphrase/);
    expect(await keyringStore.at(treeKey, 1)).toBeFalsy();
    expect(await keyringStore.load(treeKey)).toBeFalsy();
    expect(watermarks.current(treeKey).keyringCursor.length).toBe(0); // never advanced
    expect(worker.calls.lock).toEqual([]); // no sealer was created, so none to free
  });

  it('frees the just-created sealer if persistence fails after unlock (no leaked DEK-holder)', async () => {
    const bodies = [bytesFill(0xa1), bytesFill(0xa2)];
    const worker = joinWorker({ bodies, revision: 2 });
    const keyringStore = memoryKeyringStore();
    keyringStore.save = async () => {
      throw new Error('disk full');
    };
    const vault = createVault({ worker, keyringStore, watermarks: new Watermarks() });
    await expect(
      vault.joinAsMember(treeKey, treeId, 'pw', 'me', bytesFill(0x77), [{ revision: 1, bytes: bytesFill(0xf0) }, { revision: 2, bytes: bytesFill(0xf1) }], await makeInvite()),
    ).rejects.toThrow(/disk full/);
    expect(worker.calls.lock).toEqual(['s1']); // the sealer was freed
  });

  it('is chain-only: refuses on a dag-engine vault', async () => {
    const worker = joinWorker({ bodies: [bytesFill(0xa1)], revision: 1 });
    const vault = createVault({ worker, keyringStore: memoryKeyringStore(), watermarks: new Watermarks(), engine: 'dag' });
    await expect(
      vault.joinAsMember(treeKey, treeId, 'pw', 'me', bytesFill(0x77), [{ revision: 1, bytes: bytesFill(0xf0) }], await makeInvite()),
    ).rejects.toThrow(/chain-only/);
  });
});
