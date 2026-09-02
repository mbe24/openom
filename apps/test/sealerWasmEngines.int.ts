import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, {
  provision as wasmProvision,
  unlock as wasmUnlock,
  recover as wasmRecover,
  changePassphrase as wasmChangePassphrase,
  provisionMember as wasmProvisionMember,
  dagAddMember as wasmDagAddMember,
  dagRemoveMember as wasmDagRemoveMember,
  dagUnlockAsMember as wasmDagUnlockAsMember,
  dagMerge as wasmDagMerge,
  dagReseal as wasmDagReseal,
  keyringSummary as wasmKeyringSummary,
  keyringCovers as wasmKeyringCovers,
} from '../app/src/vendor/vault/openom_vault.js';
import { pushMembershipSummary } from '../app/src/core/membershipSummary.js';

// The REAL wasm sealer, driven directly (no fake worker): loads the vendored openom_sealer_bg.wasm and
// runs the passphrase lifecycle through it, selecting the engine by tag. This is the web host's half of
// OPE-278's "dag through both hosts" — the counterpart to the native VaultHost dag tests — proving the
// dag engine actually works end to end through the browser-facing wasm veneer, not just in native Rust.
//
// It runs under Node (vitest, like every *.int) because the wasm glue is engine-agnostic to the host: the
// only browser API it needs is globalThis.crypto.getRandomValues, which Node 22 provides. `--target web`
// glue's default init accepts the wasm bytes directly, so no fetch/URL loader is needed here.

const enc = new TextEncoder();
const dec = new TextDecoder();

const TREE = new Uint8Array(16).fill(7); // a fixed 16-byte tree id
const MEMBER = 'acct-1';
const replica = (n: number) => new Uint8Array(16).fill(n);

// Seal one snapshot entry with a live sealer, returning the envelope (and freeing the outcome).
function sealSnapshot(sealer: any, plaintext: string): Uint8Array {
  const out = sealer.sealEntry(
    'snapshot',
    'openom-json',
    'none',
    0,
    new Uint8Array(),
    0,
    new Uint8Array(),
    enc.encode(plaintext),
  );
  const envelope = out.envelope;
  out.free();
  return envelope;
}

beforeAll(async () => {
  const wasmUrl = new URL('../app/src/vendor/vault/openom_vault_bg.wasm', import.meta.url);
  let bytes: Buffer;
  try {
    bytes = readFileSync(fileURLToPath(wasmUrl));
  } catch (e) {
    // The vendored wasm is a gitignored build artifact — rebuild it whenever the sealer crate changes.
    throw new Error(
      'vendored sealer wasm not found — build it first: `pnpm build:sealer` (from apps/) or ' +
        `\`node scripts/build-sealer.mjs\` (from the repo root). (${(e as Error).message})`,
    );
  }
  await init({ module_or_path: bytes });
});

describe('the real wasm sealer runs the dag engine end to end (OPE-278)', () => {
  it('provisions, seals, unlocks on a fresh replica, and opens the same data', () => {
    const p = wasmProvision('dag', 'correct horse', TREE, MEMBER, replica(1));
    const anchor = p.keyring; // the opaque dag anchor to persist
    const didKey = p.didKey;
    expect(p.watermark.length).toBeGreaterThan(0); // an opaque frontier watermark, not a stub
    expect(p.needsReseal).toBe(false); // a fresh single-replica tree is not stale
    const sealerA = p.takeSealer();
    p.free();

    const envelope = sealSnapshot(sealerA, 'the family tree');
    sealerA.free(); // drop the DEK — as a lock would

    // A fresh replica unlocks from the anchor bytes alone and opens what device A sealed.
    const u = wasmUnlock('dag', anchor, 'correct horse', TREE, MEMBER, replica(2));
    expect(u.didKey).toBe(didKey); // same owner identity across provision + unlock
    const sealerB = u.takeSealer();
    u.free();
    expect(dec.decode(sealerB.openEntry('snapshot', envelope))).toBe('the family tree');
    sealerB.free();
  });

  it('changes the passphrase: the old is retired, the new opens pre-change data', () => {
    const p = wasmProvision('dag', 'old pass', TREE, MEMBER, replica(1));
    const anchor0 = p.keyring;
    const wm0 = p.watermark;
    const sealerA = p.takeSealer();
    p.free();
    const envelope = sealSnapshot(sealerA, 'keepsake');
    sealerA.free();

    // Retarget under a new passphrase, gated on the stored frontier as the floor.
    const re = wasmChangePassphrase('dag', anchor0, 'old pass', 'battery staple', TREE, MEMBER, replica(1), wm0);
    const anchor1 = re.keyring;
    re.free();

    // The NEW passphrase opens the rekeyed anchor (the DEK is unchanged); the OLD one no longer does.
    const u = wasmUnlock('dag', anchor1, 'battery staple', TREE, MEMBER, replica(2));
    const sealerB = u.takeSealer();
    u.free();
    expect(dec.decode(sealerB.openEntry('snapshot', envelope))).toBe('keepsake');
    sealerB.free();

    expect(() => wasmUnlock('dag', anchor1, 'old pass', TREE, MEMBER, replica(3))).toThrow();
  });

  it('recovers with the code under a new passphrase and opens pre-recovery data', () => {
    const p = wasmProvision('dag', 'old pass', TREE, MEMBER, replica(1));
    const anchor0 = p.keyring;
    const wm0 = p.watermark;
    const recoveryCode = p.recoveryCode;
    const didOld = p.didKey;
    const sealerA = p.takeSealer();
    p.free();
    const envelope = sealSnapshot(sealerA, 'heirloom');
    sealerA.free();

    const r = wasmRecover('dag', anchor0, recoveryCode, 'brand new pass', TREE, MEMBER, replica(2), wm0);
    expect(r.didKey).not.toBe(didOld); // recovery mints a fresh owner identity
    const sealerR = r.takeSealer();
    const anchor1 = r.keyring;
    r.free();
    // The recovered sealer opens pre-recovery data — the DEK was re-wrapped, not rotated.
    expect(dec.decode(sealerR.openEntry('snapshot', envelope))).toBe('heirloom');
    sealerR.free();

    // And a fresh unlock with the new passphrase works against the recovered anchor.
    const u = wasmUnlock('dag', anchor1, 'brand new pass', TREE, MEMBER, replica(3));
    const sealerU = u.takeSealer();
    u.free();
    expect(dec.decode(sealerU.openEntry('snapshot', envelope))).toBe('heirloom');
    sealerU.free();
  });

  it('a wrong passphrase fails closed on the dag engine', () => {
    const p = wasmProvision('dag', 'right pass', TREE, MEMBER, replica(1));
    const anchor = p.keyring;
    p.takeSealer().free();
    p.free();
    expect(() => wasmUnlock('dag', anchor, 'wrong pass', TREE, MEMBER, replica(2))).toThrow();
  });
});

describe('the engine tag selects the engine in one wasm binary (OPE-278)', () => {
  it('runs the chain engine through the same binary, proving the tag is what switches it', () => {
    const p = wasmProvision('chain', 'correct horse', TREE, MEMBER, replica(1));
    const anchor = p.keyring;
    const sealerA = p.takeSealer();
    p.free();
    const envelope = sealSnapshot(sealerA, 'chain data');
    sealerA.free();

    const u = wasmUnlock('chain', anchor, 'correct horse', TREE, MEMBER, replica(2));
    const sealerB = u.takeSealer();
    u.free();
    expect(dec.decode(sealerB.openEntry('snapshot', envelope))).toBe('chain data');
    sealerB.free();
  });

  it('an unknown engine tag is rejected (the seam FromStr, surfaced through wasm)', () => {
    expect(() => wasmProvision('mosaic', 'pass', TREE, MEMBER, replica(1))).toThrow(
      /unknown keyring engine: mosaic/,
    );
  });
});

describe('the real wasm runs dag membership + concurrent merge end to end (OPE-278)', () => {
  // Provision a dag tree and add each of `ids` as an editor; return the shared anchor after all adds plus
  // the member accounts (kdf + public keys) — the web-host counterpart to the native VaultHost membership.
  function provisionWithEditors(ownerPass: string, ids: string[]) {
    const p = wasmProvision('dag', ownerPass, TREE, MEMBER, replica(1));
    let anchor = p.keyring;
    p.takeSealer()!.free();
    p.free();
    const accounts: Record<string, { kdfParams: Uint8Array; authorPublic: Uint8Array; hpkePublic: Uint8Array }> = {};
    for (const id of ids) {
      const acct = wasmProvisionMember(`${id} pass`);
      accounts[id] = { kdfParams: acct.kdfParams, authorPublic: acct.authorPublic, hpkePublic: acct.hpkePublic };
      acct.free();
      const r = wasmDagAddMember(
        anchor, ownerPass, TREE, MEMBER, replica(1), id, 'editor',
        accounts[id].authorPublic, accounts[id].hpkePublic,
      );
      anchor = r.keyring;
      r.free();
    }
    return { anchor, accounts };
  }

  it('two replicas concurrently remove members, then merge + reseal and converge', () => {
    const ownerPass = 'owner horse';
    const { anchor: shared, accounts } = provisionWithEditors(ownerPass, ['bob', 'carol', 'dave']);

    // Concurrent removals from the SAME shared anchor: replica 1 removes bob, replica 2 removes carol.
    const remBob = wasmDagRemoveMember(shared, ownerPass, TREE, MEMBER, replica(1), 'bob');
    const branchA = remBob.keyring;
    remBob.free();
    const remCarol = wasmDagRemoveMember(shared, ownerPass, TREE, MEMBER, replica(2), 'carol');
    const branchB = remCarol.keyring;
    remCarol.free();

    // Merge B into A: the op-DAG set-unions; BOTH removals take effect (resolved membership = {owner, dave}).
    const mg = wasmDagMerge(branchA, branchB);
    const merged = mg.keyring;
    const mergedWm = mg.watermark;
    mg.free();

    // The merged write epoch is stale — it still wraps a concurrently-removed member.
    const u = wasmUnlock('dag', merged, ownerPass, TREE, MEMBER, replica(3));
    expect(u.needsReseal).toBe(true);
    u.takeSealer()!.free();
    u.free();

    // Reseal repairs it (floor = the merged frontier); the flag clears.
    const re = wasmDagReseal(merged, ownerPass, TREE, MEMBER, replica(4), mergedWm);
    expect(re.resealed).toBe(true);
    const resealed = re.keyring;
    re.free();

    const u2 = wasmUnlock('dag', resealed, ownerPass, TREE, MEMBER, replica(5));
    expect(u2.needsReseal).toBe(false);
    const ownerSealer = u2.takeSealer()!;
    u2.free();
    const post = sealSnapshot(ownerSealer, 'after the merge');
    ownerSealer.free();

    // dave (the survivor) still reads the post-merge entry.
    const ud = wasmDagUnlockAsMember(resealed, 'dave pass', accounts.dave.kdfParams, TREE, 'dave', replica(6));
    const daveSealer = ud.takeSealer()!;
    ud.free();
    expect(dec.decode(daveSealer.openEntry('snapshot', post))).toBe('after the merge');
    daveSealer.free();

    // bob and carol (both concurrently removed) are locked out after the merge + reseal.
    expect(() =>
      wasmDagUnlockAsMember(resealed, 'bob pass', accounts.bob.kdfParams, TREE, 'bob', replica(7)),
    ).toThrow();
    expect(() =>
      wasmDagUnlockAsMember(resealed, 'carol pass', accounts.carol.kdfParams, TREE, 'carol', replica(8)),
    ).toThrow();
  });

  it('an added member reads the shared data, and an unknown role is rejected', () => {
    const ownerPass = 'owner horse';
    const p = wasmProvision('dag', ownerPass, TREE, MEMBER, replica(1));
    const anchor0 = p.keyring;
    const ownerSealer = p.takeSealer()!;
    p.free();
    const envelope = sealSnapshot(ownerSealer, 'family data');
    ownerSealer.free();

    const bob = wasmProvisionMember('bob pass');
    const bobKdf = bob.kdfParams;
    const bobAuthor = bob.authorPublic;
    const bobHpke = bob.hpkePublic;
    bob.free();

    const added = wasmDagAddMember(anchor0, ownerPass, TREE, MEMBER, replica(1), 'bob', 'editor', bobAuthor, bobHpke);
    const anchor1 = added.keyring;
    added.free();

    const u = wasmDagUnlockAsMember(anchor1, 'bob pass', bobKdf, TREE, 'bob', replica(2));
    const bobSealer = u.takeSealer()!;
    u.free();
    expect(dec.decode(bobSealer.openEntry('snapshot', envelope))).toBe('family data');
    bobSealer.free();

    // An unknown role tag is rejected before any op is minted.
    expect(() =>
      wasmDagAddMember(anchor0, ownerPass, TREE, MEMBER, replica(1), 'x', 'sovereign', bobAuthor, bobHpke),
    ).toThrow(/unknown role/);
  });
});

describe('keyring membership summary + basis coverage (real wasm, OPE-293/294)', () => {
  it('dag: summary resolves members + a frontier basis, and coverage tracks the frontier', () => {
    const p = wasmProvision('dag', 'owner horse', TREE, MEMBER, replica(1));
    const anchor0 = p.keyring;
    p.takeSealer()!.free();
    p.free();

    const s0 = JSON.parse(wasmKeyringSummary('dag', anchor0));
    expect(s0.members.some((m: any) => m.memberId === MEMBER && m.role === 1)).toBe(true);
    expect(s0.basis.length).toBeGreaterThan(0);
    expect(s0.basis.every((t: string) => /^op:[0-9a-f]{64}$/.test(t))).toBe(true);

    // Our own basis is covered; a bogus tip is not; an empty basis is trivially covered.
    expect(wasmKeyringCovers('dag', anchor0, s0.basis)).toBe(true);
    expect(wasmKeyringCovers('dag', anchor0, ['op:' + 'ab'.repeat(32)])).toBe(false);
    expect(wasmKeyringCovers('dag', anchor0, [])).toBe(true);

    // Advance the frontier by adding a member.
    const bob = wasmProvisionMember('bob pass');
    const added = wasmDagAddMember(anchor0, 'owner horse', TREE, MEMBER, replica(1), 'acct-bob', 'editor', bob.authorPublic, bob.hpkePublic);
    const anchor1 = added.keyring;
    added.free();
    bob.free();
    const s1 = JSON.parse(wasmKeyringSummary('dag', anchor1));
    expect(s1.members.some((m: any) => m.memberId === 'acct-bob')).toBe(true);

    // The advanced anchor covers the OLD basis (old tip is now an ancestor); the STALE anchor does NOT
    // cover the new basis (it lacks the new tip) — exactly the pre-push staleness guard.
    expect(wasmKeyringCovers('dag', anchor1, s0.basis)).toBe(true);
    expect(wasmKeyringCovers('dag', anchor0, s1.basis)).toBe(false);
  });

  it('chain: summary + revision-based coverage', () => {
    const p = wasmProvision('chain', 'owner horse', TREE, MEMBER, replica(1));
    const anchor = p.keyring;
    p.takeSealer()!.free();
    p.free();
    const s = JSON.parse(wasmKeyringSummary('chain', anchor));
    expect(s.members.some((m: any) => m.memberId === MEMBER && m.role === 1)).toBe(true);
    expect(s.basis).toHaveLength(1);
    expect(s.basis[0]).toMatch(/^rev:1:[0-9a-f]{64}$/);
    expect(wasmKeyringCovers('chain', anchor, s.basis)).toBe(true);
    expect(wasmKeyringCovers('chain', anchor, ['rev:5:' + 'ab'.repeat(32)])).toBe(false); // my rev 1 < 5
  });

  it('the real wasm seam drives pushMembershipSummary against an in-memory /access', async () => {
    // A tiny in-memory RemoteStore: one summary per tree, CAS on a generation.
    const store = new Map<string, { generation: number; basis: string[]; members: any[] }>();
    const remote = {
      getAccess: async (id: string) => store.get(id) ?? null,
      putAccess: async (id: string, { basis, expectedGeneration, members }: any) => {
        const cur = store.get(id) ?? null;
        const curGen = cur ? cur.generation : null;
        if (expectedGeneration !== curGen) {
          const e: any = new Error('conflict');
          e.name = 'ConflictError';
          throw e;
        }
        const generation = (curGen ?? 0) + 1;
        store.set(id, { generation, basis, members });
        return { generation, unchanged: false };
      },
    };

    const p = wasmProvision('dag', 'owner horse', TREE, MEMBER, replica(1));
    const anchor = p.keyring;
    p.takeSealer()!.free();
    p.free();
    const summary = JSON.parse(wasmKeyringSummary('dag', anchor));
    const out = await pushMembershipSummary(
      remote,
      'tree-1',
      { view: summary.members, basis: summary.basis },
      { coversBasis: (stored: string[]) => wasmKeyringCovers('dag', anchor, stored), refresh: async () => summary },
    );
    expect(out.generation).toBe(1);
    expect(store.get('tree-1')!.members.some((m: any) => m.memberId === MEMBER)).toBe(true);
    expect(store.get('tree-1')!.basis).toEqual(summary.basis);
  });
});
