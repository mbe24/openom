// e2e: Mode A member JOIN + the ATTRIBUTED-WRITES invariant, against the real server. Host-node (the vitest
// runner is dockerized; a browser hits CORS). Proves the whole slice-2 security core end to end on REAL
// crypto + a real server — the piece the native harness can't reach (wasm-bindgen JsError panics off a JS
// runtime):
//   * an owner provisions a tree (genesis rev 1), seals a PRE-share entry, admits an editor (rev 2, the
//     first share), then publishes a SIGNED base (a snapshot subsuming the pre-share log) and a POST-share
//     ATTRIBUTED delta, and — as an attacker would — appends a FORGED UNSIGNED delta;
//   * the member JOINS via the invite: verifyKeyringWalk walks the chain from genesis, bound to the invite's
//     PREFIX pin (rev 1 hash) against a rev-3 head (the admit-bump), then unlockAsMember + retains every
//     revision;
//   * the member BOOTSTRAPS from the signed base (reconstructs the pre-share state from it, never replaying
//     the unsigned pre-share delta), then pulls the post-share tail on the SHARED reader rule: the attributed
//     delta is accepted (owner signature verified at a non-head revision, from retained history), and the
//     forged unsigned delta is REJECTED — the H1 close.
// Run with the compose server up:  node apps/e2e/sharing-join.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, {
  provision,
  unlock,
  provisionMember,
  addMember,
  wrapChainKeyringUpdate,
  keyringSummary,
  verifyKeyringWalk as wasmVerifyKeyringWalk,
  unlockAsMember as wasmUnlockAsMember,
  entryAttribution as wasmEntryAttribution,
  epochIsAttributed as wasmEpochIsAttributed,
  keyringHasBeenShared as wasmKeyringHasBeenShared,
  verifyEntry as wasmVerifyEntry,
} from '../app/src/vendor/vault/openom_vault.js';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { treeIdToUuid } from '../app/src/core/keyringPublish.js';
import { createVault, frameHops, ENVELOPE_VERSION } from '../app/src/core/sealer/vault.js';
import { createEntryVerifier } from '../app/src/core/sealer/entryVerifier.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { Watermarks } from '../app/src/core/watermarks.js';
import { mint, parseLink } from '../app/src/core/invite.js';

const BASE = (process.env.OPENOM_SERVER ?? 'http://localhost:6060').replace(/\/$/, '');
const enc = new TextEncoder();
const dec = new TextDecoder();
let failed = 0;
const ok = (c, m) => {
  console.log(`  ${c ? '✓' : '✗ FAIL:'} ${m}`);
  if (!c) failed++;
};

await init({ module_or_path: readFileSync(fileURLToPath(new URL('../app/src/vendor/vault/openom_vault_bg.wasm', import.meta.url))) });

const TREE = crypto.getRandomValues(new Uint8Array(16));
const uuid = treeIdToUuid(TREE);
const OWNER = crypto.randomUUID();
const MEMBER = crypto.randomUUID();
const OWNER_PASS = 'owner-pass';
const MEMBER_PASS = 'member-pass';
const rid = () => crypto.getRandomValues(new Uint8Array(16));

const ownerRemote = new RemoteStore({ baseUrl: BASE, auth: () => OWNER });
const memberRemote = new RemoteStore({ baseUrl: BASE, auth: () => MEMBER });

// Seal a delta with a live WasmSealer, returning the envelope (freeing the outcome).
const sealDelta = (sealer, counter, text) => {
  const out = sealer.sealEntry('delta', 'openom-ops', 'none', counter, new Uint8Array(), 0, new Uint8Array(), enc.encode(text));
  const env = out.envelope;
  out.free();
  return env;
};

// The 32-byte keyring hash of a raw chain keyring, from keyringSummary's `rev:<n>:<hex>` basis token.
const keyringHashOf = (rawKeyring) => {
  const token = JSON.parse(keyringSummary('chain', rawKeyring)).basis[0]; // "rev:<n>:<hex>"
  const hex = token.slice(token.lastIndexOf(':') + 1);
  return Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
};

// A DIRECT-wasm crypto worker shim (the member side): the same flat API the Comlink worker exposes, but
// calling the vendored wasm in-process — so vault.joinAsMember + createEntryVerifier run unchanged.
function directWorker() {
  const sealers = new Map();
  let seq = 0;
  const reg = (s) => {
    const id = 's' + ++seq;
    sealers.set(id, s);
    return id;
  };
  const get = (id) => {
    const s = sealers.get(id);
    if (!s) throw new Error('unknown or locked sealer');
    return s;
  };
  return {
    async verifyKeyringWalk(treeId, hops, pinnedRevision, pinnedHash) {
      const r = wasmVerifyKeyringWalk(treeId, hops, pinnedRevision, pinnedHash);
      const out = { revision: r.revision, headKeyring: r.headKeyring, signersJson: r.signersJson, bodiesFramed: r.bodiesFramed };
      r.free();
      return out;
    },
    async unlockAsMember(keyring, passphrase, kdf, treeId, memberId, trusted, replicaId, minRevision) {
      const r = wasmUnlockAsMember(keyring, passphrase, kdf, treeId, memberId, trusted, replicaId, minRevision);
      const sealerId = reg(r.takeSealer());
      const out = { watermark: r.watermark, didKey: r.didKey, needsReseal: r.needsReseal, sealerId };
      r.free();
      return out;
    },
    async openEntry(sealerId, kind, bytes) {
      return get(sealerId).openEntry(kind, bytes);
    },
    lock(sealerId) {
      const s = sealers.get(sealerId);
      if (s) {
        s.free();
        sealers.delete(sealerId);
      }
    },
    async entryAttribution(envelope) {
      const a = wasmEntryAttribution(envelope);
      const out = { keyringRevision: a.keyringRevision, keyId: a.keyId, coversThroughSeq: a.coversThroughSeq };
      a.free();
      return out;
    },
    async epochIsAttributed(keyring, keyId) {
      return wasmEpochIsAttributed(keyring, keyId);
    },
    async keyringHasBeenShared(engine, keyring) {
      return wasmKeyringHasBeenShared(engine, keyring);
    },
    async verifyEntry(version, envelope, plaintext, governing) {
      wasmVerifyEntry(version, envelope, plaintext, governing); // throws to reject
    },
  };
}

console.log(`genesis-walk join → ${BASE}\n  tree ${uuid}\n  owner ${OWNER}\n  member ${MEMBER}`);
ok((await fetch(BASE + '/health').then((r) => r.text()).catch(() => '')) === 'openom ok', 'server healthy');

// ── OWNER: provision (genesis rev 1) ───────────────────────────────────────────────────────────────────
const p = provision('chain', OWNER_PASS, TREE, OWNER, rid());
const ownerSealer = p.takeSealer();
const genesisRaw = p.keyring;
const genesisHash = keyringHashOf(genesisRaw);
p.free();

// Create the tree row (a snapshot) + publish the genesis keyring so readKeyring(from=1) resolves.
const snap = ownerSealer.sealEntry('snapshot', 'openom-json', 'none', 0, new Uint8Array(), 0, new Uint8Array(), enc.encode('{}'));
await ownerRemote.putSnapshot(uuid, snap.envelope, null);
snap.free();
await ownerRemote.putKeyring(uuid, wrapChainKeyringUpdate(genesisRaw));
ok(true, 'owner created the tree + published genesis (rev 1)');

// A PRE-share delta, sealed under the founder-only epoch (governed by rev 1 → unattributed).
const preText = '{"note":"before sharing"}';
await ownerRemote.appendLog(uuid, sealDelta(ownerSealer, 1, preText));
ok(true, 'owner sealed a pre-share entry');

// ── OWNER admits the member (rev 2) ────────────────────────────────────────────────────────────────────
const m = provisionMember(MEMBER_PASS); // the member's identity (kdf params + public keys), shared OOB via the claim
const added = addMember(genesisRaw, OWNER_PASS, TREE, OWNER, 1, MEMBER, 'editor', m.authorPublicKey, m.hpkePublicKey);
const rev2Raw = added.keyring;
added.free();
await ownerRemote.putKeyring(uuid, wrapChainKeyringUpdate(rev2Raw));
ok(true, 'owner admitted an editor member + published rev 2');

// Unlock the new keyring to get a sealer bound to rev 2 (addMember returns no sealer — it doesn't rotate
// the owner's epoch), then seal a POST-share delta with it: governed by rev 2 → attributed → signed.
const ownerRev2 = unlock('chain', rev2Raw, OWNER_PASS, TREE, OWNER, rid());
const ownerSealer2 = ownerRev2.takeSealer();
ownerRev2.free();

// FIRST-SHARE BASE: seal a SIGNED snapshot subsuming the pre-share log (covers = 1 → subsumes seq 0, the
// pre-share delta) and CAS-update the provision snapshot. This is what members bootstrap from — an
// attributed base carrying the pre-share state — so they never replay the unsigned pre-share delta. It's
// signed because the tree is now shared (ownerSealer2 carries the owner's author).
const baseState = '{"state":"through pre-share"}';
const baseSeal = ownerSealer2.sealEntry('snapshot', 'openom-json', 'none', 0, new Uint8Array(), 1, new Uint8Array(), enc.encode(baseState));
const provisionSnap = await ownerRemote.readSnapshot(uuid);
await ownerRemote.putSnapshot(uuid, baseSeal.envelope, provisionSnap.version); // CAS-update the pre-share snapshot
baseSeal.free();
ok(true, 'owner published a SIGNED base covering the pre-share history (covers=1)');

// A POST-share attributed delta (seq 1, governed by rev 2 → signed).
const postText = '{"note":"after sharing"}';
await ownerRemote.appendLog(uuid, sealDelta(ownerSealer2, 0, postText));
ok(true, 'owner sealed a post-share attributed entry (governed by rev 2)');

// A FORGED UNSIGNED delta (seq 2): the pre-share solo sealer still seals under the founder epoch with NO
// author (governing_ref 0). This is the backdate forge the invariant must reject on a shared tree.
await ownerRemote.appendLog(uuid, sealDelta(ownerSealer, 2, '{"forged":"unsigned"}'));
ok(true, 'a forged UNSIGNED delta was appended to the shared log (seq 2)');

// A THIRD revision (a second member) so the JOINER's head is rev 3 while the post-share entry stays
// governed by rev 2 — the member can only verify it from RETAINED per-revision history, not the head.
const MEMBER2 = crypto.randomUUID();
const m2 = provisionMember('member2-pass');
const added2 = addMember(rev2Raw, OWNER_PASS, TREE, OWNER, 2, MEMBER2, 'editor', m2.authorPublicKey, m2.hpkePublicKey);
const rev3Raw = added2.keyring;
added2.free();
await ownerRemote.putKeyring(uuid, wrapChainKeyringUpdate(rev3Raw));
ok(true, 'owner admitted a second member + published rev 3 (head moves past the attributed entry)');

// ── OWNER mints the invite ─────────────────────────────────────────────────────────────────────────────
// fp is over the tree's SIGNER set (owner/co-owner). Editor adds don't change it, so the fp the owner
// computes from its trusted genesis matches the fp the member computes at the head. The pin is the genesis.
const ownerChain = await ownerRemote.readKeyring(uuid, 1);
const ownerWalk = (() => {
  const r = wasmVerifyKeyringWalk(TREE, frameHops(ownerChain.revisions.map((x) => x.bytes)), 1, genesisHash);
  const out = { signersJson: r.signersJson, revision: r.revision };
  r.free();
  return out;
})();
ok(ownerWalk.revision === 3, 'the prefix pin (rev 1) verifies against a rev-3 head (the admit-bump)');
const signers = JSON.parse(ownerWalk.signersJson).map((s) => ({
  memberId: s.memberId,
  authorPublicKey: Uint8Array.from(s.authorPublicKey.match(/../g).map((h) => parseInt(h, 16))),
}));
const { link } = await mint({
  uuid,
  role: 'Editor',
  signers,
  pinnedRevision: 1,
  pinnedHash: genesisHash,
  now: Date.now(),
  ttlMs: 3600_000,
});
ok(signers.length === 1 && signers[0].memberId === OWNER, 'the signer set is the owner alone (the editor is not a signer)');

// ── MEMBER: join via the genesis-walk ──────────────────────────────────────────────────────────────────
const worker = directWorker();
const keyringStore = memoryKeyringStore();
const watermarks = new Watermarks();
const vault = createVault({ worker, keyringStore, watermarks, engine: 'chain' });
const invite = parseLink(link);
const { revisions } = await memberRemote.readKeyring(uuid, 1); // the member can read once admitted (published)
ok(revisions.length === 3, 'the member fetched the whole keyring chain (rev 1..3)');

const joined = await vault.joinAsMember('mtree', TREE, MEMBER_PASS, MEMBER, m.kdfParams, revisions, invite);
ok(!!joined.session && typeof joined.didKey === 'string' && joined.didKey.startsWith('did:'), 'joinAsMember unlocked the member at the head');
ok(
  !!(await keyringStore.at('mtree', 1)) && !!(await keyringStore.at('mtree', 2)) && !!(await keyringStore.at('mtree', 3)),
  'the member retained ALL revisions (so a non-head governing revision resolves)',
);

// ── MEMBER: the attributed-writes reader (shared tree) ─────────────────────────────────────────────────
// The verifier is on the SHARED path: has_been_shared from the verified head keyring (rev 3, first_shared=2),
// head revision bounds a legit governing_ref. Every authoritative entry must now be attributed.
const verify = createEntryVerifier({
  version: ENVELOPE_VERSION,
  worker,
  keyringAt: (rev) => keyringStore.at('mtree', rev),
  hasBeenShared: async () => worker.keyringHasBeenShared('chain', await keyringStore.load('mtree')),
  headRevision: async () => (await keyringStore.head('mtree'))?.revision ?? 0,
});
ok(await worker.keyringHasBeenShared('chain', await keyringStore.load('mtree')), 'the member sees the tree as SHARED (first_shared_revision != 0)');

// ── MEMBER: bootstrap from the SIGNED base, then pull only what it does not cover ──────────────────────
const base = await memberRemote.readSnapshot(uuid);
const baseAttr = await worker.entryAttribution(base.bytes);
ok(baseAttr.coversThroughSeq === 1, 'the base declares covers_through_seq = 1 (subsumes the pre-share delta at seq 0)');
const readState = dec.decode(new Uint8Array(await joined.session.open(base.bytes, null, { kind: 'snapshot' })));
let baseVerifyThrew = false;
try { await verify(base.bytes, enc.encode(readState)); } catch (err) { baseVerifyThrew = true; console.log(`    base verify error: ${err?.message ?? err}`); }
ok(!baseVerifyThrew, 'the signed base VERIFIES (owner-attributed snapshot on a shared tree)');
ok(readState === '{"state":"through pre-share"}', 'the member reconstructs the pre-share state FROM the base (not by replaying the delta)');

// Pull from covers-1: the pre-share delta (seq 0) is subsumed by the base and never fetched.
const cursor = baseAttr.coversThroughSeq - 1; // 0
const { entries } = await memberRemote.readLog(uuid, cursor);
ok(entries.map((e) => e.seq).every((s) => s > 0), 'the member never re-fetches the subsumed pre-share delta (seq 0)');
ok(entries.length === 2, 'the member pulls the post-share tail: the signed delta + the forged one');

let acceptedPost = false;
let rejectedForge = false;
for (const e of entries) {
  const opened = new Uint8Array(await joined.session.open(e.payload, null, { kind: 'delta' }));
  const plaintext = dec.decode(opened);
  let rejected = false;
  try { await verify(e.payload, opened); } catch (err) { rejected = true; }
  if (plaintext === postText) {
    acceptedPost = !rejected;
    ok(!rejected, 'the post-share ATTRIBUTED delta is accepted (owner signature verified at rev 2)');
  } else if (plaintext === '{"forged":"unsigned"}') {
    rejectedForge = rejected;
    ok(rejected, 'the forged UNSIGNED delta is REJECTED on the shared tree (the H1 fix)');
  }
}
ok(acceptedPost && rejectedForge, 'exactly the attributed entry survived; the forge was dropped');

await joined.session.lock();
console.log(failed ? `\n${failed} check(s) FAILED` : '\nall checks passed');
process.exit(failed ? 1 : 0);
