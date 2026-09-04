// e2e: Mode A genesis-walk JOIN + attributed READ against the real server (slice 1, Step D). Host-node
// (the vitest runner is dockerized; a browser hits CORS). Proves the WHOLE read path end to end on REAL
// crypto + a real server — the piece the native harness can't reach (wasm-bindgen JsError panics off a JS
// runtime):
//   * an owner provisions a tree (genesis rev 1), seals a PRE-share entry, admits an editor member
//     (rev 2 — which HPKE-wraps every epoch to them + carries their read access), then seals a POST-share
//     ATTRIBUTED entry with the new epoch sealer;
//   * the member JOINS via the invite: verifyKeyringWalk walks the whole chain from genesis, bound to the
//     invite's PREFIX pin (rev 1 hash) even though the head is rev 2 — the admit-bump the review fixed;
//     then unlockAsMember + retains every revision;
//   * the member READS both entries: the pre-share one is governed by rev 1 (where its epoch is wrapped
//     only to the founder → UNATTRIBUTED → accepted unsigned), the post-share one by rev 2 (where the same
//     epoch is now attributed → the owner's signature is verified). Per-revision retention is what makes
//     the SAME epoch resolve differently across revisions.
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
      const out = { keyringRevision: a.keyringRevision, keyId: a.keyId };
      a.free();
      return out;
    },
    async epochIsAttributed(keyring, keyId) {
      return wasmEpochIsAttributed(keyring, keyId);
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
const added = addMember(genesisRaw, OWNER_PASS, TREE, OWNER, 1, MEMBER, 'editor', m.hpkePublic, m.authorPublic);
const rev2Raw = added.keyring;
added.free();
await ownerRemote.putKeyring(uuid, wrapChainKeyringUpdate(rev2Raw));
ok(true, 'owner admitted an editor member + published rev 2');

// Unlock the new keyring to get a sealer bound to rev 2 (addMember returns no sealer — it doesn't rotate
// the owner's epoch), then seal a POST-share delta with it: governed by rev 2 → attributed → signed.
const ownerRev2 = unlock('chain', rev2Raw, OWNER_PASS, TREE, OWNER, rid());
const ownerSealer2 = ownerRev2.takeSealer();
ownerRev2.free();
const postText = '{"note":"after sharing"}';
await ownerRemote.appendLog(uuid, sealDelta(ownerSealer2, 0, postText));
ok(true, 'owner sealed a post-share attributed entry (governed by rev 2)');

// A THIRD revision (a second member) so the JOINER's head is rev 3 while the post-share entry stays
// governed by rev 2 — the member can only verify it from RETAINED per-revision history, not the head.
const MEMBER2 = crypto.randomUUID();
const m2 = provisionMember('member2-pass');
const added2 = addMember(rev2Raw, OWNER_PASS, TREE, OWNER, 2, MEMBER2, 'editor', m2.hpkePublic, m2.authorPublic);
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
  authorPublic: Uint8Array.from(s.authorPublic.match(/../g).map((h) => parseInt(h, 16))),
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

// ── MEMBER: read + verify every entry ──────────────────────────────────────────────────────────────────
const verify = createEntryVerifier({ version: ENVELOPE_VERSION, worker, keyringAt: (rev) => keyringStore.at('mtree', rev) });
const { entries } = await memberRemote.readLog(uuid, -1);
ok(entries.length === 2, 'the member read both log entries');

// Match entries by their opened plaintext (log order is server seq: pre then post).
let sawPre = false;
let sawPost = false;
for (const e of entries) {
  const opened = new Uint8Array(await joined.session.open(e.payload, null, { kind: 'delta' }));
  const plaintext = dec.decode(opened);
  const attr = await worker.entryAttribution(e.payload);
  let verifyThrew = false;
  try {
    await verify(e.payload, opened); // the §B3 composer: resolves the governing keyring + checks attribution
  } catch (err) {
    verifyThrew = true;
    console.log(`    verify error: ${err?.message ?? err}`);
  }
  if (plaintext === preText) {
    sawPre = true;
    ok(attr.keyringRevision === 0, 'pre-share entry is an unattributed V1 entry (no governing keyring)');
    ok(!verifyThrew, 'pre-share entry verifies (unattributed → accepted unsigned)');
  } else if (plaintext === postText) {
    sawPost = true;
    ok(attr.keyringRevision === 2, 'post-share entry is governed by rev 2 (a NON-head revision)');
    ok(!verifyThrew, 'post-share entry verifies from RETAINED rev 2 (attributed → owner signature checked)');
  }
}
ok(sawPre, 'the member decrypted the PRE-share entry (historical read access via addMember backfill)');
ok(sawPost, 'the member decrypted the POST-share attributed entry');

await joined.session.lock();
console.log(failed ? `\n${failed} check(s) FAILED` : '\nall checks passed');
process.exit(failed ? 1 : 0);
