// The crypto worker: the ONLY place the WASM sealer, the vault, and unlocked data keys live.
// Keys never reach the main thread. Exposed to the main thread via Comlink as a FLAT API of
// plain values + sealer-id HANDLES (never live WASM objects — those can't cross the worker
// boundary, and the same shape is what a future Tauri `invoke` backend needs).
//
//   vault ops        -> { keyring?, recoveryCode?, revision, sealerId? }   (plain, clone-safe)
//   sealEntry(id,…)  -> { envelope, ciphertextHash }
//   openEntry(id,…)  -> plaintext
//   lock(id)         -> frees the WasmSealer (deterministic key drop)
import * as Comlink from '../../vendor/comlink.js';
import init, {
  provision as wasmProvision,
  unlock as wasmUnlock,
  recover as wasmRecover,
  changePassphrase as wasmChangePassphrase,
  acceptRemoteKeyring as wasmAcceptRemoteKeyring,
  acceptResetKeyring as wasmAcceptResetKeyring,
  verifyEntry as wasmVerifyEntry,
  epochIsAttributed as wasmEpochIsAttributed,
  entryAttribution as wasmEntryAttribution,
  WasmSealer,
} from '../../vendor/sealer/openom_sealer.js';

let ready = null;
const ensureInit = () => (ready ??= init());

// sealerId -> live WasmSealer (holds the DEK in this worker's WASM memory).
const sealers = new Map();
let seq = 0;
const register = (sealer) => {
  const id = 's' + ++seq;
  sealers.set(id, sealer);
  return id;
};
const get = (id) => {
  const s = sealers.get(id);
  if (!s) throw new Error('unknown or locked sealer');
  return s;
};

// Copy the SealOutcome's bytes out to plain arrays, then free the WASM object.
const outcomeToPlain = (out) => {
  const plain = { envelope: out.envelope, ciphertextHash: out.ciphertextHash };
  out.free();
  return plain;
};

const api = {
  // Pre-warm: init the WASM up front (on gate mount) so only the ~1s KDF is visible at submit.
  async warm() {
    await ensureInit();
  },

  async provision(engine, passphrase, treeId, memberId, replicaId) {
    await ensureInit();
    const r = wasmProvision(engine, passphrase, treeId, memberId, replicaId);
    const sealerId = register(r.takeSealer()); // move the sealer out INSIDE the worker
    const out = {
      keyring: r.keyring,
      recoveryCode: r.recoveryCode,
      watermark: r.watermark,
      needsReseal: r.needsReseal,
      didKey: r.didKey,
      sealerId,
    };
    r.free();
    return out;
  },

  async unlock(engine, keyring, passphrase, treeId, memberId, replicaId) {
    await ensureInit();
    // No JS floor check: unlock reads the LOCAL (trusted) anchor and takes no floor in the trait — the
    // anti-rollback floor is enforced engine-side on the untrusted paths (recover + keyring sync), and JS
    // can't compare opaque watermark bytes. Freeing the result drops the just-built sealer + its DEK.
    const r = wasmUnlock(engine, keyring, passphrase, treeId, memberId, replicaId);
    const sealerId = register(r.takeSealer());
    const out = { watermark: r.watermark, needsReseal: r.needsReseal, didKey: r.didKey, sealerId };
    r.free();
    return out;
  },

  async recover(engine, keyring, recoveryCode, newPassphrase, treeId, memberId, replicaId, floor) {
    await ensureInit();
    const r = wasmRecover(engine, keyring, recoveryCode, newPassphrase, treeId, memberId, replicaId, floor);
    const sealerId = register(r.takeSealer());
    const out = {
      keyring: r.keyring,
      recoveryCode: r.recoveryCode,
      watermark: r.watermark,
      needsReseal: r.needsReseal,
      didKey: r.didKey,
      sealerId,
    };
    r.free();
    return out;
  },

  async changePassphrase(engine, keyring, oldPassphrase, newPassphrase, treeId, memberId, replicaId, floor) {
    await ensureInit();
    const r = wasmChangePassphrase(engine, keyring, oldPassphrase, newPassphrase, treeId, memberId, replicaId, floor);
    const out = { keyring: r.keyring, recoveryCode: r.recoveryCode, watermark: r.watermark };
    r.free();
    return out;
  },

  // Verify a landed entry's author attribution (§B3 launch gate). Throws if the entry wasn't validly
  // authored by a member with the required capability at its governing keyring revision — the caller
  // then refuses to merge it. `governing` is the keyring the caller resolved from the entry's
  // header.governing_ref (for the chain, the revision it decodes to).
  async verifyEntry(version, envelope, plaintext, governing) {
    await ensureInit();
    wasmVerifyEntry(version, envelope, plaintext, governing); // throws on reject
  },

  // Whether an epoch (by key_id) is attributed in `keyring` — the tree is shared under it, so entries
  // under it must be signed. Derived from the verified keyring, never an entry's own emptiness.
  async epochIsAttributed(keyring, keyId) {
    await ensureInit();
    return wasmEpochIsAttributed(keyring, keyId);
  },

  // An entry's attribution coordinates from its (AAD-bound) header: which keyring revision governs it and
  // which epoch key_id sealed it. Feeds the verify composer's governing-keyring + attributed decision.
  async entryAttribution(envelope) {
    await ensureInit();
    const a = wasmEntryAttribution(envelope);
    const out = { keyringRevision: a.keyringRevision, keyId: a.keyId };
    a.free();
    return out;
  },

  // Verify a keyring chain pulled from the untrusted server and return the validated head to store.
  // The Rust does the trust decision (verify_walk: legitimate successor vs fork/rollback/withheld hop);
  // this only marshals. `hops` is the successors framed as [u32-BE len][bytes]… (see vault.frameHops).
  // No sealer is produced — keyring state only.
  async acceptRemoteKeyring(anchor, treeId, hops) {
    await ensureInit();
    const r = wasmAcceptRemoteKeyring(anchor, treeId, hops);
    const out = { keyring: r.keyring, watermark: r.watermark };
    r.free();
    return out;
  },

  // Validate a recovery/succession RESET candidate against the trusted `anchor` (§B3 slice 4): it must be
  // a valid self-signed keyring chaining onto the anchor by hash at anchor.revision+1. The CALLER must
  // have done the out-of-band signer re-verification first — this is only the crypto commit step. Throws
  // if it's not a valid reset onto the head.
  async acceptResetKeyring(anchor, treeId, candidate) {
    await ensureInit();
    const r = wasmAcceptResetKeyring(anchor, treeId, candidate);
    const out = { keyring: r.keyring, watermark: r.watermark };
    r.free();
    return out;
  },

  // Local-development sealer (reserved dev key) — routed through the SAME worker so demo and
  // real use exercise one code path.
  async dev(treeId, replicaId) {
    await ensureInit();
    return { sealerId: register(WasmSealer.dev(treeId, replicaId)) };
  },

  async sealEntry(sealerId, kind, format, compression, replicaCounter, prevCiphertextHash, coversThroughSeq, blobId, plaintext) {
    return outcomeToPlain(
      get(sealerId).sealEntry(kind, format, compression, replicaCounter, prevCiphertextHash, coversThroughSeq, blobId, plaintext),
    );
  },

  async openEntry(sealerId, kind, envelopeBytes) {
    return get(sealerId).openEntry(kind, envelopeBytes);
  },

  // Deterministically drop the key on lock/close — do not wait for GC.
  lock(sealerId) {
    const s = sealers.get(sealerId);
    if (s) {
      s.free();
      sealers.delete(sealerId);
    }
  },
};

Comlink.expose(api);
