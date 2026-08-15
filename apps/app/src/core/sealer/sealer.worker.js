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

  async provision(passphrase, treeId, memberId, replicaId) {
    await ensureInit();
    const r = wasmProvision(passphrase, treeId, memberId, replicaId);
    const sealerId = register(r.takeSealer()); // move the sealer out INSIDE the worker
    const out = { keyring: r.keyring, recoveryCode: r.recoveryCode, revision: r.revision, sealerId };
    r.free();
    return out;
  },

  async unlock(keyring, passphrase, treeId, memberId, replicaId, minRevision) {
    await ensureInit();
    const r = wasmUnlock(keyring, passphrase, treeId, memberId, replicaId);
    // Refuse a rolled-back keyring BEFORE handing out a sealer id (unlock skips this in Rust;
    // recover checks it there). Freeing the result drops the just-built sealer + its DEK.
    if (r.revision < minRevision) {
      r.free();
      throw new Error('keyring revision rollback');
    }
    const sealerId = register(r.takeSealer());
    const out = { revision: r.revision, sealerId };
    r.free();
    return out;
  },

  async recover(keyring, recoveryCode, newPassphrase, treeId, memberId, replicaId, minRevision) {
    await ensureInit();
    const r = wasmRecover(keyring, recoveryCode, newPassphrase, treeId, memberId, replicaId, minRevision);
    const sealerId = register(r.takeSealer());
    const out = { keyring: r.keyring, recoveryCode: r.recoveryCode, revision: r.revision, sealerId };
    r.free();
    return out;
  },

  async changePassphrase(keyring, oldPassphrase, newPassphrase, treeId, memberId, minRevision) {
    await ensureInit();
    const r = wasmChangePassphrase(keyring, oldPassphrase, newPassphrase, treeId, memberId, minRevision);
    const out = { keyring: r.keyring, recoveryCode: r.recoveryCode, revision: r.revision };
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
