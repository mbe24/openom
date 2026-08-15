// The Tauri backend for the vault. On Tauri the crypto lives in the Rust host (openom-vault-host)
// so the DEK never enters the webview; this adapter is the JS side of the SAME vault surface the
// web app's vault.js exposes — createAppVault picks one or the other. Everything above the vault
// (SealerSession, the gate, LockPolicy) is identical either way.
//
// The cut is at the VAULT surface, not the worker's: keyring bytes, the anti-rollback watermark,
// and the replica id all live in Rust, so they never cross here. This adapter only marshals
// values across `invoke` and wraps the returned `sealerId` handle in a SealerSession.
//
// Errors: a Rust command that returns Err(VaultError) rejects the invoke with a plain
// { code, message } object. Callers switch on `code` (never the message text).

import { SealerSession } from './session.js';

const arr = (bytes) => Array.from(bytes ?? []); // Uint8Array → JSON number array (Tauri IPC)
const u8 = (x) => (x instanceof Uint8Array ? x : new Uint8Array(x ?? []));

/**
 * A SealerSession `core` bound to one Rust-side sealer id: forwards seal/open/lock across
 * `invoke`. If the Rust host has freed the sealer underneath us (a mobile background-lock or a
 * window teardown clears the registry), the next call rejects with code `unknown_sealer`; we
 * surface that as an `openom:sealer-locked` event so the app re-gates, the invoke-world analogue
 * of the worker's `openom:worker-error`.
 */
export function invokeCore(invoke, sealerId) {
  const guard = (p) =>
    p.catch((e) => {
      if (e?.code === 'unknown_sealer') {
        globalThis.dispatchEvent?.(new CustomEvent('openom:sealer-locked', { detail: sealerId }));
      }
      throw e;
    });
  return {
    sealEntry: (kind, format, compression, counter, prev, covers, blobId, plaintext) =>
      guard(
        invoke('sealer_seal_entry', {
          sealerId,
          kind,
          format,
          compression,
          replicaCounter: counter,
          prevCiphertextHash: arr(prev),
          coversThroughSeq: covers,
          blobId: arr(blobId),
          plaintext: arr(plaintext),
        }),
      ).then((r) => ({ envelope: u8(r.envelope), ciphertextHash: u8(r.ciphertextHash) })),
    openEntry: (kind, bytes) =>
      guard(invoke('sealer_open_entry', { sealerId, kind, envelope: arr(bytes) })).then(u8),
    lock: () => invoke('sealer_lock', { sealerId }),
  };
}

/**
 * The vault surface over `invoke`, matching vault.js: provision/unlock/recover/changePassphrase/
 * hasKeyring, each returning a ready SealerSession (except changePassphrase — the DEK is
 * unchanged, so the running session keeps working). The Rust host owns keyring + watermark
 * storage, so nothing about them is passed or returned here.
 */
export function createInvokeVault(invoke) {
  const session = (sealerId) => new SealerSession(invokeCore(invoke, sealerId));
  return {
    async hasKeyring(treeKey) {
      return invoke('vault_has_keyring', { treeKey });
    },
    async provision(treeKey, treeId, passphrase, memberId) {
      const r = await invoke('vault_provision', { treeKey, treeId: arr(treeId), passphrase, memberId });
      return { session: session(r.sealerId), recoveryCode: r.recoveryCode };
    },
    async unlock(treeKey, treeId, passphrase, memberId) {
      const r = await invoke('vault_unlock', { treeKey, treeId: arr(treeId), passphrase, memberId });
      return { session: session(r.sealerId) };
    },
    async recover(treeKey, treeId, recoveryCode, newPassphrase, memberId) {
      const r = await invoke('vault_recover', {
        treeKey,
        treeId: arr(treeId),
        recoveryCode,
        newPassphrase,
        memberId,
      });
      return { session: session(r.sealerId), recoveryCode: r.recoveryCode };
    },
    async changePassphrase(treeKey, treeId, oldPassphrase, newPassphrase, memberId) {
      const r = await invoke('vault_change_passphrase', {
        treeKey,
        treeId: arr(treeId),
        oldPassphrase,
        newPassphrase,
        memberId,
      });
      return { recoveryCode: r.recoveryCode };
    },
  };
}
