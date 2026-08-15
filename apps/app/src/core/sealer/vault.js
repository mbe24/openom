// The passphrase lifecycle, JS side: orchestrates the WASM vault (provision/unlock/recover/
// changePassphrase) with keyring storage and the anti-rollback watermark, and hands back a
// ready SealerSession. The WASM module is INJECTED (not imported) so this stays unit-testable
// without running Argon2id; the app passes the real module.
//
// Watermarking (SERVER-DATA-FORMAT §8a/§10): every flow observes the keyring `revision`, so a
// server replaying a pre-change keyring is refused. recover/changePassphrase also feed the
// current watermark down as `min_revision`, so the WASM core refuses a rolled-back keyring
// before unwrapping (recovery skips the signature, so this is its only rollback guard).
//
// Passphrases/recovery codes are handed straight to WASM and not retained here; the UI layer
// is responsible for minimising their lifetime in JS (they can't be scrubbed once GC owns
// them).

import { SealerSession } from './session.js';

/**
 * @param {object} deps
 * @param {object} deps.wasm          the WASM module: { provision, unlock, recover, changePassphrase }
 * @param {object} deps.keyringStore  { load(treeKey)->Promise<Uint8Array|null>, save(treeKey,bytes)->Promise }
 * @param {object} deps.watermarks    a Watermarks instance (observe/current)
 */
export function createVault({ wasm, keyringStore, watermarks }) {
  if (!wasm || !keyringStore || !watermarks) {
    throw new Error('createVault needs { wasm, keyringStore, watermarks }');
  }

  async function requireKeyring(treeKey) {
    const keyring = await keyringStore.load(treeKey);
    if (!keyring) throw new Error(`no keyring stored for tree ${treeKey} — provision first`);
    return keyring;
  }

  return {
    /** Whether this tree already has a keyring (→ unlock) or needs provisioning. */
    async hasKeyring(treeKey) {
      return (await keyringStore.load(treeKey)) != null;
    },

    /** Create a new encrypted tree. Returns { session, recoveryCode } — show the code once. */
    async provision(treeKey, treeId, passphrase, memberId, replicaId) {
      const r = wasm.provision(passphrase, treeId, memberId, replicaId);
      await keyringStore.save(treeKey, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: new SealerSession(r.takeSealer()), recoveryCode: r.recoveryCode };
    },

    /** Open an existing tree with a passphrase. Returns { session }. */
    async unlock(treeKey, treeId, passphrase, memberId, replicaId) {
      const keyring = await requireKeyring(treeKey);
      const r = wasm.unlock(keyring, passphrase, treeId, memberId, replicaId);
      // Observe BEFORE taking the sealer: a rollback throws here and the sealer is dropped.
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: new SealerSession(r.takeSealer()) };
    },

    /** Recover with the code + a new passphrase. Returns { session, recoveryCode } (new code). */
    async recover(treeKey, treeId, recoveryCode, newPassphrase, memberId, replicaId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = wasm.recover(keyring, recoveryCode, newPassphrase, treeId, memberId, replicaId, min);
      await keyringStore.save(treeKey, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: new SealerSession(r.takeSealer()), recoveryCode: r.recoveryCode };
    },

    /**
     * Change the passphrase (rotates the recovery code). Returns { recoveryCode } — the DEK is
     * unchanged, so the caller's existing session keeps working; no new session is made.
     */
    async changePassphrase(treeKey, treeId, oldPassphrase, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = wasm.changePassphrase(keyring, oldPassphrase, newPassphrase, treeId, memberId, min);
      await keyringStore.save(treeKey, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { recoveryCode: r.recoveryCode };
    },
  };
}
