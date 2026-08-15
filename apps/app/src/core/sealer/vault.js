// The passphrase lifecycle, JS side: orchestrates the crypto WORKER (provision/unlock/recover/
// changePassphrase) with keyring storage and the anti-rollback watermark, and hands back a
// ready SealerSession whose core proxies seal/open to the worker. Keys stay in the worker.
//
// The `worker` is INJECTED (the Comlink proxy, or a fake for tests) so orchestration is
// unit-testable without a real Worker/Argon2id. It returns plain values + a `sealerId`; the
// session is built from `workerCore(worker, sealerId)`.
//
// Watermarking (§8a/§10): every flow observes the keyring `revision` (refusing a replayed
// pre-change keyring). recover/changePassphrase pass the current watermark down as
// `min_revision`; unlock passes it too, and the worker refuses a rolled-back keyring BEFORE
// exposing a sealer id. A FRESH replica id is minted per unlock (a memoized one would let
// lock -> re-unlock reuse (replica_id, 0) and fork the log).

import { SealerSession } from './session.js';
import { workerCore } from './workerSealer.js';

function freshReplicaId() {
  const id = new Uint8Array(16);
  crypto.getRandomValues(id);
  return id;
}

/**
 * @param {object} deps
 * @param {object} deps.worker         the crypto worker proxy (provision/unlock/recover/changePassphrase/sealEntry/openEntry/lock)
 * @param {object} deps.keyringStore   { load(treeKey), save(treeKey, bytes) }
 * @param {object} deps.watermarks     a Watermarks instance
 * @param {() => Uint8Array} [deps.makeReplicaId]  fresh replica id per unlock (default: CSPRNG)
 */
export function createVault({ worker, keyringStore, watermarks, makeReplicaId = freshReplicaId }) {
  if (!worker || !keyringStore || !watermarks) {
    throw new Error('createVault needs { worker, keyringStore, watermarks }');
  }

  const requireKeyring = async (treeKey) => {
    const keyring = await keyringStore.load(treeKey);
    if (!keyring) throw new Error(`no keyring stored for tree ${treeKey} — provision first`);
    return keyring;
  };
  const sessionFor = (sealerId) => new SealerSession(workerCore(worker, sealerId));

  return {
    async hasKeyring(treeKey) {
      return (await keyringStore.load(treeKey)) != null;
    },

    async provision(treeKey, treeId, passphrase, memberId) {
      const r = await worker.provision(passphrase, treeId, memberId, makeReplicaId());
      await keyringStore.save(treeKey, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: sessionFor(r.sealerId), recoveryCode: r.recoveryCode };
    },

    async unlock(treeKey, treeId, passphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = await worker.unlock(keyring, passphrase, treeId, memberId, makeReplicaId(), min);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: sessionFor(r.sealerId) };
    },

    async recover(treeKey, treeId, recoveryCode, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = await worker.recover(keyring, recoveryCode, newPassphrase, treeId, memberId, makeReplicaId(), min);
      await keyringStore.save(treeKey, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: sessionFor(r.sealerId), recoveryCode: r.recoveryCode };
    },

    async changePassphrase(treeKey, treeId, oldPassphrase, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = await worker.changePassphrase(keyring, oldPassphrase, newPassphrase, treeId, memberId, min);
      await keyringStore.save(treeKey, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { recoveryCode: r.recoveryCode };
    },
  };
}
