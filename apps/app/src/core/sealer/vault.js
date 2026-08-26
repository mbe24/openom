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
 * Frame keyring successor revisions for `acceptRemoteKeyring`: each hop as a 4-byte big-endian length
 * prefix followed by its bytes, concatenated in ascending revision order (the wire shape the wasm's
 * `split_length_prefixed` expects).
 * @param {Uint8Array[]} revisions
 * @returns {Uint8Array}
 */
export function frameHops(revisions) {
  let total = 0;
  for (const r of revisions) total += 4 + r.length;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const r of revisions) {
    dv.setUint32(off, r.length, false); // big-endian
    off += 4;
    out.set(r, off);
    off += r.length;
  }
  return out;
}

/**
 * @param {object} deps
 * @param {object} deps.worker         the crypto worker proxy (provision/unlock/recover/changePassphrase/sealEntry/openEntry/lock)
 * @param {object} deps.keyringStore   { save(treeKey, revision, bytes), at(treeKey, revision), head, load }
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
      await keyringStore.save(treeKey, r.revision, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: sessionFor(r.sealerId), recoveryCode: r.recoveryCode, didKey: r.didKey };
    },

    async unlock(treeKey, treeId, passphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = await worker.unlock(keyring, passphrase, treeId, memberId, makeReplicaId(), min);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: sessionFor(r.sealerId), didKey: r.didKey };
    },

    async recover(treeKey, treeId, recoveryCode, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = await worker.recover(keyring, recoveryCode, newPassphrase, treeId, memberId, makeReplicaId(), min);
      await keyringStore.save(treeKey, r.revision, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { session: sessionFor(r.sealerId), recoveryCode: r.recoveryCode, didKey: r.didKey };
    },

    async changePassphrase(treeKey, treeId, oldPassphrase, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const min = watermarks.current(treeKey).keyringRevision;
      const r = await worker.changePassphrase(keyring, oldPassphrase, newPassphrase, treeId, memberId, min);
      await keyringStore.save(treeKey, r.revision, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { recoveryCode: r.recoveryCode };
    },

    /**
     * Pull newer keyring revisions from the server and adopt them if they verify. `fetchSuccessors` is
     * given our current revision and returns the successor keyring byte-arrays after it (ascending);
     * the worker (Rust) decides whether they form a legitimate chain onto our stored anchor — a fork,
     * rollback, or withheld hop is refused there and this throws without touching stored state. Every
     * worker-validated revision is RETAINED (each governs entries stamped at it) + the head watermarked, so
     * an untrusted server can never plant a keyring we didn't verify or roll us backward (§10). No-op (and
     * no fetch cost beyond the one call) when there's nothing newer.
     * @returns {Promise<{ revision: number, changed: boolean }>}
     */
    async syncKeyring(treeKey, treeId, fetchSuccessors) {
      const anchor = await requireKeyring(treeKey);
      const since = watermarks.current(treeKey).keyringRevision;
      const successors = await fetchSuccessors(since); // [{ revision, bytes }] ascending, revisions > since
      if (!successors || successors.length === 0) {
        return { revision: since, changed: false };
      }
      const r = await worker.acceptRemoteKeyring(anchor, treeId, frameHops(successors.map((s) => s.bytes)));
      // The worker validated the whole run as a legitimate chain → RETAIN every revision (each is the
      // governing keyring for entries stamped at it, §B3 launch gate) and watermark the new head. Persist
      // only after validation, so an untrusted server can never plant an unverified revision.
      for (const s of successors) await keyringStore.save(treeKey, s.revision, s.bytes);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { revision: r.revision, changed: true };
    },

    /**
     * Adopt a recovery/succession RESET (§B3 slice 4). A reset changes the authorized-signer set without
     * the old set's endorsement, so `syncKeyring` refuses it (verify_walk throws) — this is the deliberate
     * override, and the CALLER MUST have shown the new signer fingerprints for OUT-OF-BAND re-verification
     * and gotten explicit user confirmation FIRST. This only does the crypto: verify the reset is a valid
     * keyring chaining onto our trusted head, then persist it + watermark. Throws if it isn't a valid reset
     * onto the head (so a fork/rollback dressed up as a reset can't slip through). `candidate` is the
     * served reset keyring bytes.
     * @returns {Promise<{ revision: number }>}
     */
    async adoptReset(treeKey, treeId, candidate) {
      const anchor = await requireKeyring(treeKey);
      const r = await worker.acceptResetKeyring(anchor, treeId, candidate);
      await keyringStore.save(treeKey, r.revision, r.keyring);
      watermarks.observe(treeKey, { keyringRevision: r.revision });
      return { revision: r.revision };
    },
  };
}
