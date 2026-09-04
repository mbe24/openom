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
import { createSyncedDeltaSync } from '../syncedDeltaSync.js';

// The envelope format version the wasm sealer stamps and verifyEntry checks against. V1 = 1; pinned here
// (there is no runtime accessor yet) and validated end-to-end by the real seal/verify round-trip tests.
export const ENVELOPE_VERSION = 1;

const bytesEqual = (a, b) =>
  a === b || (!!a && !!b && a.length === b.length && a.every((x, i) => x === b[i]));

/**
 * A produced keyring revision the server refused because ANOTHER writer already took that revision with
 * DIFFERENT content — the local chain has diverged from the server's. NOT a transient conflict: members
 * sealing at the server's revision would be dropped as genuine rejections, so a fork must be SURFACED
 * (security-relevant), never silently treated as "already published".
 */
export class KeyringForkError extends Error {
  constructor(revision) {
    super(`keyring fork at revision ${revision}: local chain diverges from the server`);
    this.name = 'KeyringForkError';
    this.revision = revision;
  }
}

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

// The chain watermark begins with the 4-byte big-endian keyring revision, optionally followed by the
// write-epoch pin (key_id ‖ H(DEK), OPE-286); the chain-only retention + sync paths need that revision
// scalar, so read the first 4 bytes. (The dag watermark is a frontier and is never decoded — it stays
// opaque bytes end to end.)
const chainRevision = (wm) =>
  wm && wm.length >= 4 ? new DataView(wm.buffer, wm.byteOffset, 4).getUint32(0, false) : 0;

// The write-epoch pin (key_id ‖ H(DEK)) is the 48 bytes after the 4-byte revision (OPE-286).
const CHAIN_PIN_LEN = 16 + 32;

// Carry a chain watermark's recover pin forward. The accept/reset paths advance the revision WITHOUT
// opening the DEK, so the wasm returns a bare-revision watermark; splice the previously-stored pin onto the
// new revision so it isn't erased (OPE-286 phase 2). If the stored watermark carried no pin, or the new one
// already has its own, pass the new one through unchanged.
function carryChainPin(next, prev) {
  if (!next || next.length >= 4 + CHAIN_PIN_LEN) return next; // already pinned
  if (!prev || prev.length < 4 + CHAIN_PIN_LEN) return next; // nothing to carry
  const out = new Uint8Array(4 + CHAIN_PIN_LEN);
  out.set(next.subarray(0, 4), 0); // new revision
  out.set(prev.subarray(4, 4 + CHAIN_PIN_LEN), 4); // prior write-epoch pin
  return out;
}

/**
 * @param {object} deps
 * @param {object} deps.worker         the crypto worker proxy (provision/unlock/recover/changePassphrase/sealEntry/openEntry/lock)
 * @param {object} deps.keyringStore   { saveHead, loadHead, load, save(revision), at(revision), head }
 * @param {object} deps.watermarks     a Watermarks instance
 * @param {'chain'|'dag'} [deps.engine]  the deployment's keyring engine (a backend preset; default 'chain')
 * @param {(treeId: Uint8Array, keyringBytes: Uint8Array) => Promise<void>} [deps.publishKeyring]  OUTBOUND
 *        publish seam (OPE-301): called after a locally-produced chain revision is durably persisted, to
 *        wrap it as a KeyringUpdate + PUT it so peers can pull. Injected (like syncKeyring's fetchSuccessors
 *        and pushMembershipSummary's remote) so the vault stays decoupled from the server + id mapping.
 *        Absent ⇒ local-only (no publish). Its failures are SWALLOWED here — the local commit is already
 *        durable and the next sync reconciles, mirroring the offline-safe sync-retry stance.
 * @param {() => Uint8Array} [deps.makeReplicaId]  fresh replica id per unlock (default: CSPRNG)
 */
export function createVault({ worker, keyringStore, watermarks, engine = 'chain', publishKeyring, makeReplicaId = freshReplicaId }) {
  if (!worker || !keyringStore || !watermarks) {
    throw new Error('createVault needs { worker, keyringStore, watermarks }');
  }

  const requireKeyring = async (treeKey) => {
    const keyring = await keyringStore.load(treeKey);
    if (!keyring) throw new Error(`no keyring stored for tree ${treeKey} — provision first`);
    return keyring;
  };
  const sessionFor = (sealerId) => new SealerSession(workerCore(worker, sealerId));

  // Persist a flow's result: the engine-neutral head record (the unlock anchor), the chain-only per-revision
  // retention (for §B3 entry attribution), and the opaque watermark cursor. Then, for a locally-PRODUCED
  // chain revision (provision/recover/changePassphrase — NOT the inbound accept/reset paths, which take
  // their revisions FROM the server), publish it outbound so peers can pull (OPE-301). Publishing is
  // FIRE-AND-FORGET after the durable local commit: it must never join the critical path, because these
  // flows run behind the gate spinner and at first provision the PUT is EXPECTED to fail (the tree row
  // doesn't exist yet — the bootstrap sequence creates it, then republishes). Awaiting it would let a
  // black-holing network hang the gate indefinitely; the local state is already durable and the sync
  // driver's bootstrap owns the reliable, retried republish, so a lost publish here is harmless.
  const persist = async (treeKey, treeId, anchor, watermark) => {
    await keyringStore.saveHead(treeKey, engine, anchor);
    if (engine === 'chain') await keyringStore.save(treeKey, chainRevision(watermark), anchor);
    watermarks.observe(treeKey, { keyringCursor: watermark });
    if (engine === 'chain' && publishKeyring) {
      void Promise.resolve()
        .then(() => publishKeyring(treeId, anchor))
        .catch(() => {
          // Best-effort: the produced revision is durable locally; the next sync republishes/reconciles.
        });
    }
  };
  const floor = (treeKey) => watermarks.current(treeKey).keyringCursor;

  return {
    async hasKeyring(treeKey) {
      return (await keyringStore.load(treeKey)) != null;
    },

    async provision(treeKey, treeId, passphrase, memberId) {
      const r = await worker.provision(engine, passphrase, treeId, memberId, makeReplicaId());
      await persist(treeKey, treeId, r.keyring, r.watermark);
      return { session: sessionFor(r.sealerId), recoveryCode: r.recoveryCode, didKey: r.didKey };
    },

    async unlock(treeKey, treeId, passphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      // Unlock is a pure read of the LOCAL (trusted) anchor: it takes no floor and does NOT touch the
      // cursor (which is already the one persisted when this anchor last changed) — writing the read-back
      // watermark could only ever regress it in a store/cursor desync, never advance it.
      const r = await worker.unlock(engine, keyring, passphrase, treeId, memberId, makeReplicaId());
      return { session: sessionFor(r.sealerId), didKey: r.didKey, needsReseal: r.needsReseal };
    },

    async recover(treeKey, treeId, recoveryCode, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const r = await worker.recover(engine, keyring, recoveryCode, newPassphrase, treeId, memberId, makeReplicaId(), floor(treeKey));
      await persist(treeKey, treeId, r.keyring, r.watermark);
      return { session: sessionFor(r.sealerId), recoveryCode: r.recoveryCode, didKey: r.didKey };
    },

    async changePassphrase(treeKey, treeId, oldPassphrase, newPassphrase, memberId) {
      const keyring = await requireKeyring(treeKey);
      const r = await worker.changePassphrase(engine, keyring, oldPassphrase, newPassphrase, treeId, memberId, makeReplicaId(), floor(treeKey));
      await persist(treeKey, treeId, r.keyring, r.watermark);
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
      const since = chainRevision(floor(treeKey));
      const successors = await fetchSuccessors(since); // [{ revision, bytes }] ascending, revisions > since
      if (!successors || successors.length === 0) {
        return { revision: since, changed: false };
      }
      const r = await worker.acceptRemoteKeyring(anchor, treeId, frameHops(successors.map((s) => s.bytes)));
      // The worker validated the whole run as a legitimate chain → RETAIN every revision (each is the
      // governing keyring for entries stamped at it, §B3 launch gate), update the unlock head record, and
      // watermark the new head. Persist only after validation, so an untrusted server can never plant an
      // unverified revision.
      // Retain the RAW keyring body per revision — UNWRAP the served MembershipEnvelope first. §B3 verify
      // (verifyEntry/epochIsAttributed) decodes a raw Keyring, so storing the wrapped envelope would make
      // every attributed entry governed by this revision throw a hard (non-retryable) decode error, which
      // sync.js treats as a rejection → the edit is dropped and the cursor advanced past it (silent loss).
      for (const s of successors) {
        await keyringStore.save(treeKey, s.revision, await worker.unwrapChainKeyring(s.bytes));
      }
      await keyringStore.saveHead(treeKey, engine, r.keyring);
      // The accept path advances the revision without opening the DEK — carry the stored write-epoch pin
      // forward so this sync doesn't erase the recover commitment (OPE-286 phase 2).
      watermarks.observe(treeKey, { keyringCursor: carryChainPin(r.watermark, floor(treeKey)) });
      return { revision: chainRevision(r.watermark), changed: true };
    },

    /**
     * Publish this device's produced keyring TAIL so peers can pull it: PUT every retained revision the
     * server is missing, in ascending single-hop order (the chain verifier admits only revision==prior+1,
     * and re-PUT of an admitted revision is a 409, so the range must be exact). Injected callbacks keep the
     * vault server-decoupled (id mapping stays outside, mirroring `syncKeyring`):
     *   getServerHead() -> number         the server's current keyring head (0 if none yet)
     *   putUpdate(bytes) -> Promise       PUT one wrapped KeyringUpdate (throws ConflictError on 409)
     *   serverBytesAt(rev) -> bytes|null  the server's stored bytes at a revision, to disambiguate a 409
     * A 409 whose served bytes EQUAL ours is benign (already admitted / a lost race) → continue; a 409 with
     * DIFFERENT bytes is a fork → throws KeyringForkError. Network/other throws propagate. No-op when the
     * server is already at (or past) our retained head. Bounds by the RETAINED head (a crash leaves retained
     * ≥ watermark, never behind), so `at(rev)` is never null inside the range — a gap is an invariant bug.
     * @returns {Promise<{ head: number }>}
     */
    async reconcileKeyring(treeKey, { getServerHead, putUpdate, serverBytesAt }) {
      const localHead = (await keyringStore.head(treeKey))?.revision ?? 0;
      let head = await getServerHead(localHead); // passed localHead so the probe fetches head+1.. (no full history)
      while (head < localHead) {
        const rev = head + 1;
        const bytes = await keyringStore.at(treeKey, rev);
        if (!bytes) throw new Error(`keyring retention gap at revision ${rev}`);
        const update = await worker.wrapChainKeyringUpdate(bytes);
        try {
          await putUpdate(update);
          head = rev;
        } catch (e) {
          if (e?.name === 'ConflictError') {
            const served = await serverBytesAt(rev);
            if (served && bytesEqual(served, bytes)) { head = rev; continue; } // benign: already admitted
            throw new KeyringForkError(rev);
          }
          throw e;
        }
      }
      return { head: localHead };
    },

    /**
     * Assemble this tree's delta-log SyncController, verifying every landed entry against this device's
     * retained keyring chain (§B3). It lives on the vault because the vault owns the crypto worker + the
     * keyring store the entry verifier needs; the seal/open are bound to the passphrase SESSION for this
     * tree (kind:'delta'). `docId` is the server tree id (== the local keyring key after the identity
     * collapse), so keyringStore.at(docId, rev) resolves the governing revision.
     * @returns {import('../sync.js').SyncController}
     */
    makeDeltaSync({ tree, remote, docId, session, replicaKey = null, version = ENVELOPE_VERSION }) {
      const seal = (raw) => session.seal(raw, docId, { kind: 'delta' });
      const open = (sealed) => session.open(sealed, docId, { kind: 'delta' });
      return createSyncedDeltaSync({ version, tree, remote, docId, seal, open, worker, keyringStore, replicaKey });
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
      const prior = floor(treeKey);
      const r = await worker.acceptResetKeyring(anchor, treeId, candidate);
      const revision = chainRevision(r.watermark);
      await keyringStore.save(treeKey, revision, r.keyring);
      await keyringStore.saveHead(treeKey, engine, r.keyring);
      // A reset opens no epoch here — carry the stored write-epoch pin forward (OPE-286 phase 2).
      watermarks.observe(treeKey, { keyringCursor: carryChainPin(r.watermark, prior) });
      return { revision };
    },
  };
}
