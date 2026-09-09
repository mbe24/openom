// The member-side sharing/keyring orchestration for the app-core worker, extracted here so it is TESTABLE
// with fakes: the trust decisions (genesis-walk + invite-pin, member unlock) are the wasm's — proven in Rust
// (openom_vault::sharing) and end-to-end by `chain_genesis_walk_join_end_to_end` — so this module only covers
// the JS WIRING (hop framing, walk-derived retention, fail-closed ordering). The worker (appCore.worker.js)
// injects the wasm functions + the network transport + the keyring store; a test injects fakes.

// [u32-be len][bytes]… — the wire shape the wasm's `split_length_prefixed` expects. Ascending, no gaps.
export function frameHops(revisions) {
  let total = 0;
  for (const r of revisions) total += 4 + r.length;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const r of revisions) {
    dv.setUint32(off, r.length, false);
    off += 4;
    out.set(r, off);
    off += r.length;
  }
  return out;
}

// The inverse of frameHops — split a `[u32-be len][bytes]…` buffer (the walk's per-revision bodies) back out.
export function unframe(buf) {
  const out = [];
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('unframe: truncated length prefix');
    const len = dv.getUint32(off, false);
    off += 4;
    if (off + len > buf.length) throw new Error('unframe: length prefix overruns buffer');
    out.push(buf.subarray(off, off + len));
    off += len;
  }
  return out;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('odd-length signer hex');
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('non-hex character in signer key');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Concatenate a signer set's 32-byte author keys into the `trustedSigners` blob `unlockAsMember` expects —
// author keys only; the wasm derives roles/member-ids from the verified keyring itself.
function concatSigners(signers) {
  const out = new Uint8Array(signers.length * 32);
  signers.forEach((s, i) => {
    if (s.authorPublicKey.length !== 32) throw new Error('signer author key is not 32 bytes');
    out.set(s.authorPublicKey, i * 32);
  });
  return out;
}

function freshReplicaId() {
  const id = new Uint8Array(16);
  crypto.getRandomValues(id);
  return id;
}

/** A member-join failed terminally (bad walk / pin / passphrase) — nothing was persisted. */
export class JoinError extends Error {
  constructor(message) {
    super(message);
    this.name = 'JoinError';
  }
}

/** The server holds a keyring that forks off our produced tail (a 409 whose bytes differ from ours). */
export class KeyringForkError extends Error {
  constructor(revision) {
    super(`keyring fork at revision ${revision}`);
    this.name = 'KeyringForkError';
    this.revision = revision;
  }
}

function bytesEqual(a, b) {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Publish this device's produced CHAIN keyring tail so peers can pull + verify it: wrap each retained
 * revision the server is missing and PUT it in ascending single-hop order (the chain verifier admits only
 * revision == prior+1). A 409 whose served bytes equal ours is benign (already admitted); differing bytes are
 * a fork. Idempotent + safe to retry. `deps`: { wasm: { wrapChainKeyringUpdate }, transport: { readKeyring,
 * putKeyring }, keyringStore }. Returns the local head revision published to.
 */
export async function publishKeyring(deps, { docId }) {
  const { wasm, transport, keyringStore } = deps;
  const localHead = (await keyringStore.head(docId))?.revision ?? 0;
  if (localHead === 0) return { head: 0 };
  // The server's current keyring head (0 if none yet); probe from localHead so we don't refetch history.
  let head = (await transport.readKeyring(docId, localHead)).head ?? 0;
  while (head < localHead) {
    const rev = head + 1;
    const bytes = await keyringStore.at(docId, rev);
    if (!bytes) throw new Error(`keyring retention gap at revision ${rev}`);
    const update = wasm.wrapChainKeyringUpdate(bytes);
    try {
      await transport.putKeyring(docId, update);
      head = rev;
    } catch (e) {
      if (e?.name === 'ConflictError') {
        const served = (await transport.readKeyring(docId, rev)).revisions?.[0]?.bytes;
        if (served && bytesEqual(served, bytes)) {
          head = rev; // benign: this revision was already admitted with identical bytes
          continue;
        }
        throw new KeyringForkError(rev);
      }
      throw e;
    }
  }
  return { head: localHead };
}

/**
 * Join a shared CHAIN tree as a member (first-time onboarding): fetch the keyring history from the server,
 * genesis-walk + invite-pin verify it in the wasm, retain every verified revision under its WALK-DERIVED
 * number, and unlock as the member at the verified head. Fail-closed — any verification failure throws and
 * persists nothing. Returns the wasm `OpenResult` (its handle is the ready member core).
 *
 * `deps`: { wasm: { verifyKeyringWalk, unlockAsMember }, transport: { readKeyring }, keyringStore,
 *           verifyFingerprint? }. `opts`: { treeId(bytes), treeUuid(server id), docId, passphrase, memberId,
 *           memberKdfParams(bytes), pinnedRevision, pinnedHash(bytes), fp?, engine? }.
 */
export async function joinAsMember(deps, opts) {
  const { wasm, transport, keyringStore, verifyFingerprint } = deps;
  const {
    treeId, docId, passphrase, memberId, memberKdfParams,
    pinnedRevision, pinnedHash, fp, engine = 'chain',
  } = opts;
  if (engine !== 'chain') throw new JoinError('genesis-walk join is chain-only');
  // First-time action only: adopting a whole history at the invite pin would overwrite an existing local head
  // and could roll an already-joined member backward on a stale link. Refuse — resync, don't re-join.
  if (await keyringStore.load(docId)) throw new JoinError('tree already present locally — use sync, not join');

  // The server addresses a tree's keyring channel by the same id as its delta log (docId).
  const { revisions } = await transport.readKeyring(docId, 1);
  if (!revisions || revisions.length === 0) throw new JoinError('no keyring history to verify');

  // 1. Verify the walk from genesis, bound to the invite's (revision, hash) prefix pin. Any invalid transition
  //    or a pin mismatch throws → terminal, persist nothing.
  let walk;
  try {
    walk = wasm.verifyKeyringWalk(treeId, frameHops(revisions.map((r) => r.bytes)), pinnedRevision, pinnedHash);
  } catch (e) {
    throw new JoinError(e?.message ?? String(e));
  }
  const signers = JSON.parse(walk.signersJson).map((s) => ({
    memberId: s.memberId,
    authorPublicKey: hexToBytes(s.authorPublicKey),
  }));
  // 2. Optional out-of-band signer-fingerprint cross-check (anti-substitution defense-in-depth over the pin).
  if (verifyFingerprint && fp !== undefined && !(await verifyFingerprint(signers, fp))) {
    throw new JoinError('signer fingerprint does not match the invite');
  }
  // 3. Unframe the walk's RAW per-revision bodies BEFORE unlocking, so a malformed walk fails without a sealer.
  //    The walk proved genesis (rev 1) + contiguous ascending, so bodies[i] is revision i+1.
  const bodies = unframe(walk.bodiesFramed);
  if (bodies.length !== walk.revision) throw new JoinError('walk returned a mismatched revision count');

  // 4. Unlock at the verified head BEFORE persisting (a wrong passphrase then leaves no partial state).
  let res;
  try {
    res = wasm.unlockAsMember(
      engine, walk.headKeyring, passphrase, memberKdfParams, treeId, memberId,
      concatSigners(signers), freshReplicaId(), walk.revision, docId,
    );
  } catch (e) {
    throw new JoinError(e?.message ?? String(e));
  }
  // 5. Retain every RAW revision under its WALK-DERIVED number (never the server's unverified label), save the
  //    head. A store failure here frees the just-created handle so no DEK-holder leaks.
  try {
    for (let i = 0; i < bodies.length; i += 1) {
      await keyringStore.save(docId, i + 1, bodies[i]);
    }
    await keyringStore.saveHead(docId, engine, walk.headKeyring);
  } catch (e) {
    try {
      res.takeHandle()?.free();
    } catch {
      /* already gone */
    }
    throw e;
  }
  return res;
}
