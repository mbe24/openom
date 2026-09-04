// The launch-gate verify COMPOSER (§B3): turns the sealer primitives into the one function the
// SyncController takes as `verify(sealed, plaintext)`. It decides — per entry, from the VERIFIED keyring,
// never from the entry's own emptiness — whether an entry must be signed, and if so verifies it.
//
// Flow per entry:
//   1. Read the entry's governing keyring revision + sealing key_id from its header (worker.entryAttribution
//      decodes the header's opaque `governing_ref` to a revision for the chain).
//   2. revision 0 (empty governing_ref) → no governing keyring: an unattributed V1 (single-owner) entry → accept.
//      (governing_ref is AAD-bound, so a hostile server can't forge it to empty on a shared-tree entry —
//      tampering it breaks the AEAD open, and the entry never reaches here.)
//   3. Fetch the governing keyring at that revision (from the client's verified chain). Missing → a
//      RetryableVerifyError: the caller holds the entry and retries after the next keyring sync (fail-closed,
//      never merge unverified).
//   4. If the sealing epoch is NOT attributed in that keyring (wrapped only to the founder) → accept
//      (unattributed epoch — V1 communal-DEK history stays valid).
//   5. Otherwise verify: worker.verifyEntry throws to REJECT (bad signature / wrong role / unsigned on an
//      attributed epoch — which is exactly the downgrade a stripped signature would attempt).

/** A verification failure that is transient (the governing keyring isn't available yet) — the caller should
 *  hold the entry and re-verify after syncing the keyring, rather than treat it as a permanent rejection. */
export class RetryableVerifyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RetryableVerifyError';
    this.retryable = true;
  }
}

/** A PERMANENT rejection on a shared tree: an entry that cannot be a legitimately-attributed commit (an
 *  unattributed/rev-0 entry, or one governed by a revision beyond the verified head). NOT retryable — the
 *  caller drops it and advances, so a forged entry can't stall the whole tail (the livelock the invariant
 *  exists to close). */
export class SecurityVerifyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecurityVerifyError';
  }
}

/**
 * @param {object} deps
 * @param {number} deps.version   the envelope version (ENVELOPE_VERSION)
 * @param {object} deps.worker    the crypto worker proxy (entryAttribution / epochIsAttributed / verifyEntry)
 * @param {(revision: number) => Promise<Uint8Array|null>} deps.keyringAt  the client's verified keyring at a
 *        revision (from the retained chain); null if not (yet) available.
 * @param {(() => Promise<boolean>)|null} [deps.hasBeenShared]  whether the tree HAS BEEN SHARED, from the
 *        VERIFIED head keyring (monotonic). Re-read per call and STICKY: once observed true it stays true for
 *        this verifier, so a later keyring withhold can't downgrade the rule. Omit ⇒ never-shared (V1).
 * @param {(() => Promise<number>)|null} [deps.headRevision]  the verified head keyring revision — the ceiling
 *        for a legitimate governing_ref (writers publish their keyring before the entries it governs, and the
 *        keyring channel syncs before deltas, so a ref beyond the head isn't reachable). Omit ⇒ no ceiling.
 * @returns {(sealed: Uint8Array, plaintext: Uint8Array) => Promise<void>}  throws to reject (see errors above)
 */
export function createEntryVerifier({ version, worker, keyringAt, hasBeenShared = null, headRevision = null }) {
  if (!worker || !keyringAt || version == null) {
    throw new Error('createEntryVerifier needs { version, worker, keyringAt }');
  }
  let stickyShared = false;
  return async function verify(sealed, plaintext) {
    const { keyringRevision, keyId } = await worker.entryAttribution(sealed);

    // Live + sticky: once the tree is observed shared it stays shared for this session. The keyring carries
    // the monotonic marker, so a fresh session re-derives it — this only guards a mid-session withhold.
    if (!stickyShared && hasBeenShared) stickyShared = await hasBeenShared();

    if (stickyShared) {
      // SHARED: every authoritative entry MUST be attributed. rev 0 (empty governing_ref) can't be a
      // legitimately-governed entry here — it's the direct backdate forge → HARD REJECT (a retryable hold
      // would stall the whole tail forever). Pre-share unattributed history is reached via the adopted
      // signed snapshot, never replayed as a rev-0 delta.
      if (keyringRevision === 0) {
        throw new SecurityVerifyError('unattributed entry (rev 0) on a shared tree');
      }
      const governing = await keyringAt(keyringRevision);
      if (!governing) {
        // A ref ABOVE the verified head isn't legitimately reachable (writers publish the keyring before the
        // entries it governs, and the keyring channel syncs before this one) → reject, never a tail-blocking
        // hold. A ref at/below the head that isn't retained is a transient gap → hold + retry.
        const head = headRevision ? await headRevision() : keyringRevision;
        if (keyringRevision > head) {
          throw new SecurityVerifyError(`governing revision ${keyringRevision} is beyond the verified head ${head}`);
        }
        throw new RetryableVerifyError(`governing keyring revision ${keyringRevision} not retained yet`);
      }
      await worker.verifyEntry(version, sealed, plaintext, governing); // signature + role + epoch; throws → reject
      return;
    }

    // NEVER SHARED (V1 single-owner): unchanged path — unattributed entries are acceptable.
    if (keyringRevision === 0) return; // unattributed V1 entry — no governing keyring, accept
    const governing = await keyringAt(keyringRevision);
    if (!governing) {
      throw new RetryableVerifyError(`governing keyring revision ${keyringRevision} not available yet`);
    }
    if (!(await worker.epochIsAttributed(governing, keyId))) return; // epoch not shared → accept unsigned
    await worker.verifyEntry(version, sealed, plaintext, governing); // throws → REJECT
  };
}
