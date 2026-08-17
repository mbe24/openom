// The launch-gate verify COMPOSER (§B3): turns the sealer primitives into the one function the
// SyncController takes as `verify(sealed, plaintext)`. It decides — per entry, from the VERIFIED keyring,
// never from the entry's own emptiness — whether an entry must be signed, and if so verifies it.
//
// Flow per entry:
//   1. Read the entry's governing keyring revision + sealing key_id from its header (worker.entryAttribution).
//   2. keyring_revision 0 → no governing keyring: an unattributed V1 (single-owner) entry → accept.
//      (keyring_revision is AAD-bound, so a hostile server can't forge it to 0 on a shared-tree entry —
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

/**
 * @param {object} deps
 * @param {number} deps.version   the envelope version (ENVELOPE_VERSION)
 * @param {object} deps.worker    the crypto worker proxy (entryAttribution / epochIsAttributed / verifyEntry)
 * @param {(revision: number) => Promise<Uint8Array|null>} deps.keyringAt  the client's verified keyring at a
 *        revision (from the retained chain); null if not (yet) available.
 * @returns {(sealed: Uint8Array, plaintext: Uint8Array) => Promise<void>}  throws to reject (see errors above)
 */
export function createEntryVerifier({ version, worker, keyringAt }) {
  if (!worker || !keyringAt || version == null) {
    throw new Error('createEntryVerifier needs { version, worker, keyringAt }');
  }
  return async function verify(sealed, plaintext) {
    const { keyringRevision, keyId } = await worker.entryAttribution(sealed);
    if (keyringRevision === 0) return; // unattributed V1 entry — no governing keyring, accept
    const governing = await keyringAt(keyringRevision);
    if (!governing) {
      throw new RetryableVerifyError(`governing keyring revision ${keyringRevision} not available yet`);
    }
    if (!(await worker.epochIsAttributed(governing, keyId))) return; // epoch not shared → accept unsigned
    await worker.verifyEntry(version, sealed, plaintext, governing); // throws → REJECT
  };
}
