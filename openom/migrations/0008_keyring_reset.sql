-- Recovery / succession reset (track B3, slice 4). A reset is a keyring that chains onto the head by
-- HASH + revision (revision = head+1, prev_keyring_hash = hash(head)) but changes the authorized-signer
-- set WITHOUT the old set's endorsement — because the old signing key is presumed lost (a forgotten
-- passphrase, or owner succession). The server can't cryptographically tell a legitimate recovery from a
-- malicious founder-substitution, so it only ensures a reset can't roll back or fork; the CLIENT
-- re-verifies the new signer set out-of-band before trusting it. `is_reset` surfaces the change to
-- clients (a UX/telemetry hint, never a trust gate — the client determines it from the crypto).
ALTER TABLE tree_keyrings ADD COLUMN is_reset BOOLEAN NOT NULL DEFAULT false;

-- Per-tree reset cooldown: resets are rare life events, and a reset bypasses the prior-signer signature
-- gate, so a stolen Administer token could spam them. Bound the nuisance (each reset forks every member
-- into an OOB-reverify prompt) with a cooldown; the OOB re-verify is the actual security control.
ALTER TABLE trees ADD COLUMN last_reset_at TIMESTAMPTZ;
