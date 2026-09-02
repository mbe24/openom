-- Drop the write-only `keyring_hash` column. It was the signing-bytes hash of a chain Keyring, computed
-- and stored by the server but never read back (the client walks the chain via prev_keyring_hash inside
-- the signed payload). With the engine-agnostic wire (Stage 2), the server no longer parses the keyring
-- body at all — it stores the opaque `Admitted.state` and keys on the verified `Admitted.update_ref` — so
-- it cannot (and need not) compute a chain-specific hash. Pre-release: no data to preserve.
ALTER TABLE tree_keyrings DROP COLUMN keyring_hash;
