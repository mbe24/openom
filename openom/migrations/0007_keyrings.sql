-- Keyring storage (track B3, slice 2). The signed keyring is the AUTHORITATIVE membership/role list;
-- the server stores every revision (append-only) so clients walk the hash chain hop-by-hop, and derives
-- the advisory tree_access ACL from it on each accepted PUT. The server verifies the keyring's structure
-- + signatures + chain continuity (openom_crypto::chain — honest-server defense-in-depth) but never the
-- secrets: the payload's wraps/keys are opaque to it (zero-knowledge intact).
--
-- Inline BYTEA (keyrings are small — a handful of members/epochs); R2 spillover is a follow-up like the
-- delta log. The PK (tree_id, revision) IS the CAS: two racing PUTs at the same revision collide, so only
-- one lands. trees.keyring_revision (from 0001) tracks the head.
CREATE TABLE tree_keyrings (
    tree_id      UUID        NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    revision     INTEGER     NOT NULL,
    payload      BYTEA       NOT NULL,   -- the opaque signed Keyring envelope bytes
    keyring_hash BYTEA       NOT NULL,   -- signing-bytes hash of this revision (chain continuity/debug)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_id, revision)
);
