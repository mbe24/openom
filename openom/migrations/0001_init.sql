-- openom V1 metadata. Pointers, ownership and non-sensitive counts only — never
-- genealogy (that lives encrypted in R2). See plan/SERVER-DATA-FORMAT.md §7, §11.

-- Accounts (Supabase subjects) + their entitlements.
CREATE TABLE accounts (
    id         UUID        PRIMARY KEY,
    plan       SMALLINT    NOT NULL DEFAULT 0,   -- 0 = free
    max_trees  INTEGER     NOT NULL DEFAULT 1,   -- premium raises this
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per tree: who owns it, where its snapshot lives, and the CAS token.
CREATE TABLE trees (
    id                 UUID        PRIMARY KEY,
    owner_id           UUID        NOT NULL REFERENCES accounts(id),
    r2_key             TEXT        NOT NULL,
    snapshot_version   TEXT,                          -- CAS token (R2 ETag); null until first snapshot
    envelope_version   INTEGER     NOT NULL,
    aead               SMALLINT    NOT NULL,
    size_bytes         BIGINT      NOT NULL DEFAULT 0,
    ciphertext_hash    BYTEA,
    covers_through_seq BIGINT      NOT NULL DEFAULT 0,
    keyring_revision   INTEGER     NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX trees_owner_idx ON trees(owner_id);

-- The append-only delta log index (V2 uses it; V1 writes only snapshots). The
-- unique (tree_id, replica_id, replica_counter) is the idempotency "dot".
CREATE TABLE tree_log (
    tree_id         UUID        NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    seq             BIGINT      NOT NULL,
    r2_key          TEXT        NOT NULL,
    kind            SMALLINT    NOT NULL,   -- 1 = snapshot, 2 = delta
    replica_id      BYTEA       NOT NULL,
    replica_counter BIGINT      NOT NULL,
    ciphertext_hash BYTEA       NOT NULL,
    size_bytes      BIGINT      NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_id, seq),
    UNIQUE (tree_id, replica_id, replica_counter)
);

-- tree_access (membership) and member_keys (public keys) arrive with sharing (V2).
