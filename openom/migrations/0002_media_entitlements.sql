-- Media storage + the tier/entitlement enforcement surface (SERVER-DATA-FORMAT §12,
-- §17). Postgres-only, server-owned — no wire-format impact. The full billing model
-- (plan_limits thresholds + entitlement_grants ledger + family pooling) is pinned in
-- §17 but deferred until subscriptions ship; here we add just the effective
-- entitlements + meters the media path enforces, seeded per account.

-- Media blob registry: refcount + soft-delete lifecycle (§12). ref_count is driven by
-- client attach/detach; state moves pending -> live -> tombstoned (revivable) ->
-- physically deleted. The server never deletes a blob on manifest absence (§9.11), and
-- storage usage counts pending+live+tombstoned, crediting back only at physical delete
-- (§9.9a).
CREATE TABLE tree_blobs (
    tree_id         UUID        NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    blob_id         BYTEA       NOT NULL,
    r2_key          TEXT        NOT NULL,
    size_bytes      BIGINT      NOT NULL,
    ciphertext_hash BYTEA,
    ref_count       INTEGER     NOT NULL DEFAULT 0,
    state           SMALLINT    NOT NULL DEFAULT 0,   -- 0 pending, 1 live, 2 tombstoned
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    tombstoned_at   TIMESTAMPTZ,
    PRIMARY KEY (tree_id, blob_id)
);

-- Effective entitlements + usage meters on the account (owner-pays, §17). Defaults are
-- the free tier: no media at all. Billing (or the local dev seed) raises them.
-- Two INDEPENDENT meters (§17): media usage never gates tree editing, so a full media
-- pool can't lock a user out of their own tree.
ALTER TABLE accounts
    ADD COLUMN allow_media           BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN allow_streaming_media BOOLEAN NOT NULL DEFAULT false,  -- gates the streaming-AEAD construction (video)
    ADD COLUMN max_blob_bytes        BIGINT  NOT NULL DEFAULT 0,      -- per-blob cap; with the streaming flag, the de-facto video gate
    ADD COLUMN max_blob_count        INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN max_storage_bytes     BIGINT  NOT NULL DEFAULT 0,      -- media pool (the sold number)
    ADD COLUMN max_tree_bytes        BIGINT  NOT NULL DEFAULT 1073741824,  -- 1 GiB: generous, unadvertised tree reserve
    ADD COLUMN media_used_bytes      BIGINT  NOT NULL DEFAULT 0,      -- reserved at intent, reconciled at confirm (§9.9)
    ADD COLUMN tree_used_bytes       BIGINT  NOT NULL DEFAULT 0,
    ADD COLUMN blob_count            INTEGER NOT NULL DEFAULT 0;
