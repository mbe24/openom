-- Data-channel blob store (OPE-398, design.sync/design.ope398-managed-server.md §2 + §4) — the mechanical
-- slice. The managed server realizes the client's already-shipped BlobStore-over-HTTP contract
-- (packages/docsync/src/lib.rs, OPE-397) as R2 objects + a Postgres index/CAS-arbiter, exactly mirroring
-- why the scalar tree path CASes in Postgres rather than relying on S3 `If-Match` (trees.rs:6-8, "the
-- least portable S3 feature").

-- `(tree_id, key)`-keyed index: `get`/`put` are point lookups on the PK, `list(prefix)` is an index-only
-- scan (`text_pattern_ops` makes `key LIKE $2 || '%'` usable regardless of locale) — never an R2
-- ListObjectsV2 fan-out. Also the CAS arbiter for `Precondition::IfAbsent` (`ON CONFLICT DO NOTHING`, 0
-- rows -> 412) and `Precondition::Any` (`ON CONFLICT DO UPDATE`) blob PUTs — see `blobs.rs`.
CREATE TABLE tree_blob_index (
    tree_id    UUID   NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    key        TEXT   NOT NULL,   -- opaque client-chosen sub-path, e.g. "log/AbC.../7"
    etag       TEXT   NOT NULL,   -- content-hash etag, matching store-blob's Etag convention (hex sha256)
    size_bytes BIGINT NOT NULL,
    seq        BIGSERIAL,         -- insertion order; not client-visible, debugging/ordering only
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_id, key)
);
CREATE INDEX tree_blob_index_prefix_idx ON tree_blob_index (tree_id, key text_pattern_ops);

-- Per-member seen-frontier report (§4) — advisory, client-asserted PLUMBING ONLY. Nothing consumes this
-- yet to gate deletion: the two-gate GC floor (safety = the server snapshot's PUBLISHED covered frontier;
-- liveness = every current member's last-reported pull frontier) and the F3 self-heal-before-GC ordering
-- are a follow-up, security-reviewed slice (§4, §5.6/#12) — this table + PUT/GET /trees/{id}/seen exist
-- only so that follow-up has somewhere to read from; they never delete or gate anything by themselves.
-- One row per (tree, member, replica) the member has reported progress on; upserted per report.
CREATE TABLE tree_member_seen (
    tree_id     UUID   NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    member_id   UUID   NOT NULL,
    replica     TEXT   NOT NULL,
    counter     BIGINT NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_id, member_id, replica)
);
