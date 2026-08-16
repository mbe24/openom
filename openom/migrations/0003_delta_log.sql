-- Delta-log append/read (track B1). V1 wrote only snapshots; these columns let the append-only
-- tree_log carry INLINE sealed delta payloads with author attribution, and give each tree a
-- serialized sequence counter so concurrent appends get gap-free, collision-free seq numbers.
--
-- The server stays zero-knowledge: `payload` is opaque sealed bytes it never decrypts; it records only
-- metadata (member/replica/size/time) — which is exactly what the paid change-history feature reads.

ALTER TABLE tree_log
    ALTER COLUMN r2_key DROP NOT NULL,               -- inline payloads have no R2 object
    ADD COLUMN payload   BYTEA,                       -- the sealed delta bytes (NULL if spilled to R2)
    ADD COLUMN member_id UUID REFERENCES accounts(id);-- author of the change (change-history attribution)

ALTER TABLE trees
    -- Next seq to hand out, bumped under a row lock so concurrent appenders never gap or collide.
    ADD COLUMN next_log_seq BIGINT NOT NULL DEFAULT 0;
