-- Log GC floor (OPE-409) + cost-attribution rollup (OPE-412), design.sync/design.ope412-409-metering-gc.md.
-- Pre-release: no back-compat needed. This is the first consumer of tree_member_seen (inert since a1997ed).

-- The monotonic GC ratchet, one row per (tree, replica): entries with counter < floor MAY be physically
-- gone (marked, past grace, reaped). Advanced at MARK via GREATEST so it never regresses (§2.4 M1) — a wrong
-- non-zero fallback would delete a whole replica log, so a replica with NO row defaults to floor 0 in the
-- reader (never delete). GC deletes strictly below floor; the snapshot-PUT ratchet + the below-floor log
-- write both read this to reject a write beneath a reclaimed prefix (D2).
CREATE TABLE tree_gc_floor (
    tree_id UUID   NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    replica TEXT   NOT NULL,
    floor   BIGINT NOT NULL,   -- exclusive: entries with counter < floor may be reclaimed
    PRIMARY KEY (tree_id, replica)
);

-- The live snapshot's SUBSUMED coverage per replica (gate 1), REPLACED wholesale in the snapshot-PUT tx.
-- Each row is bound to the etag of the snapshot object it was published against (the ETAG-BINDING that
-- realizes D1 server-only, in place of the design's immutable content-addressed C1): GC's gate 1 trusts a
-- covered row ONLY IF its snapshot_etag equals the CURRENT live `snapshot` object's etag (tree_blob_index),
-- else it treats that replica as unpublished (covered = 0, fail-closed). The `snapshot` blob itself stays a
-- normal pointer key (Precondition::Any overwrite), unchanged.
CREATE TABLE tree_snapshot_covered (
    tree_id       UUID   NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    replica       TEXT   NOT NULL,
    counter       BIGINT NOT NULL,   -- exclusive subsumed frontier for this replica
    snapshot_etag TEXT   NOT NULL,   -- the live snapshot object's etag this coverage was published against
    PRIMARY KEY (tree_id, replica)
);

-- The GC mark column: set to now() when a log index row falls below the floor (phase 1), physically reaped
-- after the deletion grace (phase 2). A marked row is still listed + served (200) until reaped (M4) — 410
-- only once the row is actually gone.
ALTER TABLE tree_blob_index ADD COLUMN pending_delete_at TIMESTAMPTZ;

-- Cost-attribution rollup (OPE-412 §1.1): the R2 cost drivers per operation, attributed to
-- (account = the owner who pays, tree, member) and bucketed by month. `$cost = write_ops × $4.50/M
-- + read_ops × $0.36/M + gbmo(stored) × $0.015` is a query-time view, never a gate. Month rollover is a new
-- PK row (free). Incremented in the SAME tx as the write gates (write side) / best-effort on the read side.
CREATE TABLE usage_month (
    account_id  UUID   NOT NULL REFERENCES accounts(id),   -- the OWNER who pays
    tree_id     UUID   NOT NULL,
    member_id   UUID   NOT NULL,                            -- attributed to whom (owner or a member)
    month       DATE   NOT NULL,                            -- date_trunc('month', now())::date
    write_ops   BIGINT NOT NULL DEFAULT 0,
    read_ops    BIGINT NOT NULL DEFAULT 0,
    bytes_write BIGINT NOT NULL DEFAULT 0,
    bytes_read  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, tree_id, member_id, month)
);
