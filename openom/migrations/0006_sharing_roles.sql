-- Sharing / roles (track B3, slice 1: the ACL + role enforcement). The authoritative membership/role
-- lives in the client-verified signed keyring; this table is a DERIVED, advisory server ACL — defense in
-- depth + cost control (refuse a removed member before they spend the owner's quota), NOT the security
-- boundary. Populated from the keyring in slice 2; here it's the schema + the owner backfill.
CREATE TABLE tree_access (
    tree_id   UUID        NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    member_id UUID        NOT NULL,               -- a Supabase account id; NO FK to accounts (Mode-A
                                                  -- members may have no account row here — owner-pays)
    role      SMALLINT    NOT NULL,               -- 1 owner, 2 co_owner, 3 maintainer, 4 editor, 5 viewer
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_id, member_id)
);

-- Per-member abuse-rate bucket, keyed (tree_id, member_id). Its OWN table (not columns on tree_access) so
-- it survives member remove/re-add churn and doesn't entangle the hot rate UPDATE with rare, security-
-- sensitive role writes. Refill rate/burst are read from the OWNER's accounts row (owner-pays sets the
-- budget); this row holds only the live token state. Created lazily on a member's first metered op.
CREATE TABLE member_rate (
    tree_id     UUID             NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    member_id   UUID             NOT NULL,
    tokens      DOUBLE PRECISION NOT NULL,
    refilled_at TIMESTAMPTZ      NOT NULL DEFAULT now(),
    PRIMARY KEY (tree_id, member_id)
);

-- Non-account members can propose (editor) and, once promoted, commit — so these FKs to accounts(id)
-- would 500 the first such op. Drop them; the columns stay (attribution is by id, not a hard FK).
ALTER TABLE proposals DROP CONSTRAINT IF EXISTS proposals_proposer_member_id_fkey;
ALTER TABLE tree_log  DROP CONSTRAINT IF EXISTS tree_log_member_id_fkey;

-- Media attribution: who staged a blob (removed-member purge + bulk-detach, design.sharing §5).
ALTER TABLE tree_blobs ADD COLUMN uploaded_by UUID;

-- Backfill: every existing tree's owner becomes its owner-role ACL row, or authorize() would 403 the
-- owner the instant it starts consulting tree_access.
INSERT INTO tree_access (tree_id, member_id, role)
SELECT id, owner_id, 1 FROM trees
ON CONFLICT (tree_id, member_id) DO NOTHING;
