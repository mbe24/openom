-- OPE-408: a per-account rate bucket for POST /trees (create-tree).
--
-- create_tree is otherwise the only write endpoint with no rate gate: a bodyless, trivially-scriptable
-- endpoint an authenticated caller could hammer with no backoff (a DB-load vector — every attempt takes the
-- accounts-row FOR UPDATE lock + runs the entitlement count, even on the over-quota 403 path). The entitlement
-- gate caps HOW MANY trees exist; this caps the RATE of attempts.
--
-- Keyed on the ACCOUNT, not (tree, member): the tree doesn't exist yet at create time, so this can't reuse
-- member_rate (whose tree_id FKs trees(id)). Refill uses the account's existing log_rate/log_burst (the
-- owner-pays plan budget), so a create competes against the same generous rate as the data-log bucket — a
-- single bucket per the owner decision (4-B), sized well above any legitimate create cadence.
CREATE TABLE account_create_rate (
    account_id  UUID             PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    tokens      DOUBLE PRECISION NOT NULL,
    refilled_at TIMESTAMPTZ      NOT NULL DEFAULT now()
);
