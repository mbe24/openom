-- Proposals channel (track B2) — the approval side of review-changes. An editor seals a
-- KIND_PROPOSAL bundle (base version-vector + ops) and submits it here for the owner /
-- committers to review (client-side diff), then accept (apply to the tree as a real delta)
-- or reject/withdraw. Proposals are TRANSIENT and off the authoritative delta log — a
-- malicious server must never be able to replay one into the tree (the log append path
-- already refuses KIND_PROPOSAL). Zero-knowledge: the payload is opaque; the server only
-- meters, attributes, and expires it.
CREATE TABLE proposals (
    id                 UUID        PRIMARY KEY,               -- server-minted (Uuid::new_v4)
    tree_id            UUID        NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    proposer_member_id UUID        NOT NULL REFERENCES accounts(id),
    payload            BYTEA       NOT NULL,                  -- sealed KIND_PROPOSAL envelope (inline; small)
    ciphertext_hash    BYTEA       NOT NULL,
    size_bytes         BIGINT      NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL                   -- TTL auto-expiry (swept with media GC)
);
CREATE INDEX proposals_by_tree ON proposals (tree_id, expires_at);

-- Append-only daily submission ledger, so the per-member/day cap holds even across
-- create→delete→recreate churn (counting live rows would undercount). Swept by GC once
-- the day is well past.
CREATE TABLE proposal_day_counts (
    tree_id   UUID    NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    member_id UUID    NOT NULL,
    day       DATE    NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tree_id, member_id, day)
);

-- Proposal cost meters on the owner account (owner-pays, §17). Their own axis — a full
-- proposals surface never gates tree edits or media (two-meter independence). Free tier
-- disables proposals entirely (max_proposal_bytes = 0); billing raises them.
ALTER TABLE accounts
    ADD COLUMN max_proposal_bytes           BIGINT  NOT NULL DEFAULT 0,      -- per-proposal size cap; 0 disables proposals
    ADD COLUMN max_open_proposals_per_tree  INTEGER NOT NULL DEFAULT 0,      -- concurrent open proposals on one tree
    ADD COLUMN max_proposals_per_member_day INTEGER NOT NULL DEFAULT 0,      -- daily submissions per member (abuse cap)
    ADD COLUMN proposal_ttl_secs            INTEGER NOT NULL DEFAULT 604800; -- default 7-day auto-expiry
