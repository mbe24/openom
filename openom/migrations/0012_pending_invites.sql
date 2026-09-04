-- Mode A share invites — the pending-invite transport for the two-channel invite protocol
-- (plan/sharing/design.mode-a-client-flow.md §2/§7).
--
-- Authentication rides the invite LINK, a second channel the server never sees: the server stores only
-- an OPEN invite the owner minted and the invitee's MAC'd public-key claim, and the REAL membership
-- change is the client's signed keyring PUT (admitted by the ChainVerifier). So this table is advisory
-- transport + spam control, NEVER the security boundary — a malicious server can drop or fabricate a
-- row but can't forge the MAC (it lacks the link secret) or the owner's keyring signature. Rows drop
-- with the tree.
CREATE TABLE pending_invites (
    invite_id           TEXT        PRIMARY KEY,
    tree_id             UUID        NOT NULL REFERENCES trees(id) ON DELETE CASCADE,
    owner_member_id     UUID        NOT NULL,
    role                TEXT        NOT NULL,               -- the string role the MAC binds (advisory here)
    recipient_pin       TEXT,                               -- optional email pin (enforcement deferred)
    expiry              BIGINT      NOT NULL,               -- ms since the unix epoch
    status              TEXT        NOT NULL DEFAULT 'open', -- open -> claimed (one live claim)
    claim_member_id     UUID,
    claim_hpke_public   BYTEA,
    claim_author_public BYTEA,
    claim_tag           BYTEA,
    claimed_at          BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX pending_invites_tree_idx ON pending_invites (tree_id);
