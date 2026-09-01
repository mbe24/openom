-- Engine-neutral advisory membership summary (OPE-278 / the server-keyring-decoupling decision).
--
-- The server does NOT parse the keyring. The CLIENT — which verifies the keyring locally and resolves the
-- membership after every change — pushes the resolved {member_id -> role} view here, and the server stores
-- it as the advisory `tree_access` ACL (defense-in-depth + cost-control, NEVER the security boundary; the
-- crypto is the real boundary, client-side). This keeps the server keyring-FORMAT-agnostic: chain, dag, and
-- any future engine reach it through the same {member_id, role} summary with zero server changes.
--
-- Concurrency: the client interprets its own engine-opaque `basis` frontier (chain: a revision token; dag:
-- the op-DAG tip ids) to decide it is not causally behind BEFORE pushing; the server only does last-writer-
-- wins via CAS on a server-assigned `generation` (mirroring the tree_keyrings PK-as-CAS idiom). The server
-- never interprets `basis` — it stores it verbatim for staleness display + audit.
CREATE TABLE tree_access_meta (
    tree_id     UUID        PRIMARY KEY REFERENCES trees(id) ON DELETE CASCADE,
    generation  BIGINT      NOT NULL,             -- +1 per accepted summary write; the CAS token
    basis       TEXT[]      NOT NULL,             -- engine-opaque frontier tokens (client-interpreted only)
    asserted_by UUID        NOT NULL,             -- the signer account whose push landed (audit)
    asserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
