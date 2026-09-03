# openom-roles

> The capability→role policy — one source of truth for the server ACL and client keyring verify.

**Status:** built · access-control layer, load-bearing · no design doc (policy lives in code + tests)
**Last updated:** 2026-08-25

## What it is — and is not

The authorization role model: four roles — Viewer, Editor, Maintainer, Owner (plus Co-owner, between
Owner and Maintainer) — and the fixed mapping from a **capability** (`Access::Read`, `Propose`,
`StageMedia`, `Commit`, `Administer`) or an **entry kind** (`Kind::Snapshot`, `Delta`, `Proposal`,
`Media`) to the weakest role allowed to exercise it. Two call sites depend on this crate and must
agree: the server's advisory ACL gate (`openom::authz`, which re-exports `Access` directly) and the
client's landed-entry verification (`openom-vault`'s `attribution::verify_entry`, via `required_role_for_kind`).
The server is defense-in-depth; the client is the real boundary — but both apply the same matrix, so
it is defined once here instead of duplicated in two crates and drifting silently. Roles are numeric,
power **descending** (`Owner` strongest, lower value), mirroring the keyring's `MemberRole`; a gate is
simply `member_role <= required`. The values are `i16` — matching the server's `tree_access.role`
column type — with the proto `MemberRole` (`i32`) in `openom-protocol` as the authoritative vocabulary.

It is **not** the vocabulary itself — `MemberRole` and `Kind` are defined in `openom-protocol`; this
crate only assigns them to capabilities and re-exposes the role values as `i16` constants. It does no
enforcement: no I/O, no DB query, no signature check, no session/identity lookup — just the
policy-matrix data and two pure mapping functions. And it does not gate signer operations
(assigning/removing an Owner or Co-owner) — those are checked at the endpoint directly, not modeled
as an `Access` variant here.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **ROLES-1** | The capability→role matrix is fixed: `Read`→Viewer, `Propose`/`StageMedia`→Editor, `Commit`/`Administer`→Maintainer. | This is the one matrix the server ACL and client verify both apply; a silent change here silently changes both sides at once. | `tests::capability_min_roles_match_the_matrix` |
| **ROLES-2** | The entry-kind→role matrix is fixed: `Snapshot`/`Delta`→Maintainer, `Proposal`/`Media`→Editor, `Unspecified`→`None`. | This is exactly the mapping `openom-vault`'s `attribution::verify_entry` uses to authorize a landed entry by its kind. | `tests::kind_required_roles_match_the_matrix` |
| **ROLES-3** | Roles are power-descending and totally ordered: `Owner` < `Co-owner` < `Maintainer` < `Editor` < `Viewer`. | The `member_role <= required` gate used by every caller only works if "weaker" always means "numerically greater." | `tests::roles_are_power_descending` |

Run: `node scripts/cargo.mjs test -p openom-roles` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use openom_roles::{Access, required_role_for_kind, ROLE_EDITOR, ROLE_MAINTAINER};
use openom_protocol::v1::Kind;

// Capability check — e.g. the server's ACL gate for a commit request:
let member_role = ROLE_EDITOR;
let allowed = member_role <= Access::Commit.min_role();
assert!(!allowed); // Editor can't Commit — that needs Maintainer+.

// Kind check — e.g. the client's landed-entry verification:
assert_eq!(required_role_for_kind(Kind::Delta), Some(ROLE_MAINTAINER));
assert_eq!(required_role_for_kind(Kind::Proposal), Some(ROLE_EDITOR));
assert_eq!(required_role_for_kind(Kind::Unspecified), None);
```

Entry points: the `Access` enum + `Access::min_role`, `required_role_for_kind`, and the `ROLE_*`
constants (`ROLE_OWNER`, `ROLE_CO_OWNER`, `ROLE_MAINTAINER`, `ROLE_EDITOR`, `ROLE_VIEWER`).

## Position

Sits on `openom-protocol` (for the `MemberRole` / `Kind` vocabulary) and nothing else; the server's
`openom::authz` (which re-exports `Access`) and the client's `openom-vault` (`attribution::verify_entry`,
via `required_role_for_kind`) both sit on top of it. Full dependency graph: see `packages/README.md`.
