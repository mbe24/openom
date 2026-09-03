# openom-keyring-api

> The engine-agnostic vocabulary for openom's two swappable keyring engines — the resolved
> `MembershipView`, the keyless `KeyringVerifier` seam, and the `EngineKind` tag.

**Status:** built · seam / shared value types · design keyring-dag/design.swap-seam-decision.md (OPE-276)
**Last updated:** 2026-09-03

## What it is — and is not

openom runs **two** permanent keyring engines — the linear signed **chain** (`openom-keyring-chain`) and the
**DAG** (`openom-keyring-dag`) — and this crate is the small shared vocabulary both fold into so the rest of the
system binds to neither. It holds three engine-agnostic pieces: [`MembershipView`] (the resolved members
+ roles, the value the app's role display and the server's ACL derivation both consume), the keyless
[`KeyringVerifier`] seam (admit an update against prior opaque trust state, report the new state + view +
whether it changed — all the server binds to), and [`EngineKind`] (the immutable per-tree engine tag every
host boundary parses through, so the `"chain"`/`"dag"` strings can't drift).

It is deliberately **not** one `KeyringEngine` trait, and **not** the secret-holding client lifecycle
(provision / unlock / recover / author) — that returns sealer + DEK material and lives in `openom-vault`,
away from the server's keyless binding surface. It runs **no** crypto and holds **no** engine internals:
the trust `state` is opaque bytes it never parses, and the anti-rollback floor lives *inside* those bytes,
never as a field here. It is dependency-light — it defines its own `i16` role convention rather than depending
on `openom-roles` — but openom-domain-specific: the `EngineKind` roster and the `ROLE_*` values are openom's.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **KAPI-1** | `MembershipView::new` sorts members by `member_id`, so two engines resolving the same membership produce a byte-identical view. | The view is the cross-engine contract; order-independence is what makes it one. | `tests::view_sorts_members_for_a_deterministic_engine_independent_shape` |
| **KAPI-2** | Role classification is single-axis, lower-is-stronger: a signer is `ROLE_CO_OWNER`-or-stronger, the owner is the unique `ROLE_OWNER`. | Both engines and the server derive write-authority the same way. | `tests::signer_and_owner_classification_matches_the_role_axis` |
| **KAPI-3** | `EngineKind` round-trips through its tag and an unknown tag is a typed `UnknownEngine`, never a silent fallback. | The one string both host boundaries parse; a typo must fail loud, not pick a default engine. | `tests::engine_tag_round_trips_and_rejects_the_unknown` |
| **KAPI-4** | `MembershipView` round-trips through serde unchanged. | The app and server exchange the resolved view as data across process boundaries. | `tests::membership_view_round_trips_through_serde` |

The `ROLE_*` constants (`ROLE_OWNER=1 … ROLE_VIEWER=5`) are pinned to openom's proto `MemberRole` values
by `openom-roles`'s drift-guard test (`tests::keyeo_api_role_convention_matches_openom_roles`) — that
binding is asserted there, not here, so this crate keeps no openom dependency. Run: `node scripts/cargo.mjs test -p openom-keyring-api` (from the repo root).

## Usage

```rust
use openom_keyring_api::{MembershipView, MemberView, EngineKind, ROLE_OWNER, ROLE_EDITOR};

let view = MembershipView::new(
    vec![
        MemberView { member_id: "owner".into(), role: ROLE_OWNER, author_public_key: vec![], hpke_public_key: vec![] },
        MemberView { member_id: "bob".into(),   role: ROLE_EDITOR, author_public_key: vec![], hpke_public_key: vec![] },
    ],
    false, // reset_boundary
);
assert_eq!(view.owner().unwrap().member_id, "owner");
assert_eq!(view.signers().count(), 1); // only the owner; an Editor is not a signer

assert_eq!("dag".parse::<EngineKind>().unwrap().as_tag(), "dag");
```

Entry points: `MembershipView` (`new` / `signers` / `owner`), `MemberView` (`is_signer` / `is_owner`),
the `KeyringVerifier` trait (`admit` → `Admitted` | `VerifyError`), `EngineKind`, and the `ROLE_*`
constants.

## Position

Layer 1 — the seam. It sits above the two engines and below their consumers: `openom-keyring-dag` and
`openom-keyring-chain` fold into its `MembershipView`, and the server + `openom-vault` bind to it. It depends
only on `serde` + `prost`; the generic Layer-0 engines are `keyeo-dag` (DAG) and `keyeo-linear` (chain). Full dependency graph: see `packages/README.md`.
