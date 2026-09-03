# keyeo

> A generic, domain-free engine for decentralised group membership and access control — a
> sequencer-free DAG of signed ops that resolves to a converged member set + shared keys.

**Status:** built · Layer-0 generic engine, standalone-publishable · design keyring-dag (OPE-137/269)
**Last updated:** 2026-09-03

## What it is — and is not

Feed [`Keyeo`] a stream of signed [`Op`]s — add / remove / promote a member, rotate a key — and it
resolves the causal DAG into a converged [`GroupState`]: who is a member, at what role, and the current
shared encryption epoch. It is **sequencer-free**: ops carry their causal parents, concurrency is
tie-broken deterministically ([`LamportTiebreak`]), and conflicting removals are settled by a
strong-remove resolver ([`StrongRemove`]) so a member removed on one branch stays removed after a merge.
Authority is pluggable via [`AccessControl`], multi-party governance via a [`QuorumPolicy`]. Keys ride
along: each membership change can mint a fresh [`Epoch`] whose DEK is HPKE-wrapped to every current
member, and concurrent epochs **reconcile to a single shared DEK** rather than forking. Recovery,
content-addressing ([`content_id`]), and history GC ([`compact`]) round it out.

It is **not** openom, and knows nothing about family trees, protobuf, roles-as-`MemberRole`, or the
sealer. It is generic over the op id, member id, **role**, and signature-scheme types — the openom
bindings (the concrete role model, the Ed25519 seam, the authority + quorum policy) all live one layer up
in `keyeo-dag`. It owns **no storage** and assigns no total order: it consumes ops and produces resolved
state; persistence and transport are the caller's (a `blobstore` above it). It has no openom dependency
and is publishable on its own.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **KEYEO-1** | An op whose author lacks authority never changes the resolved membership. | Access control is enforced at resolution, so an unauthorized signed op is inert, not merely flagged. | `tests::an_unauthorized_op_never_changes_resolved_membership` |
| **KEYEO-2** | Resolution is order-independent: the same op set in any delivery order resolves to the same state. | Sequencer-free convergence — replicas that receive ops in different orders agree. | `tests::resolution_is_order_independent`, `epoch::tests::commitment_is_order_independent` |
| **KEYEO-3** | A content id verifies its bytes and detects any tamper. | Ops are content-addressed; a mutated op is caught, not silently accepted into the DAG. | `content::tests::content_id_verifies_and_detects_tampering` |
| **KEYEO-4** | Concurrent epochs reconcile to a single shared DEK, and a fresh epoch's DEK round-trips for every current member. | Two members re-keying at once must not fork the group's encryption; everyone lands on one key. | `epoch::tests::concurrent_epochs_reconcile_to_a_single_shared_dek`, `epoch::tests::fresh_epoch_round_trips_for_its_members` |
| **KEYEO-5** | Quorum governance is exact: `All` is unanimity (and the empty set is not a quorum); `EitherFounderOr` accepts the founder alone or the configured set. | Multi-party authority can't be met by an off-by-one or an empty roster. | `quorum::tests::all_is_unanimity_and_the_empty_set_is_not`, `quorum::tests::either_is_founder_or_unanimity` |

Run: `node scripts/cargo.mjs test -p keyeo` (from the repo root; on Windows cargo runs under WSL2/Docker).

## Usage

```rust,ignore
use keyeo::{Keyeo, StrongRemove};

// state: GroupState, access: impl AccessControl, resolver: StrongRemove — all caller-chosen type params.
let mut k = Keyeo::new(state, access, resolver);
let outcome = k.apply(signed_op)?;   // ApplyOutcome: the resolved membership + any epoch event
```

Entry points: `Keyeo` (`new` / `apply` → `ApplyOutcome`), `GroupState` / `MembershipAction` /
`MemberInit` / `SignedOp`, the `AccessControl` and `QuorumPolicy` traits, the epoch API
(`generate_epoch` / `reconcile_epochs` / `recover_epoch_dek` / `membership_commitment`), `content_id`,
and `compact` (history GC).

## Position

Layer 0 — the generic base of the keyring stack, depended on only by `keyeo-dag` (the openom binding). It
depends on `edsign` + `keyeo-crypto` (its HPKE / AEAD / KDF primitives — `keyeo` no longer carries its own
`kdf`/`hpke_wrap`) but no openom crate, so nothing openom sits beneath it. Full dependency graph: see `packages/README.md`.
