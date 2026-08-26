# openom-crdt

> The claim model's convergent operation layer — a CRDT: the operation types + their set-union merge
> (`materialize`) that folds a set of ops into the live record set. Not a log (it owns no storage).

**Status:** built · convergent op layer (a CRDT) — the claim-model direction, in active flux · design.data-model-claims.v1.md §8.2
**Last updated:** 2026-08-26

## What it is — and is not

The **data** channel (`openom-claim` / `openom-projection`) carries *facts* — a grow-only set of
records whose *disagreements* the projection resolves. This crate carries the orthogonal thing: the
*lifecycle* of those records. "Every change is an operation" (design §8.2) — a record is **added**,
**deleted**, **edited** (superseded), or a delete is **undone** (revoked). Those operations form their
own grow-only set that converges by **set-union**: two replicas that have seen the same operations
compute the same live record set, with no shared clock. `materialize` is the fold — `{ChannelItem} →
live records` — and its output is the **snapshot** the projection reads.

It is a **CRDT, not a log**: it holds the operation *types* and their *merge* (`materialize`), but owns
no storage and appends nothing — the durable log lives in `journal`, and the decoded in-memory op set
in `openom-sync` / `openom-tree` (each rebuilt by replaying the journal). It is **domain-agnostic**: it
folds opaque records by id and tracks their liveness; it never interprets what a claim *means* (that is
`openom-projection`). It holds **no** transport concern — the
`(replica_id, replica_counter)` idempotency dot rides the journal entry that *wraps* an item, never
inside the content-addressed `Op` (a dot in the hash would make the same logical op hash differently
per device and defeat dedup). And the projection depends on **no** operations crate, so the two
channels stay structurally separate: nothing in the read model can name an `Op`.

It is the claim-model replacement for `commute`'s **merge**, minus the Lamport ordering — convergence
is by set-union — and the domain composition `openom-treelog` used to bundle now lives in
`openom-claim` (the record types) and `openom-projection` (the epistemic read model).

## Shape

`ChannelItem` is either an **`Assert`** — which *is* the bare `Record` (an add needs no envelope
beyond the record's own id / author / timestamp) — or an **`Op`**, the envelope for the operations that
have no record to be:

| kind | operand | meaning |
|------|---------|---------|
| `Remove`    | a **record** id | remove your own record (same-author, observed-remove) |
| `Supersede` | a **record** id + a replacement `Record` | edit: atomically remove `prior` and assert `replacement`, carrying an edit-lineage edge |
| `Revoke`    | an **operation** id (of a `Remove`) | undo your own remove, restoring the *original* record id |

Folding `Assert` as the bare record avoids a second author/timestamp on ~99% of the stream and closes
the attribution-forgery gap a duplicate envelope would open.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **CRDT-1** | Convergent: the fold depends only on the *set* of items — not delivery order, not duplication. | Replicas agree without a shared clock — the whole point of set-union. | `tests::materialize_is_order_independent`, `tests::duplicate_items_are_idempotent` |
| **CRDT-2** | Same-author observed-remove: a `Remove` / `Supersede` / `Revoke` is honored only when its author matches the target record's (or op's) author; an op naming an unknown or other-author target is a deterministic no-op everywhere. | Censorship resistance — you can remove only your own record — as a pure fold, defense-in-depth below the transport authorization. | `tests::same_author_remove_drops_the_record`, `tests::other_author_remove_is_a_noop`, `tests::remove_of_an_unknown_target_is_a_noop`, `tests::other_author_supersede_neither_removes_nor_injects`, `tests::other_author_revoke_does_not_restore` |
| **CRDT-3** | Supersede: atomically removes `prior` and asserts `replacement`; a chain keeps only the last; two concurrent same-author supersedes of one prior fork into two live records (documented, not LWW); a replacement attributed to another author is dropped, not injected. | Edits converge deterministically; a forged replacement can't manufacture a corroborating author. | `tests::same_author_supersede_replaces_the_record`, `tests::supersede_chain_keeps_only_the_last`, `tests::concurrent_supersede_of_one_prior_forks_into_two_live`, `tests::other_author_supersede_neither_removes_nor_injects` |
| **CRDT-4** | Revoke: a same-author `Revoke` of a `Remove` restores the *original* record id (non-monotone liveness, still order-independent), so attestations/citations bound to it survive the undo; revoking an unknown or non-remove op is ignored. | Undo-of-remove without minting a new id (which a re-assert would, orphaning bound facts). | `tests::same_author_revoke_restores_a_removed_record`, `tests::revoke_of_an_unknown_or_non_remove_op_is_ignored` |
| **CRDT-5** | Content-addressed & id-verified: an `Op`'s id is `sha256(JCS(envelope − id − signature − embedded-record-signature))`; ingest (`TryFrom` / deserialize) rejects a stated id that doesn't match and a forged embedded replacement id; signing the replacement never shifts the op id. | One hashing path (shared `ContentAddressed` seam), and there is no id-skipping ingest door. | `tests::op_id_is_stable_when_the_embedded_replacement_is_signed`, `tests::a_tampered_op_id_fails_ingest`, `tests::an_op_with_a_forged_embedded_replacement_id_fails_ingest`, `tests::op_roundtrips_through_serde_and_verifies_its_id`, `tests::channel_item_dispatches_on_type` |
| **CRDT-6** | Forward-compatible / vocabulary-agnostic: a record of a `type` this build doesn't recognize is preserved verbatim (never dropped, never batch-poisoning) and folds by id/author exactly like a known one; the fold decision is invariant under any claim `predicate`/`value`. `type` and `predicate`/`value` are opaque **shape**, never interpreted **vocabulary**. | A newer app version's data type flows through an older client untouched instead of halting sync; closed-world validation lives in schema + projection, not this transport (OPE-212a). | `tests::a_novel_type_is_preserved_through_the_fold`, `tests::an_unknown_record_obeys_the_same_ops_as_any_record`, `tests::a_batch_with_novel_items_round_trips_through_the_codec_untouched`, `tests::the_fold_ignores_predicate_and_value` |

Run: `node scripts/cargo.mjs test -p openom-crdt` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use openom_claim::envelope::{Claim, Record};
use openom_crdt::{materialize, ChannelItem, Op, OpKind};

let author = "did:key:z6MkA";

// Add a name claim (an add IS the record).
let mut name = Claim::new("pA", "openom.org/core/name/v1", serde_json::json!({ "given": "Ada" }), author, 1);
name.compute_id().unwrap();
let name = Record::Claim(name);

// Later, the same author edits it (supersede: remove prior + assert replacement, atomically).
let mut better = Claim::new("pA", "openom.org/core/name/v1", serde_json::json!({ "given": "Ada Lovelace" }), author, 2);
better.compute_id().unwrap();
let better_id = better.id.clone();
let edit = Op::new(2, author, OpKind::Supersede {
    prior: name.id().to_owned(),
    replacement: Box::new(Record::Claim(better)),
}).unwrap();

let live = materialize(&[ChannelItem::Assert(name), ChannelItem::Op(edit)]);
assert_eq!(live.len(), 1);
assert_eq!(live[0].id(), better_id); // the edited record won; the prior is gone
```

Entry points: `materialize(items: &[ChannelItem]) -> Vec<Record>` (the fold that produces the
snapshot); `ChannelItem` / `Op` / `OpKind` (the operation types); `ContentAddressed` (re-used from
`openom-claim`) for the op id.

## Deferred (tracked elsewhere, deliberately not here)

- **Op signing.** `Op::signature` and `SIGN_DOMAIN` (`openom-op-v1`, distinct from the claim domain)
  are reserved; signing/verifying ops (only relevant to `signed_claims` trees — unsigned trees
  authenticate at the transport layer) is a follow-on. The fold trusts transport-validated `createdBy`.
- **Orphan byte-sweep at compaction** — the projection already hides claims whose anchor was removed
  (the read-time cascade); reclaiming their *bytes* (the never-delete ↔ tree-byte-metering question)
  is a compaction mark-sweep, deferred to **OPE-176 / OPE-179**. The deletion *policy* itself is settled
  (OPE-192): same-author-or-approval, no privileged cross-author redaction, no operator GDPR — the
  server is zero-knowledge, and export + set-union re-import make deletion advisory, not enforced.
- **Proposal disposition** — an Editor's write is a *pending* proposal; a content-addressed op can't be
  mutated to "approved", so accept/reject lives in a separate record referencing the op id (as an
  attestation references a claim), **OPE-163**.
- **Pending-until-resolvable / GC-horizon drop** of ops whose target hasn't arrived or was compacted
  away, and the byte-preserving compaction fold + `covers_through_seq`: part of **OPE-176**.

## Position

Sits in the family-tree operations layer, on top of `openom-claim` (whose `Record` it folds and whose
`ContentAddressed` seam it re-uses for the op id). It depends on **no** transport, CRDT, or projection
crate. Not yet wired into the app (the in-wasm claim engine that will host the fold, and the transport
`EntryKind` that wraps each item with the idempotency dot, are separate tasks). Full dependency graph:
see `packages/README.md`.
