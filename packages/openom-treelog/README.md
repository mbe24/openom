# openom-treelog

> The family-tree domain layer — sourced-claim facts and relationships composed over the `commute` op-based CRDT.

**Status:** built · **legacy** — the current shipping engine, being replaced by the claim model
(`openom-claim` / `openom-projection`); frozen scope, no new work · packages/README.md "in flight" note
**Last updated:** 2026-08-25

## What it is — and is not

`commute` provides typed convergent *cells* (LWW registers, tombstoned OR-sets) and self-contained ops;
this crate maps the genealogy model onto them. The design choice that matters most: a fact (a birth
date, a name) is NOT an overwritable scalar. Two relatives who record different dates must both be
*kept* as competing **sourced claims** for a human to adjudicate — silent last-writer-wins is
genealogically wrong. So a fact is an OR-set of `Claim`s plus an LWW register holding the *preferred*
pointer. Persons, families, and relationships (child/spouse links) are OR-sets of ids; sub-entities
(names, events, sources, media records/links) hang off any `SubjectId` through the same fact channel.
On top sits a propose/review/commit flow: a `Proposal` is a self-contained op bundle an editor drafts
against a base version; `Tree::review` flags facts that moved concurrently so the approver can
adjudicate, and committing never silently drops a competing claim. The crate ships as a pure-Rust core
(native, used directly by Tauri) plus a `wasm-bindgen` veneer (`WasmTree`) for the web app — one merge
implementation, two bindings.

It is **not** the direction of the app: this is the **current engine, being replaced by the claim
model**. `openom-claim` / `openom-projection` are where new family-tree data-model work happens; this
crate (and `commute` / `commute-format` beneath it) is expected to shrink and eventually retire as the
swap lands — see the "in flight" note in `packages/README.md`. It does no crypto and no I/O: claim
payloads and media/proposal bytes are opaque blobs it encodes/decodes but never inspects for meaning
beyond their own wire format. It does not decide *which* fact should be preferred for display beyond
the deterministic fallback (e.g. a "prefer a birth-type name" policy is a read-adapter concern above
this crate). It does not own transport or sync mechanics (`journal`, `openom-sync` do that) — `Tree`
only produces/consumes `commute::Op`s and delta/snapshot bytes.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **TREELOG-1** | A fact is an OR-set of claims: two concurrent, differing claims on the same field both survive — never last-writer-wins. | Genealogical corroboration/conflict must never be silently clobbered. | `tests::competing_claims_both_survive` |
| **TREELOG-2** | Preferred-claim resolution: the explicit register pointer wins if it still names a live claim, else the deterministic fallback (greatest claim id) — identical on every replica. | Every replica renders the same "preferred" value with no coordination. | `tests::preferred_pointer_selects_a_claim_and_falls_back_when_unset` |
| **TREELOG-3** | Removing a person wins over a concurrent edit to that person (they leave the roster), but the edit itself is never destroyed — it survives as an orphaned claim. | A concurrent contributor's work is never silently erased by someone else's delete. | `tests::delete_wins_but_the_concurrent_edit_is_not_lost` |
| **TREELOG-4** | A detached media link never resurrects on a stale re-delivery (OR-set tombstone semantics), even alongside another live link to the same record. | Late/duplicate delta delivery must not undo a user's detach action. | `tests::media_links_attach_detach_without_resurrection` |
| **TREELOG-5** | `MoveChild` re-parents atomically (unlink-then-link as one action), and converges cleanly with a concurrent edit to the moved child. | A re-parent is one user action; it must not be observable as a half-applied state, nor block unrelated concurrent edits. | `tests::move_child_reparents_and_survives_a_concurrent_edit` |
| **TREELOG-6** | Facts address by an opaque `SubjectId` — a person, a family, or any sub-entity — through the identical claim/preferred channel. | Family-level facts (marriage date/place) and sub-entity leaf facts (name parts, event date) need no separate machinery. | `tests::facts_attach_to_a_family_subject_not_just_persons` |
| **TREELOG-7** | A claim payload carries a layout-version byte; an unrecognized version surfaces as an opaque-but-present claim, never a silent drop. | A future claim-leaf format can land without desyncing older builds' read models. | `tests::claim_payload_is_versioned_and_unknown_versions_surface` |
| **TREELOG-8** | `Tree::review` is read-only and flags a fact the proposal touches that also moved since its `base`; committing anyway still retains every competing claim. | The approver sees "this changed underneath you" without the engine ever forcing a silent overwrite. | `tests::a_stale_proposal_on_a_moved_fact_is_flagged_and_keeps_both`, `tests::propose_review_commit_happy_path` |
| **TREELOG-9** | `Proposal::encode`/`decode` round-trips the entire op vocabulary and never panics on truncated or adversarial bytes. | A proposal is sealed and synced as bytes; a corrupt or hostile bundle must fail closed, not crash the app. | `tests::proposal_round_trips_the_whole_vocabulary`, `tests::proposal_decode_never_panics_on_junk`, `tests::proposal_decode_on_arbitrary_bytes_never_panics` |
| **TREELOG-10** | The `commute` snapshot byte encoding for a fixed script is pinned by a golden vector, asserted identically in the wasm build. | Native and wasm builds must serialize byte-for-byte identically, or synced data forks silently across platforms. | `tests::treelog_snapshot_golden_vector` |
| **TREELOG-11** | Arbitrary concurrent op sequences across replicas converge to the same snapshot regardless of merge order. | The whole domain vocabulary — not just `commute`'s primitives — must inherit convergence, replayed in any delivery order. | `tests::trees_converge_through_the_op_vocabulary` |

Run: `node scripts/cargo.mjs test -p openom-treelog` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use openom_treelog::{Tree, TreeOp};

let mut t = Tree::new([1u8; 16]); // a 16-byte replica id
t.apply(TreeOp::AddPerson { id: vec![1] });
t.apply(TreeOp::AddClaim {
    subject: vec![1],
    field: "birth.date".into(),
    claim: vec![0xC1],
    value: "1901".into(),
    source: Some("gravestone".into()),
});
t.apply(TreeOp::AddClaim {
    subject: vec![1],
    field: "birth.date".into(),
    claim: vec![0xC2],
    value: "1903".into(),
    source: Some("parish record".into()),
});

// Both sourced claims survive; the unset preferred pointer falls back to the greatest claim id.
let fact = t.fact(&[1], "birth.date");
assert_eq!(fact.claims.len(), 2, "both competing claims retained");
assert_eq!(fact.preferred.unwrap().value, "1903");
```

Entry points: `Tree::new` / `Tree::from_snapshot`, `Tree::apply` / `apply_batch` (edits, returning the
`commute::Op`s to seal + sync), `Tree::fact` / `persons` / `families` / `children_of` / `spouses_of` /
`names_of` / `events_of` / `sources` / `cites_of` / `media_of` (reads), and the `Proposal` /
`Tree::review` / `Tree::commit_proposal` approval flow. `Tree::doc()` / `doc_mut()` expose the
underlying `commute::Doc` for sync (`snapshot` / `delta_since` / `merge_bytes` / `version`).

The web app never touches `Tree` directly: with `--features wasm`, `wasm.rs` exports `WasmTree` — a
`wasm-bindgen` veneer with the same edit/read surface (`addPerson`, `addClaim`, `moveChild`,
`mergeBytes`, `snapshot`, `fact`, …), ids and op bytes marshalled as `Uint8Array`, and the nested read
model (facts, children, media links, …) as JSON strings for the caller to parse. Tauri (native) uses
`Tree` directly, so the merge logic is identical on both platforms — the golden vector above is the
byte-parity check between them.

## Position

Sits directly on `commute` (the CRDT primitives) and is used by the app today — via the `WasmTree`
veneer on the web and directly from Tauri natively — but it is the **legacy** path: the claim model
(`openom-claim` / `openom-projection`, plus a separate operations channel) is its designated
replacement, and this crate is expected to shrink as that swap lands. Full dependency graph: see
`packages/README.md`.
