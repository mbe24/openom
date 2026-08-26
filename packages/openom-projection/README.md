# openom-projection

> The read-time projection: a pure function from the claim record set to the materialized read model.

**Status:** built · read model — the claim-model direction, in active flux · design.data-model-claims.v1.md §11
**Last updated:** 2026-08-25

## What it is — and is not

The claim store is a grow-only set of records that different authors append concurrently and that sync
in any order. It carries no resolved truth — two authors may say person A and person B are the same
while a third says they are different. This crate turns that set into a materialized read model
(people, relationships, events, family unions, sources, places, media) **deterministically**: it is a
**pure function of the record set**, so every replica computes the same answer from the same records
without a shared clock. Write-time invariants that cannot hold in a concurrent append-only store become
read-time guarantees (the move keyeo's StrongRemove resolver makes). It does the *epistemic* work:
identity clustering (`same_as` / `different_from` via constraint-repair union-find), attestation-weighted
confidence, `reattribute_to`, `preferred`, name equivalence, and the assembly of relationships / events /
unions / places / sources / media over the canonical persons.

It is **not** the operations or transport layer. Deleting a record and editing (superseding) a value
are **operations in a separate channel — not claims and not the projection's job** (design
§8.2 / principle 6); the projection consumes the **live claim set** and resolves *disagreement between
authors*, never the *lifecycle* of a record. It is also **not** the write path, and it is **not yet
wasm-bound** (the in-wasm claim engine is a separate task); it depends on no operations/CRDT crate.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **PROJ-1** | Pure & order-independent: the projection depends only on the *set* of records — not delivery order, not duplication. | This is the convergence guarantee — replicas agree without a shared clock. | `tests::order_independent`, `tests::duplication_invariant` |
| **PROJ-2** | Constraint-repair: an above-threshold `different_from` is never violated — a `same_as` chain never unions two anchors cut directly or transitively by it; the skipped bridge surfaces as a conflict. | Entity-level refutation memory: "these are NOT the same" wins over a weaker merge, deterministically. | `tests::different_from_never_violated`, `tests::different_from_cuts_the_merge`, `tests::different_from_cuts_transitively` |
| **PROJ-3** | Attestation-weighted: merges / cuts / reattributions are gated by `distinct authors + independent support − rejects`; `reject`s un-merge, a refuted `different_from` stops cutting, and self-support is inadmissible. | Confidence is derived from the social graph, and a claim can never grade its own homework. | `tests::reject_attestations_unmerge`, `tests::support_attestations_boost_confidence`, `tests::refuted_different_from_does_not_cut`, `tests::self_support_is_inadmissible`, `tests::attestation_by_fingerprint_counts` |
| **PROJ-4** | Canonicalization: each cluster resolves to its minimum *anchor* id, and every fact (names, sex, relationships, events, media, citations) re-targets to it across merges; a cluster with no anchor is dropped. | One real person = one stable id, and no fact is orphaned or a non-anchor becomes canonical. | `tests::merges_two_anchors_by_same_as`, `tests::relationships_canonicalize_across_a_merge`, `tests::event_participants_canonicalize`, `tests::people_are_wellformed` |
| **PROJ-5** | `reattribute_to`: a net-positive re-home moves a claim's subject to a new anchor *before* grouping; refuted or competing re-homes resolve by score. | The dual of merge — splitting a conflated anchor — without losing the claim's author/citation/attestations. | `tests::reattribute_rehomes_a_name_and_sex`, `tests::refuted_reattribute_does_not_apply`, `tests::competing_reattribute_resolves_by_score` |
| **PROJ-6** | `preferred`: the highest-scored net-positive `preferred` whose referent resolves marks the canonical name; absent or refuted → no selection. | Which name is canonical is itself a disputable, attestable choice. | `tests::preferred_selects_a_name`, `tests::preferred_resolves_to_the_canonical_person_after_a_merge`, `tests::preferred_ignored_when_absent_or_refuted` |
| **PROJ-7** | Name equivalence: names joined (directly or transitively) by `equivalent_to` share one equivalence class. | Different renderings of one name (script/culture variants) dedup without being merged away. | `tests::equivalent_names_share_a_class` |
| **PROJ-8** | Relationships & unions: parent / partnership edges hold only between canonical persons (dangling, self-loop, and refuted edges dropped); children group by canonical parent-set into an addressable union, and a marriage event attaches. | Full-vs-half siblings fall out of the parent-set grouping, and the GUI gets a stable "family" object. | `tests::parent_child_edge`, `tests::partnership_edge`, `tests::refuted_relationship_is_dropped`, `tests::union_groups_children_and_attaches_marriage`, `tests::half_siblings_are_separate_unions`, `tests::childless_partnership_is_a_union` |
| **PROJ-9** | Events & places: each Event anchor assembles into a hyper-edge (type / EDTF date bounds / place / participants), and its place renders the `place_name` whose `validRange` covers the event date (falling back to the most-corroborated name). | An 1845 birth reads "Königsberg"; today's map, "Kaliningrad" — same point, time-appropriate name. | `tests::birth_event_assembles`, `tests::event_place_renders_time_bounded_name`, `tests::event_place_falls_back_when_no_range_covers` |
| **PROJ-10** | Value resolution: sex / biography / custom fields resolve by most-corroborated (distinct authors); a person's sources are its claims' citations resolved to their `core/source/v1` description (an unresolved `sourceId` still surfaces); media links attach to the canonical person, each with the blob's `media_hash` broken out and the rest of the shape as an open value map (mime/size/role/caption/crop/coverage as they apply), with `role == "portrait"` as the portrait selection. | The detail panel shows resolved values and their evidence, degrading gracefully rather than dropping data. | `tests::sex_resolves_by_author_majority`, `tests::biography_resolves`, `tests::custom_fields_resolve_via_definition`, `tests::custom_value_without_definition_degrades`, `tests::sources_resolve_from_citations`, `tests::citation_with_unresolved_source_still_surfaces`, `tests::media_links_attach_to_person`, `tests::media_link_carries_the_full_shape` |

Run: `node scripts/cargo.mjs test -p openom-projection` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use openom_claim::envelope::{Claim, Record};
use openom_projection::{project, Policy};
use serde_json::json;

// Anchor ids are opaque (a Person/Event/Place UUID) — `Record::try_from` doesn't hash-verify them, only
// a Claim's content-hash id.
let pa = Record::try_from(json!({
    "id": "pA", "type": "openom.org/core/person/v1", "createdAt": 1, "createdBy": "did:key:z6MkA"
}))
.unwrap();
let pb = Record::try_from(json!({
    "id": "pB", "type": "openom.org/core/person/v1", "createdAt": 1, "createdBy": "did:key:z6MkA"
}))
.unwrap();

// One author asserts the two anchors are the same person; a Claim's id is content-derived, so it's
// computed rather than made up.
let mut same_as = Claim::new(
    "pA",
    "openom.org/core/same_as/v1",
    json!({ "pair": ["pA", "pB"] }),
    "did:key:z6MkA",
    1,
);
same_as.compute_id().unwrap();

let records = vec![pa, pb, Record::Claim(same_as)];

let view = project(&records, &Policy::default());
assert_eq!(view.people.len(), 1);       // pA + pB resolved to one person
assert_eq!(view.people[0].id, "pA");    // canonical = the minimum anchor id
assert!(view.conflicts.is_empty());
```

Entry point: `project(records: &[Record], policy: &Policy) -> Projection`, where `Record` (from
`openom-claim`) is either a pure-identity `Anchor` or a `Claim`. `Policy` carries the per-relation score
thresholds; `Projection` exposes `people`, `parent_child`, `partnerships`, `unions`, `events`, and
`conflicts`.

## Position

Sits in the family-tree data-model layer, on top of `openom-claim` (whose records it reads and whose
`fingerprint` it recomputes via `openom-jcs` to match attestations) and `openom-edtf` (event/place date
bounds). It depends on **no** operations, CRDT, or transport crate — it is a pure read model. Not yet
wired into the app (the in-wasm claim engine that will host it is a separate task). Full dependency
graph: see `packages/README.md`.
