# openom-model

> The older canonical, flat, id-keyed family-tree model — nodes/edges/events/sources/media/custom
> fields, opaque ids, JCS-equivalent canonicalization, a Draft 2020-12 schema validator.

**Status:** deprecated · legacy flat model, no dependents in the workspace · superseded by the claim
model (design.data-model.md → design.data-model-claims.v1.md)

**Last updated:** 2026-08-25

## What it is — and is not

A flat, tabular representation of a family tree: `Node` (person/family), `Edge` (relationship),
`Event`, `Source`, `Media`, `FieldDef`/`FieldValue` (custom fields), each keyed by an **opaque,
random, CSPRNG-generated id** that is never content- or path-derived — correcting a fact's value
never changes its id or breaks an edge pointing at it (see [`id`]). A family tree is a DAG, not a
tree (a person has two parents), so relationships are edges, not nesting. The crate also owns
JCS-equivalent canonicalization, a per-entity content hash (the attestation-binding value), and,
behind the `validation` feature, a JSON Schema (Draft 2020-12) validator for the serialized shape.
The embedded name model (`name`, composition + equivalence) lives here too, carried over unchanged
because it does not depend on which model owns the surrounding node/edge tables.

It is **not** the direction of travel. The canonical family-tree model going forward is the
**claim model** (`openom-claim` + `openom-projection`): facts and epistemic assertions as a flat
claim set, not this crate's node/edge tables. Nothing in the workspace depends on `openom-model` —
it is not wired into any app or crate today — and the repo is pre-release with zero users, so there
is no migration cost to retiring it once the claim model lands. Do not build new work against this
crate; treat it as read-only history until it is deleted. It also does no I/O and no signing: the
`content_hash` here is a per-entity content-hash for attestation binding, not the claim model's
id/fingerprint scheme (that lives in `openom-jcs` + `openom-claim`).

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **MODEL-1** | Ids are opaque, random, and stable — never content- or path-derived. Correcting a fact's value never changes its id or breaks an edge referencing it. | The whole point of non-derived ids: facts are mutable, identity is not. | `tests::edit_preserves_id_and_edges`, `id::tests::os_ids_are_distinct` |
| **MODEL-2** | Ids are always well-formed UUIDv4; the CSPRNG source (`OsIdSource`) is used in dev *and* prod, and only tests may inject the deterministic `SeededIdSource`. | Entropy is a security property, not a dev/prod toggle — a low-entropy id would make facts guessable. | `id::tests::seeded_is_deterministic_and_wellformed` |
| **MODEL-3** | An id type serializes as a bare UUID string (`#[serde(transparent)]`), not a wrapped object. | Keeps the wire shape stable and matches the schema's `format: uuid` fields. | `id::tests::ids_serialize_as_bare_uuid_string` |
| **MODEL-4** | An edge cannot self-loop and cannot reference a node absent from the model. | Rejects a structurally impossible tree ("is its own parent") at construction time. | `tests::edge_validation` |
| **MODEL-5** | A serialize → deserialize round-trip preserves every id and the whole structure byte-for-byte-equivalent. | Stands in for compaction/snapshot folding: ids and edges must survive it unchanged. | `tests::round_trip_preserves_ids_and_structure` |
| **MODEL-6** | Canonicalization is deterministic and stable across a reparse; object keys emit in sorted order. | The same materialized state always produces identical canonical bytes. | `tests::canonicalize_is_deterministic_and_sorted` |
| **MODEL-7** | The per-entity content hash binds to that entity's own fields, not the tree: editing another fact leaves it unchanged, editing this fact changes it, and it is deterministic across a reparse. | An attestation binds to a fact's value; editing the fact must read as "attested an earlier value," never silently invalidate unrelated attestations. | `tests::content_hash_binds_to_the_fact_not_the_tree`, `tests::content_hash_is_deterministic_and_high_entropy` |
| **MODEL-8** | The reserved seams (`Node::scope`, `CrossTreeLink`, `MergeClass`) round-trip through JSON today with no behavior attached. | Federation, subtree-scoping, and text-merge can be added later without a schema break. | `tests::reserved_seams_scope_link_merge` |
| **MODEL-9** | The embedded name model's two relations are independent: composition (`borrows_from`) is directional, transitive, and acyclic (the only input to `effective_parts`); equivalence (`equivalent_to`) is symmetric and class-forming. `validate` rejects a self-equivalent edge, an unresolvable/cyclic composition chain, and a `provenance` set without an `equivalent_to` edge. | A name can borrow a surname *and* be a script rendering of another name at the same time — conflating the two axes would corrupt either display or dedup. | `name::tests::composition_and_equivalence_combine`, `name::tests::validate_rejects_bad_equivalence_and_provenance` |
| **MODEL-10** | Under the `validation` feature, a real serialized `Model` (including an embedded name) satisfies the Draft 2020-12 schema; a structurally broken one (missing tables, an illegal enum value) does not. | The schema is the cross-language contract for anything that reads or writes this model's JSON. | `schema::tests::real_model_satisfies_schema_and_junk_does_not` |

Run: `node scripts/cargo.mjs test -p openom-model` (from the repo root; on Windows cargo runs under
WSL2/Docker) — run with `--all-features` to include the `validation`-gated schema test.

## Usage

```rust
use openom_model::{content_hash, EventType, Model, NodeKind, RelationshipType, SeededIdSource, TreeId};

let mut src = SeededIdSource::new(42); // deterministic — tests only; real code uses OsIdSource
let mut m = Model::new(TreeId::generate(&mut src));

let parent = m.create_node(NodeKind::Person, &mut src);
let child = m.create_node(NodeKind::Person, &mut src);
m.add_edge(RelationshipType::ParentChild, parent, child, &mut src)
    .unwrap();
let birth = m
    .add_event(EventType::Birth, child, Some(1900), &mut src)
    .unwrap();

let before = content_hash(&m.events[&birth]).unwrap();

// Correcting a fact in place never changes its id, never breaks the edge above — but its content
// hash moves, so an attestation on the old value now reads as "attested an earlier value".
m.correct_event_timestamp(birth, Some(1901)).unwrap();
assert_eq!(m.events[&birth].id, birth);
assert_ne!(content_hash(&m.events[&birth]).unwrap(), before);
```

Entry points: `Model::new` + `create_node` / `add_edge` / `add_event` / `add_name` /
`correct_event_timestamp` (mutation), `canonical_json` / `canonicalize` (JCS-equivalent bytes),
`content_hash` (the per-entity attestation-binding hash), and, in the `name` module, `render` /
`effective_parts` / `equivalence_class` / `validate`. The `validation` feature adds `schema::ModelSchema`
for Draft 2020-12 validation of the serialized shape — off by default so `jsonschema` never bloats
the wasm bundle.

## Position

Sits in the family-tree data-model layer next to `openom-claim` / `openom-projection`, but on the
losing side of the transition: nothing in the workspace depends on `openom-model`, and it is being
superseded, not extended. Full dependency graph: see `packages/README.md`.
