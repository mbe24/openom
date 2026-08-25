# commute-format

> The commute format bridge — import/export structured documents (JSON) as mergeable `commute` cells.

**Status:** built · scaffolding, zero consumers · kept for a future GEDCOM import/export trigger
**Last updated:** 2026-08-25

## What it is — and is not

Two seams: a [`Codec`] turns a serialized format ⇄ a neutral [`ValueTree`] (mechanical — JSON now,
XML/YAML later behind the same trait), and a `Mapping` turns a `ValueTree` ⇄ `commute` cells,
carrying **identity** and a per-field **merge policy** — the substance, and where "no silent
last-writer-wins" is enforced. A scalar field auto-maps to an LWW register; a **collection with no
declared [`FieldPolicy`] is a hard error**, never a silent whole-list overwrite. Policy comes from a
static, declared [`MappingSpec`], not from the shape of any one document, so two documents that
differ only in incidental shape can't make replicas disagree.

The JSON [`Codec`] is hand-rolled, on purpose — no serde: it **rejects duplicate object keys** (which
`serde_json` silently last-writer-wins) and **rejects floats** (no canonical archive form), and it
never panics on arbitrary bytes.

It is **not** wired to anything today: this crate has **zero consumers** in the workspace. It exists
as scaffolding for a future GEDCOM import/export trigger, not because any current path needs it —
`import` / `export` produce and consume real `commute::Doc` values, but nothing in the app calls
them yet. It is also not a full CRDT engine (that's `commute`) or the family-tree domain
(`openom-treelog`) — it only bridges a document shape to cells.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **CFMT-1** | The JSON codec rejects duplicate object keys instead of silently keeping the last. | `serde_json`'s last-writer-wins-on-duplicate-key is exactly the silent-overwrite failure mode this bridge exists to avoid. | `tests::duplicate_keys_are_rejected` |
| **CFMT-2** | The JSON codec rejects floats on parse (bare, and nested in an object). | Values become a canonical, float-free archive encoding downstream; a float has no canonical form to preserve. | `tests::floats_are_rejected` |
| **CFMT-3** | Parsing never panics on arbitrary bytes — malformed input fails with a `CodecError`, and nesting past `max_depth` fails with `TooDeep` rather than a stack overflow. | An adversarial or truncated document must fail closed, not crash the process. | `tests::deep_nesting_is_bounded_not_a_stack_overflow`, `tests::trailing_bytes_are_rejected`, `proptests::parse_never_panics_on_arbitrary_bytes` |
| **CFMT-4** | `emit` then `parse` round-trips to the same `ValueTree`; `parse` then `emit` is a byte fixpoint. | The codec must be lossless in both directions or import/export would drift from the source document. | `proptests::emit_then_parse_round_trips`, `proptests::parse_then_emit_is_a_byte_fixpoint` |
| **CFMT-5** | `import` refuses a collection field (`Seq`/`Map`) with no declared `FieldPolicy` — it is a hard `MapError::UndeclaredCollection`, never an implicit policy choice. | A field added to a document later can't silently pick up lossy last-writer-wins behavior. | `tests::an_undeclared_collection_is_a_hard_error` |
| **CFMT-6** | A `Keyed` / `KeyedOrdered` collection with two elements sharing a key is rejected, not silently deduplicated. | Two elements at one key is caller error, not a mapping ambiguity to paper over. | `tests::duplicate_keys_within_a_collection_are_rejected` |
| **CFMT-7** | `import` then `export` reconstructs the document's scalar fields and keyed collections (modulo key ordering). | The bridge must be round-trip-faithful or a stored document would diverge from what was imported. | `tests::import_then_export_reconstructs_the_document` |
| **CFMT-8** | A `KeyedOrdered` field requires every element to carry its declared `order_field`; a missing one is a hard error, and export sorts by that field. | Display order must be a real, present property of the data, not inferred from arrival order. | `tests::keyed_ordered_requires_the_order_field`, `tests::keyed_ordered_sorts_by_the_order_field_on_export` |
| **CFMT-9** | `ImportMode::Merge` never removes a collection element the document omits; `ImportMode::Replace` retracts it. | Additive-by-default is the safe choice; authoritative replace is an explicit opt-in, not a surprise. | `tests::replace_mode_retracts_absent_elements_but_merge_keeps_them` |
| **CFMT-10** | A `ValueIdentity` (scalar-set) field dedups repeated values on import and round-trips through export. | Tags/aliases are a set, not a list — a repeated value in the source document must not fork replicas over an ordering artifact. | `tests::a_value_identity_scalar_set_dedups_and_round_trips` |

Run: `node scripts/cargo.mjs test -p commute-format` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use commute_format::{export, import, Codec, FieldPolicy, MappingSpec, ValueTree};
use commute_format::JsonCodec;

let codec = JsonCodec::default();
let doc = codec
    .parse(br#"{"title":"Smith Family","people":[{"id":"p1","name":"Ada"},{"id":"p2","name":"Bea"}]}"#)
    .unwrap();

// "title" is undeclared but scalar, so it auto-maps to an LWW register; "people" is a declared
// keyed collection — a collection with no declared policy would be a hard error instead.
let spec = MappingSpec {
    fields: vec![(
        "people".into(),
        FieldPolicy::Keyed { key_field: "id".into() },
    )],
};

let plan = import(&doc, &spec, &codec).unwrap();
let mut d = commute::Doc::new([0u8; 16]);
for intent in plan.intents {
    d.apply_local(intent);
}
assert_eq!(d.set_elements(b"people").len(), 2);

// export ∘ import round-trips modulo key ordering.
let rebuilt = export(&d, &spec, &codec).unwrap();
assert!(matches!(rebuilt, ValueTree::Map(_)));
```

Entry points: `JsonCodec` (the `Codec` impl, feature `json`, on by default), `import` /
`import_mode` (document → unstamped `OpIntent`s), `export` (a `commute::Doc` back to a `ValueTree`),
and `MappingSpec` / `FieldPolicy` (the declared per-field merge policy).

## Position

Sits in the operations/CRDT layer, downstream of `commute` (it produces and consumes `commute::Doc`
/ `OpIntent` / `Value`) and upstream of nothing — it has **no consumers in the workspace today**.
It is retained as scaffolding for a future GEDCOM import/export trigger, not because any current
path depends on it. Full dependency graph: see `packages/README.md`.
