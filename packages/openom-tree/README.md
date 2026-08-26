# openom-tree

> The app-facing family-tree engine: it composes `openom-crdt` (the set-union fold) and
> `openom-projection` (the read model) into the read+write surface the app talks to.

**Status:** built · pure engine (`rlib`) + `#[wasm_bindgen]` veneer (`WasmTree`) + `build-tree.mjs` → `vendor/tree/` · the JS `ClaimFamilyTree` adapter (OPE-201) is next · claim-model direction
**Last updated:** 2026-08-26

## What it is

`openom-tree` is the claim-model successor to `openom-treelog`'s engine role — the thing the app's
`FamilyTree` wraps. It owns the in-memory record set + the local author id (`createdBy`), and:

- **edits** — `assert_claim` / `assert_anchor` / `remove` / `supersede_claim` / `revoke` — each mints
  an operation, applies it to the local set optimistically, and **returns the encoded op-batch bytes**
  for the transport to seal + append. The engine is **key-less**: it never touches the DEK — sealing is
  the transport's / sealer-worker's job.
- **`merge`** ingests a peer's (or a replayed) batch — idempotent, set-union.
- **`snapshot` / `load_snapshot`** fold the live set to a snapshot batch and load one back.
- **`project`** runs the read-model projection over the live set; **`resolve_id`** maps an anchor to
  its canonical person id (the cluster's minimum-anchor id).

The op semantics + convergence live in `openom-crdt` (the `materialize` fold); the read model in
`openom-projection`. This crate is the composition and the app-facing surface — nothing more.

## Usage

```rust
use openom_tree::Tree;
use serde_json::json;

let mut tree = Tree::new("did:key:z6MkA"); // the vault-derived author id

// Add a person anchor + a name claim (each returns op-batch bytes for the transport to seal).
tree.assert_anchor("pA", "openom.org/core/person/v1", 1).unwrap();
tree.assert_claim("pA", "openom.org/core/name/v1", json!({ "parts": { "given": "Ada" } }), 1).unwrap();

let view = tree.project();
assert_eq!(view.people.len(), 1);
assert_eq!(view.people[0].id, "pA");
assert_eq!(view.people[0].names.len(), 1);
```

Run: `node scripts/cargo.mjs test -p openom-tree` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Position

Composes `openom-crdt` + `openom-projection` (+ `openom-claim` types). It depends on **no** transport
crate and holds **no** key material — edits are raw op-batch bytes the caller seals (via the existing
sealer-worker + store stack). The `#[wasm_bindgen]` veneer (`WasmTree`) +
`scripts/build-tree.mjs` → `apps/app/src/vendor/tree/` (gitignored) are built; next is the JS
`ClaimFamilyTree` adapter (OPE-201) that wraps `WasmTree` at the `library.js` factory. Takes over
`openom-treelog`'s engine/veneer role; full dependency graph in `packages/README.md`.
