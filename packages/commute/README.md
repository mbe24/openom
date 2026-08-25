# commute

> A small, self-contained operation-based CRDT — Lamport-ordered ops merged into typed convergent cells.

**Status:** built · current engine substrate, load-bearing (`openom-treelog`) · in flight — being
superseded by the claim model's set-union (see `packages/README.md` §Architecture seams)
**Last updated:** 2026-08-25

## What it is — and is not

`commute` merges a keyed collection of **typed cells** — an LWW register and a tombstoned OR-set, so
far — via **self-contained operations**: every op names its own target and carries everything needed
to apply it, referencing no other op. Ordering is a **Lamport clock** `(lamport, replica)`, never
wall-clock time, so merge decisions are deterministic and immune to device clock skew, and the
**engine owns the clock** — a caller hands in an unstamped `OpIntent`; only `Doc::apply_local` mints
a `Stamp`. Merging is commutative and idempotent by construction: every cell keeps only its
max-stamped state, so replicas that have seen the same op set agree regardless of delivery order or
redelivery. It also ships a deterministic byte codec (snapshot = full state, delta = state newer than
a version vector) so two converged replicas produce byte-identical bytes on the wire.

It is **not** a general JSON/document CRDT — `commute-format` is the bridge from JSON documents to
these cells. It is **not** a rich-text CRDT: `Value` is an opaque, indivisible leaf (`Null`, `Bool`,
`I64`, `U64`, `Bytes`, `Text`) merged whole by LWW, never character/span-level — a `text`/`sequence`
cell for free-text fields is reserved but deferred (`plan/design.schema-evolution.md`, OPE-150/151).
It carries **no floats** (a value becomes a canonical archive encoding downstream, and floats have no
canonical form) and **no domain knowledge** — `CellId`/`ElemId` are opaque bytes the caller assigns
meaning to. It does no crypto, sealing, or transport of its own; that is `openom-sealer`/`journal`.

And **it is legacy in motion**: `commute` underpins the current engine, `openom-treelog`, but the
project is transitioning to the claim model, whose set-union semantics make an op-based CRDT largely
redundant. It still ships today and is exercised hard (see Invariants); expect it to shrink or retire
as that transition completes.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **COMMUTE-1** | Merge is order-independent and idempotent: any set of ops, delivered to any replica in any (repeated) delivery order, converges to an identical checkpoint. | The whole point of an op-based CRDT — replicas that saw the same ops agree, so sync order and at-least-once retries never matter. | `tests::replicas_converge_under_any_delivery_order`, `tests::merge_is_idempotent` |
| **COMMUTE-2** | LWW register: the op with the highest Lamport stamp wins; ties across replicas break by replica id, never wall-clock time. | Deterministic conflict resolution, immune to device clock skew. | `tests::register_is_last_writer_by_stamp_across_replicas` |
| **COMMUTE-3** | OR-set: an element is live iff its add out-stamps its tombstone; a stale, re-delivered add can never resurrect an already-tombstoned element. | At-least-once delivery must not be able to undo a delete. | `tests::set_add_and_remove_resolve_by_stamp_no_resurrection` |
| **COMMUTE-4** | The byte codec is canonical: the same op run always serializes to the same bytes (a locked golden vector), and decode∘encode is a fixpoint. | Two converged replicas must produce byte-identical snapshots — a codec drift would silently fork that guarantee. | `tests::snapshot_bytes_are_a_stable_golden_vector`, `tests::encode_decode_round_trips` |
| **COMMUTE-5** | The decoder is hostile-input-safe: arbitrary bytes decode to `Ok` or a typed `DecodeError`, never a panic; a failed decode/merge leaves the document completely unchanged. | Untrusted synced bytes must fail closed, not crash or partially apply. | `tests::decode_never_panics_on_arbitrary_bytes`, `tests::merge_bytes_error_leaves_the_document_unchanged`, `tests::merge_bytes_on_junk_is_a_clean_error_not_a_panic` |
| **COMMUTE-6** | `snapshot`/`from_snapshot` round-trip exactly, and `delta_since` carries only the ops a peer's version vector doesn't already cover. | This is the actual sync substrate: coarse, log-based "everything after what I have" sync. | `tests::snapshot_round_trips`, `tests::delta_since_ships_only_the_missing_ops` |

Run: `node scripts/cargo.mjs test -p commute` (from the repo root; on Windows cargo runs under
WSL2/Docker). Fuzz (untrusted-input boundary, corpus-driven, separate detached crate): `cd
packages/commute && cargo +nightly fuzz run decode_ops` and `cargo +nightly fuzz run merge_bytes`.

## Usage

```rust
use commute::{Doc, OpIntent, Value};

let mut a = Doc::new([1u8; 16]);
let mut b = Doc::new([2u8; 16]);

// Concurrent, offline edits to the same register cell.
let op_a = a.apply_local(OpIntent::SetRegister { cell: vec![0], value: Value::I64(1901) });
let op_b = b.apply_local(OpIntent::SetRegister { cell: vec![0], value: Value::I64(1903) });

// Exchange ops in either order — merge is commutative and idempotent either way.
a.merge_op(&op_b);
b.merge_op(&op_a);
assert_eq!(a.register(&[0]), Some(&Value::I64(1903)));
assert_eq!(a.checkpoint(), b.checkpoint());

// Or sync by bytes: a fresh replica catches up from a snapshot.
let snapshot = a.snapshot();
let c = Doc::from_snapshot([3u8; 16], &snapshot).unwrap();
assert_eq!(c.checkpoint(), a.checkpoint());
```

Entry points: `Doc::new` / `Doc::apply_local` (mint a local op) / `Doc::merge_op` (integrate one op)
/ `Doc::merge_bytes` (integrate a snapshot or delta); `Doc::register` / `Doc::register_cells` and
`Doc::set_elements` / `Doc::set_cell_ids` / `Doc::set_cell_ids_with_prefix` (read); `Doc::snapshot` /
`Doc::delta_since` / `Doc::from_snapshot` (the sync codec); `Doc::version` / `Doc::changed_cells_since`
(version vectors); `Doc::checkpoint` (the convergence oracle).

## Position

`commute` depends on no other openom crate and knows nothing about family trees; today
`openom-treelog` builds the current family-tree engine directly on it, and `commute-format` bridges
JSON documents down to its cells. Full dependency graph: see `packages/README.md`.
