# docsync

> A generic local-first client sync loop — push / pull / compact / bootstrap over a `journal::DocStore`,
> abstracted over a merge `Engine` and an envelope `Sealer`.

**Status:** experimental · vendored sync-client skeleton · design docsync-sync-client-base (OPE-186 phase 3)
**Last updated:** 2026-09-03

## What it is — and is not

The transport loop, with the CRDT and the crypto factored out behind two seams. A caller supplies an
[`Engine`] for its CRDT (encode a local edit → delta bytes; merge delta/snapshot bytes into local state;
snapshot) and a [`Sealer`] for its envelope format, and gets [`SyncClient`]: `apply` a local edit, `flush`
pending deltas to the store, `pull` peers' deltas back, `compact` to a snapshot, and `bootstrap` a fresh
replica. The [`Engine`] seam is **delta-bytes-centric**, which fits both op-CRDTs (`encode(state.apply(op))`)
and doc-CRDTs (`export(update, from = before)`).

Because merges are idempotent and commutative, **delivery order and at-least-once redelivery don't
matter** — re-pulling one's own pushes is a no-op. That is the whole design constraint: it carries **no**
domain logic (no concrete op/state model, no encryption — those stay caller-side behind the two seams),
and it deliberately does **not** generalize causally-*dependent* workflows like propose/approve. Those
only stay clean for causally-independent ops, so a caller layers them *above* this loop, not inside it.
This crate is the copied-and-owned skeleton (from flowcontrol's `docsync`) that openom's own sync client
is being re-layered onto; it is not yet the production openom sync path.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **DSYNC-1** | Two replicas that push concurrently converge after each pulls the other, and a third replica bootstraps to the same state. | The correctness of the whole loop: order-independent, at-least-once-safe convergence. | `tests::two_replicas_converge_and_a_third_bootstraps` |
| **DSYNC-2** | `maybe_compact` replaces the update-log with a snapshot once the configured policy trips (e.g. `EveryNUpdates`), and the compacted state is unchanged. | Bounds log growth without a barrier or a change of semantics. | `tests::snapshot_policy_triggers_compaction_by_length` |

Run: `node scripts/cargo.mjs test -p docsync` (from the repo root).

## Usage

```rust,ignore
use docsync::{SyncClient, EveryNUpdates};

// `engine: impl Engine` (your CRDT) and `sealer: impl Sealer` (your envelope) are caller-provided.
let mut client = SyncClient::new(engine, sealer, store, "tree-doc-id");

client.apply(my_edit)?;        // stage a local edit as a delta
client.flush()?;               // seal + append pending deltas to the store
let pulled = client.pull()?;   // merge peers' deltas back (re-pulling own pushes is a no-op)
client.maybe_compact(&EveryNUpdates(256))?; // snapshot once the policy trips
```

Entry points: `SyncClient` (`new` / `apply` / `flush` / `pull` / `compact` / `maybe_compact` /
`bootstrap` / `pending_count`), the `Engine` and `Sealer` traits, the `SealCtx` / `Sealed` /
`CompactionState` value types, and the `EveryNUpdates` / `NeverCompact` policies.

## Position

The transport layer: it sits over `journal::DocStore` and under a caller's CRDT + crypto (which it never
names). Its only openom-relevant dependency is `journal`; the concrete `Engine`/`Sealer` impls live in the
consumer. Full dependency graph: see `packages/README.md`.
