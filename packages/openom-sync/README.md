# openom-sync

> The client sync loop — seal local deltas to the store, merge peers' deltas back.

**Status:** built · client orchestration, load-bearing · E2EE multi-device sync
**Last updated:** 2026-08-25

## What it is — and is not

It ties three layers that each deliberately know nothing of the others: `openom-treelog`
produces and consumes `commute` op bytes; `openom-sealer` seals those bytes into E2EE envelopes; a
`journal::DocStore` persists opaque envelopes as an append log. `SyncClient::apply` /
`apply_batch` seal a local edit and push it; `pull` opens and merges every new log entry;
`compact` / `bootstrap` fold the tree to a snapshot and load from one instead of replaying the
whole log. A second, separate channel — `push_proposal` / `pull_proposals` / `commit_proposal` —
carries staged edits that are sealed but never applied to the tree and never appended to the
tree's own log until an approver commits them.

It is **not** the store: it holds no bytes of its own beyond an in-memory write-ahead queue of
already-sealed envelopes awaiting append, and all durability is the `DocStore`'s. It is **not**
the sealer: it holds no key material beyond the `Sealer` it wraps, and never inspects what the op
bytes mean. And it makes **no authorization decision** — `commit_proposal` trusts the caller to
have already checked the approver's role. Today it seals `commute` / `openom-treelog` deltas; the
claim model's operations channel is expected to ride this same loop unchanged.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **SYNC-1** | Two replicas' concurrent pushes converge byte-identically once each has pulled the other's entries. | The whole point of a CRDT sync loop: no reconciliation server, no delivery-order requirement. | `tests::two_devices_converge_through_the_full_stack`, `tests::a_second_round_of_edits_syncs_and_pull_is_idempotent` |
| **SYNC-2** | `pull` past the last entry is a no-op. | Callers can pull speculatively or on a schedule without corrupting state or wasted work. | `tests::a_second_round_of_edits_syncs_and_pull_is_idempotent` |
| **SYNC-3** | A duplicate log entry (a retried append landing twice) merges harmlessly, never double-applying. | At-least-once delivery is assumed everywhere below this crate. | `tests::a_duplicate_appended_delta_is_harmless` |
| **SYNC-4** | The tree is not separately durable: a crashed client fully rebuilds it by replaying the sealed log alone. | The log is the durable source of truth; the in-memory tree is disposable. | `tests::a_crashed_client_rebuilds_its_tree_from_the_durable_log` |
| **SYNC-5** | Each edit is sealed exactly once; a transient append failure keeps it queued and retries the identical sealed bytes, never re-sealing. | Re-sealing on retry mints a fresh nonce under the same chain slot — a self-inflicted hash-chain fork. | `tests::a_transient_append_failure_queues_and_retries_without_loss` |
| **SYNC-6** | `bootstrap` loads the snapshot plus only the tail after its `covers_through_seq` when one exists, and falls back to a full replay when none does — both reach the same state as full history. | A fresh device or a long-lived log never forces an unbounded replay. | `tests::a_fresh_client_bootstraps_from_a_snapshot_plus_the_tail`, `tests::bootstrap_without_a_snapshot_replays_the_whole_log` |
| **SYNC-7** | A pushed proposal is sealed to its own `doc:proposals` channel — never applied to the local tree, never appended to the tree's own log; only `commit_proposal` moves it onto the tree. | A server or peer can never replay an editor's unapproved proposal into the tree. | `tests::a_proposal_travels_through_the_store_and_is_approved` |
| **SYNC-8** | Opening a log sealed under a different DEK fails; it never returns partial or garbage plaintext. | E2EE: a wrong key must fail closed at the boundary this crate calls through. | `tests::a_wrong_key_cannot_open_the_log` |

Run: `node scripts/cargo.mjs test -p openom-sync` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use journal::memory::MemoryStore;
use openom_crypto::generate_dek;
use openom_sealer::Sealer;
use openom_sync::SyncClient;
use openom_treelog::{Tree, TreeOp};
use std::sync::Arc;

let store = Arc::new(MemoryStore::new());
let dek = generate_dek().unwrap();

let sealer_a = Sealer::from_unwrapped(
    1, dek.clone(), b"tree-uuid-16byte".to_vec(), b"epoch-0".to_vec(), b"replica-a".to_vec(),
);
let mut a = SyncClient::new(Tree::new([1u8; 16]), sealer_a, store.clone(), "tree");

let sealer_b = Sealer::from_unwrapped(
    1, dek, b"tree-uuid-16byte".to_vec(), b"epoch-0".to_vec(), b"replica-b".to_vec(),
);
let mut b = SyncClient::new(Tree::new([2u8; 16]), sealer_b, store.clone(), "tree");

a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap(); // sealed + pushed to the shared log
b.pull().unwrap();                                    // opened + merged into b's tree

assert!(b.tree().has_person(&[1]));
assert_eq!(a.tree().doc().snapshot(), b.tree().doc().snapshot());
```

Entry points: `SyncClient::new`, `apply` / `apply_batch` (edit + push), `pull`, `flush` /
`pending_count` (the write-ahead queue), `compact` / `bootstrap` (snapshot compaction), and
`push_proposal` / `pull_proposals` / `commit_proposal` (the separate proposals channel).

## Position

Sits above `journal` (the opaque byte store) and `openom-sealer` (E2EE sealing), and drives
`openom-treelog` (`commute` op bytes) through `openom-protocol` envelopes today — the claim
model's operations channel is expected to ride this same loop. Full dependency graph: see
`packages/README.md`.
