# openom-sync

> The client sync loop — seal local claim-op deltas to the store, merge peers' deltas back.

**Status:** built · client orchestration, load-bearing · E2EE multi-device sync
**Last updated:** 2026-08-27

## What it is — and is not

It ties three layers that each deliberately know nothing of the others: `openom-crdt` produces and
consumes op batches (`ChannelItem`s); `openom-sealer` seals those bytes into E2EE envelopes; a
`journal::DocStore` persists opaque envelopes as an append log. `ClaimSyncClient::push_claims` seals a
local batch and pushes it; `pull_claims` opens and merges every new log entry into the accumulated op
set; `materialize` folds that set into the live record set the projection reads; `compact_claims` /
`bootstrap_claims` publish a snapshot of the live set and load from one instead of replaying the whole
log.

A claim update **is** a delta — an op-based change — so it seals as a `Kind::Delta` /
`Format::OpenomOps` entry and is deduped by the replica dot like any other delta. **Single-engine-per-
app-instance:** the whole app runs the claim engine, so this client's log carries only claim entries —
no mixed-kind routing.

It is **not** the store: it holds no bytes of its own beyond an in-memory write-ahead queue of
already-sealed envelopes awaiting append, and all durability is the `DocStore`'s. It is **not** the
sealer: it holds no key material beyond the `Sealer` it wraps, and never inspects what the op bytes
mean.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **SYNC-1** | Two replicas' concurrent pushes converge once each has pulled the other's entries. | The whole point of a CRDT sync loop: no reconciliation server, no delivery-order requirement. | `claim::tests::two_devices_converge_through_the_claim_stack` |
| **SYNC-2** | `pull_claims` past the last entry is a no-op. | Callers can pull speculatively or on a schedule without corrupting state or wasted work. | `claim::tests::pull_is_idempotent` |
| **SYNC-3** | A duplicate log entry (a retried append landing twice) folds in harmlessly, never double-inserting. | At-least-once delivery is assumed everywhere below this crate. | `claim::tests::a_duplicate_appended_entry_is_harmless` |
| **SYNC-4** | The set is not separately durable: a crashed client fully rebuilds it by replaying the sealed log alone. | The log is the durable source of truth; the in-memory op set is disposable. | `claim::tests::a_crashed_client_rebuilds_from_the_durable_log` |
| **SYNC-5** | Each batch is sealed exactly once; a transient append failure keeps it queued and retries the identical sealed bytes, never re-sealing. | Re-sealing on retry mints a fresh nonce under the same chain slot — a self-inflicted hash-chain fork. | (write-ahead queue in `push_claims` / `flush`) |
| **SYNC-6** | `bootstrap_claims` loads the snapshot plus only the tail after its `covers_through_seq` when one exists, and falls back to a full replay when none does. | A fresh device or a long-lived log never forces an unbounded replay. | `claim::tests::a_fresh_client_bootstraps_from_a_snapshot_plus_the_tail`, `claim::tests::bootstrap_without_a_snapshot_replays_the_whole_log` |
| **SYNC-7** | A same-author remove propagates and folds the record out of the live set (and out of a later snapshot — the structural GC horizon). | Deletion is a claim-model op, not a store operation; it must converge like any other. | `claim::tests::a_same_author_remove_syncs_and_drops_the_record`, `claim::tests::compaction_folds_out_removed_records` |
| **SYNC-8** | Opening a log sealed under a different DEK fails; it never returns partial or garbage plaintext. | E2EE: a wrong key must fail closed at the boundary this crate calls through. | `claim::tests::a_wrong_key_cannot_open_the_claim_log` |

Run: `node scripts/cargo.mjs test -p openom-sync` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use journal::memory::MemoryStore;
use openom_claim::envelope::Record;
use openom_crdt::ChannelItem;
use openom_crypto::generate_dek;
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_sealer::Sealer;
use openom_sync::ClaimSyncClient;
use serde_json::json;
use std::sync::Arc;

let store = Arc::new(MemoryStore::new());
let dek = generate_dek().unwrap();

let sealer_a = Sealer::from_unwrapped(
    1, dek.clone().into_inner(), TreeId::new(b"tree-uuid-16byte".to_vec()),
    KeyId::new(b"epoch-0".to_vec()), ReplicaId::new(b"replica-a".to_vec()),
);
let mut a = ClaimSyncClient::new(sealer_a, store.clone(), "tree");

let sealer_b = Sealer::from_unwrapped(
    1, dek.into_inner(), TreeId::new(b"tree-uuid-16byte".to_vec()),
    KeyId::new(b"epoch-0".to_vec()), ReplicaId::new(b"replica-b".to_vec()),
);
let mut b = ClaimSyncClient::new(sealer_b, store.clone(), "tree");

let person = ChannelItem::Assert(Record::try_from(json!({
    "id": "pA", "type": "openom.org/core/person/v1", "createdAt": 1, "createdBy": "did:key:z6MkA",
})).unwrap());

a.push_claims(&[person]).unwrap(); // sealed + pushed to the shared log
b.pull_claims().unwrap();          // opened + folded into b's set

assert_eq!(a.materialize().len(), b.materialize().len());
```

Entry points: `ClaimSyncClient::new`, `push_claims` (edit + push), `pull_claims`, `materialize` /
`items` (the read model), `flush` / `pending_count` (the write-ahead queue), and `compact_claims` /
`bootstrap_claims` (snapshot compaction).

## Position

Sits above `journal` (the opaque byte store) and `openom-sealer` (E2EE sealing), and drives
`openom-crdt` op batches through `openom-protocol` envelopes. Full dependency graph: see
`packages/README.md`.
