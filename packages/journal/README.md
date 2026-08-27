# journal

> A local-first sync backend: per-document snapshot + append-only update-log with compare-and-swap and capability negotiation, over opaque bytes.

**Status:** built · storage/sync substrate, load-bearing · backend-agnostic (memory, sqlite; future file/server backends land here unchanged)
**Last updated:** 2026-08-25

## What it is — and is not

One contract for "does this document exist, and what's in it": a `Snapshot` (a byte blob plus an
opaque `version` string) and an append-only `Update` log addressed by a monotonic `seq`, both behind
one trait, `DocStore`. Writing a snapshot is compare-and-swap — `put_snapshot` takes the caller's
last-known `version` and fails closed with `StoreError::Conflict` if it's stale, so two concurrent
writers can never silently clobber each other's state. `Caps` lets a caller ask a backend what it can
do (`remote`, `conditional_writes`, `durable`, `max_blob_bytes`) instead of hardcoding assumptions per
backend. Two backends ship today — `MemoryStore` (volatile; tests and in-process use) and `SqliteStore`
(WAL-backed when opened on a file) — and both pass the exact same conformance suite, so a third backend
(a future file store, S3, or a zero-knowledge server) only has to pass that suite to be a safe drop-in.
This is deliberately the generic storage/transport substrate underneath sync: the claim engine's
sealed op deltas + snapshots ride it, and any future channel rides exactly this same contract,
unchanged — `journal` doesn't know or care which.

It is **not** domain- or crypto-aware: `Update` is `Vec<u8>` and `Snapshot::bytes` is `Vec<u8>` —
opaque blobs the caller seals and interprets. Metadata a caller might want (device id, Lamport clock,
op count) lives *inside* that ciphertext, never in a store column, so this crate has **no `openom-*`
dependency** and nothing may be added to its schema without breaking that promise. It is not a sync
*client*: it does not seal, retry, or merge peers' deltas, or decide when to sync — that orchestration
is `openom-sync`, one layer up. It is not a server: the network endpoints, auth, and protocol framing a
real remote implementation of this contract needs live above it too (today the JS `RemoteStore`; a
possible future native `openom-store`). And `Caps::durable` is not yet wired to distinguish backends —
both `MemoryStore` and `SqliteStore` report `durable: false` today, even though `SqliteStore::open` is
in fact durable across a restart (`tests::sqlite_open_survives_a_reopen`); a caller can't yet learn
durability from `caps()` alone.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **JOURNAL-1** | `put_snapshot` is compare-and-swap: it writes only when the caller's `expected` version matches the one currently stored (including "no snapshot yet" as `None`); any mismatch — stale version, wrong string, or a write that already moved — fails closed with `StoreError::Conflict`, never a silent overwrite. | Two writers racing to snapshot the same document can never clobber each other; the loser gets a typed error, not corruption. | `tests::memory_store_conforms`, `tests::sqlite_store_conforms`, `tests::stores_agree_on_conflict_semantics` |
| **JOURNAL-2** | The update log is append-only and cursor-addressed: `read_updates(doc, since)` returns exactly the entries with `seq > since`, in order, and a document that was never written reads as empty (`(vec![], 0)`), never an error. | A sync loop can always ask "what's new since my last cursor" and get a precise, gap-free tail — the basic incremental-sync primitive. | `tests::memory_store_conforms`, `tests::sqlite_store_conforms` |
| **JOURNAL-3** | One conformance suite — empty-store reads, append/read-back, CAS accept/reject, delete — runs unmodified against every backend, and every backend passes it identically. | A new backend (file, S3, a zero-knowledge server) only has to pass the same suite to be a safe drop-in; the two shipped backends can never quietly diverge in behavior. | `tests::memory_store_conforms`, `tests::sqlite_store_conforms`, `tests::stores_agree_on_conflict_semantics` |
| **JOURNAL-4** | `SqliteStore::open` is durable across a process restart: updates appended and a snapshot written before the connection is dropped are both still there, byte-for-byte, after reopening the same file. | The property a local-first client actually needs — a confirmed local commit must survive a crash or restart, not just live in RAM. | `tests::sqlite_open_survives_a_reopen` |
| **JOURNAL-5** | Update and snapshot bytes are stored and returned exactly as given — no reinterpretation, re-encoding, or mutation anywhere in the write or read path. | The whole opacity contract: metadata the caller cares about lives inside those bytes, so the store must never touch them. | `tests::memory_store_conforms`, `tests::sqlite_store_conforms`, `tests::sqlite_open_survives_a_reopen` |

Run: `node scripts/cargo.mjs test -p journal` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use journal::memory::MemoryStore;
use journal::{DocStore, StoreError};

let store = MemoryStore::new();
let doc = "family-tree-1";

// Append opaque update bytes — journal never looks inside them.
store
    .append(doc, &[b"update-1".to_vec(), b"update-2".to_vec()])
    .unwrap();
let (updates, _cursor) = store.read_updates(doc, None).unwrap();
assert_eq!(updates.len(), 2);

// A snapshot compresses the log so far; the first write expects no prior version.
let v1 = store.put_snapshot(doc, b"snapshot-bytes", None).unwrap();

// A stale writer loses the race: a wrong `expected` version fails closed, never overwrites.
let err = store.put_snapshot(doc, b"stale", None).unwrap_err();
assert!(matches!(err, StoreError::Conflict { .. }));

// The version-holding writer wins and gets a new version back.
let v2 = store
    .put_snapshot(doc, b"snapshot-bytes-2", Some(&v1))
    .unwrap();
assert_ne!(v1, v2);
```

Entry points: `DocStore` — the trait every backend implements (`list`, `read_snapshot`,
`read_updates`, `append`, `put_snapshot`, `delete`) — and `Caps` for capability negotiation. Backends:
`memory::MemoryStore` (volatile) and `sqlite::SqliteStore::in_memory` / `sqlite::SqliteStore::open`
(file-backed, WAL).

## Position

The storage/sync layer: generic and content-agnostic, sitting below `openom-sync` (the client sync
loop that seals deltas into `Update`s and merges peers' deltas back) and below any concrete remote
implementation of this contract (today the JS `RemoteStore`; a possible future native `openom-store`).
It carries the claim engine's op deltas + snapshots, opaque to it. Full dependency graph: see
`packages/README.md`.
