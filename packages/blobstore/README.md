# blobstore

> The storage swap seam — content-addressable blobs + per-object compare-and-swap, the lowest layer at
> which openom's storage backends interchange.

**Status:** built · infrastructure seam · design sharing-sync-evolution / backend-seam
**Last updated:** 2026-09-03

## What it is — and is not

A minimal [`BlobStore`]: `get` / `put` / `list` / `delete`, where every write carries a [`Precondition`]
(create-only `IfAbsent`, compare-and-swap `IfMatch(etag)`, or unconditional `Any`). This is the boundary
where the **managed** backend (Lambda + R2) and a **BYO dumb** backend (Google Drive / Dropbox) become
interchangeable: R2 and Drive both provide put/get/list plus conditional writes (etag CAS) with **no
compute**, so an engine written against this trait runs on either. Two reference impls ship here —
[`MemoryBlob`] and [`FsBlob`] — and every impl must pass [`conformance::run`].

It is **not** `journal::DocStore`. `DocStore`'s `append -> seq` (a store-assigned total order) is
deliberately absent: sequencing needs a sequencer no dumb backend has, and nothing above needs one — the
data engine is order-independent set-union. Sequencing, anti-rollback, and metering are managed-only
guarantees that attach *below* a `BlobStore` impl (inside its `put`), **never** as new verbs on this
trait — keeping the trait the weakest common denominator both backends can meet. It is
backend/domain/crypto-agnostic: it stores opaque bytes under caller-chosen keys and never inspects them.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **BLOB-1** | `IfAbsent` succeeds only when the key is absent; a create-race loser gets `PreconditionFailed` and its bytes never land. | Create-only is how a keyring `head` or snapshot slot is claimed exactly once. | `conformance::memory_blob_conforms`, `conformance::fs_blob_conforms` |
| **BLOB-2** | `IfMatch(etag)` succeeds only against the current version; a stale etag conflicts, and a changed value gets a new etag. | The whole of the store's concurrency control — a lost update fails loud, not silently. | `conformance::memory_blob_conforms`, `conformance::fs_blob_conforms` |
| **BLOB-3** | `list(prefix)` returns exactly the keys under `prefix` (empty prefix = all); order is unspecified. | Enumerating per-replica log heads or a tree's objects without scanning everything. | `conformance::memory_blob_conforms`, `conformance::fs_blob_conforms` |
| **BLOB-4** | `delete` under `Any` is idempotent (absent key = `Ok`); `IfMatch` guards it and conflicts on a stale etag. | Cleanup and CAS'd pointer removal stay safe under retry and concurrency. | `conformance::memory_blob_conforms`, `conformance::fs_blob_conforms` |
| **BLOB-5** | Identical content yields the same reference-impl etag (`hex(sha256(bytes))`); the etag is opaque to callers. | Content addressing + a stable CAS token, without leaking the store's versioning scheme. | `conformance::memory_blob_conforms`, `conformance::fs_blob_conforms` |

`conformance::run(make)` panics on the first violation and is the contract any new backend must satisfy.
Run: `node scripts/cargo.mjs test -p blobstore` (from the repo root).

## Usage

```rust
use blobstore::{BlobStore, MemoryBlob, Precondition, BlobError};

let store = MemoryBlob::new();

// Create-only: claim a key exactly once.
let etag = store.put("tree/head", b"v1", Precondition::IfAbsent).unwrap();
assert!(matches!(
    store.put("tree/head", b"v2", Precondition::IfAbsent),
    Err(BlobError::PreconditionFailed),
));

// Compare-and-swap against the version you last read.
let etag2 = store.put("tree/head", b"v2", Precondition::IfMatch(etag)).unwrap();
assert_eq!(store.get("tree/head").unwrap().unwrap().0, b"v2");
assert_ne!(etag2, String::new());
```

A new backend implements [`BlobStore`] and proves itself with
`blobstore::conformance::run(|| MyBackend::new(...))`.

## Position

The bottom of the storage stack, **below** `journal::DocStore`. It depends on no openom crate
(`sha2` + `data-encoding` + `thiserror` only); `journal`, `openom-sync`, and the keyring engines' blob
sync sit above it. Full dependency graph: see `packages/README.md`.
