#![doc = include_str!("../README.md")]

use thiserror::Error;

pub mod conformance;
pub mod fs;
pub mod memory;

pub use fs::FsBlob;
pub use memory::MemoryBlob;

/// An opaque per-object version token. A successful [`BlobStore::put`] returns the new one; a caller
/// threads it into a later [`Precondition::IfMatch`] to compare-and-swap. The store defines its meaning
/// (R2/Drive: the object etag; the reference impls here: the content hash) — treat it as opaque.
pub type Etag = String;

/// The write precondition — the whole of the store's concurrency control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Precondition {
    /// Create-only: succeed iff the key does not exist (R2 `If-None-Match: *`).
    IfAbsent,
    /// Compare-and-swap: succeed iff the key's current version equals this etag (R2 `If-Match`).
    IfMatch(Etag),
    /// Unconditional overwrite.
    Any,
}

/// A blob-store failure.
#[derive(Debug, Error)]
pub enum BlobError {
    /// The [`Precondition`] was not met — the key already exists (`IfAbsent`), or the etag is stale
    /// (`IfMatch`). The caller should refetch and retry: this is the CAS-conflict signal.
    #[error("precondition failed (concurrent write / stale etag)")]
    PreconditionFailed,
    /// The underlying backend failed (I/O, network, …).
    #[error("blob backend: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, BlobError>;

/// The storage swap seam: content-addressable blobs + per-object CAS. Both R2 and a dumb Drive/Dropbox
/// backend satisfy this with zero compute, so an engine written against `BlobStore` runs on either.
pub trait BlobStore: Send + Sync {
    /// Fetch a blob and its current version, or `None` if absent.
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Etag)>>;

    /// Write a blob under `pre`; return the new version. [`BlobError::PreconditionFailed`] on a CAS miss.
    fn put(&self, key: &str, bytes: &[u8], pre: Precondition) -> Result<Etag>;

    /// The keys under `prefix`, with their current versions. Order is unspecified.
    fn list(&self, prefix: &str) -> Result<Vec<(String, Etag)>>;

    /// Delete a blob under `pre`. `Any` is idempotent (deleting an absent key is `Ok`); `IfMatch`/
    /// `IfAbsent` guard it. [`BlobError::PreconditionFailed`] on a CAS miss.
    fn delete(&self, key: &str, pre: Precondition) -> Result<()>;
}

/// Share one store across clients: `Arc<S>` is a `BlobStore` that delegates. (Two replicas syncing the
/// same document each hold an `Arc` of the same backend.)
impl<T: BlobStore + ?Sized> BlobStore for std::sync::Arc<T> {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Etag)>> {
        (**self).get(key)
    }
    fn put(&self, key: &str, bytes: &[u8], pre: Precondition) -> Result<Etag> {
        (**self).put(key, bytes, pre)
    }
    fn list(&self, prefix: &str) -> Result<Vec<(String, Etag)>> {
        (**self).list(prefix)
    }
    fn delete(&self, key: &str, pre: Precondition) -> Result<()> {
        (**self).delete(key, pre)
    }
}

/// The content-hash etag the reference impls use — `hex(sha256(bytes))`. Opaque to callers.
pub(crate) fn etag_of(bytes: &[u8]) -> Etag {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
}

/// Shared precondition check: given the CURRENT bytes (or `None` if absent), does `pre` hold? The one
/// place CAS semantics live, so every impl agrees.
pub(crate) fn check_pre(pre: &Precondition, current: Option<&[u8]>) -> Result<()> {
    match (pre, current) {
        (Precondition::Any, _) => Ok(()),
        (Precondition::IfAbsent, None) => Ok(()),
        (Precondition::IfAbsent, Some(_)) => Err(BlobError::PreconditionFailed),
        (Precondition::IfMatch(e), Some(b)) if &etag_of(b) == e => Ok(()),
        (Precondition::IfMatch(_), _) => Err(BlobError::PreconditionFailed),
    }
}
