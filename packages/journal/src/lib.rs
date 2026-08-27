#![doc = include_str!("../README.md")]

pub mod memory;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("version conflict: expected {expected:?}, found {found:?}")]
    Conflict {
        expected: Option<String>,
        found: Option<String>,
    },
    #[error("document not found: {0}")]
    NotFound(String),
    #[error("backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Ein Log-Eintrag ist ein OPAKER Blob — die versiegelte Envelope. Seit der
/// Verschlüsselung liegt jede Metadatenspalte (device_id, lamport, …) INNEN im
/// Chiffrat; der Store (und ein späterer Zero-Knowledge-Server) sieht nur Bytes
/// plus die vergebene `seq`. Das JS-Modell ist identisch: IndexedDbStore und die
/// SealedStore-Kette reichen rohe Envelope-Bytes durch, ohne Rahmenstruktur.
pub type Update = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Caps {
    pub remote: bool,
    pub conditional_writes: bool,
    pub durable: bool,
    pub max_blob_bytes: u64,
}

/// Die eine Schnittstelle, die ein Datenprovider implementiert.
pub trait DocStore: Send + Sync {
    fn caps(&self) -> Caps;
    fn list(&self) -> Result<Vec<String>>;
    fn read_snapshot(&self, doc: &str) -> Result<Option<Snapshot>>;
    /// Alle Updates mit seq > since.
    fn read_updates(&self, doc: &str, since: Option<u64>) -> Result<(Vec<Update>, u64)>;
    fn append(&self, doc: &str, updates: &[Update]) -> Result<u64>;
    /// Compare-and-swap: schreibt nur, wenn die erwartete Version noch gilt.
    fn put_snapshot(&self, doc: &str, bytes: &[u8], expected: Option<&str>) -> Result<String>;
    fn delete(&self, doc: &str) -> Result<()>;
}

/// Delegating impl so one store can be shared — e.g. across several sync clients, or between the
/// sync loop and a background task — through an `Arc`.
impl<T: DocStore + ?Sized> DocStore for std::sync::Arc<T> {
    fn caps(&self) -> Caps {
        (**self).caps()
    }
    fn list(&self) -> Result<Vec<String>> {
        (**self).list()
    }
    fn read_snapshot(&self, doc: &str) -> Result<Option<Snapshot>> {
        (**self).read_snapshot(doc)
    }
    fn read_updates(&self, doc: &str, since: Option<u64>) -> Result<(Vec<Update>, u64)> {
        (**self).read_updates(doc, since)
    }
    fn append(&self, doc: &str, updates: &[Update]) -> Result<u64> {
        (**self).append(doc, updates)
    }
    fn put_snapshot(&self, doc: &str, bytes: &[u8], expected: Option<&str>) -> Result<String> {
        (**self).put_snapshot(doc, bytes, expected)
    }
    fn delete(&self, doc: &str) -> Result<()> {
        (**self).delete(doc)
    }
}
