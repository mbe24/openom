//! Persistenz opaker Bytes. Kennt das Datenmodell absichtlich nicht:
//! Snapshots und Updates sind Blobs, damit dieselbe Schnittstelle später
//! auch S3 oder einen Zero-Knowledge-Server bedienen kann.

pub mod memory;
pub mod sqlite;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("version conflict: expected {expected:?}, found {found:?}")]
    Conflict { expected: Option<String>, found: Option<String> },
    #[error("document not found: {0}")]
    NotFound(String),
    #[error("backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMeta {
    pub device_id: String,
    pub lamport: u64,
    pub created_at: i64,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    /// Opake Nutzlast. Im Prototyp JSON-Ops, später ein Yrs-Update in einem
    /// Protobuf-Rahmen — der Store sieht in beiden Fällen nur Bytes.
    pub bytes: Vec<u8>,
    pub meta: UpdateMeta,
}

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
