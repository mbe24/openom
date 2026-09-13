//! The durable media blob store (OPE-435): the `SQLite` backing for `apps/app/src/core/blobs.js`'s
//! `TauriBlobStore`. Content-addressed images/attachments live NEXT TO the document, never inside it — a CRDT
//! delta carries a few hundred bytes (the hash), not a photo, and the same scan uploaded twice hashes to one
//! entry. The web build keeps these in memory (`MemoryBlobStore`, cleared on lock); the Tauri build persists
//! them here so they survive a relaunch.
//!
//! This is a LOCAL cache (`caps().remote == false`) — the bytes are not synced through the zero-knowledge
//! server. They are stored decrypted at rest (raw JPEG), matching the blobs.js contract; whether to wrap them
//! under a device key is a separate, deliberately-deferred design question (OPE-435 note).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS blobs (
       hash    TEXT PRIMARY KEY,
       mime    TEXT NOT NULL,
       w       INTEGER,
       h       INTEGER,
       bytes   BLOB NOT NULL,
       created INTEGER NOT NULL
     );";

/// One stored blob's metadata (`blob_meta`), mirroring `MemoryBlobStore.meta`'s shape.
#[derive(serde::Serialize)]
pub struct BlobMeta {
    pub mime: String,
    pub w: Option<u32>,
    pub h: Option<u32>,
    pub size: u64,
    /// Wall-clock milliseconds the blob was first stored.
    pub created: i64,
}

/// A stored blob's bytes + mime (`blob_get`); the webview wraps it in a `Blob` for an object URL.
#[derive(serde::Serialize)]
pub struct BlobData {
    pub bytes: Vec<u8>,
    pub mime: String,
}

/// The durable content-addressed media store (its own `blobs.sqlite`, separate from the vault + doc stores).
pub struct MediaStore {
    conn: Mutex<Connection>,
}

impl MediaStore {
    /// Open (or create) the media database at `path` (WAL). Pass `":memory:"` for a test store.
    ///
    /// # Errors
    /// Returns an error string if the database can't be opened or the schema can't be applied.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = WAL;\n PRAGMA synchronous = NORMAL;\n{SCHEMA}"
        ))
        .map_err(|e| e.to_string())?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Store `bytes` content-addressed by their SHA-256 (lowercase hex). Idempotent: identical bytes hash to the
    /// same entry, so a re-`put` is a no-op that returns the existing hash. Returns the hash.
    ///
    /// # Errors
    /// Returns an error string if the write fails.
    pub fn put(
        &self,
        bytes: &[u8],
        mime: Option<String>,
        w: Option<u32>,
        h: Option<u32>,
        created: i64,
    ) -> Result<String, String> {
        use std::fmt::Write as _;
        let hash = Sha256::digest(bytes).iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let mime = mime.unwrap_or_else(|| "application/octet-stream".to_string());
        self.conn()
            .execute(
                "INSERT INTO blobs (hash, mime, w, h, bytes, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(hash) DO NOTHING",
                params![hash, mime, w, h, bytes, created],
            )
            .map_err(|e| e.to_string())?;
        Ok(hash)
    }

    /// Whether a blob with `hash` is stored.
    ///
    /// # Errors
    /// Returns an error string if the read fails.
    pub fn has(&self, hash: &str) -> Result<bool, String> {
        self.conn()
            .query_row("SELECT 1 FROM blobs WHERE hash = ?1", params![hash], |_| Ok(()))
            .optional()
            .map(|o| o.is_some())
            .map_err(|e| e.to_string())
    }

    /// `hash`'s metadata, or `None` if absent.
    ///
    /// # Errors
    /// Returns an error string if the read fails.
    pub fn meta(&self, hash: &str) -> Result<Option<BlobMeta>, String> {
        self.conn()
            .query_row(
                "SELECT mime, w, h, length(bytes), created FROM blobs WHERE hash = ?1",
                params![hash],
                |r| {
                    Ok(BlobMeta {
                        mime: r.get(0)?,
                        w: r.get(1)?,
                        h: r.get(2)?,
                        size: r.get::<_, i64>(3)?.max(0).unsigned_abs(),
                        created: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// `hash`'s bytes + mime, or `None` if absent.
    ///
    /// # Errors
    /// Returns an error string if the read fails.
    pub fn get(&self, hash: &str) -> Result<Option<BlobData>, String> {
        self.conn()
            .query_row(
                "SELECT bytes, mime FROM blobs WHERE hash = ?1",
                params![hash],
                |r| Ok(BlobData { bytes: r.get(0)?, mime: r.get(1)? }),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Delete `hash` (idempotent).
    ///
    /// # Errors
    /// Returns an error string if the write fails.
    pub fn delete(&self, hash: &str) -> Result<(), String> {
        self.conn()
            .execute("DELETE FROM blobs WHERE hash = ?1", params![hash])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Every stored hash.
    ///
    /// # Errors
    /// Returns an error string if the read fails.
    pub fn list(&self) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT hash FROM blobs").map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::MediaStore;

    #[test]
    fn put_is_content_addressed_idempotent_and_round_trips() {
        let s = MediaStore::open(":memory:").unwrap();
        let h1 = s.put(b"jpeg-bytes", Some("image/jpeg".into()), Some(64), Some(48), 1_000).unwrap();
        // Same bytes → same hash → one entry (re-put is a no-op).
        let h2 = s.put(b"jpeg-bytes", Some("image/jpeg".into()), Some(64), Some(48), 2_000).unwrap();
        assert_eq!(h1, h2, "content-addressed: identical bytes hash equally");
        assert_eq!(s.list().unwrap(), vec![h1.clone()], "deduped to one entry");

        assert!(s.has(&h1).unwrap());
        let meta = s.meta(&h1).unwrap().unwrap();
        assert_eq!(
            (meta.mime.as_str(), meta.w, meta.h, meta.size, meta.created),
            ("image/jpeg", Some(64), Some(48), 10, 1_000)
        );
        let data = s.get(&h1).unwrap().unwrap();
        assert_eq!((data.bytes.as_slice(), data.mime.as_str()), (&b"jpeg-bytes"[..], "image/jpeg"));

        // A different byte string is a distinct entry.
        let other = s.put(b"other", None, None, None, 3_000).unwrap();
        assert_ne!(other, h1);
        assert_eq!(s.meta(&other).unwrap().unwrap().mime, "application/octet-stream", "default mime");

        s.delete(&h1).unwrap();
        assert!(!s.has(&h1).unwrap());
        assert!(s.get(&h1).unwrap().is_none());
        assert!(s.meta(&h1).unwrap().is_none());
        assert_eq!(s.list().unwrap(), vec![other], "delete removed only the target");
    }
}
