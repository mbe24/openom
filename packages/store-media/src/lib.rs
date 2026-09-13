//! The durable media blob store (OPE-435/436): the `SQLite` backing for `apps/app/src/core/blobs.js`'s
//! `TauriBlobStore`. Content-addressed images/attachments live NEXT TO the document, never inside it — a CRDT
//! delta carries a few hundred bytes (the hash), not a photo, and the same scan uploaded twice hashes to one
//! entry. The web build keeps these in memory (`MemoryBlobStore`, cleared on lock); the Tauri build persists
//! them here so they survive a relaunch.
//!
//! This store is a DUMB, crypto-free keyed table of OPAQUE bytes. Under OPE-436 the bytes it holds are the
//! SEALED envelope (ciphertext) — the host seals under the tree DEK before `put` and opens after `get_sealed`,
//! so the plaintext never reaches disk. The `hash` is the content address (SHA-256 of the PLAINTEXT, computed
//! by the host) and `size` is the plaintext length; the store treats both as given and never inspects a byte.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS blobs (
       hash    TEXT PRIMARY KEY,
       mime    TEXT NOT NULL,
       w       INTEGER,
       h       INTEGER,
       size    INTEGER NOT NULL,
       bytes   BLOB NOT NULL,
       created INTEGER NOT NULL
     );";

/// One stored blob's metadata (`blob_meta`), mirroring `MemoryBlobStore.meta`'s shape. `size` is the
/// PLAINTEXT length (recorded at `put`), not the sealed byte count.
#[derive(serde::Serialize)]
pub struct BlobMeta {
    pub mime: String,
    pub w: Option<u32>,
    pub h: Option<u32>,
    pub size: u64,
    /// Wall-clock milliseconds the blob was first stored.
    pub created: i64,
}

/// The descriptive fields a [`MediaStore::put`] records alongside the sealed bytes: mime, pixel dimensions,
/// the PLAINTEXT size, and the created stamp (the host computes all of these — the store just persists them).
pub struct PutMeta {
    pub mime: Option<String>,
    pub w: Option<u32>,
    pub h: Option<u32>,
    /// The plaintext length (the sealed byte count differs by the AEAD overhead).
    pub size: u64,
    /// Wall-clock milliseconds.
    pub created: i64,
}

/// A decrypted blob's bytes + mime (`blob_get`) — the shape the host returns to the webview after opening the
/// sealed bytes; it wraps them in a `Blob` for an object URL. (This store never produces the plaintext; the
/// host does. The DTO lives here so the storage crate owns the whole `blob_*` return contract.)
#[derive(serde::Serialize)]
pub struct BlobData {
    pub bytes: Vec<u8>,
    pub mime: String,
}

/// The durable content-addressed media store (its own `{doc}.media.sqlite`, separate from the vault + doc
/// stores). Holds opaque (host-sealed) bytes keyed by the plaintext content hash.
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

    /// Store `sealed` (opaque, host-sealed) bytes under the content address `hash` (SHA-256 of the plaintext,
    /// computed by the host). Idempotent: a re-`put` of the same hash is a no-op — content addressing means
    /// identical plaintext maps to one entry, so a nonced re-seal never displaces the first. `size` is the
    /// plaintext length (the sealed byte count differs by the AEAD overhead).
    ///
    /// # Errors
    /// Returns an error string if the write fails.
    pub fn put(&self, hash: &str, sealed: &[u8], meta: PutMeta) -> Result<(), String> {
        let mime = meta.mime.unwrap_or_else(|| "application/octet-stream".to_string());
        self.conn()
            .execute(
                "INSERT INTO blobs (hash, mime, w, h, size, bytes, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(hash) DO NOTHING",
                params![hash, mime, meta.w, meta.h, meta.size, sealed, meta.created],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
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

    /// `hash`'s metadata, or `None` if absent. No decryption needed — metadata is stored in the clear.
    ///
    /// # Errors
    /// Returns an error string if the read fails.
    pub fn meta(&self, hash: &str) -> Result<Option<BlobMeta>, String> {
        self.conn()
            .query_row(
                "SELECT mime, w, h, size, created FROM blobs WHERE hash = ?1",
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

    /// `hash`'s SEALED bytes + mime, or `None` if absent. The host opens the bytes under the tree DEK before
    /// returning them to the webview — this store never sees the plaintext.
    ///
    /// # Errors
    /// Returns an error string if the read fails.
    pub fn get_sealed(&self, hash: &str) -> Result<Option<(Vec<u8>, String)>, String> {
        self.conn()
            .query_row(
                "SELECT bytes, mime FROM blobs WHERE hash = ?1",
                params![hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
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
    use super::{MediaStore, PutMeta};

    fn jpeg_meta() -> PutMeta {
        PutMeta { mime: Some("image/jpeg".into()), w: Some(64), h: Some(48), size: 10, created: 1_000 }
    }

    #[test]
    fn put_is_idempotent_by_hash_and_round_trips_opaque_bytes() {
        let s = MediaStore::open(":memory:").unwrap();
        // The host passes (content-hash, sealed-bytes, PutMeta{…, plaintext-size}). The store keys on the hash
        // and treats the bytes as opaque.
        s.put("deadbeef", b"sealed-1", jpeg_meta()).unwrap();
        // Same hash → no-op (a nonced re-seal with different bytes must NOT displace the first entry).
        s.put("deadbeef", b"sealed-2-different", PutMeta { created: 2_000, ..jpeg_meta() }).unwrap();
        assert_eq!(s.list().unwrap(), vec!["deadbeef".to_string()], "deduped to one entry by hash");

        assert!(s.has("deadbeef").unwrap());
        let meta = s.meta("deadbeef").unwrap().unwrap();
        assert_eq!(
            (meta.mime.as_str(), meta.w, meta.h, meta.size, meta.created),
            ("image/jpeg", Some(64), Some(48), 10, 1_000),
            "metadata is the first put's; size is the PLAINTEXT length, not the sealed byte count"
        );
        let (sealed, mime) = s.get_sealed("deadbeef").unwrap().unwrap();
        assert_eq!((sealed.as_slice(), mime.as_str()), (&b"sealed-1"[..], "image/jpeg"), "first bytes kept");

        // A different hash is a distinct entry; default mime when none given.
        s.put("cafef00d", b"other", PutMeta { mime: None, w: None, h: None, size: 5, created: 3_000 }).unwrap();
        assert_eq!(s.meta("cafef00d").unwrap().unwrap().mime, "application/octet-stream", "default mime");

        s.delete("deadbeef").unwrap();
        assert!(!s.has("deadbeef").unwrap());
        assert!(s.get_sealed("deadbeef").unwrap().is_none());
        assert!(s.meta("deadbeef").unwrap().is_none());
        assert_eq!(s.list().unwrap(), vec!["cafef00d".to_string()], "delete removed only the target");
    }
}
