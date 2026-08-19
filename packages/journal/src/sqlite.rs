use super::*;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

// One schema for both constructors. `updates` carries only opaque bytes now — the metadata
// that used to sit in a `meta` column moved inside the sealed envelope (see `Update`).
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS docs (
       doc_id   TEXT PRIMARY KEY,
       snapshot BLOB,
       version  TEXT,
       counter  INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE IF NOT EXISTS updates (
       doc_id TEXT NOT NULL,
       seq    INTEGER NOT NULL,
       bytes  BLOB NOT NULL,
       PRIMARY KEY (doc_id, seq)
     );";

/// SQLite: dieselbe CAS-Logik und dasselbe Schema, ob flüchtig im Speicher (Tests) oder
/// dauerhaft in einer Datei (Tauri-App).
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Flüchtig — für Tests und den früheren Prototyp.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| StoreError::Backend(e.to_string()))?;
        conn.execute_batch(&format!("PRAGMA journal_mode = MEMORY;\n{SCHEMA}"))
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Dauerhaft, dateigestützt. WAL + `synchronous = NORMAL`, weil der Crash-Retry-Entwurf
    /// den dauerhaften lokalen Commit zum Write-Ahead-Punkt macht — ein `MEMORY`-Journal
    /// würde genau die Zusage brechen, dass ein bestätigter Append einen Neustart überlebt.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| StoreError::Backend(e.to_string()))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = WAL;\n PRAGMA synchronous = NORMAL;\n{SCHEMA}"
        ))
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn ensure(conn: &Connection, doc: &str) -> Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO docs (doc_id) VALUES (?1)",
            params![doc],
        )
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl DocStore for SqliteStore {
    fn caps(&self) -> Caps {
        Caps {
            remote: false,
            conditional_writes: true,
            durable: false,
            max_blob_bytes: 1 << 30,
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT doc_id FROM docs ORDER BY doc_id")
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    fn read_snapshot(&self, doc: &str) -> Result<Option<Snapshot>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT snapshot, version FROM docs WHERE doc_id = ?1")
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut rows = stmt
            .query(params![doc])
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| StoreError::Backend(e.to_string()))?
        {
            let bytes: Option<Vec<u8>> = row.get(0).ok();
            let version: Option<String> = row.get(1).ok();
            if let (Some(bytes), Some(version)) = (bytes, version) {
                return Ok(Some(Snapshot { bytes, version }));
            }
        }
        Ok(None)
    }

    fn read_updates(&self, doc: &str, since: Option<u64>) -> Result<(Vec<Update>, u64)> {
        let conn = self.conn.lock().unwrap();
        let from = since.unwrap_or(0) as i64;
        let mut stmt = conn
            .prepare("SELECT bytes, seq FROM updates WHERE doc_id = ?1 AND seq > ?2 ORDER BY seq")
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map(params![doc, from], |r| {
                let bytes: Vec<u8> = r.get(0)?;
                let seq: i64 = r.get(1)?;
                Ok((bytes, seq))
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        let mut last = from as u64;
        for row in rows {
            let (bytes, seq) = row.map_err(|e| StoreError::Backend(e.to_string()))?;
            out.push(bytes);
            last = seq as u64;
        }
        Ok((out, last))
    }

    fn append(&self, doc: &str, updates: &[Update]) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Self::ensure(&conn, doc)?;
        let mut seq: i64 = conn
            .query_row(
                "SELECT counter FROM docs WHERE doc_id = ?1",
                params![doc],
                |r| r.get(0),
            )
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        for bytes in updates {
            seq += 1;
            conn.execute(
                "INSERT INTO updates (doc_id, seq, bytes) VALUES (?1, ?2, ?3)",
                params![doc, seq, bytes],
            )
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        conn.execute(
            "UPDATE docs SET counter = ?2 WHERE doc_id = ?1",
            params![doc, seq],
        )
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(seq as u64)
    }

    fn put_snapshot(&self, doc: &str, bytes: &[u8], expected: Option<&str>) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        Self::ensure(&conn, doc)?;
        let found: Option<String> = conn
            .query_row(
                "SELECT version FROM docs WHERE doc_id = ?1",
                params![doc],
                |r| r.get(0),
            )
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        if found.as_deref() != expected {
            return Err(StoreError::Conflict {
                expected: expected.map(String::from),
                found,
            });
        }
        let counter: i64 = conn
            .query_row(
                "SELECT counter FROM docs WHERE doc_id = ?1",
                params![doc],
                |r| r.get(0),
            )
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let version = format!("v{}", counter + 1);
        conn.execute(
            "UPDATE docs SET snapshot = ?2, version = ?3, counter = ?4 WHERE doc_id = ?1",
            params![doc, bytes, version, counter + 1],
        )
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(version)
    }

    fn delete(&self, doc: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM updates WHERE doc_id = ?1", params![doc])
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        conn.execute("DELETE FROM docs WHERE doc_id = ?1", params![doc])
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }
}
