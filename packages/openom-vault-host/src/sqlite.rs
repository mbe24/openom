//! A durable [`VaultStore`] on `SQLite`, for the Tauri host.
//!
//! Holds the keyring (a wrapped DEK —
//! not secret, needs only durability) and the keyring-revision watermark (anti-rollback state)
//! in the app data dir. Fable's guidance: keep this in its OWN file (`vault.sqlite`), separate
//! from the doc store's `tree.sqlite`, so copying/restoring the tree database can't drag the
//! watermark back with it.
//!
//! [`commit_keyring`] writes the keyring and advances the watermark in ONE transaction, so a
//! crash can never leave them disagreeing. The unlock path uses [`observe_keyring_revision`] to
//! re-assert the floor without touching the keyring.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use store_schema::ResetPolicy;

use crate::VaultStore;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS keyrings (
       tree_key TEXT PRIMARY KEY,
       bytes    BLOB NOT NULL
     );
     CREATE TABLE IF NOT EXISTS watermarks (
       tree_key  TEXT PRIMARY KEY,
       watermark BLOB NOT NULL
     );";

/// The schema version stamped in the DB header (`PRAGMA user_version`). BUMP THIS whenever [`SCHEMA`] changes
/// (the golden-shape test enforces it). Anti-drift: on a version mismatch, `open` self-heals in DEBUG (renaming
/// the stale DB to a `.bak` — this store holds the only local wrapped-DEK copy + the anti-rollback watermark, so
/// it is NEVER destroyed) and FAILS CLOSED in release (errors, touches nothing). See [`store_schema`].
const SCHEMA_VERSION: i64 = 1;

pub struct SqliteVaultStore {
    conn: Mutex<Connection>,
}

impl SqliteVaultStore {
    /// Durable, file-backed (WAL). Use the app data dir on Tauri. Versioned via [`store_schema::open_versioned`]
    /// with the [`ResetPolicy::Preserve`] policy (a schema mismatch renames the stale DB to a recoverable `.bak`
    /// in debug, and fails closed in release — never destroying the keyring/watermark).
    ///
    /// # Errors
    /// Returns an error string if the database can't be opened, or (release) if the on-disk schema version
    /// doesn't match this build.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = store_schema::open_versioned(path.as_ref(), SCHEMA_VERSION, SCHEMA, ResetPolicy::Preserve)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Flüchtig — für Tests. No on-disk drift is possible, so it just creates the schema and stamps the version.
    ///
    /// # Errors
    /// Returns an error string if the in-memory database can't be opened or the schema can't be applied.
    pub fn in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.execute_batch(&format!("{SCHEMA}\nPRAGMA user_version = {SCHEMA_VERSION};"))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl VaultStore for SqliteVaultStore {
    fn load_keyring(&self, tree_key: &str) -> Result<Option<Vec<u8>>, String> {
        self.conn()
            .query_row(
                "SELECT bytes FROM keyrings WHERE tree_key = ?1",
                params![tree_key],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.to_string()),
            })
    }

    fn watermark(&self, tree_key: &str) -> Result<Vec<u8>, String> {
        // Engine-OPAQUE bytes (the anti-rollback order check lives inside the engine); read + return.
        self.conn()
            .query_row(
                "SELECT watermark FROM watermarks WHERE tree_key = ?1",
                params![tree_key],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(Vec::new()),
                other => Err(other.to_string()),
            })
    }

    fn commit_keyring(
        &self,
        tree_key: &str,
        anchor: &[u8],
        watermark: &[u8],
    ) -> Result<(), String> {
        // One transaction: the keyring write and the watermark advance land together or not at all,
        // so a crash can never leave a saved keyring with a stale cursor (or vice versa). The cursor
        // is write-through opaque bytes (the engine owns the order), so no MAX here.
        let mut guard = self.conn();
        let tx = guard.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO keyrings (tree_key, bytes) VALUES (?1, ?2)
             ON CONFLICT(tree_key) DO UPDATE SET bytes = excluded.bytes",
            params![tree_key, anchor],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO watermarks (tree_key, watermark) VALUES (?1, ?2)
             ON CONFLICT(tree_key) DO UPDATE SET watermark = excluded.watermark",
            params![tree_key, watermark],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_and_watermark_persist_across_reopen() {
        let path = std::env::temp_dir().join(format!("openom-vault-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = SqliteVaultStore::open(&path).unwrap();
            // The watermark is engine-opaque write-through bytes — last write wins (the engine, not the
            // store, owns anti-rollback), and the keyring + its cursor land in one transaction.
            s.commit_keyring("my-tree", b"kr-bytes", &[0, 0, 0, 1])
                .unwrap();
            s.commit_keyring("my-tree", b"kr-bytes", &[0, 0, 0, 3])
                .unwrap();
        }
        {
            let s = SqliteVaultStore::open(&path).unwrap();
            assert_eq!(
                s.load_keyring("my-tree").unwrap().as_deref(),
                Some(&b"kr-bytes"[..])
            );
            assert_eq!(s.watermark("my-tree").unwrap(), vec![0, 0, 0, 3]);
            assert_eq!(s.load_keyring("absent").unwrap(), None);
            assert!(s.watermark("absent").unwrap().is_empty());
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(path.with_extension(format!("sqlite{suffix}")));
        }
    }

    /// Golden-shape tripwire: if [`SCHEMA`] changes, this assertion breaks and forces the author to update it —
    /// AND, deliberately, to bump [`SCHEMA_VERSION`] in the same edit (the pair is asserted together). Compares
    /// the semantic column shape, not the literal `CREATE TABLE` text, so a pure reformat doesn't trip it.
    #[test]
    fn schema_shape_is_pinned_to_the_version() {
        let s = SqliteVaultStore::in_memory().unwrap();
        let conn = s.conn();
        let shape = store_schema::schema_shape(&conn).unwrap();
        assert_eq!(
            (SCHEMA_VERSION, shape.as_str()),
            (
                1,
                "keyrings(tree_key:TEXT nn=0 pk=1, bytes:BLOB nn=1 pk=0)\n\
                 watermarks(tree_key:TEXT nn=0 pk=1, watermark:BLOB nn=1 pk=0)\n"
            ),
            "SCHEMA changed: update this golden AND bump SCHEMA_VERSION"
        );
    }
}
