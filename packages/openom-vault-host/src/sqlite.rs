//! A durable [`VaultStore`] on SQLite, for the Tauri host. Holds the keyring (a wrapped DEK —
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

use crate::VaultStore;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS keyrings (
       tree_key TEXT PRIMARY KEY,
       bytes    BLOB NOT NULL
     );
     CREATE TABLE IF NOT EXISTS watermarks (
       tree_key         TEXT PRIMARY KEY,
       keyring_revision INTEGER NOT NULL
     );";

pub struct SqliteVaultStore {
    conn: Mutex<Connection>,
}

impl SqliteVaultStore {
    /// Durable, file-backed (WAL). Use the app data dir on Tauri.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = WAL;\n PRAGMA synchronous = NORMAL;\n{SCHEMA}"
        ))
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Flüchtig — für Tests.
    pub fn in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
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

    fn keyring_watermark(&self, tree_key: &str) -> Result<u32, String> {
        self.conn()
            .query_row(
                "SELECT keyring_revision FROM watermarks WHERE tree_key = ?1",
                params![tree_key],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u32)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(0),
                other => Err(other.to_string()),
            })
    }

    fn observe_keyring_revision(&self, tree_key: &str, revision: u32) -> Result<(), String> {
        // Monotonic: MAX with the stored floor, so a lower value can never lower it.
        self.conn()
            .execute(
                "INSERT INTO watermarks (tree_key, keyring_revision) VALUES (?1, ?2)
                 ON CONFLICT(tree_key) DO UPDATE SET keyring_revision = MAX(keyring_revision, excluded.keyring_revision)",
                params![tree_key, revision as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn commit_keyring(&self, tree_key: &str, bytes: &[u8], revision: u32) -> Result<(), String> {
        // One transaction: the keyring write and the floor advance land together or not at all,
        // so a crash can never leave a saved keyring with a stale floor (or vice versa).
        let mut guard = self.conn();
        let tx = guard.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO keyrings (tree_key, bytes) VALUES (?1, ?2)
             ON CONFLICT(tree_key) DO UPDATE SET bytes = excluded.bytes",
            params![tree_key, bytes],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO watermarks (tree_key, keyring_revision) VALUES (?1, ?2)
             ON CONFLICT(tree_key) DO UPDATE SET keyring_revision = MAX(keyring_revision, excluded.keyring_revision)",
            params![tree_key, revision as i64],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VaultErrorCode, VaultHost};

    const TREE: &[u8] = b"tree-uuid-16byte";

    #[test]
    fn keyring_and_watermark_persist_across_reopen() {
        let path = std::env::temp_dir().join(format!("openom-vault-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = SqliteVaultStore::open(&path).unwrap();
            s.commit_keyring("my-tree", b"kr-bytes", 3).unwrap();
            s.commit_keyring("my-tree", b"kr-bytes", 1).unwrap(); // lower revision — must not lower the floor
        }
        {
            let s = SqliteVaultStore::open(&path).unwrap();
            assert_eq!(
                s.load_keyring("my-tree").unwrap().as_deref(),
                Some(&b"kr-bytes"[..])
            );
            assert_eq!(s.keyring_watermark("my-tree").unwrap(), 3);
            assert_eq!(s.load_keyring("absent").unwrap(), None);
            assert_eq!(s.keyring_watermark("absent").unwrap(), 0);
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(path.with_extension(format!("sqlite{suffix}")));
        }
    }

    #[test]
    fn a_vault_host_over_sqlite_provisions_and_unlocks() {
        // The whole host, over real SQLite: provision persists a keyring; a fresh unlock (as if a
        // relaunch) re-derives the same DEK and opens data sealed before.
        let host = VaultHost::new(SqliteVaultStore::in_memory().unwrap());
        let p = host
            .provision("my-tree", TREE, "correct horse".into(), "owner")
            .unwrap();
        let envelope = host
            .seal_entry(
                &p.sealer_id,
                "snapshot",
                "openom-json",
                "none",
                0,
                Vec::new(),
                0,
                Vec::new(),
                b"data",
            )
            .unwrap()
            .envelope;
        host.lock(&p.sealer_id);

        let u = host
            .unlock("my-tree", TREE, "correct horse".into(), "owner")
            .unwrap();
        assert_eq!(
            host.open_entry(&u.sealer_id, "snapshot", &envelope)
                .unwrap(),
            b"data"
        );
        assert_eq!(
            host.unlock("my-tree", TREE, "wrong".into(), "owner")
                .unwrap_err()
                .code,
            VaultErrorCode::CryptoOpen
        );
    }
}
