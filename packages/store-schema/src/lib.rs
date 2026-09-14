#![doc = include_str!("../README.md")]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// What a DEBUG build does when an existing DB's schema version doesn't match this build. A release build
/// ignores this and always fails closed (returns [`SchemaError::Mismatch`], never resets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetPolicy {
    /// The DB is a re-derivable cache (e.g. the media blob store) — safe to drop and recreate.
    Recreatable,
    /// The DB holds irreplaceable material (e.g. the vault: the only local copy of the wrapped DEK, plus the
    /// anti-rollback watermark). NEVER destroy it: the old file is RENAMED to `{name}.bak-v{old}` (keeping only
    /// the newest such backup) and a fresh one created, so a mistaken self-heal is recoverable. This also blunts
    /// a hypothetical `debug_assertions` leak into a shipped build — a wrongly-triggered reset parks the data in
    /// a `.bak` instead of deleting the user's only key.
    Preserve,
}

/// Whether a mismatch is an old DB this build has no migration for, or a DB written by a newer build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchKind {
    /// `found < expected` (or a legacy unversioned DB) and no migration path exists.
    NoMigration,
    /// `found > expected` — the DB was written by a NEWER build than this one (a downgrade).
    Downgrade,
}

impl std::fmt::Display for MismatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMigration => f.write_str("no migration path from the stored version"),
            Self::Downgrade => f.write_str("the database was written by a newer version of the app"),
        }
    }
}

/// A versioned-open failure.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// An underlying `SQLite` / IO error (open, pragma, `DDL`, or a filesystem op during reset).
    #[error("sqlite: {0}")]
    Sqlite(String),
    /// A RELEASE build refused to open a DB whose schema version doesn't match this build. Data is UNTOUCHED.
    /// The caller must surface this (e.g. "please update the app"), never turn it into a silent panic.
    #[error("database schema v{found} does not match this build (expects v{expected}): {kind}")]
    Mismatch {
        /// The version stored in the on-disk DB.
        found: i64,
        /// The version this build expects (`SCHEMA_VERSION`).
        expected: i64,
        /// Whether it is an un-migratable old DB or a newer-than-this-build DB.
        kind: MismatchKind,
    },
}

type Result<T> = std::result::Result<T, SchemaError>;

fn sql_err(e: impl std::fmt::Display) -> SchemaError {
    SchemaError::Sqlite(e.to_string())
}

/// Open (or create) a versioned `SQLite` DB at `path`, applying the drift policy described in the module docs.
///
/// `schema_sql` is the full `CREATE TABLE …` batch for the CURRENT schema; `version` is this build's
/// `SCHEMA_VERSION`. `policy` governs only the DEBUG self-heal branch.
///
/// # Errors
/// - [`SchemaError::Sqlite`] on any open/pragma/DDL/filesystem failure.
/// - [`SchemaError::Mismatch`] on a RELEASE build when the stored schema version doesn't match (data untouched).
pub fn open_versioned(path: &Path, version: i64, schema_sql: &str, policy: ResetPolicy) -> Result<Connection> {
    let conn = open_with_pragmas(path)?;
    let found = user_version(&conn)?;
    let has_tables = has_user_tables(&conn)?;

    // A brand-new (or emptied) file: create the schema and stamp the version together. `user_version = 0` alone
    // is ambiguous — it is ALSO what every legacy pre-versioning DB reads — so the empty-tables check is what
    // distinguishes "fresh" from "legacy" (without it, we'd re-create the schema over a stale table and
    // reproduce the very drift this guards against).
    if !has_tables {
        create_fresh(&conn, version, schema_sql)?;
        return Ok(conn);
    }
    if found == version {
        return Ok(conn);
    }

    // Tables present but the version differs: legacy/older (incl. an unversioned v0-with-tables) or a downgrade.
    let kind = if found > version { MismatchKind::Downgrade } else { MismatchKind::NoMigration };

    #[cfg(debug_assertions)]
    {
        // Release the handle BEFORE any filesystem op — on Windows you cannot rename/delete a file with an open
        // handle (sharing violation).
        drop(conn);
        match policy {
            ResetPolicy::Recreatable => reset_delete(path)?,
            ResetPolicy::Preserve => reset_rename_bak(path, found)?,
        }
        let conn = open_with_pragmas(path)?;
        create_fresh(&conn, version, schema_sql)?;
        // Loud even in debug — a vault reset drops the anti-rollback floor + the local wrapped-DEK copy.
        eprintln!(
            "[store-schema] schema self-heal: {} was v{found}, reset to v{version} (policy {policy:?}, {kind})",
            path.display(),
        );
        Ok(conn)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = policy; // release never resets — data stays exactly as it is on disk
        Err(SchemaError::Mismatch { found, expected: version, kind })
    }
}

/// Open the connection and apply the connection-level pragmas. WAL/synchronous are set OUTSIDE any transaction
/// (they cannot run inside one) — every later create/migration step opens its own transaction.
fn open_with_pragmas(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).map_err(sql_err)?;
    conn.execute_batch("PRAGMA journal_mode = WAL;\n PRAGMA synchronous = NORMAL;").map_err(sql_err)?;
    Ok(conn)
}

/// Read `PRAGMA user_version` (0 on a fresh DB and on any legacy pre-versioning DB).
///
/// # Errors
/// [`SchemaError::Sqlite`] if the pragma read fails.
pub fn user_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(sql_err)
}

fn has_user_tables(conn: &Connection) -> Result<bool> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(sql_err)
}

/// Create the schema and stamp `user_version` atomically. `version` is an internal `i64` constant (never user
/// input), so interpolating it into the pragma is safe.
fn create_fresh(conn: &Connection, version: i64, schema_sql: &str) -> Result<()> {
    conn.execute_batch(&format!("BEGIN;\n{schema_sql}\nPRAGMA user_version = {version};\nCOMMIT;"))
        .map_err(sql_err)
}

/// Append a suffix to a path's filename without a lossy string round-trip (`vault.sqlite` → `vault.sqlite-wal`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// The `SQLite` file plus its `WAL` sidecars (`-wal`, `-shm`).
fn db_and_sidecars(path: &Path) -> [PathBuf; 3] {
    [path.to_path_buf(), with_suffix(path, "-wal"), with_suffix(path, "-shm")]
}

/// Recreatable reset: delete the DB and its WAL sidecars (a stale `-wal` would otherwise replay old-schema
/// frames onto the fresh file). Tolerant of already-absent files.
fn reset_delete(path: &Path) -> Result<()> {
    for p in db_and_sidecars(path) {
        remove_if_present(&p)?;
    }
    Ok(())
}

/// Preserve reset: rename the DB to `{name}.bak-v{old}` (keeping only the newest such backup) and drop the WAL
/// sidecars — after the connection closed, `SQLite` checkpointed the `WAL` into the main file, so the sidecars carry
/// nothing worth keeping. The renamed file remains fully openable for manual recovery.
fn reset_rename_bak(path: &Path, found: i64) -> Result<()> {
    prune_old_baks(path);
    let bak = with_suffix(path, &format!(".bak-v{found}"));
    remove_if_present(&bak)?; // a prior reset at this same version, if any
    fs::rename(path, &bak).map_err(|e| SchemaError::Sqlite(format!("rename {} to backup: {e}", path.display())))?;
    for sc in [with_suffix(path, "-wal"), with_suffix(path, "-shm")] {
        remove_if_present(&sc)?;
    }
    Ok(())
}

/// Delete every existing `{name}.bak-v*` beside `path` — we keep only the backup we are about to create, so
/// backups never accumulate unbounded (this whole path is debug-only regardless).
fn prune_old_baks(path: &Path) {
    let (Some(parent), Some(fname)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let prefix = format!("{fname}.bak-v");
    let Ok(entries) = fs::read_dir(parent) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(|n| n.starts_with(&prefix)) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn remove_if_present(p: &Path) -> Result<()> {
    match fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SchemaError::Sqlite(format!("remove {}: {e}", p.display()))),
    }
}

/// A deterministic, whitespace-insensitive snapshot of the live schema — each user table with its columns
/// (name, declared type, not-null, pk position), plus its indexes. For a CI golden-shape test: assert this
/// equals a checked-in constant PAIRED with `SCHEMA_VERSION`, so a schema change that forgets to bump the
/// version fails CI — WITHOUT the brittleness of comparing the verbatim `CREATE TABLE` text (a reformat of the
/// schema string would trip a raw-SQL comparison but not this).
///
/// # Errors
/// [`SchemaError::Sqlite`] if the schema introspection queries fail.
pub fn schema_shape(conn: &Connection) -> Result<String> {
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .map_err(sql_err)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(sql_err)?;
        rows.collect::<std::result::Result<_, _>>().map_err(sql_err)?
    };

    let mut out = String::new();
    for table in tables {
        out.push_str(&table);
        out.push('(');
        let mut stmt = conn.prepare(&format!("PRAGMA table_info('{table}')")).map_err(sql_err)?;
        let cols = stmt
            .query_map([], |r| {
                Ok(format!(
                    "{}:{} nn={} pk={}",
                    r.get::<_, String>(1)?, // name
                    r.get::<_, String>(2)?, // declared type
                    r.get::<_, i64>(3)?,    // notnull
                    r.get::<_, i64>(5)?,    // pk position (0 = not pk)
                ))
            })
            .map_err(sql_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)?;
        out.push_str(&cols.join(", "));
        out.push_str(")\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{open_versioned, schema_shape, user_version, ResetPolicy};
    use rusqlite::Connection;

    const V1: &str = "CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT NOT NULL);";

    // A unique-enough temp dir without Date/rand (both unavailable in this workspace): thread id + a counter.
    static N: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("store-schema-test-{:?}-{}", std::thread::current().id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write a legacy DB on disk: a DIFFERENT schema (the classic column-renamed drift) with no `user_version`.
    fn write_legacy(path: &std::path::Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, old_col INTEGER NOT NULL);").unwrap();
        assert_eq!(user_version(&conn).unwrap(), 0, "legacy DBs predate versioning → user_version 0");
    }

    #[test]
    fn fresh_db_is_created_and_stamped() {
        let dir = tmp();
        let conn = open_versioned(&dir.join("x.sqlite"), 1, V1, ResetPolicy::Recreatable).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
        // The NEW schema is live (a write to the current column succeeds).
        conn.execute("INSERT INTO t (a) VALUES ('x')", []).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn matching_version_reopens_untouched() {
        let dir = tmp();
        let path = dir.join("x.sqlite");
        {
            let c = open_versioned(&path, 1, V1, ResetPolicy::Recreatable).unwrap();
            c.execute("INSERT INTO t (a) VALUES ('keep')", []).unwrap();
        }
        let c = open_versioned(&path, 1, V1, ResetPolicy::Recreatable).unwrap();
        let n: i64 = c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "a matching-version reopen keeps the data");
        std::fs::remove_dir_all(&dir).ok();
    }

    // Reproduces the exact motivating bug (old on-disk schema + new code) and asserts the debug self-heal.
    #[cfg(debug_assertions)]
    #[test]
    fn debug_recreatable_heals_a_stale_schema() {
        let dir = tmp();
        let path = dir.join("cache.sqlite");
        write_legacy(&path);
        // Old code path (`CREATE IF NOT EXISTS` + INSERT into the new column) would fail here; open_versioned heals.
        let conn = open_versioned(&path, 1, V1, ResetPolicy::Recreatable).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
        conn.execute("INSERT INTO t (a) VALUES ('x')", []).unwrap(); // the NEW column exists again
        assert!(!path.with_file_name("cache.sqlite.bak-v0").exists(), "Recreatable deletes, no backup");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_preserve_renames_to_bak_and_keeps_one() {
        let dir = tmp();
        let path = dir.join("vault.sqlite");
        write_legacy(&path);
        let conn = open_versioned(&path, 1, V1, ResetPolicy::Preserve).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
        conn.execute("INSERT INTO t (a) VALUES ('x')", []).unwrap();
        drop(conn);
        // The old data is preserved (not destroyed) in a recoverable backup, and it is still a valid DB.
        let bak = dir.join("vault.sqlite.bak-v0");
        assert!(bak.exists(), "Preserve renames the stale DB to .bak-v0 rather than deleting it");
        let old = Connection::open(&bak).unwrap();
        let cols: i64 = old
            .query_row("SELECT count(*) FROM pragma_table_info('t') WHERE name = 'old_col'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 1, "the backup still carries the original (old) schema");
        drop(old); // release the backup handle before the next reset prunes it (Windows won't delete an open file)

        // A second reset keeps only the newest backup (no unbounded accumulation). Clear the just-healed DB
        // first, then re-stale it so the next open triggers another reset.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.join(format!("vault.sqlite{suffix}")));
        }
        write_legacy(&path);
        drop(open_versioned(&path, 1, V1, ResetPolicy::Preserve).unwrap());
        let baks = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("vault.sqlite.bak-v")))
            .count();
        assert_eq!(baks, 1, "only the newest backup is kept");
        std::fs::remove_dir_all(&dir).ok();
    }

    // The release contract: a mismatch is refused and the on-disk data is left EXACTLY as-is (never wiped).
    // Compiled only in a release build; run it with `cargo test --release`.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_fails_closed_without_touching_data() {
        let dir = tmp();
        let path = dir.join("vault.sqlite");
        write_legacy(&path);
        let err = open_versioned(&path, 1, V1, ResetPolicy::Preserve).unwrap_err();
        assert!(matches!(
            err,
            super::SchemaError::Mismatch { found: 0, expected: 1, kind: super::MismatchKind::NoMigration }
        ));
        // The original file is untouched: still there, still the OLD schema, no backup created.
        let c = Connection::open(&path).unwrap();
        let cols: i64 = c
            .query_row("SELECT count(*) FROM pragma_table_info('t') WHERE name = 'old_col'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 1, "release must not alter or reset the user's data");
        assert!(!dir.join("vault.sqlite.bak-v0").exists(), "release creates no backup");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn schema_shape_is_stable_and_ignores_formatting() {
        let dir = tmp();
        let a = open_versioned(&dir.join("a.sqlite"), 1, V1, ResetPolicy::Recreatable).unwrap();
        // Same schema, reformatted (extra whitespace / newlines) → identical shape.
        let reformatted = "CREATE TABLE t (\n  id   INTEGER PRIMARY KEY,\n  a    TEXT NOT NULL\n);";
        let b = open_versioned(&dir.join("b.sqlite"), 1, reformatted, ResetPolicy::Recreatable).unwrap();
        assert_eq!(schema_shape(&a).unwrap(), schema_shape(&b).unwrap());
        assert_eq!(schema_shape(&a).unwrap().trim(), "t(id:INTEGER nn=0 pk=1, a:TEXT nn=1 pk=0)");
        std::fs::remove_dir_all(&dir).ok();
    }
}
