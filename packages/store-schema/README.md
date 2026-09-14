# store-schema
> Versioned `SQLite` open: the one place the schema-drift policy lives — shared by the native vault and media stores.

**Status:** built · infrastructure / no-trust · design.storage (schema versioning; reviewed 2026-09-14)
**Last updated:** 2026-09-14

## What it is — and is not

`open_versioned(path, version, schema_sql, policy)` opens (or creates) a `SQLite` DB and reconciles its
`PRAGMA user_version` header with the caller's `SCHEMA_VERSION`:

- **Fresh file** (no user tables) → create the schema and stamp the version, in ONE transaction.
- **Version matches** → open as-is.
- **Mismatch** (an older/legacy DB with no migration path, or a newer/downgrade DB):
  - **Debug build** (`debug_assertions`) → self-heal per the caller's [`ResetPolicy`], so a dev's stale DB
    across a schema change resets instead of bricking the app.
  - **Release build** → return [`SchemaError::Mismatch`] and touch NOTHING. Fail closed: never destroy a
    user's data on a schema change. The caller surfaces the error (never a silent panic).

The destructive/reset path is compiled in ONLY under `debug_assertions`, so a shipped binary physically cannot
wipe a DB on a schema mismatch (the CI guard `scripts/check-no-debug-build.mjs` keeps every shipping build a
release build). Motivating bug: a `CREATE TABLE IF NOT EXISTS` column rename silently kept a stale table on an
existing device — `IF NOT EXISTS` never alters a table that already exists, and every test used a fresh
in-memory DB, so nothing caught it until a query hit the missing column at runtime.

**It is NOT a store.** It holds no tables, rows, or queries of its own — the real schemas (keyrings/watermarks,
media blobs) live in the caller crates (`openom-vault-host`, `store-media`). **It is not a migration framework
either:** pre-release the ladder is empty (a schema change just bumps the caller's `SCHEMA_VERSION`); this is the
seam a real, ordered migration ladder grows into post-launch, when the release branch stops being "error" and
becomes "migrate".

Why `user_version` over a `schema_meta` table or a schema hash: it lives in the file header (transactional with
the DDL), is ordered (upgrade vs downgrade is decidable), and needs no bootstrap table that would itself need
versioning. The hash idea survives only as a CI-time golden-shape tripwire — see [`schema_shape`].

## Invariants

| id | guarantee | why | verified by |
|----|-----------|-----|-------------|
| SS-1 | A fresh file is created + stamped; a matching-version file opens with data intact | the common paths never reset | `matching_version_reopens_untouched` |
| SS-2 | `user_version = 0` WITH existing tables is treated as legacy, not fresh — the schema is never layered over a stale table | reproduces + prevents the motivating bug (a stale DB stamped "current") | `debug_recreatable_heals_a_stale_schema` |
| SS-3 | Debug mismatch self-heals per policy; `Preserve` renames to `.bak-v{old}` (never deletes) keeping exactly one backup | the vault holds the only local wrapped-DEK copy + anti-rollback floor — a self-heal must be recoverable, not destructive | `debug_preserve_renames_to_bak_and_keeps_one` |
| SS-4 | Release mismatch returns `Mismatch` and leaves the on-disk data byte-for-byte untouched (no reset, no backup) | fail closed — a schema change must never destroy a user's data | `release_fails_closed_without_touching_data` |
| SS-5 | `schema_shape` is whitespace-insensitive — a reformatted schema string yields the same shape | the golden-shape tripwire must flag a real schema change, not a reflow | `schema_shape_is_stable_and_ignores_formatting` |

The debug-only tests run under `cargo test`; the release-contract test (SS-4) is compiled only under
`--release` (`cargo test -p store-schema --release`).

## Usage

```rust,no_run
use store_schema::{open_versioned, ResetPolicy};

// A cache DB: on a schema mismatch, a debug build drops+recreates; a release build errors (fails closed).
let path = std::env::temp_dir().join("media.sqlite");
let conn = open_versioned(
    &path,
    1, // SCHEMA_VERSION — bump whenever the schema string changes
    "CREATE TABLE blobs (hash TEXT PRIMARY KEY, bytes BLOB NOT NULL);",
    ResetPolicy::Recreatable, // vault-like stores use ResetPolicy::Preserve
)?;
conn.execute("INSERT INTO blobs (hash, bytes) VALUES (?1, ?2)", ("h", &b"x"[..]))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

A caller pairs a `SCHEMA_VERSION` const with a golden-shape test that asserts `(SCHEMA_VERSION,
schema_shape(&conn))` against a checked-in constant — so a schema change that forgets to bump the version fails
CI (see `openom-vault-host` / `store-media`).

## Position

Foundations layer, storage family: below the concrete `SQLite` stores (`openom-vault-host`, `store-media`),
which call it to open their databases. openom-free (only `rusqlite` + `thiserror`).
