//! Data-channel blob store — the R2 + Neon realization of the `store-blob` `BlobStore` contract the
//! client already speaks (`packages/docsync/src/lib.rs`, OPE-397). See
//! `plan/sync/design.ope398-managed-server.md` — this module is build-order steps 3/4 of §6.
//!
//! The server does not literally `impl store_blob::BlobStore` (that trait is synchronous, for in-process
//! local backends); these handlers realize the same logical semantics — get / put-with-precondition /
//! list-by-prefix — over HTTP, backed by R2 (opaque bytes) + a Postgres index (`tree_blob_index`) that
//! arbitrates the precondition and serves prefix LIST in O(matching rows) (§2). No DELETE route: that's
//! GC-internal only (§4, deferred — not built here).
//!
//! **Zero-knowledge**: unlike `log.rs`/`trees.rs`, there is no `Envelope` to decode here — the `sub` path
//! is the client's OPAQUE key and the body is opaque bytes. This module never parses either.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::Access;
use crate::trees::ApiError;
use crate::AppState;

/// A `sub` key's segment/length bounds — defensive validation before it ever touches R2 or Neon,
/// mirroring `store-blob`'s `FsBlob::path_for` traversal guard and `access.rs`'s `MAX_BASIS_TOKEN_LEN`
/// pattern. The client never sends anything close to these (its longest key is a log dot), so they exist
/// purely to bound a hostile request.
const MAX_SUB_LEN: usize = 512;
const MAX_SUB_SEGMENTS: usize = 16;
/// `?prefix=` bound (LIST is a Postgres index scan, not R2 traversal, but a request param still needs a
/// ceiling).
const MAX_PREFIX_LEN: usize = 512;
/// The `heads/{replica}` pointer is one small encoded counter (`docsync::encode_count`, ASCII decimal) —
/// a tiny fixed ceiling catches anything obviously wrong without per-object accounting (§1).
const HEADS_MAX_BYTES: usize = 4 * 1024;

// A value->value error conversion used as a `.map_err(fn)` argument; `&` would force a closure per call.
#[allow(clippy::needless_pass_by_value)]
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// Reject an empty/oversized key, or one with an empty/`.`/`..` segment — the traversal guard `sub` needs
/// before it's used to build an R2 key or a LIKE-prefix param.
fn validate_sub(sub: &str) -> Result<(), ApiError> {
    if sub.is_empty() || sub.len() > MAX_SUB_LEN {
        return Err(ApiError::BadRequest(
            "blob key is empty or too long".into(),
        ));
    }
    let segs: Vec<&str> = sub.split('/').collect();
    if segs.len() > MAX_SUB_SEGMENTS || segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return Err(ApiError::BadRequest(
            "blob key has an empty or traversal segment".into(),
        ));
    }
    Ok(())
}

/// `sub`'s leading path component — the namespace the shipped client wire uses (`log`, `heads`,
/// `snapshot`, `docsync::lib.rs:406-447`) to pick a per-object body-size cap (§1).
fn namespace_of(sub: &str) -> &str {
    sub.split('/').next().unwrap_or("")
}

/// Per-namespace body ceiling (§1): `log/` keeps the scalar delta cap (an immutable data-channel delta is
/// the same kind of payload), `snapshot` gets a cap close to the proxy ceiling
/// (`trees::MAX_OBJECT_BYTES`), and the tiny `heads/{replica}` pointer gets a fixed few-KB cap. A leading
/// segment outside these three (not part of the shipped client wire, §1) falls back to the smallest
/// (`log`) cap — conservative rather than permissive for an unrecognized namespace.
fn cap_for(namespace: &str) -> usize {
    match namespace {
        "snapshot" => crate::trees::MAX_OBJECT_BYTES,
        "heads" => HEADS_MAX_BYTES,
        _ => crate::log::MAX_DELTA_BYTES,
    }
}

/// `if-none-match: *` (`remoteStore.js:221`'s only conditional header) selects `Precondition::IfAbsent`;
/// anything else (including no header) is `Precondition::Any` — `IfMatch` has no wire representation yet
/// (§1, §5.5).
fn is_if_absent(headers: &HeaderMap) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "*")
}

/// The content-hash etag `store-blob`'s reference impls use (`hex(sha256(bytes))`), so a client reading
/// this store and a client reading `MemoryBlob`/`FsBlob` see the same etag convention.
fn etag_of(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes).iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn etag_header(tag: &str) -> String {
    format!("\"{tag}\"")
}

fn precondition_failed(tag: &str) -> Response {
    (StatusCode::PRECONDITION_FAILED, [(ETAG, etag_header(tag))]).into_response()
}

/// Resolve `tree_id`'s owner, minting the row if this is the first write anyone has made to it.
///
/// **Flagged default (open question #3, §3.2/§5.3 of design.ope398-managed-server.md):** with the scalar
/// `PUT /trees/{id}` gone from the client's write path, nothing else mints the `trees` row. This mirrors
/// `trees::cas_create`'s "first snapshot PUT creates the tree, gated on `max_trees`" shape — the caller
/// performing this first write becomes the owner, exactly as `cas_create` keys off `identity.member_id`
/// today — applied to the first blob PUT instead (any key; in practice the genesis delta,
/// `log/{replica}/0`). The scalar-envelope columns (`object_key`, `envelope_version`, `aead`) this table
/// still carries get placeholder defaults; a tree minted this way has no scalar snapshot, which
/// `trees::get_tree` already renders as a graceful 404 via its `snapshot_version IS NULL` check, so the
/// two write paths don't collide as long as nothing also PUTs a scalar snapshot to the same tree.
async fn resolve_or_mint_owner(state: &AppState, tree_id: Uuid, caller: Uuid) -> Result<Uuid, ApiError> {
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    if let Some(owner) = existing {
        return Ok(owner);
    }

    let inserted = sqlx::query(
        "INSERT INTO trees (id, owner_id, object_key, envelope_version, aead, size_bytes, covers_through_seq)
         SELECT $1, $2, '', 0, 0, 0, 0
         WHERE (SELECT count(*) FROM trees WHERE owner_id = $2)
             < (SELECT max_trees FROM accounts WHERE id = $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tree_id)
    .bind(caller)
    .execute(&state.db)
    .await
    .map_err(internal)?;
    if inserted.rows_affected() == 1 {
        return Ok(caller);
    }

    // 0 rows: a concurrent first-writer beat us to it, or the entitlement gate blocked the mint.
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    if let Some(owner) = existing {
        return Ok(owner);
    }
    let limits: Option<(i64, i32)> = sqlx::query_as(
        "SELECT (SELECT count(*) FROM trees WHERE owner_id = $1), a.max_trees
           FROM accounts a WHERE a.id = $1",
    )
    .bind(caller)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    match limits {
        Some((count, max)) if count >= i64::from(max) => {
            tracing::info!(event = "quota_rejected", resource = "trees", owner = %caller);
            Err(ApiError::QuotaExceeded)
        }
        None => Err(ApiError::Forbidden), // unknown account
        Some(_) => Err(ApiError::Conflict), // guard passed yet insert lost — retry
    }
}

/// `PUT /trees/{tree_id}/blobs/{*sub}` — write one opaque blob under `sub`, per the precondition mapping
/// (§1): `if-none-match: *` -> `Precondition::IfAbsent` (immutable; a conflict is `412`, which the client
/// already treats as idempotent success), no header -> `Precondition::Any` (unconditional pointer
/// overwrite, `heads/{replica}` / `snapshot`).
///
/// Authz is `Access::Commit` (§3.2), re-homed verbatim from `crate::authz::authorize`. Metering re-homes
/// `log::charge_metering` (§3.1): the rate gate fires on every PUT; the capacity gate fires only for an
/// `IfAbsent` (immutable, accumulating) write. An `IfAbsent` PUT whose key already exists short-circuits
/// before metering or the R2 write — a **flagged, non-literal reading of §2's pseudocode**: treating a
/// duplicate immutable PUT as an unmetered no-op mirrors `log::append_log`'s "re-deliveries are never
/// metered" idempotency discipline (the client already documents a same-key retry as expected,
/// `docsync/src/lib.rs:614-621`), rather than charging capacity again for bytes R2 already holds.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized, the key/body is invalid, metering rejects the
/// write, or the store access fails.
pub async fn put_blob(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, sub)): Path<(Uuid, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("blobs.put");
    validate_sub(&sub)?;
    let cap = cap_for(namespace_of(&sub));
    if body.len() > cap {
        return Err(ApiError::BadRequest(
            "blob exceeds the per-namespace size limit".into(),
        ));
    }
    let if_absent = is_if_absent(&headers);

    let owner = resolve_or_mint_owner(&state, tree_id, identity.member_id).await?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Commit).await?;

    let key = crate::storage::keys::data_blob(tree_id, &sub);
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);

    let mut tx = state.db.begin().await.map_err(internal)?;

    if if_absent {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
                .bind(tree_id)
                .bind(&sub)
                .fetch_optional(&mut *tx)
                .await
                .map_err(internal)?;
        if let Some((tag,)) = existing {
            tx.commit().await.map_err(internal)?;
            return Ok(precondition_failed(&tag));
        }
    }

    // Metering: rate always, capacity only for an immutable write (§3.1). Runs before the R2 write, in
    // the transaction that also holds the index upsert, so a rejected write charges nothing (the same
    // "metered inside the tx that's rolled back on failure" shape as log::append_log).
    crate::log::charge_metering(&mut tx, tree_id, owner, identity.member_id, size, if_absent).await?;

    state
        .storage
        .put_object(&key, body.to_vec())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let tag = etag_of(&body);
    let rows = if if_absent {
        sqlx::query(
            "INSERT INTO tree_blob_index (tree_id, key, etag, size_bytes) VALUES ($1, $2, $3, $4)
             ON CONFLICT (tree_id, key) DO NOTHING",
        )
        .bind(tree_id)
        .bind(&sub)
        .bind(&tag)
        .bind(size)
        .execute(&mut *tx)
        .await
        .map_err(internal)?
    } else {
        sqlx::query(
            "INSERT INTO tree_blob_index (tree_id, key, etag, size_bytes) VALUES ($1, $2, $3, $4)
             ON CONFLICT (tree_id, key) DO UPDATE SET etag = EXCLUDED.etag, size_bytes = EXCLUDED.size_bytes",
        )
        .bind(tree_id)
        .bind(&sub)
        .bind(&tag)
        .bind(size)
        .execute(&mut *tx)
        .await
        .map_err(internal)?
    };

    if if_absent && rows.rows_affected() == 0 {
        // Lost a race against a concurrent first-writer between our pre-check and this insert. ROLL BACK
        // (not commit): our `charge_metering` above ran in this tx, but the WINNER already accounted for
        // this immutable object — committing here would double-charge the owner's capacity for one object.
        // Rolling back reverts our charge; the winner's index row stands. The R2 write above is left (it's
        // the same deterministic content for this key, §2 — a harmless duplicate, not an orphan).
        tx.rollback().await.map_err(internal)?;
        let winner: (String,) =
            sqlx::query_as("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
                .bind(tree_id)
                .bind(&sub)
                .fetch_one(&state.db)
                .await
                .map_err(internal)?;
        return Ok(precondition_failed(&winner.0));
    }

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "blob_put", %tree_id, key = %sub, if_absent, size, "blob written");
    Ok((StatusCode::OK, [(ETAG, etag_header(&tag))]).into_response())
}

/// `GET /trees/{tree_id}/blobs/{*sub}` — the raw bytes at `sub`, or `404` if absent (graceful-absence,
/// same as `storage.rs`'s `get_object`). `Access::Read`-gated.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized, the key is invalid, or the store access fails.
pub async fn get_blob(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, sub)): Path<(Uuid, String)>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("blobs.get");
    validate_sub(&sub)?;

    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let key = crate::storage::keys::data_blob(tree_id, &sub);
    let bytes = state
        .storage
        .get_object(&key)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;

    let tag = etag_of(&bytes);
    Ok((
        StatusCode::OK,
        [
            (ETAG, etag_header(&tag)),
            (CONTENT_TYPE, "application/octet-stream".to_string()),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// Restrict the listing to keys under this sub-prefix (relative to the tree, like `sub`); omitted or
    /// empty lists the whole tree.
    prefix: Option<String>,
}

#[derive(Serialize)]
struct ListedKey {
    key: String,
    etag: String,
}

/// `GET /trees/{tree_id}/blobs?prefix=<sub>` — the keys under `prefix` (or the whole tree), served from
/// `tree_blob_index` (§2: an index scan, never an R2 `ListObjectsV2` fan-out). `Access::Read`-gated.
/// Response: `{"keys": [{"key", "etag"}]}`, keys relative to the tree segment (`remoteStore.js:205`
/// re-prepends `{tree}/`).
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized, `prefix` is oversized, or the store access fails.
pub async fn list_blobs(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("blobs.list");
    let prefix = q.prefix.unwrap_or_default();
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(ApiError::BadRequest("prefix exceeds the size limit".into()));
    }

    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, etag FROM tree_blob_index
          WHERE tree_id = $1 AND ($2 = '' OR key LIKE $2 || '%')
          ORDER BY key",
    )
    .bind(tree_id)
    .bind(&prefix)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let keys: Vec<ListedKey> = rows
        .into_iter()
        .map(|(key, etag)| ListedKey { key, etag })
        .collect();
    Ok((StatusCode::OK, Json(json!({ "keys": keys }))).into_response())
}
