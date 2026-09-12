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

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::Access;
use crate::meter::{MeterCtx, WriteAxis};
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

/// The mandatory plaintext covered-frontier header on a snapshot PUT (OPE-409, the ETAG-BINDING D1 slice):
/// base64 of a JSON `{replica: counter}` map — the SUBSUMED frontier the client's snapshot folds. Bounds
/// mirror `frontier.rs` so a hostile client can't bloat the tx.
const COVERED_HEADER: &str = "x-openom-covered";
const MAX_COVERED_REPLICAS: usize = 4096;
const MAX_COVERED_REPLICA_LEN: usize = 128;

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

/// Resolve `tree_id`'s owner, or [`ApiError::NotFound`] if the tree row doesn't exist yet.
///
/// A blob handler never mints (OPE-407, decision 3-B): the tree must be created first via the explicit
/// `POST /trees/{id}` (`trees::create_tree`), so a blob write to a tree that doesn't exist is a `404`, not
/// an implicit create. Shared by `put_blob` / `get_blob` / `list_blobs` — all three resolve the owner the
/// same way before authorizing.
async fn resolve_owner(state: &AppState, tree_id: Uuid) -> Result<Uuid, ApiError> {
    sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?
        .ok_or(ApiError::NotFound)
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

    let owner = resolve_owner(&state, tree_id).await?; // 404 if the tree was never created (OPE-407)
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Commit).await?;
    let cx = MeterCtx { account: owner, tree: tree_id, member: identity.member_id };

    // Three write kinds, each with its own precondition + GC invariant (OPE-409): an immutable `log/*` dot
    // (IfAbsent-forced + below-floor guard), the `snapshot` pointer (the covered-frontier ratchet, under the
    // tree lock), and any other pointer (`heads/*`) — the original precondition flow.
    if namespace_of(&sub) == "log" {
        put_log_blob(&state, cx, &sub, &headers, &body).await
    } else if sub == "snapshot" {
        put_snapshot_blob(&state, cx, &sub, &headers, &body).await
    } else {
        put_pointer_blob(&state, cx, &sub, &headers, &body).await
    }
}

/// Upsert the index row for `key`. `if_absent` picks the immutable `DO NOTHING` (a lost race → 0 rows) vs the
/// pointer `DO UPDATE`. Returns the affected-row count. Never touches `pending_delete_at` (only the sweep and
/// a log re-write clear the mark; pointers are never marked).
async fn upsert_index(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tree_id: Uuid,
    key: &str,
    tag: &str,
    size: i64,
    if_absent: bool,
) -> Result<u64, ApiError> {
    let q = if if_absent {
        "INSERT INTO tree_blob_index (tree_id, key, etag, size_bytes) VALUES ($1, $2, $3, $4)
         ON CONFLICT (tree_id, key) DO NOTHING"
    } else {
        "INSERT INTO tree_blob_index (tree_id, key, etag, size_bytes) VALUES ($1, $2, $3, $4)
         ON CONFLICT (tree_id, key) DO UPDATE SET etag = EXCLUDED.etag, size_bytes = EXCLUDED.size_bytes"
    };
    Ok(sqlx::query(q)
        .bind(tree_id)
        .bind(key)
        .bind(tag)
        .bind(size)
        .execute(&mut **tx)
        .await
        .map_err(internal)?
        .rows_affected())
}

/// `heads/{replica}` and any other non-`log`, non-`snapshot` key: the original precondition flow — `IfAbsent`
/// (immutable, `412` on conflict) vs `Any` (pointer overwrite). Rate always; capacity only for an `IfAbsent`
/// (accumulating) write — a pointer overwrite (`heads/`) is `PointerOnly` (rate only), unchanged from OPE-397.
async fn put_pointer_blob(
    state: &AppState,
    cx: MeterCtx,
    sub: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Response, ApiError> {
    let if_absent = is_if_absent(headers);
    let key = crate::storage::keys::data_blob(cx.tree, sub);
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
    let mut tx = state.db.begin().await.map_err(internal)?;

    if if_absent {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
                .bind(cx.tree)
                .bind(sub)
                .fetch_optional(&mut *tx)
                .await
                .map_err(internal)?;
        if let Some((tag,)) = existing {
            tx.commit().await.map_err(internal)?;
            return Ok(precondition_failed(&tag));
        }
    }

    // Head-pointer monotonicity (OPE-411): a `heads/{replica}` pointer is a plaintext monotonic count. Reject
    // an overwrite that LOWERS it — anti-rollback/griefing, so a malicious member can't roll a peer's head
    // back to disrupt them (the honest owning replica only ever advances; an idempotent re-publish of the same
    // count is fine). Under the tree ratchet lock (the SAME `SELECT … FOR UPDATE` the snapshot PUT + GC mark
    // take) so a concurrent replay of a captured older count can't slip in a lost update. The count's single
    // source of truth stays the R2 object — no denormalized DB copy to drift.
    if !if_absent && namespace_of(sub) == "heads" {
        let new_count = std::str::from_utf8(body)
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .ok_or_else(|| ApiError::BadRequest("heads pointer must be an ASCII decimal count".into()))?;
        sqlx::query("SELECT 1 FROM trees WHERE id = $1 FOR UPDATE")
            .bind(cx.tree)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
        let replica = sub.strip_prefix("heads/").unwrap_or("");
        if new_count < head_count(state, cx.tree, replica).await? {
            tx.rollback().await.map_err(internal)?;
            return Err(ApiError::conflict(
                crate::error_codes::HEAD_ROLLBACK,
                "head pointer must not move backward",
            ));
        }
    }

    // Metered inside the tx that also holds the index upsert, so a rejected write charges nothing.
    let axis = if if_absent {
        WriteAxis::Accumulating
    } else {
        WriteAxis::PointerOnly
    };
    state.meter.charge_write(&mut tx, cx, size, axis).await?;

    state
        .storage
        .put_object(&key, body.to_vec())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let tag = etag_of(body);
    let rows = upsert_index(&mut tx, cx.tree, sub, &tag, size, if_absent).await?;

    if if_absent && rows == 0 {
        // Lost a race against a concurrent first-writer between our pre-check and this insert. ROLL BACK: our
        // charge ran in this tx, but the WINNER already accounted for this immutable object — committing would
        // double-charge. Rolling back reverts our charge; the winner's row stands; the R2 write is the same
        // deterministic content (a harmless duplicate, not an orphan). Same shape as OPE-407's lost-race.
        tx.rollback().await.map_err(internal)?;
        let winner: (String,) =
            sqlx::query_as("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
                .bind(cx.tree)
                .bind(sub)
                .fetch_one(&state.db)
                .await
                .map_err(internal)?;
        return Ok(precondition_failed(&winner.0));
    }

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "blob_put", tree_id = %cx.tree, key = %sub, if_absent, size, "blob written");
    Ok((StatusCode::OK, [(ETAG, etag_header(&tag))]).into_response())
}

/// `log/{replica}/{counter}` → `(replica, counter)`. The client guarantees `replica` carries no `/`
/// (`docsync::head_from_key`), so a log key is exactly three segments; a non-numeric/negative counter is a
/// malformed log key (`400`).
fn parse_log_key(sub: &str) -> Result<(String, i64), ApiError> {
    let segs: Vec<&str> = sub.split('/').collect();
    if segs.len() != 3 || segs[0] != "log" || segs[1].is_empty() {
        return Err(ApiError::BadRequest(
            "malformed log key (expected log/{replica}/{counter})".into(),
        ));
    }
    let counter = segs[2]
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("log counter is not an integer".into()))?;
    if counter < 0 {
        return Err(ApiError::BadRequest("log counter must be non-negative".into()));
    }
    Ok((segs[1].to_string(), counter))
}

/// An immutable `log/*` delta object. M2: the PUT MUST be `IfAbsent` (`400` otherwise) — closes the
/// immutability hole GC would weaponize. D2: an `IfAbsent` PUT whose counter is below the replica's GC floor
/// (its prefix was reclaimed) is `409 below_gc_floor` — never resurrect a reaped dot; the client bootstraps.
/// `Accumulating` (capacity + rate).
async fn put_log_blob(
    state: &AppState,
    cx: MeterCtx,
    sub: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Response, ApiError> {
    if !is_if_absent(headers) {
        return Err(ApiError::BadRequest(
            "a log/* blob PUT must be immutable (if-none-match: *)".into(),
        )); // M2
    }
    let (replica, counter) = parse_log_key(sub)?;
    let key = crate::storage::keys::data_blob(cx.tree, sub);
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
    let mut tx = state.db.begin().await.map_err(internal)?;

    // D2: below the reclaimed floor → the prefix is gone; a re-add would silently diverge. 409 → bootstrap.
    // Checked first, so a re-PUT of a still-present but marked-pending dot (counter < floor, row not yet
    // reaped) also 409s rather than reporting idempotent success for a dot on its way out.
    let floor: Option<i64> =
        sqlx::query_scalar("SELECT floor FROM tree_gc_floor WHERE tree_id = $1 AND replica = $2")
            .bind(cx.tree)
            .bind(&replica)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    if floor.is_some_and(|f| counter < f) {
        tx.rollback().await.map_err(internal)?;
        return Err(ApiError::conflict(
            "below_gc_floor",
            "log entry is below the GC floor — bootstrap from a snapshot",
        ));
    }

    let existing: Option<(String,)> =
        sqlx::query_as("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
            .bind(cx.tree)
            .bind(sub)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    if let Some((tag,)) = existing {
        tx.commit().await.map_err(internal)?;
        return Ok(precondition_failed(&tag));
    }

    state
        .meter
        .charge_write(&mut tx, cx, size, WriteAxis::Accumulating)
        .await?;
    state
        .storage
        .put_object(&key, body.to_vec())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let tag = etag_of(body);
    let rows = upsert_index(&mut tx, cx.tree, sub, &tag, size, true).await?;
    if rows == 0 {
        tx.rollback().await.map_err(internal)?;
        let winner: (String,) =
            sqlx::query_as("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
                .bind(cx.tree)
                .bind(sub)
                .fetch_one(&state.db)
                .await
                .map_err(internal)?;
        return Ok(precondition_failed(&winner.0));
    }
    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "blob_put", tree_id = %cx.tree, key = %sub, if_absent = true, size, "log blob written");
    Ok((StatusCode::OK, [(ETAG, etag_header(&tag))]).into_response())
}

/// The published covered frontier the honest client seals in the snapshot body, sent ALSO as the mandatory
/// plaintext `x-openom-covered` header: base64 of a JSON `{replica: counter}` map (the SUBSUMED frontier).
fn parse_covered(headers: &HeaderMap) -> Result<BTreeMap<String, i64>, ApiError> {
    let raw = headers
        .get(COVERED_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("a snapshot PUT requires the x-openom-covered header".into()))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|_| ApiError::BadRequest("x-openom-covered is not valid base64".into()))?;
    let map: BTreeMap<String, u64> = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::BadRequest("x-openom-covered is not a valid {replica:counter} map".into()))?;
    if map.len() > MAX_COVERED_REPLICAS
        || map.keys().any(|r| r.is_empty() || r.len() > MAX_COVERED_REPLICA_LEN)
    {
        return Err(ApiError::BadRequest(
            "x-openom-covered exceeds the size limit".into(),
        ));
    }
    Ok(map
        .into_iter()
        .map(|(r, c)| (r, i64::try_from(c).unwrap_or(i64::MAX)))
        .collect())
}

/// A replica's published head count (its exclusive frontier) — the value of its `heads/{replica}` pointer
/// (`docsync::encode_count`, ASCII decimal). Absent/unparseable → 0 (a replica with no published head can
/// claim no coverage — the M3 over-claim guard then rejects any non-zero covered for it).
async fn head_count(state: &AppState, tree_id: Uuid, replica: &str) -> Result<i64, ApiError> {
    let key = crate::storage::keys::data_blob(tree_id, &format!("heads/{replica}"));
    let val = state
        .storage
        .get_object(&key)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(val
        .and_then(|b| std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse::<i64>().ok()))
        .unwrap_or(0))
}

/// The `snapshot` pointer key: overwrite the R2 object (`Any`) AND, in ONE tx holding the tree's ratchet lock
/// (the SAME `SELECT … FOR UPDATE` the sweep's MARK takes), validate + install the published covered frontier.
/// Guards, in order: M3 over-claim (`covered[r] > head[r]`), the ratchet (`covered[r] < gc_floor[r]`, or a
/// floored replica missing from the header), and M6 monotonicity (`covered[r] < the currently-published
/// counter`). On success the `tree_snapshot_covered` rows are REPLACED, each bound to the NEW snapshot etag —
/// the ETAG-BINDING that lets GC gate-1 fail closed when the live snapshot object no longer matches the
/// coverage it published. `PointerOnly` (capacity-exempt).
async fn put_snapshot_blob(
    state: &AppState,
    cx: MeterCtx,
    sub: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Response, ApiError> {
    let covered = parse_covered(headers)?; // mandatory; 400 if missing/oversized/malformed
    let key = crate::storage::keys::data_blob(cx.tree, sub);
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);

    let mut tx = state.db.begin().await.map_err(internal)?;
    // Take the per-tree ratchet lock — shared with the sweep's MARK + the below-floor log write.
    sqlx::query("SELECT 1 FROM trees WHERE id = $1 FOR UPDATE")
        .bind(cx.tree)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;

    let floor: BTreeMap<String, i64> =
        sqlx::query_as("SELECT replica, floor FROM tree_gc_floor WHERE tree_id = $1")
            .bind(cx.tree)
            .fetch_all(&mut *tx)
            .await
            .map_err(internal)?
            .into_iter()
            .collect();
    let published: BTreeMap<String, i64> =
        sqlx::query_as("SELECT replica, counter FROM tree_snapshot_covered WHERE tree_id = $1")
            .bind(cx.tree)
            .fetch_all(&mut *tx)
            .await
            .map_err(internal)?
            .into_iter()
            .collect();

    // (a) M3 over-claim: no replica may claim coverage past its published head.
    for (r, c) in &covered {
        if *c > head_count(state, cx.tree, r).await? {
            return Err(ApiError::conflict(
                crate::error_codes::COVERED_ANOMALY,
                "covered frontier exceeds a replica's published head",
            ));
        }
    }
    // (b) ratchet: covered must be at or above the GC floor for every floored replica, and may not drop one.
    for (r, f) in &floor {
        match covered.get(r) {
            Some(c) if *c >= *f => {}
            _ => {
                return Err(ApiError::conflict(
                    crate::error_codes::COVERED_ANOMALY,
                    "covered frontier is below the GC floor for a replica",
                ))
            }
        }
    }
    // (c) M6 monotonicity: covered may not regress a currently-published replica (would stall the floor).
    for (r, p) in &published {
        if covered.get(r).copied().unwrap_or(0) < *p {
            return Err(ApiError::conflict(
                crate::error_codes::COVERED_ANOMALY,
                "covered frontier regresses a currently-published replica",
            ));
        }
    }

    state
        .meter
        .charge_write(&mut tx, cx, size, WriteAxis::PointerOnly)
        .await?;
    state
        .storage
        .put_object(&key, body.to_vec())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let tag = etag_of(body);
    upsert_index(&mut tx, cx.tree, sub, &tag, size, false).await?; // Any overwrite for the snapshot pointer

    // REPLACE the covered rows, each bound to the new snapshot etag (the ETAG-BINDING).
    sqlx::query("DELETE FROM tree_snapshot_covered WHERE tree_id = $1")
        .bind(cx.tree)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    for (r, c) in &covered {
        sqlx::query(
            "INSERT INTO tree_snapshot_covered (tree_id, replica, counter, snapshot_etag)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(cx.tree)
        .bind(r)
        .bind(*c)
        .bind(&tag)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "blob_put", tree_id = %cx.tree, key = %sub, replicas = covered.len(), size, "snapshot published");
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

    let owner = resolve_owner(&state, tree_id).await?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;
    let cx = MeterCtx { account: owner, tree: tree_id, member: identity.member_id };

    // Index-first: the index row arbitrates present / reaped / not-yet-written across the GC-managed log
    // keyspace (C2/M4). A present row (even one marked `pending_delete_at`) serves 200; only a REAPED row is
    // 410 — so the grace window stays a detection window, never a premature Gone.
    let indexed: Option<i64> =
        sqlx::query_scalar("SELECT size_bytes FROM tree_blob_index WHERE tree_id = $1 AND key = $2")
            .bind(tree_id)
            .bind(&sub)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;

    if namespace_of(&sub) == "log" && indexed.is_none() {
        // No row: distinguish a GC-reaped dot (below the floor → 410 BOOTSTRAP) from a genuinely-not-yet
        // -written one (at/above the floor → 404 graceful-absence). The client never has to guess.
        let (replica, counter) = parse_log_key(&sub)?;
        let floor: Option<i64> =
            sqlx::query_scalar("SELECT floor FROM tree_gc_floor WHERE tree_id = $1 AND replica = $2")
                .bind(tree_id)
                .bind(&replica)
                .fetch_optional(&state.db)
                .await
                .map_err(internal)?;
        if floor.is_some_and(|f| counter < f) {
            return Err(ApiError::reaped(
                "this log entry was reclaimed by GC — bootstrap from a snapshot",
            ));
        }
        return Err(ApiError::NotFound); // not yet written
    }

    let key = crate::storage::keys::data_blob(tree_id, &sub);
    let bytes = state
        .storage
        .get_object(&key)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;

    let served = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    let _ = state.meter.charge_read(&state.db, cx, Some(served)).await; // Class B read op (best-effort)

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

    let owner = resolve_owner(&state, tree_id).await?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    // A `pending_delete_at`-marked row is still listed (M4) — it stays served until the sweep reaps it, so a
    // LIST reflects it like any live key. Excludes nothing new.
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

    let cx = MeterCtx { account: owner, tree: tree_id, member: identity.member_id };
    let _ = state.meter.charge_read(&state.db, cx, None).await; // Class B (LIST) op (best-effort)

    let keys: Vec<ListedKey> = rows
        .into_iter()
        .map(|(key, etag)| ListedKey { key, etag })
        .collect();
    Ok((StatusCode::OK, Json(json!({ "keys": keys }))).into_response())
}
