//! Media blob upload/download — the presigned, entitlement-gated media path
//! (SERVER-DATA-FORMAT §9.9/§9.10, §12, §17).
//!
//! Bytes never traverse Lambda: the server checks entitlements + reserves quota,
//! then hands the client a short-TTL presigned URL (upload to a *staging* key, with
//! the declared object hash signed in so the backend rejects mismatched bytes). A
//! separate **confirm** promotes staging → the canonical key only after a HEAD
//! validates size, so a referenced blob is always real. All storage bills the tree
//! **owner** (owner-pays, §17); the two account meters are independent, so media
//! usage never touches the tree-editing path.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::Access;
use crate::trees::ApiError;
use crate::AppState;

/// Client upload window. Long enough for a large media PUT, short enough that a
/// leaked URL is a brief exposure of one already-encrypted blob.
const UPLOAD_TTL: Duration = Duration::from_secs(600);
/// Client download window.
const DOWNLOAD_TTL: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
pub struct IntentRequest {
    /// Size of the exact bytes the client will upload (the whole serialized Envelope).
    size_bytes: i64,
    /// Base64 SHA-256 of those exact bytes — signed into the presigned PUT so the
    /// backend rejects a mismatched body (§9.10).
    object_sha256: String,
}

fn staging_key(tree: Uuid, blob: Uuid) -> String {
    format!("staging/{}/{}", tree.simple(), blob.simple())
}
fn final_key(tree: Uuid, blob: Uuid) -> String {
    format!("blobs/{}/{}", tree.simple(), blob.simple())
}
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// `POST /trees/{tree_id}/media/intent` — check the owner's entitlements, atomically
/// reserve quota, and return a presigned staging upload. Owner-pays: quota is the
/// tree owner's, resolved from `trees.owner_id` (§17).
pub async fn intent(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Json(req): Json<IntentRequest>,
) -> Result<Response, ApiError> {
    if req.size_bytes <= 0 {
        return Err(ApiError::BadRequest("size_bytes must be positive".into()));
    }
    // The declared object hash must be a real base64 SHA-256, or the signed presign
    // header is meaningless.
    let ok = base64::engine::general_purpose::STANDARD
        .decode(req.object_sha256.as_bytes())
        .ok()
        .is_some_and(|d| d.len() == 32);
    if !ok {
        return Err(ApiError::BadRequest(
            "object_sha256 must be base64 of a 32-byte SHA-256".into(),
        ));
    }

    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::StageMedia).await?;

    // Atomic entitlement gate + reservation (the cas_create pattern, §9.9): media
    // allowed, blob ≤ per-blob cap, pool + count have room. Reserved at intent so
    // parallel intents can't overshoot.
    let reserved = sqlx::query(
        "UPDATE accounts
            SET media_used_bytes = media_used_bytes + $2,
                blob_count = blob_count + 1
          WHERE id = $1 AND allow_media
            AND $2 <= max_blob_bytes
            AND media_used_bytes + $2 <= max_storage_bytes
            AND blob_count + 1 <= max_blob_count",
    )
    .bind(owner)
    .bind(req.size_bytes)
    .execute(&state.db)
    .await
    .map_err(internal)?;
    if reserved.rows_affected() != 1 {
        return Err(reserve_error(&state, owner, req.size_bytes).await);
    }

    // Mint the blob id + a pending row pointing at the staging key.
    let blob = Uuid::new_v4();
    let staging = staging_key(tree_id, blob);
    if let Err(e) = sqlx::query(
        "INSERT INTO tree_blobs (tree_id, blob_id, r2_key, size_bytes, state, uploaded_by)
         VALUES ($1, $2, $3, $4, 0, $5)",
    )
    .bind(tree_id)
    .bind(blob.as_bytes().as_slice())
    .bind(&staging)
    .bind(req.size_bytes)
    .bind(identity.member_id)
    .execute(&state.db)
    .await
    {
        release(&state, owner, req.size_bytes).await; // don't leak the reservation
        return Err(internal(e));
    }

    let upload = state.storage.presign_put(&staging, &req.object_sha256, UPLOAD_TTL);
    Ok((
        StatusCode::OK,
        Json(json!({
            "blob_id": blob.simple().to_string(),
            "upload_url": upload.url,
            "required_headers": upload.required_headers,
        })),
    )
        .into_response())
}

/// `POST /trees/{tree_id}/media/{blob_id}/confirm` — validate the staged upload and
/// promote it. HEAD checks the observed size ≤ what was declared/reserved (no
/// under-declaring past the reserve), reconciles the meter to the observed size,
/// then CopyObject staging → the canonical key and flips the row to `live`.
pub async fn confirm(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, blob_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let blob_bytes = blob_id.as_bytes().as_slice();
    let row: Option<(Uuid, String, i64, i16)> = sqlx::query_as(
        "SELECT t.owner_id, b.r2_key, b.size_bytes, b.state
           FROM tree_blobs b JOIN trees t ON t.id = b.tree_id
          WHERE b.tree_id = $1 AND b.blob_id = $2",
    )
    .bind(tree_id)
    .bind(blob_bytes)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let (owner, key, declared, statev) = row.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::StageMedia).await?;
    if statev == 1 {
        // Already confirmed — idempotent success (clients retry).
        return Ok(live_response(blob_id, declared));
    }
    if statev != 0 {
        return Err(ApiError::Conflict); // tombstoned; not confirmable
    }

    let head = state
        .storage
        .head_object(&key)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::BadRequest("no staged upload to confirm".into()))?;
    let actual = head.size as i64;

    if actual > declared {
        // Under-declared to dodge the reserve → reject, release, clean up.
        cleanup_rejected(&state, owner, tree_id, blob_id, declared, &key).await;
        return Err(ApiError::BadRequest(
            "uploaded size exceeds the declared size".into(),
        ));
    }
    if actual < declared {
        // Reconcile the meter down to observed size (§9.9b).
        let _ = sqlx::query("UPDATE accounts SET media_used_bytes = media_used_bytes - $2 WHERE id = $1")
            .bind(owner)
            .bind(declared - actual)
            .execute(&state.db)
            .await;
    }

    let final_k = final_key(tree_id, blob_id);
    state
        .storage
        .copy_object(&key, &final_k)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    sqlx::query("UPDATE tree_blobs SET state = 1, r2_key = $3, size_bytes = $4 WHERE tree_id = $1 AND blob_id = $2")
        .bind(tree_id)
        .bind(blob_bytes)
        .bind(&final_k)
        .bind(actual)
        .execute(&state.db)
        .await
        .map_err(internal)?;
    let _ = state.storage.delete_object(&key).await; // best-effort staging cleanup

    Ok(live_response(blob_id, actual))
}

/// `GET /trees/{tree_id}/media/{blob_id}` — a short-TTL presigned download URL for a
/// live blob. `404` for absent/pending/tombstoned (§12 graceful absence).
pub async fn get_media(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, blob_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let row: Option<(Uuid, String, i16)> = sqlx::query_as(
        "SELECT t.owner_id, b.r2_key, b.state
           FROM tree_blobs b JOIN trees t ON t.id = b.tree_id
          WHERE b.tree_id = $1 AND b.blob_id = $2",
    )
    .bind(tree_id)
    .bind(blob_id.as_bytes().as_slice())
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let (owner, key, statev) = row.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;
    if statev != 1 {
        return Err(ApiError::NotFound); // only live blobs are downloadable
    }
    let url = state.storage.presign_get(&key, DOWNLOAD_TTL);
    Ok((
        StatusCode::OK,
        Json(json!({ "blob_id": blob_id.simple().to_string(), "download_url": url })),
    )
        .into_response())
}

fn live_response(blob_id: Uuid, size: i64) -> Response {
    (
        StatusCode::OK,
        Json(json!({ "blob_id": blob_id.simple().to_string(), "state": "live", "size_bytes": size })),
    )
        .into_response()
}

/// Diagnose a failed reservation into a truthful error (media disabled / blob too
/// big / quota) and record a quota event.
async fn reserve_error(state: &AppState, owner: Uuid, size: i64) -> ApiError {
    match sqlx::query_as::<_, (bool, i64, i64)>(
        "SELECT allow_media, max_blob_bytes, max_storage_bytes FROM accounts WHERE id = $1",
    )
    .bind(owner)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some((allow, max_blob, _max_storage))) => {
            if !allow {
                ApiError::Forbidden // media not permitted on this plan
            } else if size > max_blob {
                ApiError::BadRequest("blob exceeds the per-file size limit".into())
            } else {
                tracing::info!(event = "quota_rejected", resource = "media", %owner);
                ApiError::QuotaExceeded
            }
        }
        Ok(None) => ApiError::Forbidden,
        Err(e) => ApiError::Internal(e.to_string()),
    }
}

/// Release a reservation (bytes + one count) — used when a pending row can't be
/// created, or a confirm is rejected.
async fn release(state: &AppState, owner: Uuid, size: i64) {
    let _ = sqlx::query(
        "UPDATE accounts SET media_used_bytes = media_used_bytes - $2, blob_count = blob_count - 1 WHERE id = $1",
    )
    .bind(owner)
    .bind(size)
    .execute(&state.db)
    .await;
}

async fn cleanup_rejected(
    state: &AppState,
    owner: Uuid,
    tree_id: Uuid,
    blob_id: Uuid,
    reserved: i64,
    staging: &str,
) {
    release(state, owner, reserved).await;
    let _ = sqlx::query("DELETE FROM tree_blobs WHERE tree_id = $1 AND blob_id = $2")
        .bind(tree_id)
        .bind(blob_id.as_bytes().as_slice())
        .execute(&state.db)
        .await;
    let _ = state.storage.delete_object(staging).await;
}

// ---- Presence-based GC (§9.11, §12): refcount + tombstone-with-revive ----------

/// Look up a blob's owner + state for an attach/detach op. 404 if absent; 403 if not
/// the caller's; Conflict if still pending (must confirm before referencing).
async fn load_for_ref(
    state: &AppState,
    identity: &Identity,
    tree_id: Uuid,
    blob_id: Uuid,
) -> Result<i16, ApiError> {
    let row: Option<(Uuid, i16)> = sqlx::query_as(
        "SELECT t.owner_id, b.state
           FROM tree_blobs b JOIN trees t ON t.id = b.tree_id
          WHERE b.tree_id = $1 AND b.blob_id = $2",
    )
    .bind(tree_id)
    .bind(blob_id.as_bytes().as_slice())
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let (owner, statev) = row.ok_or(ApiError::NotFound)?;
    // attach/detach mutate the refcount, which tracks the tree doc's actual references — a commit.
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Commit).await?;
    if statev == 0 {
        return Err(ApiError::Conflict); // pending — confirm before attaching
    }
    Ok(statev)
}

/// `POST /trees/{id}/media/{blob}/attach` — the client references this blob from its
/// tree doc: bump refcount, and **revive** it if it was tombstoned (§12). Meter is
/// unchanged (a tombstoned blob still occupied its bytes).
pub async fn attach(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, blob_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    load_for_ref(&state, &identity, tree_id, blob_id).await?;
    let (ref_count,): (i32,) = sqlx::query_as(
        "UPDATE tree_blobs
            SET ref_count = ref_count + 1, state = 1, tombstoned_at = NULL
          WHERE tree_id = $1 AND blob_id = $2
        RETURNING ref_count",
    )
    .bind(tree_id)
    .bind(blob_id.as_bytes().as_slice())
    .fetch_one(&state.db)
    .await
    .map_err(internal)?;
    Ok(ref_response(blob_id, ref_count, "live"))
}

/// `POST /trees/{id}/media/{blob}/detach` — drop a reference: decrement, and when it
/// hits zero move to **tombstoned** (revivable) with a timestamp — never a physical
/// delete (§9.11). Meter unchanged until the sweeper physically deletes.
pub async fn detach(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, blob_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let statev = load_for_ref(&state, &identity, tree_id, blob_id).await?;
    if statev == 2 {
        return Ok(ref_response(blob_id, 0, "tombstoned")); // already tombstoned — idempotent
    }
    let (ref_count, new_state): (i32, i16) = sqlx::query_as(
        "UPDATE tree_blobs
            SET ref_count = GREATEST(ref_count - 1, 0),
                state = CASE WHEN ref_count - 1 <= 0 THEN 2 ELSE 1 END,
                tombstoned_at = CASE WHEN ref_count - 1 <= 0 THEN now() ELSE tombstoned_at END
          WHERE tree_id = $1 AND blob_id = $2 AND state = 1
        RETURNING ref_count, state",
    )
    .bind(tree_id)
    .bind(blob_id.as_bytes().as_slice())
    .fetch_one(&state.db)
    .await
    .map_err(internal)?;
    Ok(ref_response(
        blob_id,
        ref_count,
        if new_state == 2 { "tombstoned" } else { "live" },
    ))
}

fn ref_response(blob_id: Uuid, ref_count: i32, state: &str) -> Response {
    (
        StatusCode::OK,
        Json(json!({ "blob_id": blob_id.simple().to_string(), "ref_count": ref_count, "state": state })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct SweepParams {
    /// Override the tombstone grace (seconds) — for tests/manual runs. Default 30d.
    tombstone_grace_secs: Option<i64>,
    /// Override the pending-intent expiry (seconds). Default 1h.
    pending_expiry_secs: Option<i64>,
}

const DEFAULT_TOMBSTONE_GRACE_SECS: i64 = 30 * 24 * 3600;
const DEFAULT_PENDING_EXPIRY_SECS: i64 = 3600;

/// `POST /dev/gc` (local only) — run the physical sweep. In production this logic is
/// driven by a scheduled trigger (EventBridge → an authenticated internal call), not
/// a public route.
pub async fn sweep_dev(
    State(state): State<AppState>,
    Query(p): Query<SweepParams>,
) -> Result<Response, ApiError> {
    let (deleted, expired, proposals_expired) = run_sweep(
        &state,
        p.tombstone_grace_secs.unwrap_or(DEFAULT_TOMBSTONE_GRACE_SECS),
        p.pending_expiry_secs.unwrap_or(DEFAULT_PENDING_EXPIRY_SECS),
    )
    .await?;
    Ok(Json(json!({
        "physically_deleted": deleted,
        "pending_expired": expired,
        "proposals_expired": proposals_expired,
    }))
    .into_response())
}

/// Physical GC: delete tombstoned blobs past their grace window (crediting the meter
/// back — the *only* place usage is returned, §9.9a), expire abandoned pending
/// intents (releasing the reservation + the staging object), and reclaim expired
/// proposals + stale day-count ledger rows.
async fn run_sweep(
    state: &AppState,
    tombstone_grace_secs: i64,
    pending_expiry_secs: i64,
) -> Result<(usize, usize, usize), ApiError> {
    // 1. Expired tombstones → physical delete + meter credit.
    let tombs: Vec<(Uuid, Vec<u8>, String, i64, Uuid)> = sqlx::query_as(
        "SELECT b.tree_id, b.blob_id, b.r2_key, b.size_bytes, t.owner_id
           FROM tree_blobs b JOIN trees t ON t.id = b.tree_id
          WHERE b.state = 2
            AND b.tombstoned_at <= now() - make_interval(secs => $1::double precision)",
    )
    .bind(tombstone_grace_secs)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;
    let mut deleted = 0usize;
    for (tree_id, blob, key, size, owner) in &tombs {
        let _ = state.storage.delete_object(key).await;
        release(state, *owner, *size).await;
        let _ = sqlx::query("DELETE FROM tree_blobs WHERE tree_id = $1 AND blob_id = $2")
            .bind(tree_id)
            .bind(blob.as_slice())
            .execute(&state.db)
            .await;
        deleted += 1;
    }

    // 2. Expired pending intents → release reservation + delete the staging object.
    let pend: Vec<(Uuid, Vec<u8>, String, i64, Uuid)> = sqlx::query_as(
        "SELECT b.tree_id, b.blob_id, b.r2_key, b.size_bytes, t.owner_id
           FROM tree_blobs b JOIN trees t ON t.id = b.tree_id
          WHERE b.state = 0
            AND b.created_at <= now() - make_interval(secs => $1::double precision)",
    )
    .bind(pending_expiry_secs)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;
    let mut expired = 0usize;
    for (tree_id, blob, key, size, owner) in &pend {
        release(state, *owner, *size).await;
        let _ = state.storage.delete_object(key).await;
        let _ = sqlx::query("DELETE FROM tree_blobs WHERE tree_id = $1 AND blob_id = $2")
            .bind(tree_id)
            .bind(blob.as_slice())
            .execute(&state.db)
            .await;
        expired += 1;
    }

    // 3. Expired proposals → physical delete. They're already invisible to reads (lists filter on
    // expires_at); this reclaims the rows. Proposals don't touch a byte meter, so there's nothing to
    // credit back. Old day-count ledger rows (well past the day) are reclaimed too.
    let props = sqlx::query("DELETE FROM proposals WHERE expires_at <= now()")
        .execute(&state.db)
        .await
        .map_err(internal)?;
    let _ = sqlx::query("DELETE FROM proposal_day_counts WHERE day < current_date - 1")
        .execute(&state.db)
        .await;
    let proposals_expired = props.rows_affected() as usize;

    Ok((deleted, expired, proposals_expired))
}
