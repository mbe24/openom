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

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Identity;
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
    if owner != identity.member_id {
        return Err(ApiError::Forbidden);
    }

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
        "INSERT INTO tree_blobs (tree_id, blob_id, r2_key, size_bytes, state)
         VALUES ($1, $2, $3, $4, 0)",
    )
    .bind(tree_id)
    .bind(blob.as_bytes().as_slice())
    .bind(&staging)
    .bind(req.size_bytes)
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
    if owner != identity.member_id {
        return Err(ApiError::Forbidden);
    }
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
    if owner != identity.member_id {
        return Err(ApiError::Forbidden);
    }
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
