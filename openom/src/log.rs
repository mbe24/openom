//! Delta-log append/read — the sync + change-history path (track B1).
//!
//! A tree's edits are an append-only log of sealed **delta** envelopes. Peers append their deltas and
//! pull each other's tail; all merging is client-side (the server never decrypts). The log is also the
//! substrate for the paid change-history feature, so each row keeps author metadata (member/replica/
//! size/time) beside the opaque `payload`.
//!
//! Sequence numbers are assigned under a per-tree row lock (`SELECT … FOR UPDATE`) so concurrent
//! appenders get a gap-free, collision-free total order — without it a later-committed seq could become
//! visible before an earlier one and a tail-puller would skip an entry. The idempotency dot
//! `(tree_id, replica_id, replica_counter)` makes a re-delivered append a no-op that returns the
//! original seq. Payloads are stored inline in Postgres (deltas are small; R2 spillover is a follow-up).

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use openom_protocol::v1::{Envelope, Kind};
use openom_protocol::{Message, ENVELOPE_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Identity;
use crate::trees::ApiError;
use crate::AppState;

/// Per-append inline cap. Deltas are tiny; a payload near this should be a snapshot instead. (A larger
/// ceiling + R2 spillover is a later slice.)
const MAX_DELTA_BYTES: usize = 1024 * 1024;
/// Keep a tail response comfortably under the Lambda ~6 MB response ceiling; the client pages with the
/// returned cursor.
const TAIL_BYTE_BUDGET: usize = 4 * 1024 * 1024;
const TAIL_MAX_ENTRIES: i64 = 1024;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

struct DeltaValidated {
    ciphertext_hash: Vec<u8>,
    replica_id: Vec<u8>,
    replica_counter: i64,
    size: i64,
}

/// Validate a delta envelope against the log contract: decodable, supported version, `KIND_DELTA`,
/// bound to this tree, non-dev key (prod), and a recomputable `ciphertext_hash`.
fn validate_delta(body: &[u8], tree_id: Uuid, reject_dev_key: bool) -> Result<DeltaValidated, ApiError> {
    let env = Envelope::decode(body).map_err(|e| ApiError::BadRequest(format!("not a valid envelope: {e}")))?;
    if env.version != ENVELOPE_VERSION {
        return Err(ApiError::BadRequest(format!(
            "unsupported envelope version {} (server speaks {ENVELOPE_VERSION})",
            env.version
        )));
    }
    let header = env.header.as_ref().ok_or_else(|| ApiError::BadRequest("envelope has no header".into()))?;
    if header.kind() != Kind::Delta {
        return Err(ApiError::BadRequest("the log path accepts only KIND_DELTA".into()));
    }
    if header.tree_id.as_slice() != tree_id.as_bytes() {
        return Err(ApiError::BadRequest("header tree_id does not match the url".into()));
    }
    if reject_dev_key && header.key_id.as_slice() == openom_crypto::DEV_KEY_ID {
        return Err(ApiError::BadRequest("dev key_id refused under RUN_MODE=production (§16)".into()));
    }
    let computed = Sha256::digest(&env.ciphertext);
    if header.ciphertext_hash.as_slice() != computed.as_slice() {
        return Err(ApiError::BadRequest("ciphertext_hash does not match the ciphertext".into()));
    }
    Ok(DeltaValidated {
        ciphertext_hash: header.ciphertext_hash.clone(),
        replica_id: header.replica_id.clone(),
        replica_counter: header.replica_counter as i64,
        size: body.len() as i64,
    })
}

#[derive(Serialize)]
struct AppendResult {
    seq: i64,
}

/// `POST /trees/{tree_id}/log` — append one sealed delta. Returns its assigned `seq` (or the existing
/// one on an idempotent re-delivery). The tree must already exist (created by an initial snapshot PUT).
pub async fn append_log(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("log.append");
    if body.len() > MAX_DELTA_BYTES {
        return Err(ApiError::BadRequest("delta exceeds the per-append size limit".into()));
    }
    let d = validate_delta(&body, tree_id, !state.config.is_local())?;

    let mut tx = state.db.begin().await.map_err(internal)?;
    // Serialize seq assignment on this tree: lock the row, so concurrent appenders can't gap/collide.
    let row: Option<(Uuid, i64)> =
        sqlx::query_as("SELECT owner_id, next_log_seq FROM trees WHERE id = $1 FOR UPDATE")
            .bind(tree_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    let (owner, next_seq) = row.ok_or(ApiError::NotFound)?;
    if owner != identity.member_id {
        return Err(ApiError::Forbidden);
    }

    // Idempotent re-delivery: the dot is already present → return its seq, assign nothing new.
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT seq FROM tree_log WHERE tree_id = $1 AND replica_id = $2 AND replica_counter = $3",
    )
    .bind(tree_id)
    .bind(&d.replica_id)
    .bind(d.replica_counter)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    if let Some((seq,)) = existing {
        tx.commit().await.map_err(internal)?;
        return Ok((StatusCode::OK, Json(AppendResult { seq })).into_response());
    }

    let seq = next_seq;
    sqlx::query(
        "INSERT INTO tree_log
             (tree_id, seq, kind, replica_id, replica_counter, member_id, payload, ciphertext_hash, size_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(tree_id)
    .bind(seq)
    .bind(Kind::Delta as i16)
    .bind(&d.replica_id)
    .bind(d.replica_counter)
    .bind(identity.member_id)
    .bind(body.as_ref())
    .bind(&d.ciphertext_hash)
    .bind(d.size)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query("UPDATE trees SET next_log_seq = $1, updated_at = now() WHERE id = $2")
        .bind(seq + 1)
        .bind(tree_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "log_append", %tree_id, seq, "delta appended");
    Ok((StatusCode::OK, Json(AppendResult { seq })).into_response())
}

#[derive(Deserialize)]
pub struct LogQuery {
    /// Return entries with `seq > since`. Omit (or -1) for the whole retained log.
    since: Option<i64>,
}

#[derive(Serialize)]
struct LogEntry {
    seq: i64,
    member: Option<String>,
    replica: String,
    counter: i64,
    time: String,            // created_at as text — for the change-history / activity feed
    payload: Option<String>, // base64 of the sealed delta bytes (None if spilled to R2 — later)
}

#[derive(Serialize)]
struct LogTail {
    entries: Vec<LogEntry>,
    next_cursor: i64,
    oldest_retained_seq: i64,
    head_seq: i64,
}

/// `GET /trees/{tree_id}/log?since=N` — the ordered tail after `since`, byte-budgeted, with the cursor
/// to continue and the retained-window bounds. A cursor below the retained window is a `410` telling the
/// client to bootstrap from a snapshot (never a silently truncated tail).
pub async fn get_log(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Query(q): Query<LogQuery>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("log.read");
    let since = q.since.unwrap_or(-1);

    let meta: Option<(Uuid, i64)> =
        sqlx::query_as("SELECT owner_id, next_log_seq FROM trees WHERE id = $1")
            .bind(tree_id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    let (owner, next_seq) = meta.ok_or(ApiError::NotFound)?;
    if owner != identity.member_id {
        return Err(ApiError::Forbidden);
    }

    let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(seq) FROM tree_log WHERE tree_id = $1")
        .bind(tree_id)
        .fetch_one(&state.db)
        .await
        .map_err(internal)?;
    // Gap check: if the client's cursor is before the oldest retained entry, entries it still needs
    // were reclaimed — it must bootstrap from a snapshot rather than get a silently truncated tail.
    if let Some(o) = oldest {
        if since + 1 < o {
            return Err(ApiError::Gone("log tail no longer retained — bootstrap from a snapshot".into()));
        }
    }

    let rows: Vec<(i64, Option<Uuid>, Vec<u8>, i64, Option<Vec<u8>>, i64, String)> = sqlx::query_as(
        "SELECT seq, member_id, replica_id, replica_counter, payload, size_bytes, created_at::text
           FROM tree_log
          WHERE tree_id = $1 AND seq > $2
          ORDER BY seq
          LIMIT $3",
    )
    .bind(tree_id)
    .bind(since)
    .bind(TAIL_MAX_ENTRIES)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let mut entries = Vec::new();
    let mut budget = 0usize;
    let mut next_cursor = since;
    for (seq, member, replica, counter, payload, size, created_at) in rows {
        if !entries.is_empty() && budget + size as usize > TAIL_BYTE_BUDGET {
            break; // page here; the client pulls again from next_cursor
        }
        budget += size as usize;
        entries.push(LogEntry {
            seq,
            member: member.map(|m| m.to_string()),
            replica: b64(&replica),
            counter,
            time: created_at,
            payload: payload.map(|p| b64(&p)),
        });
        next_cursor = seq;
    }

    Ok((
        StatusCode::OK,
        Json(LogTail { entries, next_cursor, oldest_retained_seq: oldest.unwrap_or(0), head_seq: next_seq - 1 }),
    )
        .into_response())
}
