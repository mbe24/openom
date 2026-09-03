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
//! original seq. Small payloads are stored inline in Postgres; a payload over `INLINE_MAX_BYTES` spills
//! to an R2 object (`payload` NULL + `object_key` set) and is resolved back transparently on tail-pull, so
//! the client sees the same bytes either way.
//!
//! A new append is metered against the tree owner (owner-pays, §17): a per-account token bucket
//! (abuse rate → 429) and the tree-byte capacity meter (→ 403), both inside the append transaction so
//! a rejection charges nothing. Re-deliveries are never metered (they return before the gates). The
//! byte meter is monotonic until log GC reclaims compacted-away entries and credits it back (follow-up).

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
use crate::authz::Access;
use crate::trees::ApiError;
use crate::AppState;

/// Absolute per-append cap. Deltas are tiny; a payload near this should be a snapshot instead. Kept
/// under Axum's default request-body limit so the ceiling is enforced here with a clear 400.
const MAX_DELTA_BYTES: usize = 1024 * 1024;
/// Payloads at or below this stay inline in Postgres; larger ones spill to an R2 object (see
/// `append_log`). Settled ops are far smaller than this, so the spill path is exercised mainly by bulk
/// imports — but it always exists, so a large delta is stored, not rejected.
const INLINE_MAX_BYTES: usize = 32 * 1024;
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
fn validate_delta(
    body: &[u8],
    tree_id: Uuid,
    reject_dev_key: bool,
) -> Result<DeltaValidated, ApiError> {
    let env = Envelope::decode(body)
        .map_err(|e| ApiError::BadRequest(format!("not a valid envelope: {e}")))?;
    if env.version != ENVELOPE_VERSION {
        return Err(ApiError::BadRequest(format!(
            "unsupported envelope version {} (server speaks {ENVELOPE_VERSION})",
            env.version
        )));
    }
    let header = env
        .header
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("envelope has no header".into()))?;
    if header.kind() != Kind::Delta {
        return Err(ApiError::BadRequest(
            "the log path accepts only KIND_DELTA".into(),
        ));
    }
    if header.tree_id.as_slice() != tree_id.as_bytes() {
        return Err(ApiError::BadRequest(
            "header tree_id does not match the url".into(),
        ));
    }
    if reject_dev_key && header.key_id.as_slice() == openom_crypto::DEV_KEY_ID {
        return Err(ApiError::BadRequest(
            "dev key_id refused under STORAGE=cloud (§16)".into(),
        ));
    }
    let computed = Sha256::digest(&env.ciphertext);
    if header.ciphertext_hash.as_slice() != computed.as_slice() {
        return Err(ApiError::BadRequest(
            "ciphertext_hash does not match the ciphertext".into(),
        ));
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

/// Insert the log row and bump the tree's seq counter, inside the caller's transaction. `inline_payload`
/// and `object_key` are mutually exclusive: inline rows carry the bytes, spilled rows carry the R2 key.
/// The caller owns the commit (so a spilled object can be GC'd if the commit itself fails).
#[allow(clippy::too_many_arguments)]
async fn insert_delta_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tree_id: Uuid,
    seq: i64,
    d: &DeltaValidated,
    member_id: Uuid,
    inline_payload: Option<&[u8]>,
    object_key: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO tree_log
             (tree_id, seq, kind, replica_id, replica_counter, member_id, payload, object_key, ciphertext_hash, size_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(tree_id)
    .bind(seq)
    .bind(Kind::Delta as i16)
    .bind(&d.replica_id)
    .bind(d.replica_counter)
    .bind(member_id)
    .bind(inline_payload)
    .bind(object_key)
    .bind(&d.ciphertext_hash)
    .bind(d.size)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    sqlx::query("UPDATE trees SET next_log_seq = $1, updated_at = now() WHERE id = $2")
        .bind(seq + 1)
        .bind(tree_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

/// Best-effort delete of a spilled object orphaned by a failed append transaction. A leftover object is
/// harmless (no row references it) and would otherwise wait for a future sweep; we clean it up eagerly.
async fn spill_gc(state: &AppState, object_key: Option<&str>) {
    if let Some(key) = object_key {
        if let Err(e) = state.storage.delete_object(key).await {
            tracing::warn!(%e, key = %key, "could not delete orphaned spilled delta object");
        }
    }
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
        return Err(ApiError::BadRequest(
            "delta exceeds the per-append size limit".into(),
        ));
    }
    let d = validate_delta(&body, tree_id, state.config.storage_is_cloud())?;

    let mut tx = state.db.begin().await.map_err(internal)?;
    // Serialize seq assignment on this tree: lock the row, so concurrent appenders can't gap/collide.
    let row: Option<(Uuid, i64)> =
        sqlx::query_as("SELECT owner_id, next_log_seq FROM trees WHERE id = $1 FOR UPDATE")
            .bind(tree_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    let (owner, next_seq) = row.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(
        &state.db,
        tree_id,
        owner,
        identity.member_id,
        Access::Commit,
    )
    .await?;

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

    // Metering — capacity charged to the tree OWNER (owner-pays, §17); rate is PER-MEMBER so one
    // abusive member can't drain a shared bucket and DoS the owner + co-members. Only a genuinely new
    // append is metered (re-deliveries returned above, so a retrying client is never metered).
    //
    // (1a) Per-member abuse rate: a token bucket keyed (tree, member), refilled at the OWNER's plan rate
    // (owner-pays sets the budget; the member holds the state). Lazily created full on first append. The
    // WHERE guard on the UPDATE branch re-derives the balance so check and debit can't race; 0 rows → over.
    let (m_rate, m_burst): (f64, i32) =
        sqlx::query_as("SELECT log_rate, log_burst FROM accounts WHERE id = $1")
            .bind(owner)
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
    let member_ok = sqlx::query(
        "INSERT INTO member_rate (tree_id, member_id, tokens, refilled_at)
         VALUES ($1, $2, $3::float8 - 1, now())
         ON CONFLICT (tree_id, member_id) DO UPDATE
           SET tokens = LEAST($3::float8, member_rate.tokens
                              + EXTRACT(EPOCH FROM (now() - member_rate.refilled_at)) * $4) - 1,
               refilled_at = now()
           WHERE LEAST($3::float8, member_rate.tokens
                       + EXTRACT(EPOCH FROM (now() - member_rate.refilled_at)) * $4) >= 1",
    )
    .bind(tree_id)
    .bind(identity.member_id)
    .bind(m_burst)
    .bind(m_rate)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if member_ok.rows_affected() != 1 {
        let retry = if m_rate > 0.0 {
            (1.0 / m_rate).ceil() as u64
        } else {
            60
        };
        tracing::info!(event = "rate_rejected", resource = "log_member", %tree_id, member = %identity.member_id);
        return Err(ApiError::TooManyRequests(retry.max(1)));
    }

    // (A coarse per-account backstop against *coordinated* multi-member bursts is a follow-up — it needs
    // its own burst budget with headroom above one member's, not the shared log_burst the per-member
    // bucket already uses. The per-member bucket above is the substantive abuse isolation.)

    // (2) Byte capacity: the tree-byte meter (§17), an axis independent of the media
    // pool. Charge the delta's size; 0 rows → the tree reserve is full.
    let capped = sqlx::query(
        "UPDATE accounts SET tree_used_bytes = tree_used_bytes + $2
          WHERE id = $1 AND tree_used_bytes + $2 <= max_tree_bytes",
    )
    .bind(owner)
    .bind(d.size)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if capped.rows_affected() != 1 {
        tracing::info!(event = "quota_rejected", resource = "log", %tree_id, %owner);
        return Err(ApiError::QuotaExceeded);
    }

    let seq = next_seq;

    // Spill an oversized payload to R2 rather than storing it inline in Postgres. The PUT runs inside
    // the append transaction — the object key is `…/log/{seq}` and seq is only known under the row lock,
    // and it must be after the authz/idempotency/quota gates so no object is written for a request that
    // is then rejected. Large deltas are rare (settled ops are tiny; this mainly covers bulk imports),
    // so the extra time the tree row lock is held across the PUT is paid only on that uncommon path. If
    // the transaction fails after the PUT, the object is orphaned — GC'd best-effort below, mirroring the
    // snapshot path in `trees::put_tree`.
    let object_key = if body.len() > INLINE_MAX_BYTES {
        let key = crate::storage::keys::delta(tree_id, seq);
        state
            .storage
            .put_object(&key, body.to_vec())
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Some(key)
    } else {
        None
    };
    // Inline rows carry the sealed bytes; spilled rows carry a NULL payload + the R2 key.
    let inline_payload: Option<&[u8]> = if object_key.is_some() {
        None
    } else {
        Some(body.as_ref())
    };

    // From here on a failure orphans any spilled object, so every error path GCs it first.
    if let Err(e) = insert_delta_row(
        &mut tx,
        tree_id,
        seq,
        &d,
        identity.member_id,
        inline_payload,
        object_key.as_deref(),
    )
    .await
    {
        spill_gc(&state, object_key.as_deref()).await;
        return Err(e);
    }
    if let Err(e) = tx.commit().await.map_err(internal) {
        spill_gc(&state, object_key.as_deref()).await;
        return Err(e);
    }
    tracing::info!(event = "log_append", %tree_id, seq, spilled = object_key.is_some(), "delta appended");
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
    time: String, // created_at as text — for the change-history / activity feed
    payload: Option<String>, // base64 of the sealed delta bytes, inline or resolved from R2 (§12 spill)
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
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let oldest: Option<i64> =
        sqlx::query_scalar("SELECT MIN(seq) FROM tree_log WHERE tree_id = $1")
            .bind(tree_id)
            .fetch_one(&state.db)
            .await
            .map_err(internal)?;
    // Gap check: if the client's cursor is before the oldest retained entry, entries it still needs
    // were reclaimed — it must bootstrap from a snapshot rather than get a silently truncated tail.
    if let Some(o) = oldest {
        if since + 1 < o {
            return Err(ApiError::Gone(
                "log tail no longer retained — bootstrap from a snapshot".into(),
            ));
        }
    }

    let rows: Vec<(i64, Option<Uuid>, Vec<u8>, i64, Option<Vec<u8>>, Option<String>, i64, String)> =
        sqlx::query_as(
            "SELECT seq, member_id, replica_id, replica_counter, payload, object_key, size_bytes, created_at::text
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
    for (seq, member, replica, counter, payload, object_key, size, created_at) in rows {
        if !entries.is_empty() && budget + size as usize > TAIL_BYTE_BUDGET {
            break; // page here; the client pulls again from next_cursor
        }
        budget += size as usize;
        // Resolve the payload transparently: inline bytes if present, else fetch the spilled object from
        // R2 (checked before the budget cap, so we never fetch beyond what we return). A spilled row whose
        // object is missing is a data-integrity fault (the row asserts the payload exists), not a
        // graceful-404 like an absent snapshot — surface it rather than return a truncated delta.
        let payload_b64 = match (payload, &object_key) {
            (Some(bytes), _) => Some(b64(&bytes)),
            (None, Some(key)) => {
                let bytes = state
                    .storage
                    .get_object(key)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?
                    .ok_or_else(|| {
                        ApiError::Internal(format!("spilled delta payload missing for seq {seq}"))
                    })?;
                Some(b64(&bytes))
            }
            (None, None) => None,
        };
        entries.push(LogEntry {
            seq,
            member: member.map(|m| m.to_string()),
            replica: b64(&replica),
            counter,
            time: created_at,
            payload: payload_b64,
        });
        next_cursor = seq;
    }

    Ok((
        StatusCode::OK,
        Json(LogTail {
            entries,
            next_cursor,
            oldest_retained_seq: oldest.unwrap_or(0),
            head_seq: next_seq - 1,
        }),
    )
        .into_response())
}
