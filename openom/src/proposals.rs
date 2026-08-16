//! Proposals channel — the approval side of review-changes (track B2).
//!
//! An editor submits a sealed `KIND_PROPOSAL` bundle (a base version-vector + a batch of ops) for the
//! owner/committers to review and then accept (apply to the tree as a real delta, client-side) or
//! reject/withdraw. Proposals are **transient and off the authoritative delta log**: they are never
//! folded into tree state by the server, and the log append path refuses `KIND_PROPOSAL` outright, so a
//! malicious server can't replay an editor's proposal into the tree. The server is zero-knowledge — the
//! payload is opaque; it only meters, attributes, lists, and expires.
//!
//! Metering is owner-pays (§17) on the proposal's own axis (never gating tree edits or media): a
//! per-proposal byte cap, a per-tree open-proposal cap, and a per-member/day submission cap backed by
//! an append-only ledger so it holds across create→delete churn. Free tier disables proposals
//! (`max_proposal_bytes = 0`). Authorization goes through the shared [`crate::authz`] seam — V1 is
//! owner-only; B3 will let editors propose and restrict accept/list to committers by changing that seam.

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

/// Absolute per-proposal ceiling regardless of plan — a bundle near this should be a snapshot, not a
/// proposal. The plan's `max_proposal_bytes` gates below this.
const MAX_PROPOSAL_BYTES: usize = 1024 * 1024;
/// Keep a list response under the Lambda response ceiling; proposals are few and small, but bound it.
const LIST_BYTE_BUDGET: usize = 4 * 1024 * 1024;
const LIST_MAX: i64 = 512;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// Validate a proposal envelope: decodable, supported version, `KIND_PROPOSAL`, bound to this tree,
/// non-dev key (prod), recomputable `ciphertext_hash`. (No replica dot — each POST is a fresh proposal
/// with a server-minted id, not an idempotent append.)
fn validate_proposal(body: &[u8], tree_id: Uuid, reject_dev_key: bool) -> Result<Vec<u8>, ApiError> {
    let env = Envelope::decode(body).map_err(|e| ApiError::BadRequest(format!("not a valid envelope: {e}")))?;
    if env.version != ENVELOPE_VERSION {
        return Err(ApiError::BadRequest(format!(
            "unsupported envelope version {} (server speaks {ENVELOPE_VERSION})",
            env.version
        )));
    }
    let header = env.header.as_ref().ok_or_else(|| ApiError::BadRequest("envelope has no header".into()))?;
    if header.kind() != Kind::Proposal {
        return Err(ApiError::BadRequest("the proposals path accepts only KIND_PROPOSAL".into()));
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
    Ok(header.ciphertext_hash.clone())
}

#[derive(Serialize)]
struct CreateResult {
    id: String,
    expires_at: String,
}

/// `POST /trees/{tree_id}/proposals` — submit a sealed proposal. Metered against the tree owner.
pub async fn create_proposal(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("proposal.create");
    if body.len() > MAX_PROPOSAL_BYTES {
        return Err(ApiError::BadRequest("proposal exceeds the per-item size limit".into()));
    }
    let size = body.len() as i64;
    let ciphertext_hash = validate_proposal(&body, tree_id, !state.config.is_local())?;

    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    // Editor+ may propose (the whole point of the role); metered to the owner (owner-pays).
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Propose).await?;

    // Owner's proposal entitlements (owner-pays).
    let (max_bytes, max_open, max_day, ttl): (i64, i32, i32, i32) = sqlx::query_as(
        "SELECT max_proposal_bytes, max_open_proposals_per_tree, max_proposals_per_member_day, proposal_ttl_secs
           FROM accounts WHERE id = $1",
    )
    .bind(owner)
    .fetch_one(&state.db)
    .await
    .map_err(internal)?;
    if max_bytes == 0 || max_open < 1 || max_day < 1 {
        return Err(ApiError::Forbidden); // proposals not enabled on this plan
    }
    if size > max_bytes {
        return Err(ApiError::BadRequest("proposal exceeds the plan's per-proposal size limit".into()));
    }

    let mut tx = state.db.begin().await.map_err(internal)?;

    // Concurrency cap, per-(tree, proposer): each member gets up to `max_open` still-open proposals, so
    // one editor can't fill a tree-global pool for the whole TTL and starve the others (total is bounded
    // by members × max_open, and membership is itself capped).
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proposals WHERE tree_id = $1 AND proposer_member_id = $2 AND expires_at > now()",
    )
    .bind(tree_id)
    .bind(identity.member_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    if open >= max_open as i64 {
        tracing::info!(event = "quota_rejected", resource = "proposals_open", %tree_id, member = %identity.member_id);
        return Err(ApiError::QuotaExceeded);
    }

    // Per-member/day cap via the append-only ledger — the WHERE on the UPDATE branch refuses the
    // increment past the cap (0 rows), and the INSERT branch is the day's first submission.
    let day_ok = sqlx::query(
        "INSERT INTO proposal_day_counts (tree_id, member_id, day, count)
         VALUES ($1, $2, current_date, 1)
         ON CONFLICT (tree_id, member_id, day)
           DO UPDATE SET count = proposal_day_counts.count + 1
           WHERE proposal_day_counts.count < $3",
    )
    .bind(tree_id)
    .bind(identity.member_id)
    .bind(max_day)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if day_ok.rows_affected() != 1 {
        tracing::info!(event = "quota_rejected", resource = "proposals_per_day", %tree_id, member = %identity.member_id);
        return Err(ApiError::QuotaExceeded);
    }

    let id = Uuid::new_v4();
    let expires: String = sqlx::query_scalar(
        "INSERT INTO proposals (id, tree_id, proposer_member_id, payload, ciphertext_hash, size_bytes, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
         RETURNING expires_at::text",
    )
    .bind(id)
    .bind(tree_id)
    .bind(identity.member_id)
    .bind(body.as_ref())
    .bind(&ciphertext_hash)
    .bind(size)
    .bind(ttl as f64)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "proposal_created", %tree_id, %id, member = %identity.member_id);
    Ok((StatusCode::OK, Json(CreateResult { id: id.simple().to_string(), expires_at: expires })).into_response())
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// Include already-expired proposals too (default: only open ones).
    #[serde(default)]
    include_expired: bool,
}

#[derive(Serialize)]
struct ProposalEntry {
    id: String,
    proposer: String,
    size_bytes: i64,
    created_at: String,
    expires_at: String,
    ciphertext_hash: String,
    payload: String, // base64 sealed KIND_PROPOSAL bytes
}

#[derive(Serialize)]
struct ProposalList {
    proposals: Vec<ProposalEntry>,
}

/// `GET /trees/{tree_id}/proposals` — list the tree's open proposals (payloads inline) for review.
pub async fn list_proposals(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("proposal.list");
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let rows: Vec<(Uuid, Uuid, i64, String, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, proposer_member_id, size_bytes, created_at::text, expires_at::text, ciphertext_hash, payload
           FROM proposals
          WHERE tree_id = $1 AND ($2 OR expires_at > now())
          ORDER BY created_at
          LIMIT $3",
    )
    .bind(tree_id)
    .bind(q.include_expired)
    .bind(LIST_MAX)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let mut proposals = Vec::new();
    let mut budget = 0usize;
    for (id, proposer, size, created_at, expires_at, hash, payload) in rows {
        if !proposals.is_empty() && budget + payload.len() > LIST_BYTE_BUDGET {
            break;
        }
        budget += payload.len();
        proposals.push(ProposalEntry {
            id: id.simple().to_string(),
            proposer: proposer.to_string(),
            size_bytes: size,
            created_at,
            expires_at,
            ciphertext_hash: b64(&hash),
            payload: b64(&payload),
        });
    }
    Ok((StatusCode::OK, Json(ProposalList { proposals })).into_response())
}

/// `DELETE /trees/{tree_id}/proposals/{proposal_id}` — resolve (accepted/rejected) or withdraw a
/// proposal. Idempotent: deleting an already-gone proposal is a success (the client accepts then
/// deletes, and may retry). Does not decrement the day ledger — the daily cap counts submissions.
pub async fn delete_proposal(
    State(state): State<AppState>,
    identity: Identity,
    Path((tree_id, proposal_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("proposal.delete");
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;

    // Policy: a Maintainer+ may resolve any proposal (accept/reject); the proposer may withdraw their
    // OWN. Neither is a plain capability gate, so fetch the proposer and branch. A missing proposal is an
    // idempotent success (the client accepts then deletes, and may retry) — but only for someone who
    // could have deleted it, so an unauthorized caller is refused before we reveal existence.
    let proposer: Option<Uuid> =
        sqlx::query_scalar("SELECT proposer_member_id FROM proposals WHERE tree_id = $1 AND id = $2")
            .bind(tree_id)
            .bind(proposal_id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    if proposer != Some(identity.member_id) {
        // Not the proposer (or the proposal is gone) → require Maintainer+.
        crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    }

    sqlx::query("DELETE FROM proposals WHERE tree_id = $1 AND id = $2")
        .bind(tree_id)
        .bind(proposal_id)
        .execute(&state.db)
        .await
        .map_err(internal)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "deleted": true }))).into_response())
}
