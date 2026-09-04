//! Mode A share invites — the pending-invite transport for the two-channel invite protocol
//! (plan/sharing/design.mode-a-client-flow.md §2/§7).
//!
//! Authentication rides the invite LINK, a second channel the server never sees: the server stores only
//! an OPEN invite the owner minted and the invitee's MAC'd public-key claim, and the REAL membership
//! change is the client's signed keyring PUT (admitted by the ChainVerifier). So this layer is advisory
//! transport + spam control, NEVER the security boundary — a malicious server can drop or fabricate a
//! row but can't forge the MAC (it lacks the link secret `s`) or the owner's keyring signature.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::{authorize, Access};
use crate::trees::ApiError;
use crate::AppState;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn unb64(s: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| ApiError::BadRequest("invalid base64".into()))
}

async fn tree_owner(db: &sqlx::PgPool, tree_id: Uuid) -> Result<Uuid, ApiError> {
    sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct CreateInvite {
    invite_id: String,
    role: String,
    #[serde(default)]
    recipient_pin: Option<String>,
    expiry: i64,
}

/// `POST /trees/{tree_id}/invites` — an owner/Maintainer mints a pending invite. The server holds no
/// secret; the link (carrying `s`) is delivered out of band by the owner.
pub async fn create_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Json(body): Json<CreateInvite>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    if body.invite_id.is_empty() || body.invite_id.len() > 64 || body.role.len() > 32 {
        return Err(ApiError::BadRequest("invalid invite fields".into()));
    }
    sqlx::query(
        "INSERT INTO pending_invites (invite_id, tree_id, owner_member_id, role, recipient_pin, expiry)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&body.invite_id)
    .bind(tree_id)
    .bind(identity.member_id)
    .bind(&body.role)
    .bind(&body.recipient_pin)
    .bind(body.expiry)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({ "invite_id": body.invite_id })))
}

#[derive(Deserialize)]
pub struct ClaimBody {
    member_id: String,
    hpke_public: String,
    author_public: String,
    tag: String,
}

/// `PUT /invites/{invite_id}/claim` — the invitee (signed in) submits its MAC'd public keys. The server
/// enforces `member_id == the JWT sub`, the invite is OPEN + unexpired, and ONE live claim. It does NOT
/// verify the MAC (only the owner, holding the link secret, can) — this is the honest-server gate; the
/// real defense is the owner's tag check at admit.
pub async fn claim_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(invite_id): Path<String>,
    Json(body): Json<ClaimBody>,
) -> Result<StatusCode, ApiError> {
    let member_id = Uuid::parse_str(&body.member_id)
        .map_err(|_| ApiError::BadRequest("member_id is not a uuid".into()))?;
    if member_id != identity.member_id {
        return Err(ApiError::Forbidden); // may only claim as yourself (== the JWT sub)
    }
    let hpke = unb64(&body.hpke_public)?;
    let author = unb64(&body.author_public)?;
    let tag = unb64(&body.tag)?;
    if hpke.len() != 32 || author.len() != 32 {
        return Err(ApiError::BadRequest("keys must be 32 bytes".into()));
    }
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT status, expiry FROM pending_invites WHERE invite_id = $1")
            .bind(&invite_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    let (status, expiry) = row.ok_or(ApiError::NotFound)?;
    if status != "open" {
        return Err(ApiError::Conflict); // already claimed — one live claim
    }
    if now_ms() > expiry {
        return Err(ApiError::Forbidden); // expired
    }
    // CAS the claim in (WHERE status='open' so a race resolves to exactly one claimant).
    let done = sqlx::query(
        "UPDATE pending_invites
         SET status='claimed', claim_member_id=$1, claim_hpke_public=$2, claim_author_public=$3,
             claim_tag=$4, claimed_at=$5
         WHERE invite_id=$6 AND status='open'",
    )
    .bind(member_id)
    .bind(&hpke)
    .bind(&author)
    .bind(&tag)
    .bind(now_ms())
    .bind(&invite_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    if done.rows_affected() == 0 {
        return Err(ApiError::Conflict); // lost the claim race
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct ClaimView {
    member_id: String,
    hpke_public: String,
    author_public: String,
    tag: String,
}

#[derive(Serialize)]
pub struct InviteView {
    invite_id: String,
    role: String,
    recipient_pin: Option<String>,
    expiry: i64,
    status: String,
    claim: Option<ClaimView>,
}

type InviteRow = (
    String,
    String,
    Option<String>,
    i64,
    String,
    Option<Uuid>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// `GET /trees/{tree_id}/invites` — the owner lists its pending invites + any claims (to admit).
pub async fn list_invites(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
) -> Result<Json<Vec<InviteView>>, ApiError> {
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    let rows: Vec<InviteRow> = sqlx::query_as(
        "SELECT invite_id, role, recipient_pin, expiry, status,
                claim_member_id, claim_hpke_public, claim_author_public, claim_tag
         FROM pending_invites WHERE tree_id = $1 ORDER BY created_at",
    )
    .bind(tree_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    let out = rows
        .into_iter()
        .map(|(invite_id, role, recipient_pin, expiry, status, cm, ch, ca, ct)| {
            let claim = match (cm, ch, ca, ct) {
                (Some(m), Some(h), Some(a), Some(t)) => Some(ClaimView {
                    member_id: m.to_string(),
                    hpke_public: b64(&h),
                    author_public: b64(&a),
                    tag: b64(&t),
                }),
                _ => None,
            };
            InviteView { invite_id, role, recipient_pin, expiry, status, claim }
        })
        .collect();
    Ok(Json(out))
}

/// `DELETE /invites/{invite_id}` — the owner consumes/cancels an invite after admitting it. Idempotent.
pub async fn delete_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let tree_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tree_id FROM pending_invites WHERE invite_id = $1")
            .bind(&invite_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    let Some(tree_id) = tree_id else {
        return Ok(StatusCode::NO_CONTENT); // already gone — idempotent
    };
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    sqlx::query("DELETE FROM pending_invites WHERE invite_id = $1")
        .bind(&invite_id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
