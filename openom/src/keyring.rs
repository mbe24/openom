//! Keyring storage + ACL derivation (track B3, slice 2).
//!
//! The signed keyring is the AUTHORITATIVE membership/role list. The server stores every revision
//! (append-only) so clients walk the hash chain hop-by-hop, verifies each candidate against the stored
//! head (honest-server defense-in-depth — `openom_keyring::chain`), and DERIVES the advisory `tree_access`
//! ACL from the keyring's non-secret `members` list. Zero-knowledge is intact: the server reads only the
//! non-secret member ids/roles + the signatures it verifies; the wraps/keys stay opaque, never decrypted.
//!
//! Verification is the REAL authorization for a write here (`verify_transition` accepts only a prior
//! signer's signature); the role gate on the endpoint is coarse cost-control. Genesis (revision 1) is
//! checked with `verify_reset` (structure + self-signed + wrap-complete). A recovery/succession *reset*
//! (a non-chaining keyring) is intentionally NOT accepted yet — that needs its own policy (slice 4), so a
//! non-genesis keyring that doesn't chain onto the head is refused rather than silently trusted.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use openom_keyring::{keyring_hash, verify_reset, verify_transition, ChainError, KeyringAnchor};
use openom_protocol::v1::Keyring;
use openom_protocol::Message;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::Access;
use crate::trees::ApiError;
use crate::AppState;

/// Keyrings are small (a handful of members/epochs). A hard ceiling stops a hostile client forcing
/// pathological decode/verify work; the crypto layer bounds list sizes beyond this.
const MAX_KEYRING_BYTES: usize = 512 * 1024;
/// Cap a history response's revision count (keyrings are small; bound it for the Lambda ceiling anyway).
const HISTORY_MAX: i64 = 512;
/// Per-tree cooldown between recovery/succession resets (a reset is a rare life event; this bounds abuse).
const RESET_COOLDOWN_SECS: f64 = 3600.0;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// A rejected keyring transition → HTTP. A rollback/fork is a *conflict* (the head moved — refetch and
/// rebuild); everything else is a malformed/unauthorized candidate → 400.
fn keyring_err(e: ChainError) -> ApiError {
    match e {
        ChainError::NonSequential | ChainError::Fork => ApiError::Conflict,
        other => ApiError::BadRequest(format!("keyring rejected: {other}")),
    }
}

/// `PUT /trees/{tree_id}/keyring` — accept a new signed keyring revision: verify it against the stored
/// head, persist it append-only (the `(tree_id, revision)` PK is the CAS), advance the head, and derive
/// the `tree_access` ACL from its members. All in one tx under the tree row lock.
pub async fn put_keyring(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("keyring.put");
    if body.len() > MAX_KEYRING_BYTES {
        return Err(ApiError::BadRequest("keyring exceeds the size limit".into()));
    }
    let candidate =
        Keyring::decode(body.as_ref()).map_err(|e| ApiError::BadRequest(format!("not a valid keyring: {e}")))?;
    if candidate.tree_id.as_slice() != tree_id.as_bytes() {
        return Err(ApiError::BadRequest("keyring tree_id does not match the url".into()));
    }

    let mut tx = state.db.begin().await.map_err(internal)?;
    // Serialize concurrent keyring PUTs on this tree; read the owner + current head revision.
    let row: Option<(Uuid, i32)> =
        sqlx::query_as("SELECT owner_id, keyring_revision FROM trees WHERE id = $1 FOR UPDATE")
            .bind(tree_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    let (owner, head_rev) = row.ok_or(ApiError::NotFound)?;
    // Coarse cost-control gate (owner via fast-path; a maintainer+ may attempt). The crypto below is the
    // real authorization — a non-signer's candidate fails verify_transition even if they pass this.
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;

    // Verify: genesis (no keyring yet) via verify_reset; otherwise a strict successor of the stored head,
    // OR a recovery/succession RESET (slice 4).
    let (anchor, is_reset) = if head_rev == 0 {
        if candidate.revision != 1 {
            return Err(ApiError::BadRequest("first keyring must be revision 1".into()));
        }
        (verify_reset(&candidate).map_err(keyring_err)?, false)
    } else {
        let prior_bytes: Vec<u8> =
            sqlx::query_scalar("SELECT payload FROM tree_keyrings WHERE tree_id = $1 AND revision = $2")
                .bind(tree_id)
                .bind(head_rev)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?;
        let prior = Keyring::decode(prior_bytes.as_slice())
            .map_err(|_| ApiError::Internal("stored keyring is corrupt".into()))?;
        match verify_transition(&KeyringAnchor::from_keyring(&prior), &candidate) {
            Ok(a) => (a, false),
            // A recovery/succession reset: it chains onto our head by hash + revision (so it can't roll
            // back or fork), but changes the authorized-signer set without the old set's endorsement
            // (the old signing key is presumed lost) — which verify_transition reports as
            // UnendorsedSetChange. verify_reset confirms it's a self-consistent, wrap-complete,
            // self-signed keyring. The server can't tell a legitimate recovery from a founder-substitution
            // attack; the CLIENT re-verifies the new signer set out-of-band (is_reset surfaces it). The
            // revision + prev-hash guards are redundant with UnendorsedSetChange (which is only reached
            // after those pass) but stated explicitly as the reset's defining shape.
            Err(ChainError::UnendorsedSetChange)
                if candidate.revision == head_rev as u32 + 1
                    && candidate.prev_keyring_hash == keyring_hash(&prior) =>
            {
                (verify_reset(&candidate).map_err(keyring_err)?, true)
            }
            Err(e) => return Err(keyring_err(e)),
        }
    };

    // A reset bypasses the prior-signer signature gate, so rate-cap it per tree (a stolen Administer token
    // could otherwise spam resets, forking every member into an OOB-reverify prompt). Atomic in SQL: the
    // UPDATE lands only outside the cooldown, and stamps the new reset time.
    if is_reset {
        let capped = sqlx::query(
            "UPDATE trees SET last_reset_at = now()
              WHERE id = $1 AND (last_reset_at IS NULL OR last_reset_at <= now() - make_interval(secs => $2))",
        )
        .bind(tree_id)
        .bind(RESET_COOLDOWN_SECS)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        if capped.rows_affected() != 1 {
            tracing::info!(event = "rate_rejected", resource = "keyring_reset", %tree_id);
            return Err(ApiError::TooManyRequests(RESET_COOLDOWN_SECS as u64));
        }
        tracing::info!(event = "keyring_reset", %tree_id, revision = candidate.revision);
    }

    // Persist append-only. The PK (tree_id, revision) is the CAS backstop: a racing PUT that verified
    // against the same head inserts 0 rows here and loses.
    let inserted = sqlx::query(
        "INSERT INTO tree_keyrings (tree_id, revision, payload, keyring_hash, is_reset)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tree_id, revision) DO NOTHING",
    )
    .bind(tree_id)
    .bind(candidate.revision as i32)
    .bind(body.as_ref())
    .bind(anchor.keyring_hash.as_slice())
    .bind(is_reset)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError::Conflict); // another PUT won this revision
    }
    sqlx::query("UPDATE trees SET keyring_revision = $1, updated_at = now() WHERE id = $2")
        .bind(candidate.revision as i32)
        .bind(tree_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;

    // Derive the ACL from the non-secret members list: upsert everyone present, drop everyone gone.
    let mut ids: Vec<Uuid> = Vec::with_capacity(candidate.members.len());
    for m in &candidate.members {
        let id = Uuid::parse_str(&m.member_id)
            .map_err(|_| ApiError::BadRequest("keyring member_id is not a uuid".into()))?;
        sqlx::query(
            "INSERT INTO tree_access (tree_id, member_id, role) VALUES ($1, $2, $3)
             ON CONFLICT (tree_id, member_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(tree_id)
        .bind(id)
        .bind(m.role as i16)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        ids.push(id);
    }
    // Remove everything belonging to members no longer in the keyring (guard the empty case — never nuke
    // the ACL). Dropping the ACL row cuts their access; we also reclaim their transient state so a removed
    // member leaves nothing behind: their open proposals and their rate bucket. Pending (un-attached)
    // media uploads are left to the existing GC sweep (it releases the reservation + staging object);
    // live/attached blobs stay — they're part of the tree now (bulk-detach of a departed member's media
    // is a heavier policy, a follow-up).
    if !ids.is_empty() {
        sqlx::query("DELETE FROM tree_access WHERE tree_id = $1 AND member_id <> ALL($2)")
            .bind(tree_id)
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query("DELETE FROM proposals WHERE tree_id = $1 AND proposer_member_id <> ALL($2)")
            .bind(tree_id)
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query("DELETE FROM member_rate WHERE tree_id = $1 AND member_id <> ALL($2)")
            .bind(tree_id)
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
    }

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "keyring_put", %tree_id, revision = candidate.revision, members = ids.len());
    Ok((StatusCode::OK, Json(json!({ "revision": candidate.revision }))).into_response())
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Return revisions with `revision >= from` (default 1 — the whole retained chain).
    from: Option<i32>,
}

#[derive(Serialize)]
struct KeyringRevision {
    revision: i32,
    payload: String, // base64 of the opaque signed keyring bytes
    /// True if this revision is a recovery/succession reset (the signer set changed unendorsed). A UX
    /// hint so the client can prompt out-of-band re-verification — NOT a trust gate (the client decides
    /// from the crypto, never this flag).
    is_reset: bool,
}

#[derive(Serialize)]
struct KeyringHistory {
    revisions: Vec<KeyringRevision>,
    head: i32,
}

/// `GET /trees/{tree_id}/keyring?from=N` — the keyring chain from revision N to head, so a returning
/// client walks `prev_keyring_hash` hop-by-hop. Empty list (head 0) when the tree has no keyring yet.
pub async fn get_keyring(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Query(q): Query<HistoryQuery>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("keyring.get");
    let meta: Option<(Uuid, i32)> =
        sqlx::query_as("SELECT owner_id, keyring_revision FROM trees WHERE id = $1")
            .bind(tree_id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    let (owner, head) = meta.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let from = q.from.unwrap_or(1);
    let rows: Vec<(i32, Vec<u8>, bool)> = sqlx::query_as(
        "SELECT revision, payload, is_reset FROM tree_keyrings WHERE tree_id = $1 AND revision >= $2 ORDER BY revision LIMIT $3",
    )
    .bind(tree_id)
    .bind(from)
    .bind(HISTORY_MAX)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let revisions = rows
        .into_iter()
        .map(|(revision, payload, is_reset)| KeyringRevision { revision, payload: b64(&payload), is_reset })
        .collect();
    Ok((StatusCode::OK, Json(KeyringHistory { revisions, head })).into_response())
}

#[derive(Serialize)]
struct AccessMember {
    member_id: String,
    role: i16,
}

/// `GET /trees/{tree_id}/access` — the current derived member list (id + role). A read convenience for a
/// members/sharing UI; the authoritative source is the keyring, this is its derived projection.
pub async fn get_access(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let rows: Vec<(Uuid, i16)> =
        sqlx::query_as("SELECT member_id, role FROM tree_access WHERE tree_id = $1 ORDER BY role")
            .bind(tree_id)
            .fetch_all(&state.db)
            .await
            .map_err(internal)?;
    let members: Vec<AccessMember> =
        rows.into_iter().map(|(id, role)| AccessMember { member_id: id.to_string(), role }).collect();
    Ok((StatusCode::OK, Json(json!({ "members": members }))).into_response())
}
