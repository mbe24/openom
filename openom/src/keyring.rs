//! Keyring storage + ACL derivation (track B3).
//!
//! The signed keyring is the AUTHORITATIVE membership/role list. The server stores every revision
//! (append-only) so clients walk the hash chain hop-by-hop, admits each candidate through the keyless
//! verifier seam (`KeyringVerifier` — honest-server defense-in-depth, and engine-agnostic per OPE-278 so
//! the dag engine admits through the same surface), and DERIVES the advisory `tree_access` ACL from the
//! returned `MembershipView`. Zero-knowledge is intact: the server reads only the non-secret member
//! ids/roles + the signatures it verifies; the wraps/keys stay opaque, never decrypted.
//!
//! Admission is the REAL authorization for a write here (a candidate is accepted only as a signed successor
//! of the stored head, or a self-signed genesis at first sight); the role gate on the endpoint is coarse
//! cost-control. A recovery/succession *reset* — a keyring that chains onto the head by hash + revision but
//! re-founds the signer set unendorsed (the old signing key is presumed lost) — is admitted with the view's
//! `reset_boundary` set; the CLIENT re-verifies the new signer set out-of-band (`is_reset` surfaces it), and
//! a per-tree cooldown bounds abuse.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use openom_keyring::decode_governing_ref;
use openom_keyring::verifier::ChainVerifier;
use openom_keyring_api::{EngineKind, KeyringVerifier, VerifyError};
use openom_protocol::v1::KeyringUpdate;
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
/// The `KeyringUpdate` wire version this server understands; a higher one is refused, not misparsed.
const KEYRING_UPDATE_VERSION: u32 = 1;

/// The server's keyring-engine registry: an engine tag → its keyless verifier. This is the ONE dispatch
/// point — a new **sequencer-backed** engine is one arm here and nothing else changes. Sequencer-free
/// engines (the dag) never reach this endpoint (they sync via content-addressed blobs and push an advisory
/// `MembershipView` over `/access`), so an unknown/dag tag is refused. The `engine` field is only a routing
/// hint anyway: the dispatched verifier re-checks the inner `MembershipEnvelope`'s own engine tag, so a
/// lying hint can't make the wrong verifier accept a body.
fn verifier_for(engine: &str) -> Option<Box<dyn KeyringVerifier + Send + Sync>> {
    match engine.parse::<EngineKind>() {
        Ok(EngineKind::Chain) => Some(Box::new(ChainVerifier)),
        _ => None,
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// A rejected keyring update → HTTP. A rollback/fork/stale-head is a *conflict* (the head moved — refetch
/// and rebuild); a malformed/unauthenticated/unauthorized candidate is a 400. Neutral `VerifyError` (from
/// the keyless seam), so the mapping is engine-agnostic.
fn verify_err(e: VerifyError) -> ApiError {
    match e {
        VerifyError::Rollback | VerifyError::Stale => ApiError::Conflict,
        VerifyError::Malformed => ApiError::BadRequest("keyring rejected: malformed".into()),
        VerifyError::Unauthenticated => {
            ApiError::BadRequest("keyring rejected: unauthenticated".into())
        }
        VerifyError::Unauthorized => ApiError::BadRequest("keyring rejected: unauthorized".into()),
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
        return Err(ApiError::BadRequest(
            "keyring exceeds the size limit".into(),
        ));
    }
    // Parse ONLY the engine-agnostic outer envelope — never a keyring body. Its `engine` tag routes to a
    // verifier; its `payload` is the opaque membership update the verifier admits; its tree_id/update_ref
    // are hints the server will cross-check against the VERIFIED facts `admit` returns (never trusts alone).
    let update = KeyringUpdate::decode(body.as_ref())
        .map_err(|e| ApiError::BadRequest(format!("not a valid keyring update: {e}")))?;
    if update.version != KEYRING_UPDATE_VERSION {
        return Err(ApiError::BadRequest(
            "unsupported keyring update version".into(),
        ));
    }
    let verifier = verifier_for(&update.engine)
        .ok_or_else(|| ApiError::BadRequest("unknown or unsupported keyring engine".into()))?;

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
    crate::authz::authorize(
        &state.db,
        tree_id,
        owner,
        identity.member_id,
        Access::Administer,
    )
    .await?;

    // Bind the keyless verifier seam (OPE-278): `ChainVerifier::admit` runs the SAME chain-walk this
    // endpoint did inline — verify_transition, with a verify_reset fallback for a recovery/succession reset
    // that re-founds the signer set unendorsed — and hands back the resolved membership `view` plus whether
    // the candidate crossed a recovery/reset boundary. The ACL derivation and the reset-cooldown gate below
    // now read from the engine-neutral `MembershipView`, not chain-specific fields, so the same surface will
    // serve the dag engine once its admit arm lands. The server is not the security boundary: it trusts the
    // founding keyring (first sight) and re-verifies every transition; the CLIENT re-verifies a reset's new
    // signer set out-of-band (is_reset surfaces it).
    let prior_state: Option<Vec<u8>> = if head_rev == 0 {
        // "First keyring is revision 1" is enforced inside the verifier's bootstrap (it verifies the signed
        // genesis), so the server no longer re-checks a body field it no longer parses.
        None
    } else {
        Some(
            sqlx::query_scalar(
                "SELECT payload FROM tree_keyrings WHERE tree_id = $1 AND revision = $2",
            )
            .bind(tree_id)
            .bind(head_rev)
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?,
        )
    };
    let admitted = verifier
        .admit(prior_state.as_deref(), &update.payload)
        .map_err(verify_err)?;
    // Cross-check the VERIFIED tree id (from the signed body) against the URL — never the update's own hint.
    if admitted.tree_id != tree_id.as_bytes() {
        return Err(ApiError::BadRequest(
            "keyring tree_id does not match the url".into(),
        ));
    }
    // The canonical position, from the VERIFIED body: the chain encodes its revision as the governing-ref.
    // The server keys storage / CAS / head-advance on THIS, never on the unauthenticated update hint.
    let revision = decode_governing_ref(&admitted.update_ref)
        .ok_or_else(|| ApiError::BadRequest("keyring update_ref is not a chain revision".into()))?
        as i32;
    let is_reset = admitted.view.reset_boundary;

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
        tracing::info!(event = "keyring_reset", %tree_id, revision);
    }

    // Persist append-only, storing the ENGINE-OPAQUE `Admitted.state` (never a parsed body). The PK
    // (tree_id, revision) is the CAS backstop: a racing PUT that verified against the same head inserts 0
    // rows here and loses — and the revision-only governing-ref makes two same-revision successors collide.
    let inserted = sqlx::query(
        "INSERT INTO tree_keyrings (tree_id, revision, payload, is_reset)
         VALUES ($1, $2, $3, $4) ON CONFLICT (tree_id, revision) DO NOTHING",
    )
    .bind(tree_id)
    .bind(revision)
    .bind(admitted.state.as_slice())
    .bind(is_reset)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError::Conflict); // another PUT won this revision
    }
    sqlx::query("UPDATE trees SET keyring_revision = $1, updated_at = now() WHERE id = $2")
        .bind(revision)
        .bind(tree_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;

    // Derive the advisory ACL from the resolved membership view via the SHARED writer — the same path the
    // engine-neutral membership-summary endpoint (`access::put_access`) uses, so the chain (in-tx here,
    // drift-free) and the dag (over `/access`) can never derive different ACLs. `MemberView.role` is already
    // the shared i16 role axis. Departed members' transient state (proposals + rate bucket) is reclaimed
    // inside `apply_membership`.
    let mut members: Vec<(Uuid, i16)> = Vec::with_capacity(admitted.view.members.len());
    for m in &admitted.view.members {
        let id = Uuid::parse_str(&m.member_id)
            .map_err(|_| ApiError::BadRequest("keyring member_id is not a uuid".into()))?;
        members.push((id, m.role));
    }
    crate::access::apply_membership(&mut tx, tree_id, owner, &members).await?;

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "keyring_put", %tree_id, revision, members = members.len());
    Ok((StatusCode::OK, Json(json!({ "revision": revision }))).into_response())
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
        .map(|(revision, payload, is_reset)| KeyringRevision {
            revision,
            payload: b64(&payload),
            is_reset,
        })
        .collect();
    Ok((StatusCode::OK, Json(KeyringHistory { revisions, head })).into_response())
}

// The derived member list read endpoint (`GET /trees/{id}/access`) moved to `crate::access::get_access`,
// alongside the membership-summary write path it now shares state with.
