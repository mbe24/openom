//! Advisory membership summary + ACL derivation (OPE-278 / the server-keyring-decoupling decision).
//!
//! The server stays keyring-FORMAT-agnostic. The client verifies the keyring locally, resolves the
//! membership, and pushes the resolved `{member_id -> role}` view here; the server stores it as the advisory
//! `tree_access` ACL — used for coarse cost-control + the collaboration features (notifications, server-side
//! revocation, proposal routing, a sharing dashboard), NEVER as the security boundary (the crypto is that,
//! client-side — see `authz.rs`). So chain, dag, and any future engine reach the ACL through one
//! engine-neutral summary with zero server changes.
//!
//! [`apply_membership`] is the ONE place the ACL + a departed member's transient state are written, shared
//! by the chain keyring PUT (`put_keyring`, in-tx and drift-free) and this summary endpoint (the dag path +
//! everyone's re-assert path), so the two can never derive different ACLs.
//!
//! Concurrency: the client interprets its own engine-opaque `basis` frontier (chain: a revision token; dag:
//! the op-DAG tip ids) to confirm it is not causally behind BEFORE pushing; the server only does
//! last-writer-wins via CAS on a server-assigned `generation`. The server never interprets `basis` — a dag
//! frontier is an unordered set the server couldn't order anyway.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Identity;
use crate::trees::ApiError;
use crate::AppState;

fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// The summary is small (a family's members + a short frontier). Hard caps stop a hostile client bloating
/// the meta row or forcing pathological work.
const MAX_BASIS_TOKENS: usize = 64;
const MAX_BASIS_TOKEN_LEN: usize = 128;
const MAX_MEMBERS: usize = 4096;

/// Apply a resolved membership list to a tree's advisory state in one transaction: pin the owner (invariant),
/// upsert every asserted member's role, drop everyone gone, and reclaim a departed member's transient state
/// (their open proposals + rate bucket) so they leave nothing behind.
///
/// The OWNER row is never dropped or downgraded — the owner is known independently (`trees.owner_id`), so an
/// unverified summary can neither lock the owner out of its non-fast-path features nor (via a compromised
/// co-owner session) zero out the whole ACL. An empty member list is refused (never nuke the ACL). Shared by
/// `put_keyring` and `put_access`.
pub(crate) async fn apply_membership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tree_id: Uuid,
    owner_id: Uuid,
    members: &[(Uuid, i16)],
) -> Result<(), ApiError> {
    if members.is_empty() {
        return Err(ApiError::BadRequest("membership list is empty".into()));
    }
    // Owner first, pinned at ROLE_OWNER regardless of what the (unverified) list asserts for it.
    let mut ids: Vec<Uuid> = Vec::with_capacity(members.len() + 1);
    sqlx::query(
        "INSERT INTO tree_access (tree_id, member_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (tree_id, member_id) DO UPDATE SET role = $3",
    )
    .bind(tree_id)
    .bind(owner_id)
    .bind(openom_roles::ROLE_OWNER)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    ids.push(owner_id);

    for (id, role) in members {
        if *id == owner_id {
            continue; // owner is pinned above; ignore any asserted downgrade of it
        }
        sqlx::query(
            "INSERT INTO tree_access (tree_id, member_id, role) VALUES ($1, $2, $3)
             ON CONFLICT (tree_id, member_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(tree_id)
        .bind(id)
        .bind(role)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
        ids.push(*id);
    }

    // Drop everyone no longer present (ids always contains the owner → never the empty case) and reclaim a
    // departed member's transient state. Pending (un-attached) media uploads are left to the GC sweep;
    // live/attached blobs stay — they're part of the tree now.
    sqlx::query("DELETE FROM tree_access WHERE tree_id = $1 AND member_id <> ALL($2)")
        .bind(tree_id)
        .bind(&ids)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    sqlx::query("DELETE FROM proposals WHERE tree_id = $1 AND proposer_member_id <> ALL($2)")
        .bind(tree_id)
        .bind(&ids)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    sqlx::query("DELETE FROM member_rate WHERE tree_id = $1 AND member_id <> ALL($2)")
        .bind(tree_id)
        .bind(&ids)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

#[derive(Deserialize)]
pub struct SummaryBody {
    /// Engine-opaque frontier tokens (chain: a revision token; dag: op-DAG tip ids). Stored verbatim; the
    /// server never interprets them — the client checks its own trust state covers the stored basis first.
    basis: Vec<String>,
    /// The CAS generation the client last saw (`null` ⇔ it expects no summary yet). The write lands only if
    /// it matches the stored generation.
    #[serde(default)]
    expected_generation: Option<i64>,
    members: Vec<SummaryMember>,
}

#[derive(Deserialize)]
struct SummaryMember {
    member_id: String,
    role: i16,
}

/// The normalized asserted set with the owner pinned at ROLE_OWNER (matching [`apply_membership`]), sorted —
/// for the unchanged-check against the stored ACL.
fn normalized(members: &[(Uuid, i16)], owner_id: Uuid) -> Vec<(Uuid, i16)> {
    let mut v: Vec<(Uuid, i16)> = members
        .iter()
        .filter(|(id, _)| *id != owner_id)
        .copied()
        .collect();
    v.push((owner_id, openom_roles::ROLE_OWNER));
    v.sort_unstable();
    v.dedup();
    v
}

/// `PUT /trees/{tree_id}/access` — accept a client-asserted advisory membership summary. The client has
/// locally verified the keyring; the server stores the resolved `{member_id, role}` view as the advisory ACL
/// WITHOUT parsing the keyring. Gated at SIGNER level (owner or co-owner): the summary has no crypto
/// backstop, so this gate IS the authorization (deliberately tighter than `Administer` — a Maintainer can't
/// author a keyring change, so never needs to assert membership). CAS on the per-tree `generation` makes
/// concurrent multi-device pushes converge; an identical re-assert is a no-op that does not bump it.
pub async fn put_access(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Json(body): Json<SummaryBody>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("access.put");
    if body.basis.len() > MAX_BASIS_TOKENS
        || body.basis.iter().any(|t| t.len() > MAX_BASIS_TOKEN_LEN)
    {
        return Err(ApiError::BadRequest("basis exceeds the size limit".into()));
    }
    if body.members.len() > MAX_MEMBERS {
        return Err(ApiError::BadRequest("member list exceeds the size limit".into()));
    }
    // Parse + validate before touching the db: member_id MUST be an account UUID (the whole advisory layer
    // — gate, notifications, joins — keys on it), and the role must be in the 1..=5 axis.
    let mut members: Vec<(Uuid, i16)> = Vec::with_capacity(body.members.len());
    for m in &body.members {
        let id = Uuid::parse_str(&m.member_id)
            .map_err(|_| ApiError::BadRequest("member_id is not a uuid".into()))?;
        if !(openom_roles::ROLE_OWNER..=openom_roles::ROLE_VIEWER).contains(&m.role) {
            return Err(ApiError::BadRequest("role out of range".into()));
        }
        members.push((id, m.role));
    }

    let mut tx = state.db.begin().await.map_err(internal)?;
    // Serialize concurrent pushes on this tree; read the owner under the lock.
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1 FOR UPDATE")
        .bind(tree_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;

    // Signer gate: owner fast-path, else a current co-owner-or-stronger in the (pre-write) ACL.
    if identity.member_id != owner {
        let role: Option<i16> =
            sqlx::query_scalar("SELECT role FROM tree_access WHERE tree_id = $1 AND member_id = $2")
                .bind(tree_id)
                .bind(identity.member_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(internal)?;
        match role {
            Some(r) if r <= openom_roles::ROLE_CO_OWNER => {}
            _ => return Err(ApiError::Forbidden),
        }
    }

    // CAS: the client's expected generation must match the stored one (both `None` ⇔ no summary yet).
    let current: Option<i64> =
        sqlx::query_scalar("SELECT generation FROM tree_access_meta WHERE tree_id = $1")
            .bind(tree_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    if body.expected_generation != current {
        return Err(ApiError::Conflict); // stale — re-GET the summary and retry
    }

    // Idempotent re-assert: if the asserted membership already equals what's stored, don't bump the
    // generation or churn the audit row — so a client's "re-assert on every sync" is a genuine no-op and
    // doesn't fight other devices' cached generation (which would 409-churn them).
    if current.is_some() {
        let mut stored: Vec<(Uuid, i16)> =
            sqlx::query_as("SELECT member_id, role FROM tree_access WHERE tree_id = $1")
                .bind(tree_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(internal)?;
        stored.sort_unstable();
        if stored == normalized(&members, owner) {
            tx.commit().await.map_err(internal)?;
            return Ok((
                StatusCode::OK,
                Json(json!({ "generation": current, "unchanged": true })),
            )
                .into_response());
        }
    }

    apply_membership(&mut tx, tree_id, owner, &members).await?;

    let next = current.unwrap_or(0) + 1;
    sqlx::query(
        "INSERT INTO tree_access_meta (tree_id, generation, basis, asserted_by, asserted_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (tree_id)
           DO UPDATE SET generation = $2, basis = $3, asserted_by = $4, asserted_at = now()",
    )
    .bind(tree_id)
    .bind(next)
    .bind(&body.basis)
    .bind(identity.member_id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;

    tx.commit().await.map_err(internal)?;
    tracing::info!(event = "access_summary", %tree_id, generation = next, members = members.len());
    Ok((StatusCode::OK, Json(json!({ "generation": next }))).into_response())
}

#[derive(Serialize)]
struct AccessMember {
    member_id: String,
    role: i16,
}

/// `GET /trees/{tree_id}/access` — the current advisory member list + the summary's CAS `generation`, opaque
/// `basis`, and last-asserted time. The client reads `{generation, basis}` before a push (to CAS + to check
/// its trust state covers the stored basis); a sharing UI reads `members`. Read gate. `generation`/`basis`
/// are absent (`null`/`[]`) for a tree whose ACL was derived in-tx by the chain keyring PUT and never
/// summary-pushed.
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
    crate::authz::authorize(
        &state.db,
        tree_id,
        owner,
        identity.member_id,
        crate::authz::Access::Read,
    )
    .await?;

    let rows: Vec<(Uuid, i16)> =
        sqlx::query_as("SELECT member_id, role FROM tree_access WHERE tree_id = $1 ORDER BY role")
            .bind(tree_id)
            .fetch_all(&state.db)
            .await
            .map_err(internal)?;
    let members: Vec<AccessMember> = rows
        .into_iter()
        .map(|(id, role)| AccessMember {
            member_id: id.to_string(),
            role,
        })
        .collect();

    let meta: Option<(i64, Vec<String>, String)> = sqlx::query_as(
        "SELECT generation, basis, asserted_at::text FROM tree_access_meta WHERE tree_id = $1",
    )
    .bind(tree_id)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let (generation, basis, asserted_at) = match meta {
        Some((g, b, a)) => (Some(g), b, Some(a)),
        None => (None, Vec::new(), None),
    };

    Ok((
        StatusCode::OK,
        Json(json!({
            "members": members,
            "generation": generation,
            "basis": basis,
            "asserted_at": asserted_at,
        })),
    )
        .into_response())
}
