//! Seen-frontier report — plumbing for the future log-GC floor
//! (`plan/sync/design.ope398-managed-server.md` §4, build-order step 5).
//!
//! `PUT` lets a member advisorally report its own `BlobSyncClient::frontier()` (what it has
//! PULLED/FOLDED so far) per replica; `GET` (Administer-gated) reads the raw reports back. The worker
//! reports on every sync tick whose pull frontier advanced (`appCore.worker.js` `syncData`).
//!
//! This is now the **gate-2 (liveness) input** to the two-gate log-GC floor: `gc::mark_tree` takes, per
//! replica, the MIN reported frontier over the current members who reported inside the activity window, and
//! the floor is `max(gc_floor, min(gate1_covered, gate2_seen))` (see `gc.rs`). So a member's un-pulled log
//! tail is never reaped from under it while it stays active; a member silent past the window drops out of
//! the min and must re-bootstrap from the snapshot instead (safe — the snapshot's covered frontier is the
//! gate-1 safety input). These reports are advisory and client-asserted, never authoritative: over-claiming
//! only pins THIS member's own floor higher (it can't force deletion), the same trust model as `access.rs`'s
//! membership summary.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::Access;
use crate::trees::ApiError;
use crate::AppState;

/// Hard caps on a report — a member's own frontier is small (one entry per replica it knows of); these
/// stop a hostile client bloating the table (mirrors `access.rs`'s `MAX_BASIS_TOKENS`/`MAX_BASIS_TOKEN_LEN`).
const MAX_REPLICAS: usize = 4096;
const MAX_REPLICA_LEN: usize = 128;

// A value->value error conversion used as a `.map_err(fn)` argument; `&` would force a closure per call.
#[allow(clippy::needless_pass_by_value)]
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

#[derive(Deserialize)]
pub struct FrontierBody {
    /// `replica -> counter`, the caller's own `Frontier` (`docsync/src/lib.rs:400-404`): the next,
    /// exclusive counter this replica's log entries are covered up to, from the reporting member's point
    /// of view.
    frontier: BTreeMap<String, u64>,
}

/// `PUT /v1/trees/{tree_id}/frontier` — upsert the caller's own reported frontier, one row per replica.
///
/// **Gate choice**: `Access::Read` — any current member may self-report its own pull progress. Unlike
/// `access.rs`'s membership summary (which mutates the security-adjacent advisory ACL and so is
/// signer-gated), a frontier report can never cause DATA LOSS: gate 2 only ever pulls the floor DOWN
/// (`floor = min(gate1_covered, gate2_seen)`), so no report — honest, stale, or forged — can push the floor
/// above gate 1, the snapshot's covered-frontier safety line, and nothing below a published snapshot is ever
/// lost (a straggler re-adopts it). At worst a bad report costs the reporter its own extra re-bootstrap. So
/// the ordinary tree-membership gate is enough.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized, the report is oversized, or the store access fails.
pub async fn put_frontier(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Json(body): Json<FrontierBody>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("frontier.put");
    if body.frontier.len() > MAX_REPLICAS || body.frontier.keys().any(|r| r.len() > MAX_REPLICA_LEN) {
        return Err(ApiError::BadRequest(
            "frontier exceeds the size limit".into(),
        ));
    }

    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Read).await?;

    let mut tx = state.db.begin().await.map_err(internal)?;
    for (replica, counter) in &body.frontier {
        let counter = i64::try_from(*counter).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO tree_member_seen (tree_id, member_id, replica, counter, reported_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tree_id, member_id, replica) DO UPDATE
               SET counter = EXCLUDED.counter, reported_at = now()",
        )
        .bind(tree_id)
        .bind(identity.member_id)
        .bind(replica)
        .bind(counter)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(StatusCode::OK.into_response())
}

#[derive(Serialize)]
struct FrontierRow {
    member_id: String,
    replica: String,
    counter: i64,
    reported_at: String,
}

/// `GET /v1/trees/{tree_id}/frontier` — every member's last-reported per-replica frontier, raw.
/// `Access::Administer`-gated per the design (§4): server cost-control internals, not ordinary sync
/// traffic.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized or the store access fails.
pub async fn get_frontier(
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
    crate::authz::authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;

    let rows: Vec<(Uuid, String, i64, String)> = sqlx::query_as(
        "SELECT member_id, replica, counter, reported_at::text FROM tree_member_seen
          WHERE tree_id = $1 ORDER BY member_id, replica",
    )
    .bind(tree_id)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let frontier: Vec<FrontierRow> = rows
        .into_iter()
        .map(|(member_id, replica, counter, reported_at)| FrontierRow {
            member_id: member_id.to_string(),
            replica,
            counter,
            reported_at,
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "frontier": frontier }))).into_response())
}
