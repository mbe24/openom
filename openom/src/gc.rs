//! Log GC — the two-phase mark → grace → reap sweep behind the two-gate floor (OPE-409,
//! `plan/sync/design.ope412-409-metering-gc.md` Part 2). SECURITY-CRITICAL: a bug here is SILENT DATA LOSS,
//! so every default fails closed (a missing snapshot / floor / member report never deletes).
//!
//! `floor[r] = max(gc_floor[r], min(gate1_covered[r], gate2_seen[r]))`, delete strictly below, ratchet never
//! regresses. Gate 1 (safety) = the live snapshot's SUBSUMED covered frontier, trusted per replica ONLY if
//! its `snapshot_etag` matches the CURRENT live `snapshot` object's etag (the ETAG-BINDING that realizes D1
//! server-side — a regressed/rewritten snapshot makes that replica read as unpublished, covered 0). Gate 2
//! (liveness) = the min over every in-window CURRENT member's reported frontier. GC never deletes `heads/*`
//! or the `snapshot` pointer; it only ever marks/reaps `log/*` objects. Mirrors `media::run_sweep`'s
//! mark/grace/reap + credit-back shape.

use std::collections::BTreeMap;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::trees::ApiError;
use crate::AppState;

/// How recent a member's frontier report must be to constrain gate 2 (§2.9 proposed 30d).
const DEFAULT_ACTIVITY_WINDOW_SECS: i64 = 30 * 24 * 3600;
/// How long a marked log row survives before reap — the detection + self-heal window (§2.9 proposed 7d).
const DEFAULT_DELETION_GRACE_SECS: i64 = 7 * 24 * 3600;

// A value->value error conversion used as a `.map_err(fn)` argument; `&` would force a closure per call.
#[allow(clippy::needless_pass_by_value)]
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// The gate-2 liveness constraint: each in-window CURRENT member's reported per-replica frontier.
struct Gate2 {
    /// One map per in-window current member. EMPTY ⇒ no current member has reported in the window ⇒ gate 2
    /// is +∞ / no-constraint (M1: never 0 — that would collapse the floor to gate 1 only, which is correct).
    members: Vec<BTreeMap<String, i64>>,
}

impl Gate2 {
    /// The gate-2 constraint for one replica: `None` (no in-window members) means +∞; otherwise the min over
    /// members of their reported counter, treating a replica ABSENT from a present member's report as 0
    /// (that member hasn't seen it, so it pins the floor for `r` at 0 — fail-closed).
    fn constraint(&self, replica: &str) -> Option<i64> {
        if self.members.is_empty() {
            return None;
        }
        Some(
            self.members
                .iter()
                .map(|m| m.get(replica).copied().unwrap_or(0))
                .min()
                .unwrap_or(0),
        )
    }
}

/// Gather gate 2: the reports of every in-window CURRENT member (owner ∪ `tree_access`). A member with no
/// in-window report is excluded (gate 1 keeps that sound); a removed member is excluded (not owner, not in
/// `tree_access`).
async fn gate2(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tree_id: Uuid,
    owner: Uuid,
    window_secs: i64,
) -> Result<Gate2, ApiError> {
    let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT s.member_id, s.replica, s.counter
           FROM tree_member_seen s
          WHERE s.tree_id = $1
            AND s.reported_at >= now() - make_interval(secs => $2::double precision)
            AND (s.member_id = $3
                 OR EXISTS (SELECT 1 FROM tree_access a WHERE a.tree_id = $1 AND a.member_id = s.member_id))",
    )
    .bind(tree_id)
    .bind(window_secs)
    .bind(owner)
    .fetch_all(&mut **tx)
    .await
    .map_err(internal)?;

    let mut by_member: BTreeMap<Uuid, BTreeMap<String, i64>> = BTreeMap::new();
    for (member, replica, counter) in rows {
        by_member.entry(member).or_default().insert(replica, counter);
    }
    Ok(Gate2 {
        members: by_member.into_values().collect(),
    })
}

/// MARK one tree under its per-tree ratchet lock (the SAME `SELECT … FOR UPDATE` the snapshot PUT takes).
/// Advances `tree_gc_floor` (GREATEST — never regresses) and sets `pending_delete_at` on the log rows now
/// below the floor. Returns the number of rows newly marked.
async fn mark_tree(state: &AppState, tree_id: Uuid, window_secs: i64) -> Result<u64, ApiError> {
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let Some(owner) = owner else { return Ok(0) };

    let mut tx = state.db.begin().await.map_err(internal)?;
    // The per-tree lock — shared with the snapshot-PUT ratchet check + the below-floor log write.
    sqlx::query("SELECT 1 FROM trees WHERE id = $1 FOR UPDATE")
        .bind(tree_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;

    // Gate 1: the covered frontier, ONLY the rows still bound to the live snapshot object's etag (fail-closed
    // ETAG-BINDING). No live snapshot object → no trusted coverage → nothing advances (floor stays put).
    let live_etag: Option<String> =
        sqlx::query_scalar("SELECT etag FROM tree_blob_index WHERE tree_id = $1 AND key = 'snapshot'")
            .bind(tree_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    let covered: BTreeMap<String, i64> = match &live_etag {
        Some(live) => sqlx::query_as(
            "SELECT replica, counter FROM tree_snapshot_covered WHERE tree_id = $1 AND snapshot_etag = $2",
        )
        .bind(tree_id)
        .bind(live)
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?
        .into_iter()
        .collect(),
        None => BTreeMap::new(),
    };
    if covered.is_empty() {
        // Nothing to advance (gate 1 unpublished/empty). Commit the (no-op) lock release and return.
        tx.commit().await.map_err(internal)?;
        return Ok(0);
    }

    let g2 = gate2(&mut tx, tree_id, owner, window_secs).await?;
    let gc_floor: BTreeMap<String, i64> =
        sqlx::query_as("SELECT replica, floor FROM tree_gc_floor WHERE tree_id = $1")
            .bind(tree_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(internal)?
            .into_iter()
            .collect();

    let mut marked = 0u64;
    for (replica, cov) in &covered {
        // floor[r] = max(gc_floor[r], min(covered[r], gate2[r])). gate2 None (no in-window members) = +∞.
        let lowered = match g2.constraint(replica) {
            Some(g) => (*cov).min(g),
            None => *cov,
        };
        let existing = gc_floor.get(replica).copied().unwrap_or(0);
        let floor_r = existing.max(lowered);

        // Advance the ratchet (GREATEST guards against any concurrent bump).
        sqlx::query(
            "INSERT INTO tree_gc_floor (tree_id, replica, floor) VALUES ($1, $2, $3)
             ON CONFLICT (tree_id, replica) DO UPDATE SET floor = GREATEST(tree_gc_floor.floor, EXCLUDED.floor)",
        )
        .bind(tree_id)
        .bind(replica)
        .bind(floor_r)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;

        if floor_r > 0 {
            // Mark log rows strictly below the floor. The CASE guards the ::bigint cast so it NEVER runs on a
            // non-`log`/non-numeric key (Postgres evaluates a CASE branch only when its WHEN matches) — a NULL
            // result is not `< floor`, so those rows are simply excluded. GC touches only `log/*` here.
            let res = sqlx::query(
                "UPDATE tree_blob_index SET pending_delete_at = now()
                  WHERE tree_id = $1
                    AND pending_delete_at IS NULL
                    AND (CASE
                           WHEN split_part(key, '/', 1) = 'log'
                            AND split_part(key, '/', 2) = $2
                            AND split_part(key, '/', 3) ~ '^[0-9]+$'
                           THEN split_part(key, '/', 3)::bigint
                         END) < $3",
            )
            .bind(tree_id)
            .bind(replica)
            .bind(floor_r)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            marked += res.rows_affected();
        }
    }

    tx.commit().await.map_err(internal)?;
    Ok(marked)
}

/// REAP: physically delete every marked log row past the deletion grace. Index-row-authoritative — the row
/// delete + the meter credit commit in ONE tx, THEN the R2 object is deleted best-effort. Returns
/// `(reaped_rows, reclaimed_bytes)`.
async fn reap_marked(state: &AppState, grace_secs: i64) -> Result<(u64, i64), ApiError> {
    let rows: Vec<(Uuid, String, i64, Uuid)> = sqlx::query_as(
        "SELECT b.tree_id, b.key, b.size_bytes, t.owner_id
           FROM tree_blob_index b JOIN trees t ON t.id = b.tree_id
          WHERE b.pending_delete_at IS NOT NULL
            AND b.pending_delete_at <= now() - make_interval(secs => $1::double precision)",
    )
    .bind(grace_secs)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let mut reaped = 0u64;
    let mut reclaimed = 0i64;
    for (tree_id, key, size, owner) in &rows {
        let mut tx = state.db.begin().await.map_err(internal)?;
        // Re-check under the delete: a concurrent reaper may have already taken this row.
        let deleted = sqlx::query(
            "DELETE FROM tree_blob_index WHERE tree_id = $1 AND key = $2 AND pending_delete_at IS NOT NULL",
        )
        .bind(tree_id)
        .bind(key)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        if deleted.rows_affected() != 1 {
            tx.rollback().await.map_err(internal)?;
            continue;
        }
        // Credit the reclaimed immutable bytes back to the owner (the same seam that spent them). Same tx as
        // the row delete, so a credit is never double-applied and never applied without the delete.
        state
            .meter
            .credit_storage(&mut tx, *owner, *size)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;

        // Best-effort R2 delete AFTER the authoritative row delete (a leftover object is a harmless orphan the
        // age-gated reconcile job — deliberately not built here, M5 — would catch).
        let object_key = crate::storage::keys::data_blob(*tree_id, key);
        let _ = state.storage.delete_object(&object_key).await;
        reaped += 1;
        reclaimed += *size;
    }
    Ok((reaped, reclaimed))
}

/// The whole sweep: MARK every tree that has `log/*` objects (each under its own per-tree lock), then REAP
/// the marked rows past the grace. Returns `(marked, reaped, reclaimed_bytes)`.
async fn run_log_gc(
    state: &AppState,
    window_secs: i64,
    grace_secs: i64,
) -> Result<(u64, u64, i64), ApiError> {
    let trees: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT DISTINCT tree_id FROM tree_blob_index WHERE split_part(key, '/', 1) = 'log'",
    )
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    let mut marked = 0u64;
    for (tree_id,) in &trees {
        marked += mark_tree(state, *tree_id, window_secs).await?;
    }
    let (reaped, reclaimed) = reap_marked(state, grace_secs).await?;
    Ok((marked, reaped, reclaimed))
}

#[derive(Deserialize)]
pub struct GcParams {
    /// Override the gate-2 activity window (seconds) — for tests/manual runs. Default 30d.
    activity_window_secs: Option<i64>,
    /// Override the mark→reap deletion grace (seconds). Default 7d.
    deletion_grace_secs: Option<i64>,
}

/// `POST /dev/log/gc` (local only) — run the log GC sweep. In production this logic is driven by a scheduled
/// trigger (`EventBridge` → an authenticated internal call), not a public route — exactly like
/// `media::sweep_dev`.
///
/// # Errors
/// Returns [`ApiError`] if the store or DB access fails.
pub async fn gc_dev(State(state): State<AppState>, Query(p): Query<GcParams>) -> Result<Response, ApiError> {
    let (marked, reaped, reclaimed) = run_log_gc(
        &state,
        p.activity_window_secs.unwrap_or(DEFAULT_ACTIVITY_WINDOW_SECS),
        p.deletion_grace_secs.unwrap_or(DEFAULT_DELETION_GRACE_SECS),
    )
    .await?;
    tracing::info!(event = "log_gc", marked, reaped, reclaimed_bytes = reclaimed, "log GC sweep");
    Ok(Json(json!({
        "marked": marked,
        "reaped": reaped,
        "reclaimed_bytes": reclaimed,
    }))
    .into_response())
}
