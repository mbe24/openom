//! The `Meter` seam — cost attribution + minimal enforcement, one swappable impl below the `BlobStore` layer
//! (`plan/sync/design.ope412-409-metering-gc.md` Part 1, OPE-412).
//!
//! It replaces the free-function `log::charge_metering` with a trait that keeps a clean **observe / enforce /
//! reconcile** split:
//! - **enforce** ([`Meter::charge_write`]): the existing capacity + rate gates — 403/429 — inside the
//!   caller's tx, so a rollback reverts the charge.
//! - **observe** ([`Meter::charge_write`]/[`Meter::charge_read`] also fold into `usage_month`; [`Meter::observe`]):
//!   the cost-attribution rollup — per `(account, tree, member, month)` write/read ops + bytes. Today a Neon
//!   upsert; the seam is what lets a later graduation to an out-of-band event pipeline swap one impl.
//! - **reconcile** ([`Meter::credit_storage`]): GC (`gc.rs`) credits reclaimed bytes back — the same seam that
//!   spends, reconciles.
//!
//! [`AppState`](crate::AppState) holds an `Arc<dyn Meter>` (dyn, not generic — a flat non-generic `AppState`
//! and unchanged handler signatures, per §1.4). [`PgMeter`] is the prod impl.

use async_trait::async_trait;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::trees::ApiError;

/// Who a charge is attributed to: the `account` that pays (the tree owner, owner-pays §17), the `tree`, and
/// the `member` who drove the op.
#[derive(Debug, Clone, Copy)]
pub struct MeterCtx {
    pub account: Uuid,
    pub tree: Uuid,
    pub member: Uuid,
}

/// Whether a write ACCUMULATES immutable R2 bytes (so the capacity gate fires) or just overwrites a pointer
/// (rate only — charging capacity per sync tick would over-count the same logical state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAxis {
    /// Immutable append (a `log/*` object, a scalar delta) — capacity + rate.
    Accumulating,
    /// Pointer overwrite (`heads/{replica}`, the `snapshot` pointer) — rate only.
    PointerOnly,
}

/// The out-of-band graduation hook's event shape ([`Meter::observe`]). Inert today (default no-op).
#[derive(Debug, Clone, Copy)]
pub enum MeterEvent {
    Write { bytes: i64, axis: WriteAxis },
    Read { bytes: Option<i64> },
    Reclaim { bytes: i64 },
}

/// A gate rejection from [`Meter::charge_write`]. `Internal` carries a store error the caller renders as 500
/// (the gate SQL itself failing, not a policy decision).
#[derive(Debug)]
pub enum MeterError {
    /// The per-(tree, member) rate bucket is empty — 429 with this `Retry-After` (whole seconds; coarsened for
    /// a non-privileged caller so the value can't fingerprint the owner's plan rate, F1).
    RateLimited { retry_after_secs: u64 },
    /// The owner's tree-byte capacity is exhausted — 403 (`quota_exceeded`; read-only degradation, never
    /// lockout). `limit`/`used` are the owner's plan figures, present ONLY for a caller at or above
    /// [`BILLING_ARG_MIN_ROLE`] (F1: a lower-role collaborator must not learn the owner's tier/headroom);
    /// `None` → the client renders a figure-free message.
    CapacityExceeded { limit: Option<i64>, used: Option<i64> },
    /// The gate's own SQL failed — surfaced as 500, cause logged not leaked.
    Internal(String),
}

/// Callers at or above this role (numerically `<=`, roles are power-descending) receive the precise billing
/// figures (quota `{limit, used}`, exact rate retry-after); below it the owner's plan numbers are withheld
/// (F1). One tunable — raise to `ROLE_CO_OWNER` to restrict further.
const BILLING_ARG_MIN_ROLE: i16 = openom_roles::ROLE_MAINTAINER;

impl From<MeterError> for ApiError {
    fn from(e: MeterError) -> Self {
        match e {
            MeterError::RateLimited { retry_after_secs } => Self::TooManyRequests(retry_after_secs.max(1)),
            MeterError::CapacityExceeded { limit, used } => {
                let args = match (limit, used) {
                    (Some(limit), Some(used)) => serde_json::json!({ "limit": limit, "used": used }),
                    _ => serde_json::Value::Null,
                };
                Self::Coded {
                    status: axum::http::StatusCode::FORBIDDEN,
                    code: crate::error_codes::QUOTA_EXCEEDED,
                    detail: "account resource limit reached".into(),
                    args,
                }
            }
            MeterError::Internal(m) => Self::Internal(m),
        }
    }
}

/// The caller's role on the tree, resolved on the rare rejection path only: the owner (`member == account`,
/// owner-pays) is the strongest role; otherwise the `tree_access` row (absent → not privileged). Used solely
/// to gate the billing figures in the two rejection errors — never on the happy path.
async fn caller_is_privileged(tx: &mut Transaction<'_, Postgres>, cx: MeterCtx) -> bool {
    if cx.member == cx.account {
        return true; // the tree owner
    }
    let role: Option<i16> = sqlx::query_scalar("SELECT role FROM tree_access WHERE tree_id = $1 AND member_id = $2")
        .bind(cx.tree)
        .bind(cx.member)
        .fetch_optional(&mut **tx)
        .await
        .ok()
        .flatten();
    role.is_some_and(|r| r <= BILLING_ARG_MIN_ROLE)
}

/// The cost/enforce seam. One impl per environment: [`PgMeter`] in prod; a test double can exercise handler
/// 403/429 branches without a live DB.
#[async_trait]
pub trait Meter: Send + Sync {
    /// ENFORCE + OBSERVE. The capacity (Accumulating only) + rate gates inside the caller's `tx` (a rollback
    /// reverts the charge), AND a `usage_month` `write_ops`/`bytes_write` increment for this
    /// `(account, tree, member, month)`.
    ///
    /// # Errors
    /// [`MeterError::RateLimited`] / [`MeterError::CapacityExceeded`] on a gate rejection; [`MeterError::Internal`]
    /// if the gate SQL fails.
    async fn charge_write(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        cx: MeterCtx,
        size_bytes: i64,
        axis: WriteAxis,
    ) -> Result<(), MeterError>;

    /// Rate-gate a create-tree (OPE-408): a per-ACCOUNT token bucket, committed independently (its own tx via
    /// `pool`) so even a rejected create (over-quota / forbidden) still consumes a token — else POST /trees, the
    /// only otherwise-ungated write, could be hammered with no backoff. Refills at the account's
    /// `log_rate`/`log_burst`. An unknown account (no row) is not gated — the handler forbids it anyway.
    ///
    /// # Errors
    /// [`MeterError::RateLimited`] on an empty bucket; [`MeterError::Internal`] if the gate SQL fails.
    async fn charge_create(&self, pool: &PgPool, account: Uuid) -> Result<(), MeterError>;

    /// OBSERVE only (no gate today): count `read_ops`/`bytes_read` for `(account, tree, member, month)`. `bytes`
    /// from `tree_blob_index` before the store fetch; `None` for a LIST. Best-effort — a metering hiccup must
    /// never fail a read, so a store error is logged, not returned.
    ///
    /// # Errors
    /// Reserved for a future synchronous read gate; today always `Ok`.
    async fn charge_read(&self, pool: &PgPool, cx: MeterCtx, bytes: Option<i64>) -> Result<(), MeterError>;

    /// RECONCILE: credit reclaimed bytes back to the owner's tree-byte capacity, in the sweep's row-delete tx
    /// (GC, `gc.rs`). Mirrors media's `release()`.
    ///
    /// # Errors
    /// Returns the underlying [`sqlx::Error`] if the credit UPDATE fails.
    async fn credit_storage(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
        bytes: i64,
    ) -> Result<(), sqlx::Error>;

    /// Graduation hook: an out-of-band emit (Telemetry API / EMF) for the observe path. Default no-op today.
    fn observe(&self, _cx: &MeterCtx, _event: MeterEvent) {}
}

/// The production `Meter`: Neon (Postgres) gates + the `usage_month` rollup. Holds no state — every method
/// takes the caller's tx/pool.
pub struct PgMeter;

/// Fold one write into the cost rollup, in the caller's tx. A genuinely-new write only (re-deliveries return
/// before the meter is called), so `+1 write_op` is exact.
async fn record_write(
    tx: &mut Transaction<'_, Postgres>,
    cx: MeterCtx,
    size_bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO usage_month (account_id, tree_id, member_id, month, write_ops, bytes_write)
         VALUES ($1, $2, $3, date_trunc('month', now())::date, 1, $4)
         ON CONFLICT (account_id, tree_id, member_id, month) DO UPDATE
           SET write_ops = usage_month.write_ops + 1,
               bytes_write = usage_month.bytes_write + EXCLUDED.bytes_write",
    )
    .bind(cx.account)
    .bind(cx.tree)
    .bind(cx.member)
    .bind(size_bytes)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[async_trait]
impl Meter for PgMeter {
    async fn charge_write(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        cx: MeterCtx,
        size_bytes: i64,
        axis: WriteAxis,
    ) -> Result<(), MeterError> {
        // (1) Per-member abuse rate: a token bucket keyed (tree, member), refilled at the OWNER's plan rate
        // (owner-pays sets the budget, the member holds the state), lazily created full on first write; the
        // WHERE guard on the UPDATE branch re-derives the balance so check and debit can't race (0 rows →
        // over). Ported verbatim from the former `log::charge_metering`.
        //
        // SIZING (OPE-408): the default log_rate=10/s, log_burst=200 (migration 0004) is comfortably above the
        // real client cadence, so a normal multi-PUT sync tick (a delta or few + a heads pointer + sometimes a
        // snapshot) never false-429s: same-key rewrites are already floored at >=1s by the client (OPE-410), so
        // sustained legit writes stay well under 10/s, and a reconnect/backlog burst is absorbed by the 200-token
        // headroom then drains at 10/s. A runaway per-member loop is still capped at 10/s (owner-pays, and now a
        // hard-removable member per OPE-421). A single generous bucket, per the owner decision (4-B).
        let (m_rate, m_burst): (f64, i32) =
            sqlx::query_as("SELECT log_rate, log_burst FROM accounts WHERE id = $1")
                .bind(cx.account)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| MeterError::Internal(e.to_string()))?;
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
        .bind(cx.tree)
        .bind(cx.member)
        .bind(m_burst)
        .bind(m_rate)
        .execute(&mut **tx)
        .await
        .map_err(|e| MeterError::Internal(e.to_string()))?;
        if member_ok.rows_affected() != 1 {
            // A positive ceil'd retry-after in whole seconds; the saturating f64->u64 cast is intentional.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let exact = if m_rate > 0.0 { (1.0 / m_rate).ceil() as u64 } else { 60 };
            // F1: a non-privileged caller gets a fixed coarse backoff, not the exact 1/rate that would reveal
            // the owner's plan rate. Privileged callers (owner/co-owner/maintainer) get the precise value.
            let retry_after_secs = if caller_is_privileged(tx, cx).await { exact } else { exact.max(60) };
            tracing::info!(event = "rate_rejected", resource = "meter", tree = %cx.tree, member = %cx.member);
            return Err(MeterError::RateLimited { retry_after_secs });
        }

        // (2) Byte capacity: the tree-byte meter (§17), only for an accumulating (immutable) write — a pointer
        // overwrite doesn't grow R2 usage, so charging it would over-count the same logical state each tick.
        if axis == WriteAxis::Accumulating {
            let capped = sqlx::query(
                "UPDATE accounts SET tree_used_bytes = tree_used_bytes + $2
                  WHERE id = $1 AND tree_used_bytes + $2 <= max_tree_bytes",
            )
            .bind(cx.account)
            .bind(size_bytes)
            .execute(&mut **tx)
            .await
            .map_err(|e| MeterError::Internal(e.to_string()))?;
            if capped.rows_affected() != 1 {
                tracing::info!(event = "quota_rejected", resource = "meter", tree = %cx.tree, owner = %cx.account);
                // F1: attach the owner's plan figures ONLY for a privileged caller; a lower-role collaborator
                // gets the code with no numbers, so it can't read the owner's tier/headroom.
                let (limit, used) = if caller_is_privileged(tx, cx).await {
                    let row: (i64, i64) =
                        sqlx::query_as("SELECT max_tree_bytes, tree_used_bytes FROM accounts WHERE id = $1")
                            .bind(cx.account)
                            .fetch_one(&mut **tx)
                            .await
                            .map_err(|e| MeterError::Internal(e.to_string()))?;
                    (Some(row.0), Some(row.1))
                } else {
                    (None, None)
                };
                return Err(MeterError::CapacityExceeded { limit, used });
            }
        }

        // (3) OBSERVE: fold this write into the cost rollup, same tx (a rollback reverts it with the charge).
        record_write(tx, cx, size_bytes)
            .await
            .map_err(|e| MeterError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn charge_create(&self, pool: &PgPool, account: Uuid) -> Result<(), MeterError> {
        // A per-account token bucket in its OWN committed statement, so a rejected create still spends a token
        // (the create handler rolls its entitlement tx back on a 403, so a shared tx would refund the debit and
        // defeat the anti-hammer purpose). Refill uses the account's log_rate/log_burst; the WHERE guard makes
        // check-and-debit atomic per row (0 rows → over), exactly as the per-member data bucket above.
        let Some((rate, burst)): Option<(f64, i32)> =
            sqlx::query_as("SELECT log_rate, log_burst FROM accounts WHERE id = $1")
                .bind(account)
                .fetch_optional(pool)
                .await
                .map_err(|e| MeterError::Internal(e.to_string()))?
        else {
            return Ok(()); // unknown account — the handler forbids it; nothing to rate-gate
        };
        let ok = sqlx::query(
            "INSERT INTO account_create_rate (account_id, tokens, refilled_at)
             VALUES ($1, $2::float8 - 1, now())
             ON CONFLICT (account_id) DO UPDATE
               SET tokens = LEAST($2::float8, account_create_rate.tokens
                                  + EXTRACT(EPOCH FROM (now() - account_create_rate.refilled_at)) * $3) - 1,
                   refilled_at = now()
               WHERE LEAST($2::float8, account_create_rate.tokens
                           + EXTRACT(EPOCH FROM (now() - account_create_rate.refilled_at)) * $3) >= 1",
        )
        .bind(account)
        .bind(burst)
        .bind(rate)
        .execute(pool)
        .await
        .map_err(|e| MeterError::Internal(e.to_string()))?;
        if ok.rows_affected() != 1 {
            // The create caller is always the tree owner (creating their own tree), so the exact 1/rate
            // retry-after leaks nothing (it's their own plan rate).
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let retry_after_secs = if rate > 0.0 { (1.0 / rate).ceil() as u64 } else { 60 };
            tracing::info!(event = "rate_rejected", resource = "create_tree", owner = %account);
            return Err(MeterError::RateLimited { retry_after_secs });
        }
        Ok(())
    }

    async fn charge_read(&self, pool: &PgPool, cx: MeterCtx, bytes: Option<i64>) -> Result<(), MeterError> {
        // Best-effort: a metering write must never fail the read it counts. Log a store error and proceed.
        let res = sqlx::query(
            "INSERT INTO usage_month (account_id, tree_id, member_id, month, read_ops, bytes_read)
             VALUES ($1, $2, $3, date_trunc('month', now())::date, 1, $4)
             ON CONFLICT (account_id, tree_id, member_id, month) DO UPDATE
               SET read_ops = usage_month.read_ops + 1,
                   bytes_read = usage_month.bytes_read + EXCLUDED.bytes_read",
        )
        .bind(cx.account)
        .bind(cx.tree)
        .bind(cx.member)
        .bind(bytes.unwrap_or(0))
        .execute(pool)
        .await;
        if let Err(e) = res {
            tracing::warn!(%e, tree = %cx.tree, "could not record read usage (best-effort)");
        }
        Ok(())
    }

    async fn credit_storage(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
        bytes: i64,
    ) -> Result<(), sqlx::Error> {
        // Clamp at 0: the tree-byte meter is monotonic-until-GC, and a credit must never drive it negative
        // (mirrors media `release`, defensively floored).
        sqlx::query("UPDATE accounts SET tree_used_bytes = GREATEST(tree_used_bytes - $2, 0) WHERE id = $1")
            .bind(owner)
            .bind(bytes)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}
