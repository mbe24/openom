//! Reserved seam for GC / snapshot compaction (item 5) — **not yet implemented**.
//!
//! This module records the planned shape of snapshot-and-prune so the integration surface is stable,
//! without building the prune itself. Per `plan/local-first/design.gc-snapshots.md`, pruning is
//! Phase-3 and must be gated on a host-supplied *stable frontier* — keyeo is transport-agnostic and
//! does not know which frontier all peers have synced past, so a bare `gc()` is data-loss territory.
//! The entry point takes the frontier + a retention policy instead:
//!
//! ```ignore
//! k.compact(&stable_frontier, &policy)
//! ```
//!
//! The seam today:
//! - [`Frontier`] is at what point in the op DAG a peer may be pruned below.
//! - [`Snapshot`] is the signed materialized state + epoch a compaction anchors to.
//! - [`RetentionPolicy`] decides when to snapshot and how much tail to keep.
//! - [`compact`] is a **no-op** today (nothing prunes), reserving the call shape. The DAG still keeps
//!   history; a snapshot/`compact` that actually drops op's lands with the sync layer (FLO-81).

use crate::dag::resolver::MemberId;
use crate::Role;

/// A set of op ids known to have been replicated to all peers — the most recent frontier below which
/// the local store may prune. Until a sync layer supplies it, callers pass a conservative frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier<OId: crate::dag::resolver::OpId> {
    /// The op-ids at the cut — the frontier below which the local store may prune.
    pub ops: Vec<OId>,
}

/// A signed snapshot: the materialized membership (+ epoch wraps) at a frontier, plus a commitment to
/// the pruned history. What `compact` anchors to once implemented (item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<
    OId: crate::dag::resolver::OpId,
    Id: MemberId,
    R: Role,
    S: crate::SignatureScheme,
> {
    pub frontier: Vec<OId>,
    pub state: crate::dag::resolver::GroupState<Id, R, S>,
    pub prev_snapshot: Option<[u8; 32]>,
    /// The monotonic ever-shared marker, carried so it survives pruning: once the op history that first
    /// shared the tree is dropped, `Keyeo::ever_shared`'s effective-Add scan can't see it, so the checkpoint
    /// must record it. Verified monotone against the prior snapshot on adoption (the pruning slice).
    pub ever_shared: bool,
}

/// The retention POLICY now lives in `keyeo-core` — `keyeo_core::RetentionPolicy` (metrics→plan) + the
/// `Retention` enum (`Never` = the full-retention default), shared by every engine. This module keeps only
/// the dag-specific compaction MECHANISM: the [`Frontier`] cut, the [`Snapshot`] rebuild base, and `compact`.
///
/// Reserve the seam. **No-op today** — it accepts the stable frontier + the policy's plan and returns nothing
/// to prune. When the pruning slice implements it (as the dag's `keyeo_core::Compaction` impl) it will:
/// (1) author a signed [`Snapshot`] if the plan warrants one, (2) compute a horizon from `plan.keep_last`
/// clamped to `stable`, (3) drop ops causally below that horizon, leaving the snapshot as the rebuild base.
pub fn compact<OId: crate::dag::resolver::OpId>(
    _stable: &Frontier<OId>,
    _plan: keyeo_core::RetentionPlan,
) -> Vec<OId> {
    Vec::new()
}
