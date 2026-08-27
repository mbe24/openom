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
use crate::roles::Role;

/// A set of op ids known to have been replicated to all peers — the most recent frontier below which
/// the local store may prune. Until a sync layer supplies it, callers pass a conservative frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier<OId: crate::dag::resolver::OpId> {
    pub heads: Vec<OId>,
}

/// A signed snapshot: the materialized membership (+ epoch wraps) at a frontier, plus a commitment to
/// the pruned history. What `compact` anchors to once implemented (item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<
    OId: crate::dag::resolver::OpId,
    Id: MemberId,
    R: Role,
    S: crate::signature::SignatureScheme,
> {
    pub frontier: Vec<OId>,
    pub state: crate::dag::resolver::GroupState<Id, R, S>,
    pub prev_snapshot: Option<[u8; 32]>,
}

/// When to snapshot and how much tail to retain. The pluggable *policy* (the fixed *mechanism* is the
/// snapshot itself). Kept deliberately small; see the design doc's `RetentionPolicy`.
pub trait RetentionPolicy<OId: crate::dag::resolver::OpId>: Send + Sync {
    /// Whether a snapshot is warranted given how many ops exist and how many since the last one.
    fn should_snapshot(&self, op_count: usize, since_last: usize) -> bool;
    /// A prune horizon never beyond the host-supplied stable frontier.
    fn prune_horizon(&self, stable: &Frontier<OId>) -> Frontier<OId>;
}

/// A `NeverPrune` default — high-security / full-audit: retain everything, never GC. This is the safe
/// default until the resolver + stability vector are proven.
pub struct NeverPrune;

impl<OId: crate::dag::resolver::OpId> RetentionPolicy<OId> for NeverPrune {
    fn should_snapshot(&self, _op_count: usize, _since_last: usize) -> bool {
        false
    }
    fn prune_horizon(&self, stable: &Frontier<OId>) -> Frontier<OId> {
        let _ = stable; // never prune; keep the stable frontier as-is
        Frontier { heads: Vec::new() }
    }
}

/// Reserve the seam. **No-op today** — it accepts the stable frontier + policy and returns nothing to
/// prune. When item 5 is implemented it: (1) author a snapshot if `policy.should_snapshot`, (2) compute
/// a horizon from `policy.prune_horizon(stable)`, (3) drop ops causally below that horizon, leaving the
/// snapshot as the rebuild base.
pub fn compact<OId: crate::dag::resolver::OpId>(
    _stable: &Frontier<OId>,
    _policy: &impl RetentionPolicy<OId>,
) -> Vec<OId> {
    Vec::new()
}
