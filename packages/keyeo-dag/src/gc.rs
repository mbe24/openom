//! GC / snapshot compaction for the dag engine — the persistable data types.
//!
//! Compaction must be gated on a host-supplied *stable frontier* — keyeo is transport-agnostic and does not
//! know which frontier all peers have synced past, so pruning below an arbitrary point is data-loss territory.
//! The `keyeo_core::Compaction` impl (in `engine.rs`, over the [`Retained`](crate::engine::Retained) view)
//! takes that frontier + the retention plan and returns a [`Compacted`] decision the CALLER signs (via
//! [`Signed::sign`](keyeo_core::Signed::sign)) and applies.
//!
//! This module owns the data types the mechanism produces/consumes:
//! - [`Frontier`] — at what point in the op DAG a peer may be pruned below (the stable cut).
//! - [`Compacted`] — the decision `compact` returns.
//!
//! keyeo returns the compaction DECISION as plain data; it does NOT define the signed checkpoint type. The
//! consumer builds and signs its own checkpoint (via [`Signed::sign`](keyeo_core::Signed::sign) over its own
//! [`CanonicalBytes`](keyeo_core::CanonicalBytes) body) from the decision's `(frontier, state, has_been_shared)`,
//! adding any consumer-specific fields (openom's checkpoint, for one, also preserves sealing). The engine stays
//! agnostic to what the checkpoint ultimately carries.

use crate::dag::resolver::MemberId;
use crate::Role;

/// A set of op ids known to have been replicated to all peers — the most recent frontier below which
/// the local store may prune. Until a sync layer supplies it, callers pass a conservative frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier<OId: crate::dag::resolver::OpId> {
    /// The op-ids at the cut — the frontier below which the local store may prune.
    pub ops: Vec<OId>,
}

/// The (UNSIGNED) decision the dag's [`keyeo_core::Compaction`] impl returns: the checkpoint content to author
/// (its frontier + resolved `state` + `has_been_shared`) and the `prune` set.
///
/// the ops the caller may drop.
///
/// `compact` takes no signing key and no `&mut`, so it never signs and never mutates: the CALLER (which holds
/// the member's key) builds its own checkpoint body from `(frontier, state, has_been_shared)` and signs it via
/// [`Signed::sign`](keyeo_core::Signed::sign), then applies `prune` to its store. Kept engine-native (the prune
/// is a causal-DAG computation) but returned as plain data so the vault owns the signing + the store owns the drop.
#[derive(Clone, Debug)]
pub struct Compacted<
    OId: crate::dag::resolver::OpId,
    Id: MemberId,
    R: Role,
    S: crate::SignatureScheme,
> {
    /// The stable frontier the checkpoint anchors at — the retained tail attaches to these tips.
    pub frontier: Vec<OId>,
    /// The resolved state to sign into the caller's checkpoint.
    pub state: crate::dag::resolver::GroupState<Id, R, S>,
    pub has_been_shared: bool,
    /// Op ids the caller may drop: strictly below the frontier AND not needed by any retained op.
    pub prune: Vec<OId>,
}

// The dag's compaction MECHANISM (the `keyeo_core::Compaction` impl for `Keyeo`) lives in `engine.rs`, where it
// can read the engine's causal graph to compute the prune set; it returns a [`Compacted`] decision the
// caller signs (via [`Signed::sign`]) and applies. The retention POLICY (`keyeo_core::RetentionPolicy` +
// the `Retention` enum) is engine-neutral in keyeo-core. This module owns the [`Frontier`] cut + [`Compacted`].
