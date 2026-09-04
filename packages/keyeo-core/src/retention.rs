//! Engine-neutral retention / compaction vocabulary.
//!
//! Both keyring engines' histories grow (the dag's op-closure, the chain's retained revisions), and both
//! bound that growth the same way: a signed CHECKPOINT that carries the essential state forward, plus a
//! PRUNE of the history below it. This module is the shared surface for that:
//!
//! - the POLICY ([`RetentionPolicy`] / [`Retention`]) is pure `metrics → plan` — engine-agnostic, no
//!   position type, zero-cost;
//! - the MECHANISM ([`Compaction`]) is a FUNCTIONAL contract (no `&mut self`) each engine implements with
//!   its own state/position types.
//!
//! Why functional: openom holds each engine's serialized state as a blob and calls the engine per-operation
//! (the dag `resolve(anchor_bytes)`, the chain verify-fns over revision blobs); neither engine is a live
//! object. So `compact` takes the state by reference and RETURNS the compaction for the caller to apply — the
//! same shape for the CRDT dag and the linear chain, the model difference living inside each impl. The
//! `compact` IMPLEMENTATIONS carry the security bar (an authenticated checkpoint, pinned adoption, a
//! coverage-bounded prune) and land with the pruning slice; this crate defines only the contract + policy.

/// What an engine reports about its retained history for a policy decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionMetrics {
    /// The number of retained items (dag: ops; chain: revisions).
    pub items: usize,
    /// The retained history's serialized byte size.
    pub bytes: u64,
}

/// The policy's decision — pure data, no engine types. `keep_last` is a COUNT of the most-recent items to
/// retain past a checkpoint; the engine's `compact` converts it to its own horizon (a revision, a frontier),
/// clamped to the host `stable` cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPlan {
    /// Retain everything — no checkpoint, no prune.
    KeepAll,
    /// Author a checkpoint and prune all but the last `keep_last` items.
    Snapshot { keep_last: usize },
}

/// The pluggable retention POLICY: metrics in → a plan out. Shared by every engine (and a keyeo library user
/// may write a bespoke impl). Because it names no position type, it moves cleanly to this crate and both
/// engines' `compact` translate its `keep_last` into their own horizon.
pub trait RetentionPolicy: Send + Sync {
    fn plan(&self, metrics: &RetentionMetrics) -> RetentionPlan;
}

/// The closed retention config a deployment selects at runtime — a zero-cost `enum` (no `dyn`). `Never` is
/// the full-retention library opt-out (unbounded, auditable); the others bound the history by item count or
/// serialized byte size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Never prune — retain the full history.
    Never,
    /// Checkpoint + prune once the retained item count exceeds `n`, keeping the last `n`.
    AfterItems(u32),
    /// Checkpoint + prune once the retained byte size exceeds `b`, keeping roughly `b` bytes' worth.
    AfterBytes(u64),
}

impl RetentionPolicy for Retention {
    fn plan(&self, m: &RetentionMetrics) -> RetentionPlan {
        match *self {
            Retention::Never => RetentionPlan::KeepAll,
            Retention::AfterItems(n) => {
                if m.items > n as usize {
                    RetentionPlan::Snapshot { keep_last: n as usize }
                } else {
                    RetentionPlan::KeepAll
                }
            }
            Retention::AfterBytes(b) => {
                if m.bytes > b {
                    // Keep roughly `b` bytes of the most recent items. A byte policy can only produce a COUNT
                    // horizon (that's the `RetentionPlan` contract), so it converts via the average item size
                    // — a deliberate, documented approximation, not a byte-exact cut.
                    let avg = (m.bytes / (m.items.max(1) as u64)).max(1);
                    RetentionPlan::Snapshot { keep_last: (b / avg) as usize }
                } else {
                    RetentionPlan::KeepAll
                }
            }
        }
    }
}

/// A compaction failure. keyeo-core is engine-neutral, so the engine-specific detail is carried as a string.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("compaction failed: {0}")]
pub struct CompactionError(pub String);

/// The engine-neutral COMPACTION mechanism — a FUNCTIONAL contract (no `&mut self`): read the caller-held
/// serialized `state`, and return the compaction (a checkpoint + a prune marker) for the caller to store and
/// apply, never pruning above the host-supplied `stable` cut. Both engines implement this same shape; the
/// CRDT-vs-linear difference lives inside each impl. Adding a 3rd engine is one more impl and nothing else.
///
/// The IMPLEMENTATIONS are where the pruning SECURITY lives (an authenticated, pin-adopted checkpoint; a
/// coverage-bounded prune) — they land with the pruning slice, gated on its own review.
pub trait Compaction {
    /// The serialized retained history the caller holds (dag: the op-anchor; chain: the retained revisions).
    type State;
    /// The host "all peers have synced past here" cut — `compact` never prunes above it (dag: a frontier of
    /// op-ids; chain: a revision). A peer that hasn't synced past the pruned point can't catch up from the
    /// log, so this is the data-loss guard.
    type Cut;
    /// What the caller stores + prunes to — a checkpoint plus the marker of what may be dropped.
    type Output;

    fn compact(
        state: &Self::State,
        stable: &Self::Cut,
        plan: RetentionPlan,
    ) -> Result<Self::Output, CompactionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(items: usize, bytes: u64) -> RetentionMetrics {
        RetentionMetrics { items, bytes }
    }

    #[test]
    fn never_always_keeps_all() {
        assert_eq!(Retention::Never.plan(&m(1_000, 1 << 30)), RetentionPlan::KeepAll);
    }

    #[test]
    fn after_items_snapshots_only_over_the_threshold() {
        assert_eq!(Retention::AfterItems(10).plan(&m(10, 0)), RetentionPlan::KeepAll);
        assert_eq!(
            Retention::AfterItems(10).plan(&m(11, 0)),
            RetentionPlan::Snapshot { keep_last: 10 }
        );
    }

    #[test]
    fn after_bytes_keeps_roughly_the_byte_budget_worth() {
        // 100 items, 1000 bytes → avg 10 bytes/item; budget 200 bytes → keep ~20 items.
        assert_eq!(
            Retention::AfterBytes(200).plan(&m(100, 1000)),
            RetentionPlan::Snapshot { keep_last: 20 }
        );
        assert_eq!(Retention::AfterBytes(2000).plan(&m(100, 1000)), RetentionPlan::KeepAll);
    }
}
