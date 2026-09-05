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
//! - [`Snapshot`] — the authenticated checkpoint a compaction anchors to: a [`Signed`] over a
//!   [`Snapshot`] (the signature layer). Authority-on-adoption (the `prev_snapshot` continuity +
//!   `has_been_shared` monotonicity checks) is still pending — the reader/adopt wiring, not this module.
//! - [`Compacted`] — the decision `compact` returns.
//!
//! What is NOT built yet: the caller-side flow (author the snapshot, drop the pruned ops, produce the new
//! anchor) and the adoption/verification path. The compaction DECISION itself is implemented and tested.

use crate::dag::resolver::MemberId;
use crate::Role;

/// A set of op ids known to have been replicated to all peers — the most recent frontier below which
/// the local store may prune. Until a sync layer supplies it, callers pass a conservative frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier<OId: crate::dag::resolver::OpId> {
    /// The op-ids at the cut — the frontier below which the local store may prune.
    pub ops: Vec<OId>,
}

/// A checkpoint's captured content: the materialized membership (+ epoch wraps) at a frontier, the
/// pruned-history commitment (`prev_snapshot`), the monotonic shared-marker, and the authoring signer.
///
/// Signing is a generic concern, so this bare type is the *content* and the authenticated form is simply
/// [`Signed<Snapshot>`](keyeo_core::Signed) — "a signed snapshot". Construct that with
/// [`Signed::sign`](keyeo_core::Signed::sign) and read it with [`Signed::verify`](keyeo_core::Signed::verify),
/// the only accessor — so no caller can act on an unverified checkpoint. Once ops below the frontier are
/// pruned, `Signed<Snapshot>` IS the trust root a fresh reader adopts, so it MUST be authenticated: `verify`
/// binds this whole content (membership + RVK + `has_been_shared` + `author`) to the signer. Establishing that
/// the signer is an AUTHORIZED signer (at the prior checkpoint / genesis) and `has_been_shared` monotonicity
/// across `prev_snapshot` is the adoption path's job — the same self-contained-signature / separate-authority
/// split as epochs.
///
/// Every field is inside the signature (via the exhaustive [`CanonicalBytes`](keyeo_core::CanonicalBytes) impl
/// in `canonical.rs`) — a new field is a compile error until it is encoded, so nothing trust-relevant can slip
/// out of the signed bytes.
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
    /// The monotonic has-been-shared marker, carried so it survives pruning: once the op history that first
    /// shared the tree is dropped, `Keyeo::has_been_shared`'s effective-Add scan can't see it, so the checkpoint
    /// must record it. Verified monotone against the prior snapshot on adoption (the pruning slice).
    ///
    /// Deliberately a BOOL, not an ordinal. The chain records `first_shared_revision` (WHICH revision sharing
    /// began at); the dag has no natural single ordinal for that (a genesis + effective-Add scan doesn't map
    /// onto "revision N"), so a compacted dag checkpoint keeps "it was shared" but not "since when" — an
    /// accepted, deliberate scope difference. If forensic "shared since X" is ever wanted for dag trees, capture
    /// it before first compaction; it can't be reconstructed after.
    pub has_been_shared: bool,
    /// The member (a signer: Owner/CoOwner) who authored this checkpoint. Bound INTO the signed bytes (the
    /// exhaustive [`CanonicalBytes`](keyeo_core::CanonicalBytes)), so the author label can't be swapped on a
    /// pruned root. The signer's public key + signature live on the [`Signed`](keyeo_core::Signed) envelope,
    /// not here.
    pub author: Id,
}

/// The (UNSIGNED) decision the dag's [`keyeo_core::Compaction`] impl returns: the checkpoint to author (its
/// frontier + resolved `state` + `has_been_shared`) and the `prune` set — the ops the caller may drop. `compact`
/// takes no signing key and no `&mut`, so it never signs and never mutates: the CALLER (which holds the
/// member's key) builds a [`Snapshot`] from `(frontier, state, has_been_shared)` and signs it via
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
    /// The resolved state to sign into the [`Snapshot`].
    pub state: crate::dag::resolver::GroupState<Id, R, S>,
    pub has_been_shared: bool,
    /// Op ids the caller may drop: strictly below the frontier AND not needed by any retained op.
    pub prune: Vec<OId>,
}

// The dag's compaction MECHANISM (the `keyeo_core::Compaction` impl for `Keyeo`) lives in `engine.rs`, where it
// can read the engine's causal graph to compute the prune set; it returns a [`Compacted`] decision the
// caller signs (via [`Signed::sign`]) and applies. The retention POLICY (`keyeo_core::RetentionPolicy` +
// the `Retention` enum) is engine-neutral in keyeo-core. This module owns the [`Frontier`] cut + the
// [`Snapshot`] rebuild base + [`Compacted`].

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::resolver::{GroupId, GroupState, MemberInit};
    use crate::{ContentId, Ed25519};
    use keyeo_core::{CanonicalBytes, Signed};

    #[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
    struct TRole;
    impl Role for TRole {
        fn grants_at_least(&self, _: &Self) -> bool {
            true
        }
    }

    /// A non-trivial state: one member (id/role/keys) + a pinned recovery authority, so the canonical
    /// encoding exercises the membership AND the RVK the signature must bind.
    fn sample_state() -> GroupState<String, TRole, Ed25519> {
        GroupState::create(
            GroupId(b"tree".to_vec()),
            &[MemberInit {
                id: "owner".to_string(),
                role: TRole,
                author_public_key: [1u8; 32],
                hpke_public_key: [2u8; 32],
            }],
        )
        .with_reset_authority(Some([9u8; 32]))
    }

    fn sample_snapshot(has_been_shared: bool) -> Snapshot<ContentId, String, TRole, Ed25519> {
        Snapshot {
            frontier: vec![],
            state: sample_state(),
            prev_snapshot: None,
            has_been_shared,
            author: "owner".to_string(),
        }
    }

    fn canon(snap: &Snapshot<ContentId, String, TRole, Ed25519>) -> Vec<u8> {
        let mut b = Vec::new();
        snap.write_canonical(&mut b);
        b
    }

    #[test]
    fn a_signed_checkpoint_round_trips_through_verify() {
        // The whole `Signed` mechanism, over a real checkpoint: sign, then `verify` (the only accessor) returns
        // the snapshot. Wrong-key / tampered-body rejection is proven generically in `keyeo_core::signed`.
        let sk = edsign::SigningKey::from_seed(&[7u8; 32]);
        let snap = sample_snapshot(true);
        let signed = Signed::<_, Ed25519>::sign(snap.clone(), &sk);
        assert_eq!(signed.verify(), Some(&snap), "a freshly-signed checkpoint verifies and yields its snapshot");
    }

    #[test]
    fn every_checkpoint_field_is_inside_the_signed_bytes() {
        // Changing ANY body field changes the canonical bytes the signature covers — so none can be tampered on
        // a pruned root while keeping the signature valid. Since `Signed` signs exactly these bytes, "in the
        // canonical bytes" == "signed". The RVK + epoch + has_been_shared + author are the load-bearing ones.
        let base = sample_snapshot(true);
        let baseline = canon(&base);

        let mut t = base.clone();
        t.has_been_shared = false;
        assert_ne!(canon(&t), baseline, "has_been_shared is signed");

        let mut t = base.clone();
        t.state.epoch = 99;
        assert_ne!(canon(&t), baseline, "state (epoch) is signed");

        let mut t = base.clone();
        t.state.reset_authority = Some([0u8; 32]);
        assert_ne!(canon(&t), baseline, "the RVK (recovery authority) is signed");

        let mut t = base.clone();
        t.author = "mallory".to_string();
        assert_ne!(canon(&t), baseline, "the author label is signed — it can't be relabeled on a pruned root");

        let mut t = base.clone();
        t.prev_snapshot = Some([1u8; 32]);
        assert_ne!(canon(&t), baseline, "prev_snapshot is signed");

        let mut t = base.clone();
        t.frontier = vec![ContentId([5u8; 32])];
        assert_ne!(canon(&t), baseline, "the frontier is signed");
    }
}
