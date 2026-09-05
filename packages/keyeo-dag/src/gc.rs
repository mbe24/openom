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
/// the pruned history. What `compact` anchors to once implemented (item 5). Once ops below the frontier are
/// pruned, the Snapshot IS the trust root a fresh reader adopts, so it MUST be authenticated — the author
/// signature ([`Snapshot::author`] / [`verify_snapshot`]) binds the whole state (membership + RVK) to a signer.
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
    /// shared the tree is dropped, `Keyeo::has_been_shared`'s effective-Add scan can't see it, so the checkpoint
    /// must record it. Verified monotone against the prior snapshot on adoption (the pruning slice).
    pub has_been_shared: bool,
    /// The member (a signer: Owner/CoOwner) who authored this checkpoint. The signature binds to their key.
    pub author: Id,
    /// Author signature over the canonical `(frontier, prev_snapshot, has_been_shared, state)` — proves the
    /// checkpoint was signed by the holder of `author_public_key`. AUTHORITY (that this key is an authorized
    /// signer at the prior checkpoint / genesis, and `has_been_shared` monotonicity across `prev_snapshot`) is
    /// checked on ADOPTION, not here — the same self-contained-signature / separate-authority split as epochs.
    pub signature: <S as crate::SignatureScheme>::Signature,
    pub author_public_key: <S as crate::SignatureScheme>::PublicKey,
}

impl<OId: crate::dag::resolver::OpId, Id: MemberId, R: Role, S: crate::SignatureScheme>
    Snapshot<OId, Id, R, S>
{
    /// Author a signed checkpoint: an authorized signer signs the canonical content with their Ed25519 key.
    /// Mirrors [`crate::epoch::Epoch::author`] — the signature is self-contained (verify with
    /// [`verify_snapshot`]); the adoption path additionally establishes the author's authority.
    #[allow(clippy::too_many_arguments)]
    pub fn author(
        frontier: Vec<OId>,
        state: crate::dag::resolver::GroupState<Id, R, S>,
        prev_snapshot: Option<[u8; 32]>,
        has_been_shared: bool,
        author: Id,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self
    where
        S: crate::SignatureScheme<PublicKey = [u8; 32], Signature = [u8; 64]>,
    {
        let canon = crate::canonical::canonical_encode_snapshot::<OId, Id, R, S>(
            &frontier,
            &prev_snapshot,
            has_been_shared,
            &state,
        );
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&canon).to_bytes();
        let author_public_key = signing_key.verifying_key().to_bytes();
        Snapshot { frontier, state, prev_snapshot, has_been_shared, author, signature, author_public_key }
    }
}

/// Verify a snapshot's **author signature** over its canonical content: proves the checkpoint was signed by
/// the holder of its self-asserted `author_public_key`. Self-contained — it does NOT establish AUTHORITY (that
/// the key is an authorized signer at the prior checkpoint / genesis, nor `has_been_shared` monotonicity across
/// `prev_snapshot`); that is the adoption path's job (the pruning slice). Mirrors [`crate::epoch::verify_epoch`].
/// Run at ingest so a bad-signature checkpoint never enters the adoption candidate set.
pub fn verify_snapshot<
    OId: crate::dag::resolver::OpId,
    Id: MemberId,
    R: Role,
    S: crate::SignatureScheme,
>(
    snapshot: &Snapshot<OId, Id, R, S>,
) -> bool {
    let canon = crate::canonical::canonical_encode_snapshot::<OId, Id, R, S>(
        &snapshot.frontier,
        &snapshot.prev_snapshot,
        snapshot.has_been_shared,
        &snapshot.state,
    );
    S::verify(&snapshot.author_public_key, &canon, &snapshot.signature).is_ok()
}

/// The (UNSIGNED) decision the dag's [`keyeo_core::Compaction`] impl returns: the checkpoint to author (its
/// frontier + resolved `state` + `has_been_shared`) and the `prune` set — the ops the caller may drop. `compact`
/// takes no signing key and no `&mut`, so it never signs and never mutates: the CALLER (which holds the
/// member's key) authors the signed [`Snapshot`] from `(frontier, state, has_been_shared)` via [`Snapshot::author`]
/// and applies `prune` to its store. Kept engine-native (the prune is a causal-DAG computation) but returned as
/// plain data so the vault owns the signing + the store owns the drop.
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
// caller signs (via [`Snapshot::author`]) and applies. The retention POLICY (`keyeo_core::RetentionPolicy` +
// the `Retention` enum) is engine-neutral in keyeo-core. This module owns the [`Frontier`] cut + the
// [`Snapshot`] rebuild base + [`Compacted`].

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::resolver::{GroupId, GroupState, MemberInit};
    use crate::{ContentId, Ed25519};

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

    fn author_sample(has_been_shared: bool) -> Snapshot<ContentId, String, TRole, Ed25519> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        Snapshot::author(vec![], sample_state(), None, has_been_shared, "owner".to_string(), &sk)
    }

    #[test]
    fn a_signed_snapshot_verifies_and_any_tamper_is_rejected() {
        let s = author_sample(true);
        assert!(verify_snapshot(&s), "a freshly-authored snapshot verifies");

        // Flip the monotonic has_been_shared marker → the signature no longer covers it.
        let mut t = s.clone();
        t.has_been_shared = false;
        assert!(!verify_snapshot(&t), "tampering has_been_shared breaks the signature");

        // Tamper a state field (the epoch) → rejected.
        let mut t = s.clone();
        t.state.epoch = 99;
        assert!(!verify_snapshot(&t), "tampering the state breaks the signature");

        // Tamper the recovery authority (the RVK) → rejected (the checkpoint binds the RVK, so a pruned reader
        // can't be handed a checkpoint with an attacker's recovery key).
        let mut t = s.clone();
        t.state.reset_authority = Some([0u8; 32]);
        assert!(!verify_snapshot(&t), "tampering the RVK breaks the signature");

        // A forged author_public_key (claiming a different signer) → rejected.
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let mut t = s.clone();
        t.author_public_key = other.verifying_key().to_bytes();
        assert!(!verify_snapshot(&t), "a mismatched author key is rejected");
    }

    #[test]
    fn has_been_shared_is_inside_the_signed_bytes() {
        // Distinct has_been_shared values yield distinct signatures over the same state — the marker is signed, so
        // an attacker can't flip a shared checkpoint to unshared and keep the signature valid.
        assert_ne!(author_sample(true).signature, author_sample(false).signature);
    }
}
