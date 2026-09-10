//! Checkpoint DTO layer (compaction step 2a): the serializable, members-only view of a resolved keyring
//! `GroupState` that an adopted checkpoint carries across a prune.
//!
//! `reset_authority` and `group_id` are deliberately NOT here — they are already `DagAnchor`-level fields,
//! restored around this view on resolve. And keyeo's own typed epoch machinery (`epoch`/`history_commitment`/
//! `dek_wraps`) is NOT carried: openom never uses that path — its DEK material rides the opaque `sealing`
//! envelope, and the membership view (`view_of`) reads only `members`. So the checkpoint state is exactly the
//! member map, plus the two counters a `MemberState` has that a `MemberInit` lacks.

use crate::client::{SealingEntry, SealingOrigin};
use crate::{KeyringRole, KeyringState};
use keyeo_dag::{CanonicalBytes, Ed25519, GroupId, MemberState, Signed};
use serde::{Deserialize, Serialize};

/// A member's full resolved state at the anchor boundary. Mirrors `MemberInitDto` but adds `member_counter` +
/// `access_counter` — the strong-remove / rekey-race counters that distinguish a `MemberState` from a
/// `MemberInit`. Dropping them would corrupt a later re-add or rekey race on a compacted replica (a removed
/// member keeps an ODD `member_counter`), so they are load-bearing, not cosmetic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MemberStateDto {
    id: String,
    role: KeyringRole,
    member_counter: u64,
    access_counter: u64,
    author_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
}

/// The members-only view of a resolved `GroupState` — the checkpoint's authenticated membership base.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GroupStateView {
    /// Sorted by id, so the encoding is deterministic — a signed / content-addressed checkpoint requires it.
    members: Vec<MemberStateDto>,
}

impl GroupStateView {
    /// Capture the members of a resolved keyring state.
    pub(crate) fn of(state: &KeyringState) -> Self {
        let mut members: Vec<MemberStateDto> = state
            .members
            .iter()
            .map(|(id, m)| MemberStateDto {
                id: id.clone(),
                role: m.role,
                member_counter: m.member_counter,
                access_counter: m.access_counter,
                author_public_key: m.author_public_key,
                hpke_public_key: m.hpke_public_key,
            })
            .collect();
        members.sort_by(|a, b| a.id.cmp(&b.id));
        Self { members }
    }

    /// Rebuild a resolved `GroupState`, restoring the anchor-level `group_id` + `reset_authority` around the
    /// member map. `epoch`/`dek_wraps` are left at their defaults (unused by openom).
    pub(crate) fn into_state(self, group_id: GroupId, reset_authority: Option<[u8; 32]>) -> KeyringState {
        let mut state = KeyringState::create(group_id, &[]).with_reset_authority(reset_authority);
        state.members = self
            .members
            .into_iter()
            .map(|m| {
                (
                    m.id,
                    MemberState {
                        role: m.role,
                        member_counter: m.member_counter,
                        access_counter: m.access_counter,
                        author_public_key: m.author_public_key,
                        hpke_public_key: m.hpke_public_key,
                    },
                )
            })
            .collect();
        state
    }
}

impl CanonicalBytes for MemberStateDto {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure (no `..`): a new member field is a compile error until it is in the signed
        // bytes. All fields are length-bounded scalars/keys, so this is a plain, deterministic encoding.
        let Self { id, role, member_counter, access_counter, author_public_key, hpke_public_key } = self;
        let idb = id.as_bytes();
        out.extend_from_slice(&(idb.len() as u64).to_le_bytes());
        out.extend_from_slice(idb);
        out.extend_from_slice(&role.0.to_le_bytes());
        out.extend_from_slice(&member_counter.to_le_bytes());
        out.extend_from_slice(&access_counter.to_le_bytes());
        out.extend_from_slice(author_public_key);
        out.extend_from_slice(hpke_public_key);
    }
}

impl CanonicalBytes for GroupStateView {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // `members` is sorted by id in `of`, so the length-prefixed run is deterministic across replicas.
        let Self { members } = self;
        out.extend_from_slice(&(members.len() as u64).to_le_bytes());
        for m in members {
            m.write_canonical(out);
        }
    }
}

/// The signed body of an openom keyring compaction checkpoint (step 2a) — the GENERIC skeleton mirroring keyeo's
/// `Snapshot`: the dominating cut, the membership base at that cut, the continuity pointer, the shared-marker,
/// and the author. The openom-SPECIFIC sealing preservation (retained epochs + escrow + the minting-ops bound)
/// is layered on next. Carried as `Signed<Checkpoint>` — the SOLE carrier, so every trust-relevant field is
/// inside the signature (the exhaustive-destructure [`CanonicalBytes`] below makes a new unsigned field a
/// compile error).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Checkpoint {
    /// The dominating cut this checkpoint anchors at, each frontier op paired with its absolute lamport depth.
    /// The depths are LOAD-BEARING (spike-proven): `adopt` admits single-branch continuations via the `.any()`
    /// merge horizon, and two such ops on different-depth tips need the seed to reproduce the full-history
    /// strong-remove tiebreak. The keys alone ARE the frontier, so no separate plain `frontier` list is kept.
    pub frontier_depths: Vec<([u8; 32], u64)>,
    /// The resolved membership at the cut.
    pub state: GroupStateView,
    /// Hash of the prior checkpoint — the continuity chain a returning member validates. None at the first.
    pub prev_snapshot: Option<[u8; 32]>,
    /// Monotone shared-marker, carried because the sharing `Add` is pruned below the cut.
    pub has_been_shared: bool,
    /// The resolved recovery authority (RVK) at the cut. Carried in the SIGNED body (OPE-381): a
    /// `RotateRecoveryAuthority`'s only effect is to change `reset_authority`, so if the rotate op is pruned
    /// below the cut and this isn't preserved, the checkpoint base would fall back to the genesis authority —
    /// silently reverting the rotation (a retired recovery code would work again, and the owner's new one
    /// would not). `None` = a group with no recovery authority.
    pub reset_authority: Option<[u8; 32]>,
    /// The preserved folded sealing — the retained epochs + escrow, re-expressed as synthetic `SealingEntry`s
    /// (fold order preserved). The vault authors this by folding to completion (merging any `added_wraps` into
    /// the epochs) and emitting one entry per surviving epoch, so a below-cut joiner's wrap is NOT dropped. The
    /// `bytes` stay opaque here — keyring-dag never interprets sealing.
    pub sealing: Vec<SealingEntry>,
    /// The count of epoch-minting ops pruned below the cut. `fold_sealing` seeds its `minting_ops` counter from
    /// this so the OPE-289 ordinal-plausibility bound continues correctly across the prune (a retained epoch's
    /// ordinal must stay below the true minting count, not the post-prune one).
    pub minting_ops_baseline: u32,
    /// The signer (Owner/CoOwner) who authored the checkpoint — bound into the signed bytes so it can't be
    /// relabeled on a pruned root.
    pub author: String,
}

/// An authored, verifiable checkpoint. `verify()` (the only body accessor) binds the whole `Checkpoint` to the
/// signer; adoption authority (that the signer was authorized, `prev_snapshot` continuity, monotonicity) is a
/// separate, later gate.
pub(crate) type SignedCheckpoint = Signed<Checkpoint, Ed25519>;

/// Encode an `Option<[u8; N]>` (a hash / recovery-authority key) into `out` as a tagged, unambiguous byte
/// run: `1 ‖ the N bytes` when present, a lone `0` when absent. Used for a checkpoint's `prev_snapshot` and
/// (OPE-381) its 32-byte `reset_authority`. INJECTIVE — distinct values encode to distinct appended bytes
/// (kani-proven in `verification` below), which is what keeps those fields tamper-evident inside the
/// checkpoint signature. Generic over `N` because the injectivity is length-independent (tag + verbatim
/// copy), so kani can prove it at a small `N` that generalises to the 32-byte instance the checkpoint uses.
fn push_opt_hash<const N: usize>(out: &mut Vec<u8>, h: Option<&[u8; N]>) {
    match h {
        Some(k) => {
            out.push(1);
            out.extend_from_slice(k);
        }
        None => out.push(0),
    }
}

impl CanonicalBytes for Checkpoint {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure (no `..`): a new checkpoint field is a compile error until it is encoded here,
        // so nothing trust-relevant can slip out of the signed bytes.
        let Self { frontier_depths, state, prev_snapshot, has_been_shared, reset_authority, sealing, minting_ops_baseline, author } = self;
        out.extend_from_slice(b"openom:checkpoint:v1");
        // frontier_depths — sorted, length-prefixed. The (op-id) keys ARE the dominating cut; the paired depths
        // seed the strong-remove tiebreak across the prune.
        let mut fd = frontier_depths.clone();
        fd.sort_unstable();
        out.extend_from_slice(&(fd.len() as u64).to_le_bytes());
        for (id, d) in &fd {
            out.extend_from_slice(id);
            out.extend_from_slice(&d.to_le_bytes());
        }
        // membership view — its own exhaustive-destructure canonical encoding (members sorted by construction),
        // length-prefixed so the boundary is unambiguous.
        let mut state_bytes = Vec::new();
        state.write_canonical(&mut state_bytes);
        out.extend_from_slice(&(state_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&state_bytes);
        push_opt_hash(out, prev_snapshot.as_ref());
        out.push(u8::from(*has_been_shared));
        // reset_authority (OPE-381) — the resolved RVK at the cut, in the signed bytes so a signature can't be
        // replayed for a different recovery authority. Same tagged-Option encoding as prev_snapshot.
        push_opt_hash(out, reset_authority.as_ref());
        // sealing — ORDERED (the fold order is part of what's signed), length-prefixed; each entry is
        // op_id ‖ origin-tag ‖ length-prefixed opaque bytes ‖ length-prefixed author.
        out.extend_from_slice(&(sealing.len() as u64).to_le_bytes());
        for e in sealing {
            let SealingEntry { op_id, origin, author, bytes } = e;
            out.extend_from_slice(op_id);
            out.push(match origin {
                SealingOrigin::Genesis => 0,
                SealingOrigin::Remove => 1,
                SealingOrigin::Reseal => 2,
                SealingOrigin::Other => 3,
            });
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes);
            out.extend_from_slice(&(author.len() as u64).to_le_bytes());
            out.extend_from_slice(author.as_bytes());
        }
        out.extend_from_slice(&minting_ops_baseline.to_le_bytes());
        let a = author.as_bytes();
        out.extend_from_slice(&(a.len() as u64).to_le_bytes());
        out.extend_from_slice(a);
    }
}

#[cfg(kani)]
mod verification {
    use super::push_opt_hash;

    /// OPE-381 / F1 tamper-evidence, at the field level. The tagged `Option<[u8; 32]>` encoding used for a
    /// checkpoint's `reset_authority` (and `prev_snapshot`) is INJECTIVE: distinct values encode to distinct
    /// appended bytes. Because `reset_authority` therefore contributes uniquely to the checkpoint's canonical
    /// (signed) bytes, a signature over one checkpoint can never validate a checkpoint with a DIFFERENT
    /// recovery authority — the compaction-survival mechanism (F1) is tamper-evident, not just preserved.
    ///
    /// Scope, honestly: this proves the pure, symbolically-verifiable CORE. The full "every checkpoint field
    /// is in the signed bytes" guarantee is covered by the `write_canonical` unit tests; F1's end-to-end
    /// survival by `a_rotation_survives_compaction`; and the resolver-level rotation-takeover defense by the
    /// `a_concurrent_refound_ladder_cannot_hijack_a_rotation` attack test plus the
    /// `no_op_id_lets_the_rotation_ladder_win` (op-id grinding) and `the_ladder_defense_is_order_independent`
    /// (arrival-order + 3-level ladder) proptests. (The generic keyeo-dag BEC proptest covers Remove/Add only,
    /// NOT rotation, so it is not evidence for this defense.) The op-DAG resolver is not symbolically
    /// tractable, so kani here stays on the pure logic, as elsewhere in the workspace. Proven for every pair
    /// of distinct `Option<[u8; 32]>` values.
    // A 2-byte key keeps the byte-vec comparison bounded (the encoding is generic over the key length and its
    // injectivity does not depend on it, so this generalises to the checkpoint's 32-byte `reset_authority`).
    #[kani::proof]
    #[kani::unwind(4)]
    fn reset_authority_encoding_is_injective() {
        let a: Option<[u8; 2]> = kani::any();
        let b: Option<[u8; 2]> = kani::any();
        kani::assume(a != b);
        let mut ba = Vec::new();
        let mut bb = Vec::new();
        push_opt_hash(&mut ba, a.as_ref());
        push_opt_hash(&mut bb, b.as_ref());
        assert_ne!(ba, bb);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_state_view_round_trips_members_losslessly() {
        let gid = GroupId::new(b"tree".to_vec());
        let mut state = KeyringState::create(gid.clone(), &[]).with_reset_authority(Some([9u8; 32]));
        // Two members with DISTINCT, non-zero counters — exactly the fields a `MemberInit` re-genesis would
        // lose. bob's ODD member_counter models a removed-but-present member.
        state.members.insert(
            "alice".into(),
            MemberState { role: KeyringRole(3), member_counter: 4, access_counter: 2, author_public_key: [1u8; 32], hpke_public_key: [2u8; 32] },
        );
        state.members.insert(
            "bob".into(),
            MemberState { role: KeyringRole(1), member_counter: 1, access_counter: 0, author_public_key: [3u8; 32], hpke_public_key: [4u8; 32] },
        );

        let view = GroupStateView::of(&state);
        let rebuilt = view.clone().into_state(gid.clone(), Some([9u8; 32]));

        assert_eq!(rebuilt.members, state.members, "members (roles + keys + both counters) round-trip losslessly");
        assert_eq!(rebuilt.reset_authority, state.reset_authority, "reset_authority is restored");
        assert_eq!(rebuilt.group_id, state.group_id, "group_id is restored");

        // The view rides the wire inside the checkpoint, so it must serialize deterministically.
        let bytes = postcard::to_allocvec(&view).unwrap();
        let back: GroupStateView = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, view, "the view serde round-trips");
    }

    fn sample_state() -> KeyringState {
        let mut state =
            KeyringState::create(GroupId::new(b"tree".to_vec()), &[]).with_reset_authority(Some([9u8; 32]));
        state.members.insert(
            "owner".into(),
            MemberState { role: KeyringRole(3), member_counter: 0, access_counter: 0, author_public_key: [1u8; 32], hpke_public_key: [2u8; 32] },
        );
        state
    }

    fn sample_checkpoint() -> Checkpoint {
        Checkpoint {
            frontier_depths: vec![([5u8; 32], 2), ([6u8; 32], 1)],
            state: GroupStateView::of(&sample_state()),
            prev_snapshot: Some([9u8; 32]),
            has_been_shared: true,
            reset_authority: Some([7u8; 32]),
            sealing: vec![SealingEntry { op_id: [8u8; 32], origin: SealingOrigin::Genesis, author: "owner".into(), bytes: vec![1, 2, 3] }],
            minting_ops_baseline: 2,
            author: "owner".into(),
        }
    }

    #[test]
    fn checkpoint_signs_serde_round_trips_and_verifies() {
        let cp = sample_checkpoint();
        let sk = edsign::SigningKey::from_seed(&[7u8; 32]);
        let signed: SignedCheckpoint = Signed::sign(cp.clone(), &sk);

        let bytes = postcard::to_allocvec(&signed).unwrap();
        let back: SignedCheckpoint = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.verify(), Some(&cp), "the checkpoint signs, serdes, and verifies end-to-end");
    }

    #[test]
    fn every_checkpoint_field_is_in_the_signed_bytes() {
        let canon = |c: &Checkpoint| {
            let mut b = Vec::new();
            c.write_canonical(&mut b);
            b
        };
        let base = sample_checkpoint();
        let baseline = canon(&base);

        let mut t = base.clone();
        t.frontier_depths.push(([7u8; 32], 3));
        assert_ne!(canon(&t), baseline, "frontier_depths keys (the cut) are signed");
        let mut t = base.clone();
        t.frontier_depths[0].1 = 99;
        assert_ne!(canon(&t), baseline, "frontier_depths depths are signed");
        let mut t = base.clone();
        t.prev_snapshot = None;
        assert_ne!(canon(&t), baseline, "prev_snapshot is signed");
        let mut t = base.clone();
        t.has_been_shared = false;
        assert_ne!(canon(&t), baseline, "has_been_shared is signed");
        let mut t = base.clone();
        t.reset_authority = None;
        assert_ne!(canon(&t), baseline, "reset_authority is signed");
        let mut t = base.clone();
        t.author = "mallory".into();
        assert_ne!(canon(&t), baseline, "author is signed");
        let mut t = base.clone();
        t.sealing[0].bytes.push(9);
        assert_ne!(canon(&t), baseline, "sealing bytes are signed");
        let mut t = base.clone();
        t.sealing[0].origin = SealingOrigin::Reseal;
        assert_ne!(canon(&t), baseline, "sealing origin is signed");
        let mut t = base.clone();
        t.minting_ops_baseline = 5;
        assert_ne!(canon(&t), baseline, "minting_ops_baseline is signed");

        let mut other = sample_state();
        other.members.insert(
            "bob".into(),
            MemberState { role: KeyringRole(1), member_counter: 0, access_counter: 0, author_public_key: [3u8; 32], hpke_public_key: [4u8; 32] },
        );
        let mut t = base.clone();
        t.state = GroupStateView::of(&other);
        assert_ne!(canon(&t), baseline, "the membership state is signed");
    }
}
