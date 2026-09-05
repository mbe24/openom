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
        GroupStateView { members }
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

/// The signed body of an openom keyring compaction checkpoint (step 2a) — the GENERIC skeleton mirroring keyeo's
/// `Snapshot`: the dominating cut, the membership base at that cut, the continuity pointer, the shared-marker,
/// and the author. The openom-SPECIFIC sealing preservation (retained epochs + escrow + the minting-ops bound)
/// is layered on next. Carried as `Signed<Checkpoint>` — the SOLE carrier, so every trust-relevant field is
/// inside the signature (the exhaustive-destructure [`CanonicalBytes`] below makes a new unsigned field a
/// compile error).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Checkpoint {
    /// The dominating cut this checkpoint anchors at — the frontier op-ids the retained tail attaches to.
    pub frontier: Vec<[u8; 32]>,
    /// Each frontier op's absolute lamport depth, so the strong-remove tiebreak survives the prune.
    pub frontier_depths: Vec<([u8; 32], u64)>,
    /// The resolved membership at the cut.
    pub state: GroupStateView,
    /// Hash of the prior checkpoint — the continuity chain a returning member validates. None at the first.
    pub prev_snapshot: Option<[u8; 32]>,
    /// Monotone shared-marker, carried because the sharing `Add` is pruned below the cut.
    pub has_been_shared: bool,
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

impl CanonicalBytes for Checkpoint {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure (no `..`): a new checkpoint field is a compile error until it is encoded here,
        // so nothing trust-relevant can slip out of the signed bytes.
        let Checkpoint { frontier, frontier_depths, state, prev_snapshot, has_been_shared, sealing, minting_ops_baseline, author } = self;
        out.extend_from_slice(b"openom:checkpoint:v1");
        // frontier — sorted for determinism, length-prefixed.
        let mut f = frontier.clone();
        f.sort_unstable();
        out.extend_from_slice(&(f.len() as u64).to_le_bytes());
        for id in &f {
            out.extend_from_slice(id);
        }
        // frontier_depths — sorted, length-prefixed.
        let mut fd = frontier_depths.clone();
        fd.sort_unstable();
        out.extend_from_slice(&(fd.len() as u64).to_le_bytes());
        for (id, d) in &fd {
            out.extend_from_slice(id);
            out.extend_from_slice(&d.to_le_bytes());
        }
        // membership view — deterministic postcard (its members are sorted by construction), length-prefixed.
        let state_bytes = postcard::to_allocvec(state).expect("GroupStateView serialization is infallible");
        out.extend_from_slice(&(state_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&state_bytes);
        match prev_snapshot {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(h);
            }
            None => out.push(0),
        }
        out.push(u8::from(*has_been_shared));
        // sealing — ORDERED (the fold order is part of what's signed), length-prefixed; each entry is
        // op_id ‖ origin-tag ‖ length-prefixed opaque bytes.
        out.extend_from_slice(&(sealing.len() as u64).to_le_bytes());
        for e in sealing {
            out.extend_from_slice(&e.op_id);
            out.push(match e.origin {
                SealingOrigin::Genesis => 0,
                SealingOrigin::Remove => 1,
                SealingOrigin::Reseal => 2,
                SealingOrigin::Other => 3,
            });
            out.extend_from_slice(&(e.bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&e.bytes);
        }
        out.extend_from_slice(&minting_ops_baseline.to_le_bytes());
        let a = author.as_bytes();
        out.extend_from_slice(&(a.len() as u64).to_le_bytes());
        out.extend_from_slice(a);
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
            frontier: vec![[5u8; 32], [6u8; 32]],
            frontier_depths: vec![([5u8; 32], 2), ([6u8; 32], 1)],
            state: GroupStateView::of(&sample_state()),
            prev_snapshot: Some([9u8; 32]),
            has_been_shared: true,
            sealing: vec![SealingEntry { op_id: [8u8; 32], origin: SealingOrigin::Genesis, bytes: vec![1, 2, 3] }],
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
        t.frontier.push([7u8; 32]);
        assert_ne!(canon(&t), baseline, "frontier is signed");
        let mut t = base.clone();
        t.frontier_depths[0].1 = 99;
        assert_ne!(canon(&t), baseline, "frontier_depths is signed");
        let mut t = base.clone();
        t.prev_snapshot = None;
        assert_ne!(canon(&t), baseline, "prev_snapshot is signed");
        let mut t = base.clone();
        t.has_been_shared = false;
        assert_ne!(canon(&t), baseline, "has_been_shared is signed");
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
