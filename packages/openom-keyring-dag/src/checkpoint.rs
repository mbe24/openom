//! Checkpoint DTO layer (compaction step 2a): the serializable, members-only view of a resolved keyring
//! `GroupState` that an adopted checkpoint carries across a prune.
//!
//! `reset_authority` and `group_id` are deliberately NOT here — they are already `DagAnchor`-level fields,
//! restored around this view on resolve. And keyeo's own typed epoch machinery (`epoch`/`history_commitment`/
//! `dek_wraps`) is NOT carried: openom never uses that path — its DEK material rides the opaque `sealing`
//! envelope, and the membership view (`view_of`) reads only `members`. So the checkpoint state is exactly the
//! member map, plus the two counters a `MemberState` has that a `MemberInit` lacks.

use crate::{KeyringRole, KeyringState};
use keyeo_dag::{GroupId, MemberState};
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
}
