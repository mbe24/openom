//! `LamportTiebreak` resolver — simple deterministic ordering.

use crate::access::AccessControl;
use crate::blocklace::Graph;
use crate::dag::resolver::{
    GroupState, MemberId, MemberState, MembershipAction, MembershipEvent, OpId, Resolver, SignedOp,
};
use crate::Role;
use crate::SignatureScheme;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct LamportTiebreak;

impl<OId: OpId, R: Role, Op: SignedOp<R = R, S = S>, S: SignatureScheme> Resolver<OId, R, Op, S>
    for LamportTiebreak
{
    type State = ();
    type Error = std::convert::Infallible;

    fn rebuild_required(_state: &Self::State, _op: &Op, _frontier: &HashSet<OId>) -> bool {
        false
    }

    fn process(
        state: Self::State,
        _graph: &Graph<OId>,
        _ops: &HashMap<OId, Op>,
        _ac: &impl AccessControl<Op::MemberId, R, S>,
        _genesis: &GroupState<Op::MemberId, R, S>,
    ) -> Result<Self::State, Self::Error> {
        Ok(state)
    }

    fn ignored(_state: &Self::State) -> HashSet<OId> {
        HashSet::new()
    }
}

type ApplyResult<Id, R, S> = Result<(GroupState<Id, R, S>, Vec<MembershipEvent<Id>>), String>;

/// Fold one membership action into `state`, returning the new state and any [`MembershipEvent`]s.
///
/// # Errors
/// Returns `Err(String)` if the action is invalid for the current state (e.g. an operation on an absent
/// member or an otherwise illegal membership transition).
// One cohesive dispatch: each arm folds one action variant into the shared `state` + `events`. Splitting
// arms out would thread both across a call boundary for no clarity gain (the AGENTS.md coupled-state case).
#[allow(clippy::too_many_lines)]
pub fn apply_action<Id: MemberId, R: Role, S: SignatureScheme>(
    mut state: GroupState<Id, R, S>,
    action: &MembershipAction<Id, R, S>,
) -> ApplyResult<Id, R, S> {
    let mut events = Vec::new();
    match action {
        MembershipAction::Create { initial_members } => {
            // Preserve the pinned recovery authority AND the group_id across a (re)genesis fold: in openom's
            // seeded construction both live on the base state and the in-DAG Create is inert, so this keeps
            // them from being reset if a Create is ever folded. Dropping group_id here would leave the
            // RESOLVED state's group_id empty after any folded Create — and that resolved value is exactly
            // what the seam exports as the verified `Admitted.tree_id`, so it must survive the fold.
            let mut created = GroupState::create(state.group_id.clone(), initial_members);
            created.reset_authority.clone_from(&state.reset_authority);
            Ok((created, events))
        }
        MembershipAction::Add {
            member,
            role,
            author_public_key,
            hpke_public_key,
            ..
        } => {
            match state.members.get_mut(member) {
                // Re-add of a previously removed member = legitimate re-onboarding: reactivate the
                // record (bump the counter back to an active parity) and refresh their role/keys from
                // this Add. Adding a member who is already *active* is still an error.
                Some(s) if !s.is_active() => {
                    s.member_counter += 1;
                    s.role = role.clone();
                    s.author_public_key = author_public_key.clone();
                    s.hpke_public_key = *hpke_public_key;
                }
                Some(_) => return Err(format!("{member:?} is already an active member")),
                None => {
                    state.members.insert(
                        member.clone(),
                        MemberState::new(role.clone(), author_public_key.clone(), *hpke_public_key),
                    );
                }
            }
            events.push(MembershipEvent::MemberAdded {
                member: member.clone(),
            });
            Ok((state, events))
        }
        MembershipAction::Remove { member } => {
            if let Some(s) = state.members.get_mut(member) {
                if !s.is_active() {
                    return Err(format!("{member:?} is already removed"));
                }
                s.member_counter += 1;
                events.push(MembershipEvent::MemberRemoved {
                    member: member.clone(),
                });
            } else {
                return Err(format!("{member:?} is not a member"));
            }
            Ok((state, events))
        }
        MembershipAction::ChangeRole { member, new_role } => {
            if let Some(s) = state.members.get_mut(member) {
                if !s.is_active() {
                    return Err(format!("{member:?} is not an active member"));
                }
                s.role = new_role.clone();
                s.access_counter += 1;
                events.push(MembershipEvent::RoleChanged {
                    member: member.clone(),
                });
            } else {
                return Err(format!("{member:?} is not a member"));
            }
            Ok((state, events))
        }
        // Recovery re-founding: retarget the member's (the Owner's) signing + HPKE keys in place. The
        // member stays active and no one else is touched — a minimal forward delta. keeps the opaque
        // `recovery_rewrap` out of the resolved state (it is carried by the op for openom's sealer). Only
        // an active member can be re-founded; authority (RVK-signature + Owner-target) is decided by the
        // caller before this runs (see `key_matches_registration` + `AccessControl`).
        MembershipAction::ReFound {
            member,
            new_author_public_key,
            new_hpke_public_key,
            ..
        } => {
            match state.members.get_mut(member) {
                Some(s) if s.is_active() => {
                    s.author_public_key = new_author_public_key.clone();
                    s.hpke_public_key = *new_hpke_public_key;
                    s.access_counter += 1;
                }
                _ => return Err(format!("{member:?} is not an active member to re-found")),
            }
            Ok((state, events))
        }
        // Rotate the recovery authority: replace the pinned key. Membership is untouched — this only
        // changes who may authorize a future recovery. Authority (signed by the CURRENT authority) is
        // decided by the caller before this runs (see `key_matches_registration`).
        // Voluntary self-rekey: retarget the member's OWN signing + HPKE keys in place — identical
        // mechanics to a re-founding, but authorized by the member's current key, not the recovery
        // authority (decided by the caller; see `key_matches_registration` + `AccessControl`). Not a
        // recovery, so it does not participate in the reset-merge carve-out.
        MembershipAction::Retarget {
            member,
            new_author_public_key,
            new_hpke_public_key,
        } => {
            match state.members.get_mut(member) {
                Some(s) if s.is_active() => {
                    s.author_public_key = new_author_public_key.clone();
                    s.hpke_public_key = *new_hpke_public_key;
                    s.access_counter += 1;
                }
                _ => return Err(format!("{member:?} is not an active member to retarget")),
            }
            Ok((state, events))
        }
        MembershipAction::RotateRecoveryAuthority { new_reset_authority, .. } => {
            state.reset_authority = Some(new_reset_authority.clone());
            Ok((state, events))
        }
        // All membership-inert no-ops, for different reasons:
        //  - Reseal (OPE-282): a forward-secrecy reseal rides the op's `sealing` and the sealer validates its
        //    coverage — nothing to apply to the membership graph.
        //  - Propose / Approve / Commit (v2 quorum): a Propose/Approve records intent; a Commit's target is
        //    applied by the quorum resolver at the Commit's position, not here.
        MembershipAction::Reseal
        | MembershipAction::Propose { .. }
        | MembershipAction::Approve { .. }
        | MembershipAction::Commit { .. } => Ok((state, events)),
    }
}

pub fn apply_remove_unsafe<Id: MemberId, R: Role, S: SignatureScheme>(
    mut state: GroupState<Id, R, S>,
    member: &Id,
) -> GroupState<Id, R, S> {
    if let Some(s) = state.members.get_mut(member) {
        if s.member_counter % 2 == 0 {
            s.member_counter += 1;
        }
    }
    state
}
