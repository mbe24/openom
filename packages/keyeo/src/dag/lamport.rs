//! LamportTiebreak resolver — simple deterministic ordering.

use crate::access::AccessControl;
use crate::blocklace::Graph;
use crate::dag::resolver::{
    GroupState, MemberId, MemberState, MembershipAction, MembershipEvent, OpId, Resolver, SignedOp,
};
use crate::roles::Role;
use crate::signature::SignatureScheme;
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

pub fn apply_action<Id: MemberId, R: Role, S: SignatureScheme>(
    mut state: GroupState<Id, R, S>,
    action: &MembershipAction<Id, R, S>,
) -> ApplyResult<Id, R, S> {
    let mut events = Vec::new();
    match action {
        MembershipAction::Create { initial_members } => {
            // Preserve any pinned recovery authority across a (re)genesis fold: in openom's seeded
            // construction the authority lives on the base state and the in-DAG Create is inert, so this
            // keeps `reset_authority` from being reset to None if a Create is ever folded.
            let mut created = GroupState::create(initial_members);
            created.reset_authority = state.reset_authority.clone();
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
                Some(_) => return Err(format!("{:?} is already an active member", member)),
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
                    return Err(format!("{:?} is already removed", member));
                }
                s.member_counter += 1;
                events.push(MembershipEvent::MemberRemoved {
                    member: member.clone(),
                });
            } else {
                return Err(format!("{:?} is not a member", member));
            }
            Ok((state, events))
        }
        MembershipAction::ChangeRole { member, new_role } => {
            if let Some(s) = state.members.get_mut(member) {
                if !s.is_active() {
                    return Err(format!("{:?} is not an active member", member));
                }
                s.role = new_role.clone();
                s.access_counter += 1;
                events.push(MembershipEvent::RoleChanged {
                    member: member.clone(),
                });
            } else {
                return Err(format!("{:?} is not a member", member));
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
                _ => return Err(format!("{:?} is not an active member to re-found", member)),
            }
            Ok((state, events))
        }
        // Quorum-protocol ops (v2) don't directly mutate membership: a Propose/Approve records intent,
        // and a Commit's *target* is applied by the quorum resolver at the Commit's position, not here.
        // Folding one of these is a no-op; the effect enters via the resolver, not `apply_action`.
        MembershipAction::Propose { .. }
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
