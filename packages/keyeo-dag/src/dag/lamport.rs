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
            return Ok((created, events));
        }
        MembershipAction::Add {
            member,
            role,
            author_public_key,
            hpke_public_key,
            ..
        } => apply_add(&mut state, member, role, author_public_key, hpke_public_key, &mut events)?,
        MembershipAction::Remove { member } => apply_remove(&mut state, member, &mut events)?,
        MembershipAction::ChangeRole { member, new_role } => {
            apply_change_role(&mut state, member, new_role, &mut events)?;
        }
        // Recovery re-founding: retarget the Owner's signing + HPKE keys in place (identical mechanics to a
        // voluntary Retarget below); authority (RVK-signature + Owner-target) is decided by the caller
        // before this runs (see `key_matches_registration` + `AccessControl`).
        MembershipAction::ReFound {
            member,
            new_author_public_key,
            new_hpke_public_key,
            ..
        } => retarget_keys(&mut state, member, new_author_public_key, new_hpke_public_key, "re-found")?,
        // Voluntary self-rekey: same mechanics as a re-founding, but authorized by the member's current
        // key, not the recovery authority. Not a recovery, so it does not join the reset-merge carve-out.
        MembershipAction::Retarget {
            member,
            new_author_public_key,
            new_hpke_public_key,
        } => retarget_keys(&mut state, member, new_author_public_key, new_hpke_public_key, "retarget")?,
        // Replace the pinned recovery authority. Membership is untouched — this only changes who may
        // authorize a future recovery (signed by the CURRENT authority, checked by the caller).
        MembershipAction::RotateRecoveryAuthority { new_reset_authority, .. } => {
            state.reset_authority = Some(new_reset_authority.clone());
        }
        // All membership-inert no-ops, for different reasons:
        //  - Reseal (OPE-282): a forward-secrecy reseal rides the op's `sealing` and the sealer validates its
        //    coverage — nothing to apply to the membership graph.
        //  - Propose / Approve / Commit (v2 quorum): a Propose/Approve records intent; a Commit's target is
        //    applied by the quorum resolver at the Commit's position, not here.
        MembershipAction::Reseal
        | MembershipAction::Propose { .. }
        | MembershipAction::Approve { .. }
        | MembershipAction::Commit { .. } => {}
    }
    Ok((state, events))
}

/// Add a member, or reactivate a previously-removed one (legitimate re-onboarding: bump the counter back
/// to an active parity and refresh their role/keys). Adding an already-active member is an error.
fn apply_add<Id: MemberId, R: Role, S: SignatureScheme>(
    state: &mut GroupState<Id, R, S>,
    member: &Id,
    role: &R,
    author_public_key: &<S as SignatureScheme>::PublicKey,
    hpke_public_key: &[u8; 32],
    events: &mut Vec<MembershipEvent<Id>>,
) -> Result<(), String> {
    match state.members.get_mut(member) {
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
    Ok(())
}

/// Remove an active member (bump their counter to an inactive parity). An absent or already-removed
/// member is an error.
fn apply_remove<Id: MemberId, R: Role, S: SignatureScheme>(
    state: &mut GroupState<Id, R, S>,
    member: &Id,
    events: &mut Vec<MembershipEvent<Id>>,
) -> Result<(), String> {
    let Some(s) = state.members.get_mut(member) else {
        return Err(format!("{member:?} is not a member"));
    };
    if !s.is_active() {
        return Err(format!("{member:?} is already removed"));
    }
    s.member_counter += 1;
    events.push(MembershipEvent::MemberRemoved {
        member: member.clone(),
    });
    Ok(())
}

/// Change an active member's role. An absent or inactive member is an error.
fn apply_change_role<Id: MemberId, R: Role, S: SignatureScheme>(
    state: &mut GroupState<Id, R, S>,
    member: &Id,
    new_role: &R,
    events: &mut Vec<MembershipEvent<Id>>,
) -> Result<(), String> {
    let Some(s) = state.members.get_mut(member) else {
        return Err(format!("{member:?} is not a member"));
    };
    if !s.is_active() {
        return Err(format!("{member:?} is not an active member"));
    }
    s.role = new_role.clone();
    s.access_counter += 1;
    events.push(MembershipEvent::RoleChanged {
        member: member.clone(),
    });
    Ok(())
}

/// Retarget an active member's signing + HPKE keys in place — the shared mechanics of `ReFound` and
/// `Retarget`; `verb` names the operation for the error. Membership is untouched (the member stays active);
/// authority is decided by the caller before this runs.
fn retarget_keys<Id: MemberId, R: Role, S: SignatureScheme>(
    state: &mut GroupState<Id, R, S>,
    member: &Id,
    new_author_public_key: &<S as SignatureScheme>::PublicKey,
    new_hpke_public_key: &[u8; 32],
    verb: &str,
) -> Result<(), String> {
    match state.members.get_mut(member) {
        Some(s) if s.is_active() => {
            s.author_public_key = new_author_public_key.clone();
            s.hpke_public_key = *new_hpke_public_key;
            s.access_counter += 1;
        }
        _ => return Err(format!("{member:?} is not an active member to {verb}")),
    }
    Ok(())
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
