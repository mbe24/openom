//! Access control — pluggable authorization policy.
use crate::dag::resolver::{GroupState, MemberId, MembershipAction};
use crate::Role;
use crate::SignatureScheme;
use std::marker::PhantomData;

pub trait AccessControl<Id: MemberId, R: Role, S: SignatureScheme>: Send + Sync {
    fn is_authorized(
        &self,
        state: &GroupState<Id, R, S>,
        author: &Id,
        action: &MembershipAction<Id, R, S>,
    ) -> bool;

    /// Whether `action` (evaluated against `state`, the resolved state at the op's causal position) is a
    /// **privileged** change — one that alters the authority structure (the signer set, governance, or
    /// recovery material) rather than an ordinary member change.
    ///
    /// Used only by the reset-merge carve-out ([`crate::dag::strong_remove::StrongRemove`]): a privileged
    /// op that is *concurrent* with a surviving recovery re-founding ([`MembershipAction::ReFound`]) is
    /// voided. A recovery is minted precisely when key custody is in doubt, so a concurrent authority
    /// change is, with meaningful probability, the very escalation the recovery defends against; voiding
    /// it costs one re-approval by holders who still have their keys, and never loses an ordinary member
    /// edit (which is not privileged, so it auto-merges). Default: `false` — a consumer with no
    /// recovery/reset concept has no carve-out and this is inert.
    fn is_privileged(
        &self,
        _state: &GroupState<Id, R, S>,
        _action: &MembershipAction<Id, R, S>,
    ) -> bool {
        false
    }
}

/// Default access control: requires a minimum role for modification actions.
/// Generic over any role type — truly domain-agnostic.
#[derive(Clone, Debug)]
pub struct DefaultAccessControl<R: Role> {
    pub min_role: R,
}

impl<R: Role> DefaultAccessControl<R> {
    pub fn new(min_role: R) -> Self {
        Self { min_role }
    }
}

impl<Id: MemberId, R: Role, S: SignatureScheme> AccessControl<Id, R, S>
    for DefaultAccessControl<R>
{
    fn is_authorized(
        &self,
        state: &GroupState<Id, R, S>,
        author: &Id,
        action: &MembershipAction<Id, R, S>,
    ) -> bool {
        match action {
            MembershipAction::Create { initial_members } => {
                initial_members.iter().any(|m| &m.id == author)
            }
            _ => state.has_access(author, &self.min_role),
        }
    }
}

/// Multi-tenant access control via closure.
pub struct DynAccessControl<Id: MemberId, R: Role, S: SignatureScheme, F>
where
    F: Fn(&GroupState<Id, R, S>, &Id, &MembershipAction<Id, R, S>) -> bool + Send + Sync,
{
    pub f: F,
    pub _marker: PhantomData<fn(Id, R, S)>,
}

impl<Id: MemberId, R: Role, S: SignatureScheme, F> AccessControl<Id, R, S>
    for DynAccessControl<Id, R, S, F>
where
    F: Fn(&GroupState<Id, R, S>, &Id, &MembershipAction<Id, R, S>) -> bool + Send + Sync,
{
    fn is_authorized(
        &self,
        state: &GroupState<Id, R, S>,
        author: &Id,
        action: &MembershipAction<Id, R, S>,
    ) -> bool {
        (self.f)(state, author, action)
    }
}
