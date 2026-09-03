//! Generic multi-signer quorum — the domain-free core of v2 governance (see
//! `plan/design.keyring-quorum-v2.md`). A [`Requirement`] is a generic M-of-N over member ids; the
//! resolver counts DISTINCT approvers and asks the requirement whether quorum is met. Fail-closed: an
//! insufficient (or empty) approver set is never satisfied.
//!
//! Nothing here is membership-specific — `Requirement`/[`Requirement::satisfied_by`] are generic over
//! the id type, so this is the part of quorum that trivially fits a unified `Engine<Op, State, Resolver>`
//! (the coupling, if any, lives only in the `QuorumPolicy` that *produces* a `Requirement` from state).

use std::collections::HashSet;

use keyeo_core::{Requirement, Role, SignatureScheme};

use crate::dag::resolver::{GroupState, MemberId, MembershipAction};

/// The domain seam for multi-signer quorum — parallel to `AccessControl`. Given the resolved state at a
/// proposal's causal position and the proposed `target`, it says **who may approve** and **what quorum is
/// required**. The quorum resolver never reads roles itself; it asks the policy — so all membership
/// coupling lives here, not in the engine (the property the unified `Engine<Op, State, Resolver>` needs).
pub trait QuorumPolicy<Id: MemberId, R: Role, S: SignatureScheme>: Send + Sync {
    /// The members permitted to approve a proposal of `target`, at the proposal's causal position.
    fn eligible(&self, state: &GroupState<Id, R, S>, target: &MembershipAction<Id, R, S>) -> HashSet<Id>;
    /// The quorum a proposal of `target` requires (e.g. `Either(Sole(founder), All(co-owners))`).
    fn requirement(
        &self,
        state: &GroupState<Id, R, S>,
        target: &MembershipAction<Id, R, S>,
    ) -> Requirement<Id>;
}

/// **Individual** governance — a single authorized signer's action stands on its own. The positive dual
/// of a collective quorum, and the default: no change goes through Propose/Approve/Commit; each op's
/// authority is decided by `AccessControl` alone. Under this policy a `Commit` never reaches quorum (the
/// eligible set is empty and the requirement is fail-closed), so the quorum ops are inert — exactly the
/// pre-v2 behaviour.
#[derive(Clone, Debug, Default)]
pub struct Individual;

impl<Id: MemberId, R: Role, S: SignatureScheme> QuorumPolicy<Id, R, S> for Individual {
    fn eligible(&self, _: &GroupState<Id, R, S>, _: &MembershipAction<Id, R, S>) -> HashSet<Id> {
        HashSet::new()
    }
    fn requirement(&self, _: &GroupState<Id, R, S>, _: &MembershipAction<Id, R, S>) -> Requirement<Id> {
        // Fail-closed: `All` of the empty set is never satisfied, so no Commit ever takes effect.
        Requirement::All(HashSet::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn individual_governance_never_reaches_quorum() {
        // `Individual`'s requirement is fail-closed for every approver set — so a Commit under it never
        // takes effect, and the quorum ops are inert (the pre-v2 / default behaviour).
        use crate::dag::resolver::GroupState;
        use crate::Ed25519;
        #[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
        struct TRole;
        impl Role for TRole {
            fn grants_at_least(&self, _: &Self) -> bool {
                true
            }
        }
        let state = GroupState::<String, TRole, Ed25519>::new();
        let target = MembershipAction::<String, TRole, Ed25519>::Remove { member: "x".into() };
        let req = QuorumPolicy::requirement(&Individual, &state, &target);
        assert!(!req.satisfied_by(&set(&["anyone", "everyone"])));
        assert!(QuorumPolicy::eligible(&Individual, &state, &target).is_empty());
    }
}
