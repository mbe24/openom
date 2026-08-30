//! Generic multi-signer quorum — the domain-free core of v2 governance (see
//! `plan/design.keyring-quorum-v2.md`). A [`Requirement`] is a generic M-of-N over member ids; the
//! resolver counts DISTINCT approvers and asks the requirement whether quorum is met. Fail-closed: an
//! insufficient (or empty) approver set is never satisfied.
//!
//! Nothing here is membership-specific — `Requirement`/[`Requirement::satisfied_by`] are generic over
//! the id type, so this is the part of quorum that trivially fits a unified `Engine<Op, State, Resolver>`
//! (the coupling, if any, lives only in the `QuorumPolicy` that *produces* a `Requirement` from state).

use std::collections::HashSet;
use std::hash::Hash;

use crate::dag::resolver::{GroupState, MemberId, MembershipAction};
use crate::roles::Role;
use crate::signature::SignatureScheme;

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

/// What a privileged change requires to take effect — a generic M-of-N over member ids.
#[derive(Clone, Debug)]
pub enum Requirement<Id> {
    /// A single designated approver suffices (e.g. the founder).
    Sole(Id),
    /// Any one of the set.
    Any(HashSet<Id>),
    /// Every member of the set (unanimity). Fail-closed: the empty set is NOT unanimity.
    All(HashSet<Id>),
    /// At least `m` distinct members of the set.
    Threshold(usize, HashSet<Id>),
    /// Either sub-requirement — e.g. founder OR unanimity-of-co-owners.
    Either(Box<Requirement<Id>>, Box<Requirement<Id>>),
}

impl<Id: Eq + Hash> Requirement<Id> {
    /// Is the requirement satisfied by `approvers` (a set of DISTINCT approving ids)? Callers pass a set,
    /// so a signer who approved twice is already counted once (the distinct-author tally rule). Fail-closed
    /// throughout: `All` of nobody and an unmet `Threshold` are both false.
    pub fn satisfied_by(&self, approvers: &HashSet<Id>) -> bool {
        match self {
            Requirement::Sole(id) => approvers.contains(id),
            Requirement::Any(set) => set.iter().any(|m| approvers.contains(m)),
            Requirement::All(set) => !set.is_empty() && set.iter().all(|m| approvers.contains(m)),
            Requirement::Threshold(m, set) => {
                set.iter().filter(|x| approvers.contains(x)).count() >= *m
            }
            Requirement::Either(a, b) => a.satisfied_by(approvers) || b.satisfied_by(approvers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sole_needs_exactly_that_approver() {
        let req = Requirement::Sole("founder".to_string());
        assert!(req.satisfied_by(&set(&["founder"])));
        assert!(req.satisfied_by(&set(&["founder", "bob"])));
        assert!(!req.satisfied_by(&set(&["bob"])));
        assert!(!req.satisfied_by(&set(&[])), "fail-closed: nobody approving is never enough");
    }

    #[test]
    fn all_is_unanimity_and_the_empty_set_is_not() {
        let req = Requirement::All(set(&["a", "b", "c"]));
        assert!(req.satisfied_by(&set(&["a", "b", "c"])));
        assert!(req.satisfied_by(&set(&["a", "b", "c", "d"])), "extra approvers are harmless");
        assert!(!req.satisfied_by(&set(&["a", "b"])), "one short is not unanimity");
        // Fail-closed: "unanimity of nobody" must be FALSE, else an empty denominator auto-approves.
        assert!(!Requirement::<String>::All(set(&[])).satisfied_by(&set(&[])));
    }

    #[test]
    fn any_needs_one_of_the_set() {
        let req = Requirement::Any(set(&["a", "b"]));
        assert!(req.satisfied_by(&set(&["b"])));
        assert!(!req.satisfied_by(&set(&["c"])));
        assert!(!req.satisfied_by(&set(&[])));
    }

    #[test]
    fn threshold_counts_distinct_members_of_the_set() {
        let req = Requirement::Threshold(2, set(&["a", "b", "c"]));
        assert!(req.satisfied_by(&set(&["a", "b"])));
        assert!(req.satisfied_by(&set(&["a", "b", "c"])));
        assert!(!req.satisfied_by(&set(&["a"])), "one short of the threshold");
        assert!(
            !req.satisfied_by(&set(&["a", "x", "y", "z"])),
            "approvers outside the set don't count toward the threshold"
        );
    }

    #[test]
    fn individual_governance_never_reaches_quorum() {
        // `Individual`'s requirement is fail-closed for every approver set — so a Commit under it never
        // takes effect, and the quorum ops are inert (the pre-v2 / default behaviour).
        use crate::dag::resolver::GroupState;
        use crate::signature::Ed25519;
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

    #[test]
    fn either_is_founder_or_unanimity() {
        // openom's shape: founder alone, OR every co-owner.
        let req = Requirement::Either(
            Box::new(Requirement::Sole("founder".to_string())),
            Box::new(Requirement::All(set(&["co1", "co2"]))),
        );
        assert!(req.satisfied_by(&set(&["founder"])), "founder path");
        assert!(req.satisfied_by(&set(&["co1", "co2"])), "unanimity path");
        assert!(!req.satisfied_by(&set(&["co1"])), "neither: partial co-owners, no founder");
        assert!(!req.satisfied_by(&set(&[])), "neither");
    }
}
