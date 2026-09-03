//! The domain-free core of multi-signer quorum: a generic M-of-N [`Requirement`] over member ids.
//!
//! Nothing here is membership-specific — [`Requirement`]/[`Requirement::satisfied_by`] are generic over
//! the id type. This is the part of quorum that trivially fits any keyeo engine (the coupling, if any,
//! lives only in the `QuorumPolicy` that *produces* a `Requirement` from resolved state, which stays
//! engine-side). Fail-closed throughout: an insufficient (or empty) approver set is never satisfied.

use std::collections::HashSet;
use std::hash::Hash;

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
