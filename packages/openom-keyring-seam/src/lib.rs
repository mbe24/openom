//! openom-keyring-seam — the engine-agnostic vocabulary for swapping openom's two keyring engines
//! (the linear chain and the DAG), per the OPE-276 decision (plan/keyring-dag/design.swap-seam-decision.md).
//!
//! Deliberately **not** one `KeyringEngine` trait. This crate holds the two low-level, engine-agnostic
//! pieces both engines share:
//! - [`MembershipView`] — the resolved membership + roles, the shared value type the app (moderator/role
//!   display) and the server (ACL derivation) both consume regardless of engine. It's essentially a
//!   rename of code that already exists twice (chain's `roles::moderators`, dag's `active_members`).
//! - [`KeyringVerifier`] — the **keyless** server-side seam: admit an update against prior trust state,
//!   report the resolved view + whether it changed. The server binds only to this (plus its own
//!   persistence of the opaque `state` bytes).
//!
//! The secret-holding **client lifecycle trait** (provision/unlock/recover/change-passphrase/author) is
//! NOT here — it returns sealer/DEK material and lives with the sealer. **Sync** stays engine-owned over
//! the `Blob` seam. See the decision doc for the full four-piece shape and the guardrails.

use serde::{Deserialize, Serialize};

/// Which keyring engine backs a tree. Bound immutably at provision and recorded in signed/pinned material
/// (so a hostile store can't flip a tree's interpretation); the app selects the concrete engine on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineKind {
    Chain,
    Dag,
}

/// One member of the resolved keyring, engine-agnostic. Both engines fold to this: chain from
/// `Keyring.members`, dag from the resolved `GroupState`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    pub member_id: String,
    /// An openom-roles value (`ROLE_OWNER` = 1 … `ROLE_VIEWER` = 5); **lower is stronger**.
    pub role: i16,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

impl MemberView {
    /// A **signer** (keyring-write authority) is a CoOwner or stronger — the single-axis mapping both
    /// engines already use (`openom_roles::ROLE_CO_OWNER`).
    pub fn is_signer(&self) -> bool {
        self.role <= openom_roles::ROLE_CO_OWNER
    }
    /// The unique Owner / founder.
    pub fn is_owner(&self) -> bool {
        self.role == openom_roles::ROLE_OWNER
    }
}

/// The resolved membership + roles of a keyring — the shared vocabulary consumed regardless of engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipView {
    /// Active members, **sorted by `member_id`** for a deterministic, engine-independent view.
    pub members: Vec<MemberView>,
    /// This admission established or advanced across a recovery re-founding — the signal the server's
    /// reset cooldown gates on. Chain: a verified reset; dag: a `ReFound` / `RotateRecoveryAuthority`
    /// admission (or the privileged-carve-out class).
    pub reset_boundary: bool,
}

impl MembershipView {
    /// Build a view from members, sorting for determinism (so two engines that resolve the same
    /// membership produce byte-identical views).
    pub fn new(mut members: Vec<MemberView>, reset_boundary: bool) -> Self {
        members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Self {
            members,
            reset_boundary,
        }
    }

    /// The signer subset (CoOwner or stronger) — what keyring-write authority checks and the server's
    /// ACL derivation care about.
    pub fn signers(&self) -> impl Iterator<Item = &MemberView> {
        self.members.iter().filter(|m| m.is_signer())
    }

    /// The unique Owner, if present.
    pub fn owner(&self) -> Option<&MemberView> {
        self.members.iter().find(|m| m.is_owner())
    }
}

/// The outcome of admitting one update against prior trust state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The engine-**opaque** trust state to persist (chain: the accepted head bytes; dag: the op
    /// closure). The anti-rollback floor lives INSIDE these bytes, never as a shared field (guardrail).
    pub state: Vec<u8>,
    pub view: MembershipView,
    /// `false` = the update was validly admitted but changed no membership — the DAG's honest no-op case
    /// (a signed op the resolver gives no effect) and idempotent re-serves. **Mandatory** so that
    /// "acceptance ⇒ change" is never baked into a consumer (e.g. the server always advancing a revision).
    pub changed: bool,
}

/// Why an update was refused — neutral vocabulary, neither chain's `ChainError` nor the DAG's op errors.
/// The full engine-specific detail can be kept as diagnostics behind this classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Undecodable or structurally invalid bytes.
    Malformed,
    /// A signature did not verify, or the author is unknown.
    Unauthenticated,
    /// Behind the trust state — a replay or a withheld hop (an anti-rollback refusal that is recoverable
    /// by re-fetching), distinct from a hostile [`VerifyError::Rollback`].
    Stale,
    /// Validly authenticated, but the author lacked the authority for this change.
    Unauthorized,
    /// A detected rollback / withholding against already-trusted state (chain: fatal; dag: advisory —
    /// structurally it can't regress, so this is a loud signal, not data loss).
    Rollback,
}

/// The **keyless** server-side verifier seam. Admit an update against prior trust state — no secrets, no
/// mutable state beyond what it is handed — and report the new opaque state + resolved view + whether it
/// changed. Chain and dag each implement it; the server (and the client's adoption path) bind only to
/// this. `admit` is the neutral "admit an update against prior state" verb — not chain's "accept/reject a
/// revision", not the DAG's "op / resolve" — so neither model leaks into the abstraction.
pub trait KeyringVerifier {
    /// Admit `update` against `prior_state` (`None` = first sight / bootstrap). Returns the new opaque
    /// trust state + resolved view + a `changed` flag, or a neutral refusal.
    fn admit(&self, prior_state: Option<&[u8]>, update: &[u8]) -> Result<Admitted, VerifyError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, role: i16) -> MemberView {
        MemberView {
            member_id: id.to_string(),
            role,
            author_public_key: vec![role as u8],
            hpke_public_key: vec![role as u8],
        }
    }

    #[test]
    fn view_sorts_members_for_a_deterministic_engine_independent_shape() {
        // Two engines that resolve the same membership in different internal orders must produce the same
        // view — sorting by member_id is what makes MembershipView the shared contract.
        let a = MembershipView::new(vec![m("carol", 4), m("owner", 1), m("bob", 2)], false);
        let b = MembershipView::new(vec![m("bob", 2), m("carol", 4), m("owner", 1)], false);
        assert_eq!(a, b, "member order does not affect the resolved view");
        assert_eq!(
            a.members.iter().map(|m| m.member_id.as_str()).collect::<Vec<_>>(),
            vec!["bob", "carol", "owner"],
        );
    }

    #[test]
    fn signer_and_owner_classification_matches_the_role_axis() {
        let v = MembershipView::new(vec![m("owner", 1), m("bob", 2), m("dave", 3), m("ed", 4)], false);
        assert_eq!(v.owner().map(|o| o.member_id.as_str()), Some("owner"));
        // signers = Owner(1) + CoOwner(2); Maintainer(3)/Editor(4) are not.
        let signers: Vec<_> = v.signers().map(|s| s.member_id.clone()).collect();
        assert_eq!(signers, vec!["bob".to_string(), "owner".to_string()]);
    }

    #[test]
    fn membership_view_round_trips_through_serde() {
        let v = MembershipView::new(vec![m("owner", 1), m("bob", 2)], true);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<MembershipView>(&json).unwrap(), v);
    }
}
