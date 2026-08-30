//! openom-keyring-dag — openom's keyring layer over the generic `keyeo` group-membership DAG (the
//! sequencer-free keyring, OPE-137). keyeo stays domain-free and publishable; every openom specific — the
//! Ed25519 seam, the role model, the authority policy, and the quorum policy — lives here.
//!
//! - **v1** (BYO / sequencer-free): ordinary members + **founder-signed** governance + rotation, via
//!   [`KeyringAccess`] (signer-gated authority).
//! - **v2** multi-signer **quorum** ("co-owners collectively"): [`FounderOrUnanimity`] — a privileged
//!   change is authorized by the founder alone OR by unanimity of the co-owners, decomposed into
//!   Propose/Approve/Commit ops that keyeo's quorum resolver tallies at the proposal's causal position.
//!
//! This crate deliberately depends on `openom-sign` (not `ed25519-dalek`) so keyeo's own dalek edge is
//! replaced by openom's `verify_strict` seam (OPE-215).

use keyeo::{AccessControl, GroupState, MembershipAction, QuorumPolicy, Requirement, Role, SigError, SignatureScheme};
use std::collections::HashSet;

/// openom's Ed25519 plugged into keyeo's `SignatureScheme` seam, so the engine verifies with
/// openom-sign's `verify_strict` (rejecting small-order / torsion keys and non-canonical signatures)
/// rather than keyeo's built-in dalek path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenomSign;

impl SignatureScheme for OpenomSign {
    type PublicKey = [u8; 32];
    type Signature = [u8; 64];
    fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), SigError> {
        let vk = openom_sign::VerifyingKey::from_bytes(pk).map_err(|_| SigError)?;
        vk.verify(msg, &openom_sign::Signature::from_bytes(sig))
            .map_err(|_| SigError)
    }
}

/// A keyring role, power-descending (**lower is stronger**): `ROLE_OWNER = 1` … `ROLE_VIEWER = 5`,
/// matching openom's `MemberRole` access axis (openom-roles). Wraps the `i16` so a role can be a signed,
/// content-addressed op field (keyeo requires `Role: Serialize`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct KeyringRole(pub i16);

impl KeyringRole {
    pub const OWNER: Self = Self(openom_roles::ROLE_OWNER);
    pub const CO_OWNER: Self = Self(openom_roles::ROLE_CO_OWNER);
    pub const MAINTAINER: Self = Self(openom_roles::ROLE_MAINTAINER);
    pub const EDITOR: Self = Self(openom_roles::ROLE_EDITOR);
    pub const VIEWER: Self = Self(openom_roles::ROLE_VIEWER);

    /// A signer (keyring administrative authority) is a `CoOwner` or stronger (`Owner`).
    fn is_signer(self) -> bool {
        self.0 <= openom_roles::ROLE_CO_OWNER
    }

    /// The Owner (founder) — the unique keyring root.
    fn is_owner(self) -> bool {
        self.0 == openom_roles::ROLE_OWNER
    }
}

impl Role for KeyringRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        // Power-descending: a stronger (lower-valued) role grants everything a weaker one does.
        self.0 <= other.0
    }
}

/// The concrete keyeo instantiation for the openom keyring: op ids are 32-byte content hashes, member
/// ids are openom member-id strings, roles are [`KeyringRole`], signatures are [`OpenomSign`].
pub type KeyringAction = MembershipAction<String, KeyringRole, OpenomSign>;
pub type KeyringOp = keyeo::Op<[u8; 32], String, KeyringRole, OpenomSign>;
pub type KeyringState = GroupState<String, KeyringRole, OpenomSign>;
pub type KeyringMemberInit = keyeo::MemberInit<String, KeyringRole, OpenomSign>;
pub type KeyringEngine = keyeo::Keyeo<KeyringOp, KeyringAccess, keyeo::StrongRemove>;
/// The v2 keyring engine — same authority + strong-remove, plus a [`KeyringQuorum`] multi-signer policy
/// for privileged changes. Construct with `Keyeo::with_quorum(state, KeyringAccess, StrongRemove,
/// KeyringQuorum::founder_or_unanimity())` (or any other [`QuorumRule`]).
pub type KeyringQuorumEngine =
    keyeo::Keyeo<KeyringOp, KeyringAccess, keyeo::StrongRemove, KeyringQuorum>;

/// Sign a membership op with an openom-sign key. keyeo's `Op::sign` is dalek-specific; this signs over
/// keyeo's canonical encoding with the openom-sign seam instead, so the adapter never touches dalek.
pub fn sign_op(
    id: [u8; 32],
    parents: Vec<[u8; 32]>,
    author: impl Into<String>,
    action: KeyringAction,
    key: &openom_sign::SigningKey,
) -> KeyringOp {
    let author = author.into();
    let canonical = keyeo::canonical_encode(&parents, &author, &action);
    let signature = key.sign(&canonical).to_bytes();
    let author_public_key = key.verifying_key().to_bytes();
    keyeo::Op::new(id, parents, author, action, signature, author_public_key)
}

/// openom keyring authority — v1, founder-signed governance (multi-signer quorum is v2).
///
/// Keyring-write authority is **signer-gated**, not role-threshold-based: only a **signer** (Owner or
/// CoOwner) may author a keyring change. A `MemberRole` below CoOwner (Maintainer / Editor / Viewer)
/// carries content/moderation authority elsewhere in openom, but grants **no keyring-write authority**
/// here. Within that gate:
/// - touching a **signer** (adding/removing/retargeting an Owner or CoOwner) requires the **Owner**;
/// - touching an **ordinary member** requires any **signer** (CoOwner or Owner);
/// - the **Owner is unique and immutable** in v1 — no second Owner may be created, and the Owner may not
///   be removed or demoted (not even by themselves): "the founder can't leave" (transfer is a v2 op);
/// - any **non-Owner** member may **remove themselves** (a deliberate BYO-offline widening).
///
/// This mirrors openom's two-axis model as a single-axis re-model under a declared lockstep invariant
/// (Owner↔Founder-signer, CoOwner-member↔CoOwner-signer). Authorization is evaluated by the resolver at
/// each op's causal position — see keyeo's authority-aware `StrongRemove` (OPE-258).
pub struct KeyringAccess;

impl KeyringAccess {
    /// The weakest role permitted to author a change **touching** a member whose role is `target`:
    /// touching a signer needs the Owner; touching an ordinary member needs any signer (CoOwner+).
    fn required_for(target: KeyringRole) -> KeyringRole {
        if target.is_signer() {
            KeyringRole::OWNER
        } else {
            KeyringRole::CO_OWNER
        }
    }

    /// The role a member currently holds at this causal position (Viewer if absent — a target that
    /// isn't a member is "ordinary", never a signer).
    fn role_of(state: &KeyringState, member: &str) -> KeyringRole {
        state
            .members
            .get(member)
            .map(|m| m.role)
            .unwrap_or(KeyringRole::VIEWER)
    }
}

impl AccessControl<String, KeyringRole, OpenomSign> for KeyringAccess {
    fn is_authorized(
        &self,
        state: &KeyringState,
        author: &String,
        action: &KeyringAction,
    ) -> bool {
        // Genesis Create: the author must be a listed initial member, and there must be EXACTLY ONE
        // Owner (the founder). This seeds the "exactly one Owner" invariant; no later op can add, remove,
        // or demote an Owner, so it holds for the keyring's whole life.
        if let MembershipAction::Create { initial_members } = action {
            let owners = initial_members.iter().filter(|m| m.role.is_owner()).count();
            return owners == 1 && initial_members.iter().any(|m| &m.id == author);
        }
        // Every other change requires an active member author.
        let author_role = match state.members.get(author) {
            Some(m) if m.is_active() => m.role,
            _ => return false,
        };
        match action {
            MembershipAction::Create { .. } => false, // handled above
            MembershipAction::Add { role, .. } => {
                // No second Owner, ever; otherwise the author must out-rank what the target role needs.
                !role.is_owner() && author_role.grants_at_least(&Self::required_for(*role))
            }
            MembershipAction::ChangeRole { member, new_role } => {
                let current = Self::role_of(state, member);
                // The Owner can't be demoted, and no one may be promoted INTO Owner (uniqueness). The
                // author must out-rank both the current standing and the target role.
                !current.is_owner()
                    && !new_role.is_owner()
                    && author_role.grants_at_least(&Self::required_for(current))
                    && author_role.grants_at_least(&Self::required_for(*new_role))
            }
            MembershipAction::Remove { member } => {
                let current = Self::role_of(state, member);
                // The Owner can never be removed — not even by themselves (the founder can't leave).
                if current.is_owner() {
                    return false;
                }
                // Widen: any non-Owner member may remove THEMSELVES.
                if author == member {
                    return true;
                }
                author_role.grants_at_least(&Self::required_for(current))
            }
            // Quorum-protocol ops (v2): the author must be a signer to participate; the wrapped target's
            // authority is decided by the quorum resolver (founder-or-unanimity), not here.
            MembershipAction::Propose { .. }
            | MembershipAction::Approve { .. }
            | MembershipAction::Commit { .. } => author_role.is_signer(),
        }
    }
}

/// The member a change *acts on* — the one whose consent shouldn't gate their own removal/demotion.
/// Excluded from both the eligible set and the unanimity denominator (you don't need a member's
/// approval to remove or demote them).
fn target_member(action: &KeyringAction) -> Option<&String> {
    match action {
        MembershipAction::Remove { member } | MembershipAction::ChangeRole { member, .. } => {
            Some(member)
        }
        _ => None,
    }
}

/// The active Owner (founder), if any. The Owner is unique and immutable in openom, so this is `Some`
/// for any well-formed keyring; the `None` arm is defensive (fail-closed).
fn active_owner(state: &KeyringState) -> Option<String> {
    state
        .members
        .iter()
        .find(|(_, m)| m.is_active() && m.role.is_owner())
        .map(|(id, _)| id.clone())
}

/// The per-keyring governance rule — so one family tree can be founder-only, another 3-of-4, another
/// founder-or-unanimity, all from the same [`KeyringQuorum`] policy. The founder (Owner) is always
/// eligible to propose/approve; the co-owners are the collective body. Every rule is still bounded by
/// founder-equivalent authority (see [`KeyringQuorum::requirement`]).
///
/// Note (not yet wired): the chosen rule must be **authenticated and pinned** per keyring — set at
/// genesis and replicated — so every replica evaluates the same denominator and an attacker can't
/// weaken it (e.g. 3-of-4 → 1-of-4). Today it's a construction-time parameter the client is responsible
/// for keeping consistent across a family's replicas; pinning it into the signed root is a follow-up
/// (OPE-260 hardening / the unified-substrate governance-config question).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumRule {
    /// The founder alone — co-owners have no governance vote (a single-admin family).
    FounderOnly,
    /// The founder alone, OR unanimity of the co-owners.
    FounderOrUnanimity,
    /// The founder alone, OR at least `m` of the co-owners.
    FounderOrThreshold(usize),
    /// At least `m` of the signers (Owner + co-owners), with no special founder path — a flat M-of-N.
    Threshold(usize),
}

/// openom's v2 multi-signer quorum, parameterised by a per-keyring [`QuorumRule`]. A privileged change
/// takes effect when the rule's requirement is met by the distinct eligible approvers — e.g. the founder
/// alone, or unanimity of co-owners, or M of N.
///
/// The quorum grants **founder-equivalent** authority and no more: [`Self::requirement`] asks
/// [`KeyringAccess`] whether the *founder* could authorize this target directly, and returns a
/// fail-closed (empty-`All`) requirement if not. This binds owner-immutability (no removing/demoting the
/// Owner, no second Owner) to the quorum path too — closing the hole that a Commit applies its target
/// via `apply_action` without re-checking target-level access. The member being removed/demoted is
/// excluded from the denominator (their consent isn't needed to evict them).
#[derive(Clone, Copy, Debug)]
pub struct KeyringQuorum {
    rule: QuorumRule,
}

impl KeyringQuorum {
    pub fn new(rule: QuorumRule) -> Self {
        Self { rule }
    }
    /// The founder alone governs (single-admin family).
    pub fn founder_only() -> Self {
        Self::new(QuorumRule::FounderOnly)
    }
    /// The founder alone, OR every co-owner (the collective-when-offline default).
    pub fn founder_or_unanimity() -> Self {
        Self::new(QuorumRule::FounderOrUnanimity)
    }
    /// The founder alone, OR at least `m` co-owners.
    pub fn founder_or_threshold(m: usize) -> Self {
        Self::new(QuorumRule::FounderOrThreshold(m))
    }
    /// A flat `m`-of-N over the signers (Owner + co-owners), no special founder path.
    pub fn threshold(m: usize) -> Self {
        Self::new(QuorumRule::Threshold(m))
    }
}

impl KeyringQuorum {
    /// Active members matching `pred` (a role test), minus the change's own target member.
    fn signer_set(
        state: &KeyringState,
        excluded: Option<&String>,
        pred: impl Fn(KeyringRole) -> bool,
    ) -> HashSet<String> {
        state
            .members
            .iter()
            .filter(|(id, m)| m.is_active() && pred(m.role) && Some(*id) != excluded)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl QuorumPolicy<String, KeyringRole, OpenomSign> for KeyringQuorum {
    fn eligible(&self, state: &KeyringState, target: &KeyringAction) -> HashSet<String> {
        // Any signer may propose/approve under every rule; the rule only decides how many are required.
        Self::signer_set(state, target_member(target), KeyringRole::is_signer)
    }

    fn requirement(&self, state: &KeyringState, target: &KeyringAction) -> Requirement<String> {
        let Some(founder) = active_owner(state) else {
            return Requirement::All(HashSet::new()); // fail-closed: no founder, no founder-equivalence
        };
        // Founder-equivalent, not founder-exceeding: a quorum can authorize exactly what the founder
        // could do alone. What even the Owner can't do directly (self-removal, a second Owner, …), no
        // quorum can do either — so owner-immutability holds on the quorum path.
        if !KeyringAccess.is_authorized(state, &founder, target) {
            return Requirement::All(HashSet::new());
        }
        let excluded = target_member(target);
        let co_owners =
            || Self::signer_set(state, excluded, |r| r == KeyringRole::CO_OWNER);
        let sole = || Box::new(Requirement::Sole(founder.clone()));
        match self.rule {
            QuorumRule::FounderOnly => Requirement::Sole(founder),
            QuorumRule::FounderOrUnanimity => {
                Requirement::Either(sole(), Box::new(Requirement::All(co_owners())))
            }
            QuorumRule::FounderOrThreshold(m) => {
                Requirement::Either(sole(), Box::new(Requirement::Threshold(m, co_owners())))
            }
            QuorumRule::Threshold(m) => {
                Requirement::Threshold(m, Self::signer_set(state, excluded, KeyringRole::is_signer))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyeo::{ApplyOutcome, Keyeo, StrongRemove};

    fn sk(seed: u8) -> openom_sign::SigningKey {
        openom_sign::SigningKey::from_seed(&[seed; 32])
    }
    fn vk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }
    fn minit(id: &str, role: KeyringRole, seed: u8) -> KeyringMemberInit {
        KeyringMemberInit {
            id: id.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
        }
    }
    fn engine(members: &[KeyringMemberInit]) -> KeyringEngine {
        Keyeo::new(KeyringState::create(members), KeyringAccess, StrongRemove)
    }
    fn add(member: &str, role: KeyringRole, seed: u8) -> KeyringAction {
        MembershipAction::Add {
            member: member.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
            member_proof: None,
        }
    }
    fn members(k: &KeyringEngine) -> Vec<(String, KeyringRole)> {
        let mut m = k.state().active_members();
        m.sort();
        m
    }

    #[test]
    fn founder_signed_governance_resolves_through_keyeo() {
        // founder (Owner) creates the group and adds bob as a CoOwner (a signer); bob (a signer) then
        // adds an ordinary Editor. The openom seams (OpenomSign, KeyringRole, KeyringAccess) resolve end
        // to end.
        let mut k = engine(&[minit("founder", KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: vec![minit("founder", KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        // founder adds bob into the signer set (touching a signer → needs Owner ✓)
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1)))
            .unwrap();
        // bob (a signer) adds carol as an ordinary Editor (touching an ordinary member → needs a signer ✓)
        k.apply(sign_op([3; 32], vec![[2; 32]], "bob", add("carol", KeyringRole::EDITOR, 3), &sk(2)))
            .unwrap();

        assert_eq!(
            members(&k),
            vec![
                ("bob".to_string(), KeyringRole::CO_OWNER),
                ("carol".to_string(), KeyringRole::EDITOR),
                ("founder".to_string(), KeyringRole::OWNER),
            ]
        );
    }

    #[test]
    fn a_maintainer_cannot_write_the_keyring() {
        // A Maintainer is NOT a signer, so it has NO keyring-write authority — not even to add an
        // ordinary member. Admit-then-resolve: the op is admitted (valid signature) but has no effect.
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("dave", KeyringRole::MAINTAINER, 4),
        ]);
        let r = k
            .apply(sign_op([1; 32], vec![], "dave", add("mallory", KeyringRole::EDITOR, 9), &sk(4)))
            .unwrap();
        assert!(matches!(r, ApplyOutcome::Applied { events } if events.is_empty()));
        assert!(
            !members(&k).iter().any(|(m, _)| m == "mallory"),
            "a Maintainer is not a signer and cannot add a member"
        );
    }

    #[test]
    fn only_the_owner_may_touch_the_signer_set() {
        // A CoOwner is a signer, but still cannot promote someone INTO the signer set nor remove another
        // signer — that requires the Owner (founder-signed governance; unanimity/quorum is v2).
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::EDITOR, 3),
        ]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            "bob",
            MembershipAction::ChangeRole {
                member: "carol".to_string(),
                new_role: KeyringRole::CO_OWNER,
            },
            &sk(2),
        ))
        .unwrap();
        assert!(
            members(&k).contains(&("carol".to_string(), KeyringRole::EDITOR)),
            "a CoOwner can't create another signer"
        );
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            "bob",
            MembershipAction::Remove {
                member: "founder".to_string(),
            },
            &sk(2),
        ))
        .unwrap();
        assert!(
            members(&k).iter().any(|(m, _)| m == "founder"),
            "a CoOwner can't remove the Owner"
        );
    }

    #[test]
    fn the_owner_is_unique_and_immutable() {
        // No second Owner may be created, and the Owner may not be removed or demoted — not even by
        // themselves ("the founder can't leave"). Each op is admitted but has no effect.
        let mut k = engine(&[minit("founder", KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: vec![minit("founder", KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        // a second Owner is forbidden
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", add("regent", KeyringRole::OWNER, 5), &sk(1)))
            .unwrap();
        assert!(!members(&k).iter().any(|(m, _)| m == "regent"), "no second Owner");
        // the Owner cannot self-remove
        k.apply(sign_op(
            [3; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::Remove {
                member: "founder".to_string(),
            },
            &sk(1),
        ))
        .unwrap();
        // ...nor self-demote
        k.apply(sign_op(
            [4; 32],
            vec![[3; 32]],
            "founder",
            MembershipAction::ChangeRole {
                member: "founder".to_string(),
                new_role: KeyringRole::CO_OWNER,
            },
            &sk(1),
        ))
        .unwrap();
        assert_eq!(
            members(&k),
            vec![("founder".to_string(), KeyringRole::OWNER)],
            "the Owner remains, alone and unchanged"
        );
    }

    #[test]
    fn any_non_owner_may_remove_themselves() {
        // The widen decision: any non-Owner may self-remove (a BYO/offline convenience), even an Editor.
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("ed", KeyringRole::EDITOR, 6),
        ]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            "ed",
            MembershipAction::Remove {
                member: "ed".to_string(),
            },
            &sk(6),
        ))
        .unwrap();
        assert!(
            !members(&k).iter().any(|(m, _)| m == "ed"),
            "an Editor may remove themselves"
        );
    }

    #[test]
    fn a_co_owner_manages_ordinary_members() {
        // A signer (CoOwner) may add and remove ordinary members.
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::EDITOR, 3),
        ]);
        k.apply(sign_op([1; 32], vec![], "bob", add("dave", KeyringRole::EDITOR, 4), &sk(2)))
            .unwrap();
        assert!(members(&k).iter().any(|(m, _)| m == "dave"), "a CoOwner may add an ordinary member");
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            "bob",
            MembershipAction::Remove {
                member: "carol".to_string(),
            },
            &sk(2),
        ))
        .unwrap();
        assert!(
            !members(&k).iter().any(|(m, _)| m == "carol"),
            "a CoOwner may remove an ordinary member"
        );
    }

    #[test]
    fn the_openom_sign_seam_rejects_a_forged_signature() {
        // A structurally-valid op whose signature is over the wrong bytes must be rejected by the
        // engine's authenticate step, i.e. by OpenomSign::verify (openom-sign verify_strict).
        let mut k = engine(&[minit("founder", KeyringRole::OWNER, 1)]);
        let action = MembershipAction::Remove {
            member: "founder".to_string(),
        };
        let bad_sig = sk(1).sign(b"not the canonical op bytes").to_bytes();
        let op = keyeo::Op::new([1; 32], vec![], "founder".to_string(), action, bad_sig, vk(1));
        assert!(matches!(k.apply(op).unwrap_err(), keyeo::Error::BadSignature));
    }

    // ---- v2 multi-signer quorum (FounderOrUnanimity) ----

    fn quorum_engine_with(members: &[KeyringMemberInit], quorum: KeyringQuorum) -> KeyringQuorumEngine {
        Keyeo::with_quorum(KeyringState::create(members), KeyringAccess, StrongRemove, quorum)
    }
    fn quorum_engine(members: &[KeyringMemberInit]) -> KeyringQuorumEngine {
        quorum_engine_with(members, KeyringQuorum::founder_or_unanimity())
    }
    fn genesis(members: &[KeyringMemberInit]) -> KeyringOp {
        sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: members.to_vec(),
            },
            &sk(1),
        )
    }
    fn propose(id: u8, parents: Vec<[u8; 32]>, author: &str, seed: u8, target: KeyringAction) -> KeyringOp {
        sign_op(
            [id; 32],
            parents,
            author,
            MembershipAction::Propose { proposal_id: [7; 32], target: Box::new(target) },
            &sk(seed),
        )
    }
    fn approve(id: u8, parents: Vec<[u8; 32]>, author: &str, seed: u8) -> KeyringOp {
        sign_op([id; 32], parents, author, MembershipAction::Approve { proposal_id: [7; 32] }, &sk(seed))
    }
    fn commit(id: u8, parents: Vec<[u8; 32]>, author: &str, seed: u8) -> KeyringOp {
        sign_op([id; 32], parents, author, MembershipAction::Commit { proposal_id: [7; 32] }, &sk(seed))
    }
    fn promote(member: &str, new_role: KeyringRole) -> KeyringAction {
        MembershipAction::ChangeRole { member: member.to_string(), new_role }
    }
    fn q_role_of(k: &KeyringQuorumEngine, member: &str) -> Option<KeyringRole> {
        k.state().members.get(member).filter(|m| m.is_active()).map(|m| m.role)
    }

    #[test]
    fn unanimous_co_owners_promote_a_signer_without_the_founder() {
        // Promoting an Editor into the signer set normally needs the Owner. Via quorum, unanimity of the
        // co-owners (bob + carol) authorizes it with no founder approval — the co-owners-collective path.
        let m = [
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::CO_OWNER, 3),
            minit("ed", KeyringRole::EDITOR, 6),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(2, vec![[1; 32]], "bob", 2, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        k.apply(approve(3, vec![[2; 32]], "carol", 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], "bob", 2)).unwrap();
        assert_eq!(q_role_of(&k, "ed"), Some(KeyringRole::CO_OWNER), "unanimity of co-owners promotes");
    }

    #[test]
    fn one_co_owner_short_of_unanimity_does_not_promote() {
        // Same target, but carol never approves — unanimity is unmet and the founder isn't in the tally,
        // so ed stays an Editor (fail-closed).
        let m = [
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::CO_OWNER, 3),
            minit("ed", KeyringRole::EDITOR, 6),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(2, vec![[1; 32]], "bob", 2, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        k.apply(commit(3, vec![[2; 32]], "bob", 2)).unwrap();
        assert_eq!(q_role_of(&k, "ed"), Some(KeyringRole::EDITOR), "bob alone is not unanimity");
    }

    #[test]
    fn the_founder_alone_promotes_via_the_sole_path() {
        // The founder needs no co-owner approvals: Sole(founder) is satisfied by the proposer alone.
        let m = [
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("ed", KeyringRole::EDITOR, 6),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(2, vec![[1; 32]], "founder", 1, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        k.apply(commit(3, vec![[2; 32]], "founder", 1)).unwrap();
        assert_eq!(q_role_of(&k, "ed"), Some(KeyringRole::CO_OWNER), "founder alone suffices");
    }

    #[test]
    fn quorum_cannot_remove_the_immutable_owner() {
        // Owner-immutability binds the quorum path: even unanimity of every co-owner can't evict the
        // founder, because the founder couldn't do it directly (self-removal is forbidden) and the quorum
        // is founder-EQUIVALENT, never founder-exceeding. The requirement is fail-closed.
        let m = [
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::CO_OWNER, 3),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(2, vec![[1; 32]], "bob", 2, MembershipAction::Remove { member: "founder".into() })).unwrap();
        k.apply(approve(3, vec![[2; 32]], "carol", 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], "bob", 2)).unwrap();
        assert_eq!(q_role_of(&k, "founder"), Some(KeyringRole::OWNER), "no quorum can remove the Owner");
    }

    // ---- dynamic quorum: per-keyring QuorumRule ----

    #[test]
    fn founder_only_rule_ignores_co_owner_unanimity() {
        // A single-admin family: even unanimity of every co-owner can't act; only the founder (Sole) can.
        let m = [
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::CO_OWNER, 3),
            minit("ed", KeyringRole::EDITOR, 6),
        ];
        // co-owners bob + carol try to promote ed -> refused under FounderOnly.
        let mut k = quorum_engine_with(&m, KeyringQuorum::founder_only());
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(2, vec![[1; 32]], "bob", 2, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        k.apply(approve(3, vec![[2; 32]], "carol", 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], "bob", 2)).unwrap();
        assert_eq!(q_role_of(&k, "ed"), Some(KeyringRole::EDITOR), "co-owner unanimity is powerless here");
        // the founder alone still governs.
        let mut k2 = quorum_engine_with(&m, KeyringQuorum::founder_only());
        k2.apply(genesis(&m)).unwrap();
        k2.apply(propose(2, vec![[1; 32]], "founder", 1, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        k2.apply(commit(3, vec![[2; 32]], "founder", 1)).unwrap();
        assert_eq!(q_role_of(&k2, "ed"), Some(KeyringRole::CO_OWNER), "founder alone governs");
    }

    #[test]
    fn threshold_rule_needs_m_of_n_signers() {
        // A "3 of 4" family: founder + 3 co-owners, any 3 signers suffice, no special founder path.
        let m = [
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::CO_OWNER, 3),
            minit("dave", KeyringRole::CO_OWNER, 4),
            minit("ed", KeyringRole::EDITOR, 6),
        ];
        // Two signers (bob proposer + carol) is short of 3 -> refused.
        let mut short = quorum_engine_with(&m, KeyringQuorum::threshold(3));
        short.apply(genesis(&m)).unwrap();
        short.apply(propose(2, vec![[1; 32]], "bob", 2, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        short.apply(approve(3, vec![[2; 32]], "carol", 3)).unwrap();
        short.apply(commit(4, vec![[3; 32]], "bob", 2)).unwrap();
        assert_eq!(q_role_of(&short, "ed"), Some(KeyringRole::EDITOR), "2 of 4 is short of the threshold");
        // Three signers (bob + carol + dave) meet 3-of-4 -> applied, without the founder.
        let mut ok = quorum_engine_with(&m, KeyringQuorum::threshold(3));
        ok.apply(genesis(&m)).unwrap();
        ok.apply(propose(2, vec![[1; 32]], "bob", 2, promote("ed", KeyringRole::CO_OWNER))).unwrap();
        ok.apply(approve(3, vec![[2; 32]], "carol", 3)).unwrap();
        ok.apply(approve(4, vec![[3; 32]], "dave", 4)).unwrap();
        ok.apply(commit(5, vec![[4; 32]], "bob", 2)).unwrap();
        assert_eq!(q_role_of(&ok, "ed"), Some(KeyringRole::CO_OWNER), "3 of 4 signers meet the threshold");
    }
}
