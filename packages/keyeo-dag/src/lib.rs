#![doc = include_str!("../README.md")]

use keyeo::{AccessControl, GroupState, MembershipAction, QuorumPolicy, Requirement, Role};
use std::collections::HashSet;

pub mod blob_sync;
pub mod client;
pub mod recovery;
pub mod verifier;

// The signature scheme is keyeo's unified [`Ed25519`] (verify = edsign's `verify_strict`, rejecting
// small-order / torsion keys and non-canonical signatures) — re-exported so `keyeo_dag::Ed25519` names
// the scheme the keyring types are instantiated with. It replaces the old crate-local `OpenomSign`, a
// byte-identical duplicate of the same edsign verify that was deduplicated into keyeo-core (OPE-306).
pub use keyeo::Ed25519;

/// A keyring role, power-descending (**lower is stronger**): `ROLE_OWNER = 1` … `ROLE_VIEWER = 5`,
/// bound to keyeo-api's engine-neutral role convention ([`keyeo_api::ROLE_OWNER`] …) — which openom's
/// `openom-keyring::roles` drift-guard pins to the proto `MemberRole` values, so the engine never has to
/// depend on openom-roles (and stays openom-free). Wraps the `i16` so a role can be a signed,
/// content-addressed op field (keyeo requires `Role: Serialize`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct KeyringRole(pub i16);

impl KeyringRole {
    pub const OWNER: Self = Self(keyeo_api::ROLE_OWNER);
    pub const CO_OWNER: Self = Self(keyeo_api::ROLE_CO_OWNER);
    pub const MAINTAINER: Self = Self(keyeo_api::ROLE_MAINTAINER);
    pub const EDITOR: Self = Self(keyeo_api::ROLE_EDITOR);
    pub const VIEWER: Self = Self(keyeo_api::ROLE_VIEWER);

    /// A signer (keyring administrative authority) is a `CoOwner` or stronger (`Owner`).
    fn is_signer(self) -> bool {
        self.0 <= keyeo_api::ROLE_CO_OWNER
    }

    /// The Owner (founder) — the unique keyring root.
    fn is_owner(self) -> bool {
        self.0 == keyeo_api::ROLE_OWNER
    }
}

impl Role for KeyringRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        // Power-descending: a stronger (lower-valued) role grants everything a weaker one does.
        self.0 <= other.0
    }
}

/// The concrete keyeo instantiation for the openom keyring: op ids are 32-byte content hashes, member
/// ids are openom member-id strings, roles are [`KeyringRole`], signatures are keyeo's unified [`Ed25519`].
pub type KeyringAction = MembershipAction<String, KeyringRole, Ed25519>;
pub type KeyringOp = keyeo::Op<[u8; 32], String, KeyringRole, Ed25519>;
pub type KeyringState = GroupState<String, KeyringRole, Ed25519>;
pub type KeyringMemberInit = keyeo::MemberInit<String, KeyringRole, Ed25519>;
pub type KeyringEngine = keyeo::Keyeo<KeyringOp, KeyringAccess, keyeo::StrongRemove>;
/// The v2 keyring engine — same authority + strong-remove, plus a [`KeyringQuorum`] multi-signer policy
/// for privileged changes. Construct with `Keyeo::with_quorum(state, KeyringAccess, StrongRemove,
/// KeyringQuorum::founder_or_unanimity())` (or any other [`QuorumRule`]).
pub type KeyringQuorumEngine =
    keyeo::Keyeo<KeyringOp, KeyringAccess, keyeo::StrongRemove, KeyringQuorum>;

/// Sign a membership op with an edsign key. keyeo's `Op::sign` is dalek-specific; this signs over
/// keyeo's canonical encoding with the edsign seam instead, so the adapter never touches dalek.
pub fn sign_op(
    id: [u8; 32],
    parents: Vec<[u8; 32]>,
    author: impl Into<String>,
    action: KeyringAction,
    key: &edsign::SigningKey,
) -> KeyringOp {
    let author = author.into();
    // No sealing on these ops — sign_op is the id-supplied constructor used across tests + the keyless
    // paths; the sealing-carrying, content-addressed minting lives in the DagKeyring client facade (OPE-273).
    // Group id is UNSCOPED here: sign_op is single-group (tests / keyless fixtures); the production minting
    // path (`client::mint`) binds the real group id (openom: the tree id).
    let group_id = keyeo::GroupId::unscoped();
    let canonical = keyeo::canonical_encode(&group_id, &parents, &author, &action, &[]);
    let signature = key.sign(&canonical).to_bytes();
    let author_public_key = key.verifying_key().to_bytes();
    keyeo::Op::new(id, group_id, parents, author, action, signature, author_public_key)
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

impl AccessControl<String, KeyringRole, Ed25519> for KeyringAccess {
    fn is_authorized(
        &self,
        state: &KeyringState,
        author: &String,
        action: &KeyringAction,
    ) -> bool {
        // Genesis Create: authorized ONLY at an unestablished causal position (no members yet), with the
        // author a listed initial member and EXACTLY ONE Owner (the founder). The empty-state gate is the
        // OPE-271 hardening: keyeo's `apply_action` applies a `Create` by *replacing* the whole
        // `GroupState`, and a `Create` is self-certifying (the engine authenticates it against its OWN
        // `initial_members`, not the resolved state), so absent this gate a second, attacker-signed
        // `Create{owner: self}` folded at any populated position would WIPE the resolved roster and
        // re-found the group under the attacker. Gating on `is_empty()` means a `Create` can only ever
        // seed an unestablished group and can never re-found an established one. In openom's
        // out-of-band-seeded construction the genesis membership is the engine's trusted base, so every
        // in-DAG `Create` is a no-op and no `Create` can reset the roster.
        if let MembershipAction::Create { initial_members } = action {
            let owners = initial_members.iter().filter(|m| m.role.is_owner()).count();
            return state.members.is_empty()
                && owners == 1
                && initial_members.iter().any(|m| &m.id == author);
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
            // Recovery re-founding: this is the DOMAIN half of the ReFound gate — a ReFound may retarget
            // ONLY the Owner (founder), the unique + immutable keyring root, and no one else. The other
            // half — that the op is signed by the group's pinned recovery authority (RVK) — is enforced by
            // the engine (`key_matches_registration` → `reset_authority`); the two AND together, so a
            // ReFound needs BOTH the RVK signature AND an Owner target to take effect. `author_role` above
            // is unused here (the signer is the RVK, not the member), which is fine.
            MembershipAction::ReFound { member, .. } => Self::role_of(state, member).is_owner(),
            // Rotating the recovery authority: the RVK-signature (current authority signs) is enforced by
            // the engine; here we bind the domain shape — only the Owner may author a rotation. Revoking a
            // prior recovery-key holder is the Owner's prerogative.
            MembershipAction::RotateRecoveryAuthority { .. } => author_role.is_owner(),
            // Voluntary self-rekey (change-passphrase): a member retargets their OWN keys. The engine's D3
            // check ensures the author's CURRENT registered key signs it; the only domain rule is self-only
            // — you can't rekey another member. Any active member may rekey themselves.
            MembershipAction::Retarget { member, .. } => member == author,
            // A forward-secrecy reseal (OPE-282): any active member may author one — minting a fresh DEK
            // needs only public keys, so a member locked out of the current write epoch can still repair it.
            // The engine's D3 check binds it to the author's current key; the sealer's coverage check binds
            // WHAT it may contain, so no role gate is needed here.
            MembershipAction::Reseal => true,
        }
    }

    fn is_privileged(&self, state: &KeyringState, action: &KeyringAction) -> bool {
        // The authority-structure-changing ops — everything the reset-merge carve-out voids when it is
        // concurrent with a surviving recovery. Ordinary member changes (adding/removing/re-roling a
        // non-signer) are NOT privileged, so they auto-merge across a recovery (compass: never lose an
        // innocent edit). Signer-set changes, governance (quorum), and recovery are.
        match action {
            // Adding a signer is privileged; adding an ordinary member is not.
            MembershipAction::Add { role, .. } => role.is_signer(),
            // Touching a signer in either direction (promoting into, or demoting/removing out of).
            MembershipAction::ChangeRole { member, new_role } => {
                new_role.is_signer() || Self::role_of(state, member).is_signer()
            }
            MembershipAction::Remove { member } => Self::role_of(state, member).is_signer(),
            // Governance and recovery are always authority-structure changes.
            MembershipAction::Propose { .. }
            | MembershipAction::Approve { .. }
            | MembershipAction::Commit { .. }
            | MembershipAction::ReFound { .. }
            | MembershipAction::RotateRecoveryAuthority { .. } => true,
            // Retargeting a signer's key touches the authority structure (privileged); an ordinary
            // member's self-rekey does not.
            MembershipAction::Retarget { member, .. } => Self::role_of(state, member).is_signer(),
            // A reseal changes no signer/governance/recovery structure — a routine forward-secrecy repair,
            // so it auto-merges (never carve-out-voided by a concurrent recovery).
            MembershipAction::Reseal => false,
            MembershipAction::Create { .. } => false,
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

impl QuorumPolicy<String, KeyringRole, Ed25519> for KeyringQuorum {
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

    fn sk(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
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
        Keyeo::new(KeyringState::create(keyeo::GroupId::unscoped(), members), KeyringAccess, StrongRemove)
    }
    fn engine_with_rvk(members: &[KeyringMemberInit], rvk_pub: [u8; 32]) -> KeyringEngine {
        Keyeo::new(
            KeyringState::create(keyeo::GroupId::unscoped(), members).with_reset_authority(Some(rvk_pub)),
            KeyringAccess,
            StrongRemove,
        )
    }
    fn refound(member: &str, new_seed: u8, era: u64) -> KeyringAction {
        MembershipAction::ReFound {
            member: member.to_string(),
            new_author_public_key: vk(new_seed),
            new_hpke_public_key: [new_seed; 32],
            era,
        }
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
        // adds an ordinary Editor. The openom seams (Ed25519, KeyringRole, KeyringAccess) resolve end
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
    fn a_second_create_cannot_re_found_and_wipe_the_roster() {
        // OPE-271: keyeo's `apply_action` applies a Create by REPLACING GroupState, and a Create is
        // self-certifying (the engine authenticates it against its own initial_members), so both attack
        // shapes below are admitted with a valid signature. Without the empty-state gate on Create, either
        // would wipe the resolved roster and install mallory as sole Owner. The gate makes any Create at a
        // populated causal position a no-op, so the real roster survives untouched.
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
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1)))
            .unwrap();

        // Attack A — a second genesis childed on the real chain (sorts AFTER it in topo order: the classic
        // "later Create replaces the accumulated state" wipe).
        let re_found = |id: u8, parents: Vec<[u8; 32]>| {
            sign_op(
                [id; 32],
                parents,
                "mallory",
                MembershipAction::Create {
                    initial_members: vec![minit("mallory", KeyringRole::OWNER, 9)],
                },
                &sk(9),
            )
        };
        k.apply(re_found(9, vec![[2; 32]])).unwrap(); // admitted (self-certifying), folded as a no-op
        // Attack B — a CONCURRENT second genesis (no parents) whose OpId [0;32] sorts BEFORE the real
        // genesis [1;32], so it is folded FIRST — defeating any naive "first Create wins" rule.
        k.apply(re_found(0, vec![])).unwrap();

        assert_eq!(
            members(&k),
            vec![
                ("bob".to_string(), KeyringRole::CO_OWNER),
                ("founder".to_string(), KeyringRole::OWNER),
            ],
            "neither a later nor an OpId-grinding concurrent Create may re-found the group"
        );
        assert!(
            !k.state().members.contains_key("mallory"),
            "the attacker's self-signed re-genesis has no effect"
        );
    }

    #[test]
    fn an_op_carrying_a_key_that_is_not_the_authors_registered_key_is_ignored() {
        // D3 (retarget-tolerant authentication): admission verifies an op against its OWN carried key, so
        // an impostor CAN get a forged op admitted by claiming a member's id and signing with their own
        // key. Authority is then decided at the op's causal position, where the carried key must equal the
        // author's REGISTERED key — so the forgery has no effect. (This is also what will let a late op
        // signed under a since-retargeted key resolve identically on every replica once recovery lands.)
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
        ]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: vec![
                    minit("founder", KeyringRole::OWNER, 1),
                    minit("bob", KeyringRole::CO_OWNER, 2),
                ],
            },
            &sk(1),
        ))
        .unwrap();

        // Mallory forges an op AS "bob" (a co-owner who could add an editor) but signs it with HER key
        // (seed 9), so the op carries vk(9), not bob's registered vk(2).
        let forged = sign_op([2; 32], vec![[1; 32]], "bob", add("mallory", KeyringRole::EDITOR, 9), &sk(9));
        let outcome = k.apply(forged).unwrap(); // admitted — the signature matches its own carried key ...
        assert!(
            matches!(outcome, ApplyOutcome::Applied { events } if events.is_empty()),
            "the forged op is admitted but resolves to no membership change"
        );
        assert!(
            !members(&k).iter().any(|(m, _)| m == "mallory"),
            "an op signed under a key that isn't the author's registered key carries no authority"
        );

        // Control: the REAL bob, signing with his registered key (seed 2), adds an editor as expected.
        k.apply(sign_op([3; 32], vec![[1; 32]], "bob", add("carol", KeyringRole::EDITOR, 3), &sk(2)))
            .unwrap();
        assert!(
            members(&k).iter().any(|(m, _)| m == "carol"),
            "the same action by the author's registered key is authorized — the key identity is the gate"
        );
    }

    #[test]
    fn a_refound_signed_by_the_recovery_authority_retargets_the_owner() {
        // OPE-269 recovery: a ReFound signed by the group's pinned recovery authority (the RVK) re-founds
        // the Owner — swapping in a fresh signing + HPKE key — WITHOUT touching anyone else or the Owner's
        // role. A minimal forward delta: the owner who lost their device regains control, and their new
        // key is now the registered one for future ops.
        let rvk = crate::recovery::derive_rvk(&[42u8; 32]);
        let rvk_pub = rvk.verifying_key().to_bytes();
        let mut k = engine_with_rvk(
            &[
                minit("founder", KeyringRole::OWNER, 1),
                minit("bob", KeyringRole::CO_OWNER, 2),
            ],
            rvk_pub,
        );
        // A root op so later ops have a parent (the in-DAG Create is inert per OPE-271; membership + the
        // recovery authority both come from the seeded base).
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: vec![
                    minit("founder", KeyringRole::OWNER, 1),
                    minit("bob", KeyringRole::CO_OWNER, 2),
                ],
            },
            &sk(1),
        ))
        .unwrap();
        assert_eq!(k.state().members.get("founder").unwrap().author_public_key, vk(1));

        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", refound("founder", 7, 1), &rvk))
            .unwrap();
        let owner = k.state().members.get("founder").unwrap();
        assert_eq!(owner.author_public_key, vk(7), "recovery retargets the Owner signing key");
        assert_eq!(owner.hpke_public_key, [7u8; 32], "and the Owner HPKE key");
        assert_eq!(owner.role, KeyringRole::OWNER, "owner-hood is preserved — a delta, not a re-genesis");
        assert_eq!(
            k.state().members.get("bob").unwrap().author_public_key,
            vk(2),
            "no other member is touched by a recovery"
        );
    }

    #[test]
    fn a_refound_is_rejected_without_the_recovery_authority_or_against_a_non_owner() {
        // Both halves of the ReFound gate. (a) A ReFound signed by a NON-authority key (mallory's own) is
        // admitted — self-certifying — but carries no authority, so the Owner key is untouched. (b) Even
        // with the real RVK, a ReFound may retarget ONLY the Owner: aimed at a co-owner it has no effect.
        let rvk = crate::recovery::derive_rvk(&[42u8; 32]);
        let rvk_pub = rvk.verifying_key().to_bytes();
        let mut k = engine_with_rvk(
            &[
                minit("founder", KeyringRole::OWNER, 1),
                minit("bob", KeyringRole::CO_OWNER, 2),
            ],
            rvk_pub,
        );
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: vec![
                    minit("founder", KeyringRole::OWNER, 1),
                    minit("bob", KeyringRole::CO_OWNER, 2),
                ],
            },
            &sk(1),
        ))
        .unwrap();

        // (a) forged by mallory's key (seed 9), not the pinned RVK.
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", refound("founder", 7, 1), &sk(9)))
            .unwrap();
        assert_eq!(
            k.state().members.get("founder").unwrap().author_public_key,
            vk(1),
            "a ReFound not signed by the pinned recovery authority has no effect"
        );
        // (b) the real RVK, but targeting a co-owner instead of the Owner.
        k.apply(sign_op([3; 32], vec![[1; 32]], "bob", refound("bob", 7, 1), &rvk))
            .unwrap();
        assert_eq!(
            k.state().members.get("bob").unwrap().author_public_key,
            vk(2),
            "a ReFound may re-found only the Owner, never another member"
        );
    }

    // ---- RRK rotation: revoke a prior recovery-key holder (OPE-272) ----

    #[test]
    fn rotating_the_recovery_authority_revokes_the_old_rvk() {
        // The only genuine revoke-prior-holder path. After rotating the pinned authority from rvk1 to
        // rvk2 (signed by the CURRENT authority rvk1), the old rvk1 can no longer authorize a recovery,
        // but the new rvk2 can.
        let rvk1 = crate::recovery::derive_rvk(&[42u8; 32]);
        let rvk2 = crate::recovery::derive_rvk(&[43u8; 32]);
        let mut k = engine_with_rvk(&[minit("founder", KeyringRole::OWNER, 1)], rvk1.verifying_key().to_bytes());
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create { initial_members: vec![minit("founder", KeyringRole::OWNER, 1)] },
            &sk(1),
        ))
        .unwrap();
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::RotateRecoveryAuthority {
                new_reset_authority: rvk2.verifying_key().to_bytes(),
            },
            &rvk1,
        ))
        .unwrap();
        // the rotated-out authority can't recover any more...
        k.apply(sign_op([3; 32], vec![[2; 32]], "founder", refound("founder", 7, 1), &rvk1))
            .unwrap();
        assert_eq!(
            k.state().members.get("founder").unwrap().author_public_key,
            vk(1),
            "a ReFound signed by the rotated-out old authority is rejected"
        );
        // ...but the new authority can.
        k.apply(sign_op([4; 32], vec![[2; 32]], "founder", refound("founder", 7, 1), &rvk2))
            .unwrap();
        assert_eq!(
            k.state().members.get("founder").unwrap().author_public_key,
            vk(7),
            "a ReFound signed by the new authority re-founds the owner"
        );
    }

    #[test]
    fn a_rotation_not_signed_by_the_current_authority_is_rejected() {
        // Gating on the OLD authority is what makes rotation safe: a rotation not signed by the current
        // recovery key (here mallory's own key) has no effect, so it can't seize recovery power.
        let rvk1 = crate::recovery::derive_rvk(&[42u8; 32]);
        let rvk2 = crate::recovery::derive_rvk(&[43u8; 32]);
        let mut k = engine_with_rvk(&[minit("founder", KeyringRole::OWNER, 1)], rvk1.verifying_key().to_bytes());
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create { initial_members: vec![minit("founder", KeyringRole::OWNER, 1)] },
            &sk(1),
        ))
        .unwrap();
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::RotateRecoveryAuthority {
                new_reset_authority: rvk2.verifying_key().to_bytes(),
            },
            &sk(9), // NOT the current authority
        ))
        .unwrap();
        k.apply(sign_op([3; 32], vec![[2; 32]], "founder", refound("founder", 7, 1), &rvk2))
            .unwrap();
        assert_eq!(
            k.state().members.get("founder").unwrap().author_public_key,
            vk(1),
            "the forged rotation had no effect — rvk2 is still not the authority"
        );
        k.apply(sign_op([4; 32], vec![[2; 32]], "founder", refound("founder", 7, 1), &rvk1))
            .unwrap();
        assert_eq!(
            k.state().members.get("founder").unwrap().author_public_key,
            vk(7),
            "the original authority still governs recovery"
        );
    }

    // ---- bounded fork-merge horizon (OPE-270) ----

    #[test]
    fn a_fork_branching_from_before_the_merge_horizon_is_rejected() {
        // GHOST-derived anti-rollback hygiene: once a stable frontier is pinned as the merge horizon, an
        // op that branches from BEFORE it is rejected as a stale fork, not merged — closing the
        // rollback/equivocation vector of re-introducing history past the compaction cut. An op that
        // builds ON the horizon is accepted.
        let mut k = engine(&[minit("founder", KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create { initial_members: vec![minit("founder", KeyringRole::OWNER, 1)] },
            &sk(1),
        ))
        .unwrap();
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1)))
            .unwrap();

        // Pin the horizon at the current tip [2].
        k.set_merge_horizon(vec![[2; 32]]);

        // A fork off [1] (before the horizon) is rejected outright.
        let stale = k.apply(sign_op([4; 32], vec![[1; 32]], "founder", add("mallory", KeyringRole::EDITOR, 9), &sk(1)));
        assert!(
            matches!(stale, Err(keyeo::Error::StaleFork)),
            "a fork from before the horizon is rejected, not merged"
        );
        assert!(!k.state().members.contains_key("mallory"), "and never enters the resolved state");

        // An op building ON the horizon [2] is accepted normally.
        k.apply(sign_op([3; 32], vec![[2; 32]], "founder", add("carol", KeyringRole::EDITOR, 3), &sk(1)))
            .unwrap();
        assert!(k.state().members.contains_key("carol"), "an op that builds on the horizon is accepted");
    }

    // ---- RESET-MERGE: how a recovery interacts with concurrent ops (OPE-269) ----

    fn recovery_genesis(k: &mut KeyringEngine) {
        // A shared root op for the reset-merge tests: genesis {founder(Owner), bob(CoOwner)}.
        k.apply(sign_op(
            [1; 32],
            vec![],
            "founder",
            MembershipAction::Create {
                initial_members: vec![
                    minit("founder", KeyringRole::OWNER, 1),
                    minit("bob", KeyringRole::CO_OWNER, 2),
                ],
            },
            &sk(1),
        ))
        .unwrap();
    }

    #[test]
    fn an_ordinary_member_add_concurrent_with_recovery_auto_merges() {
        // Compass #2 (never lose data): a recovery must not clobber an innocent relative's concurrent
        // work. bob adds an ordinary editor on one branch while the owner is recovered on another — both
        // survive, because an ordinary member add is not privileged and so isn't carved out.
        let rvk = crate::recovery::derive_rvk(&[42u8; 32]);
        let mut k = engine_with_rvk(
            &[minit("founder", KeyringRole::OWNER, 1), minit("bob", KeyringRole::CO_OWNER, 2)],
            rvk.verifying_key().to_bytes(),
        );
        recovery_genesis(&mut k);
        k.apply(sign_op([2; 32], vec![[1; 32]], "bob", add("erin", KeyringRole::EDITOR, 5), &sk(2)))
            .unwrap();
        k.apply(sign_op([3; 32], vec![[1; 32]], "founder", refound("founder", 7, 1), &rvk))
            .unwrap();
        assert_eq!(
            k.state().members.get("erin").map(|m| m.role),
            Some(KeyringRole::EDITOR),
            "an ordinary add concurrent with recovery auto-merges — nothing innocent is lost"
        );
        assert_eq!(k.state().members.get("founder").unwrap().author_public_key, vk(7), "owner recovered");
    }

    #[test]
    fn a_privileged_op_concurrent_with_recovery_is_voided_but_a_later_owner_op_stands() {
        // The carve-out. A compromised founder key (the thief) adds an accomplice SIGNER concurrent with
        // the legitimate recovery — precisely the escalation a recovery defends against — so it is voided.
        // Then, AFTER the recovery, the recovered owner adds a signer with the NEW key: not concurrent
        // with the recovery, so it stands. Together: the thief's concurrent grab dies, real governance
        // resumes on the new key.
        let rvk = crate::recovery::derive_rvk(&[42u8; 32]);
        let mut k = engine_with_rvk(
            &[minit("founder", KeyringRole::OWNER, 1), minit("bob", KeyringRole::CO_OWNER, 2)],
            rvk.verifying_key().to_bytes(),
        );
        recovery_genesis(&mut k);
        // thief branch (old founder key) and recovery branch (RVK), concurrent children of genesis.
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", add("mallory", KeyringRole::CO_OWNER, 9), &sk(1)))
            .unwrap();
        k.apply(sign_op([3; 32], vec![[1; 32]], "founder", refound("founder", 7, 1), &rvk))
            .unwrap();
        assert!(
            !k.state().members.contains_key("mallory"),
            "a signer add concurrent with the recovery is voided by the carve-out"
        );
        assert_eq!(k.state().members.get("founder").unwrap().author_public_key, vk(7), "owner recovered");
        assert!(k.state().members.contains_key("bob"), "the innocent co-owner is untouched");
        // post-recovery: the recovered owner (new key sk(7)) adds a signer — not concurrent with R*.
        k.apply(sign_op([4; 32], vec![[3; 32]], "founder", add("carol", KeyringRole::CO_OWNER, 3), &sk(7)))
            .unwrap();
        assert_eq!(
            k.state().members.get("carol").map(|m| m.role),
            Some(KeyringRole::CO_OWNER),
            "the recovered owner governs normally with the new key after recovery"
        );
    }

    #[test]
    fn reset_merge_converges_regardless_of_arrival_order() {
        // BEC: the carve-out depends only on the op DAG + causal authorization, never arrival order, so
        // two replicas that see the thief-add and the recovery in opposite orders converge identically.
        let rvk = crate::recovery::derive_rvk(&[42u8; 32]);
        let rvk_pub = rvk.verifying_key().to_bytes();
        let mk = || {
            let mut k = engine_with_rvk(
                &[minit("founder", KeyringRole::OWNER, 1), minit("bob", KeyringRole::CO_OWNER, 2)],
                rvk_pub,
            );
            recovery_genesis(&mut k);
            k
        };
        let thief =
            sign_op([2; 32], vec![[1; 32]], "founder", add("mallory", KeyringRole::CO_OWNER, 9), &sk(1));
        let recovery = sign_op([3; 32], vec![[1; 32]], "founder", refound("founder", 7, 1), &rvk);

        let mut k1 = mk();
        k1.apply(thief.clone()).unwrap();
        k1.apply(recovery.clone()).unwrap();

        let mut k2 = mk();
        k2.apply(recovery).unwrap();
        k2.apply(thief).unwrap();

        assert_eq!(
            k1.state().active_members(),
            k2.state().active_members(),
            "the carve-out resolves identically regardless of op arrival order (BEC)"
        );
        assert_eq!(
            k1.state().members.get("founder").unwrap().author_public_key,
            k2.state().members.get("founder").unwrap().author_public_key,
            "the recovered owner key converges"
        );
        assert!(!k1.state().members.contains_key("mallory"), "and the carve-out held in both orders");
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
    fn the_edsign_seam_rejects_a_forged_signature() {
        // A structurally-valid op whose signature is over the wrong bytes must be rejected by the
        // engine's authenticate step, i.e. by Ed25519::verify (edsign verify_strict).
        let mut k = engine(&[minit("founder", KeyringRole::OWNER, 1)]);
        let action = MembershipAction::Remove {
            member: "founder".to_string(),
        };
        let bad_sig = sk(1).sign(b"not the canonical op bytes").to_bytes();
        let op = keyeo::Op::new([1; 32], keyeo::GroupId::unscoped(), vec![], "founder".to_string(), action, bad_sig, vk(1));
        assert!(matches!(k.apply(op).unwrap_err(), keyeo::Error::BadSignature));
    }

    // ---- v2 multi-signer quorum (FounderOrUnanimity) ----

    fn quorum_engine_with(members: &[KeyringMemberInit], quorum: KeyringQuorum) -> KeyringQuorumEngine {
        Keyeo::with_quorum(KeyringState::create(keyeo::GroupId::unscoped(), members), KeyringAccess, StrongRemove, quorum)
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
