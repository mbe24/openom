//! openom-keyring-dag — the openom-specific adapter over the generic `keyeo` group-membership DAG
//! (the sequencer-free keyring, OPE-137). keyeo stays domain-free and publishable; every openom
//! specific — the Ed25519 seam, the role model, and the authority policy — lives here.
//!
//! v1 scope (BYO / sequencer-free): ordinary members + **founder-signed** governance + rotation. The
//! multi-signer **quorum** ("co-owners collectively", founder-or-unanimity) is v2 — see
//! `plan/design.keyring-dag.md`. This crate deliberately depends on `openom-sign` (not `ed25519-dalek`)
//! so keyeo's own dalek edge is replaced by openom's `verify_strict` seam (OPE-215).

use keyeo::{AccessControl, GroupState, MembershipAction, Role, SigError, SignatureScheme};

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

/// openom keyring authority — v1, founder-signed governance (quorum is v2).
///
/// The role a change requires depends on **what it touches**:
/// - touching a **signer** (`CoOwner` or stronger) requires the **Owner** (founder);
/// - touching an **ordinary member** (`Maintainer` or weaker) requires **Maintainer+**;
/// - a member may always **remove themselves**.
///
/// (Authorization is evaluated by the resolver at each op's causal position — see keyeo's
/// authority-aware `StrongRemove`, OPE-258.)
pub struct KeyringAccess;

impl KeyringAccess {
    /// The weakest role permitted to add/remove/retarget a member whose role is `target`.
    fn required_for(target: KeyringRole) -> KeyringRole {
        if target.is_signer() {
            KeyringRole::OWNER
        } else {
            KeyringRole::MAINTAINER
        }
    }
}

impl AccessControl<String, KeyringRole, OpenomSign> for KeyringAccess {
    fn is_authorized(
        &self,
        state: &KeyringState,
        author: &String,
        action: &KeyringAction,
    ) -> bool {
        // The author's current role at this causal position; a non-member may only author the genesis
        // Create (naming themselves an initial member).
        let author_role = match state.members.get(author) {
            Some(m) if m.is_active() => m.role,
            _ => {
                return matches!(
                    action,
                    MembershipAction::Create { initial_members }
                        if initial_members.iter().any(|m| &m.id == author)
                );
            }
        };
        match action {
            MembershipAction::Create { initial_members } => {
                initial_members.iter().any(|m| &m.id == author)
            }
            MembershipAction::Add { role, .. } => {
                author_role.grants_at_least(&Self::required_for(*role))
            }
            MembershipAction::ChangeRole { member, new_role } => {
                // Must be able to manage both the current standing and the target role — so a Maintainer
                // can't demote an Owner (touching the current role needs Owner) nor promote into the
                // signer set (touching the target role needs Owner).
                let current = state
                    .members
                    .get(member)
                    .map(|m| m.role)
                    .unwrap_or(KeyringRole::VIEWER);
                author_role.grants_at_least(&Self::required_for(current))
                    && author_role.grants_at_least(&Self::required_for(*new_role))
            }
            MembershipAction::Remove { member } => {
                if author == member {
                    return true; // self-removal is always allowed
                }
                let current = state
                    .members
                    .get(member)
                    .map(|m| m.role)
                    .unwrap_or(KeyringRole::VIEWER);
                author_role.grants_at_least(&Self::required_for(current))
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
        // founder (Owner) creates the group, adds bob as Maintainer; bob (Maintainer) then adds an
        // ordinary Editor. The openom seams (OpenomSign, KeyringRole, KeyringAccess) resolve end to end.
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
        k.apply(sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::MAINTAINER, 2), &sk(1)))
            .unwrap();
        k.apply(sign_op([3; 32], vec![[2; 32]], "bob", add("carol", KeyringRole::EDITOR, 3), &sk(2)))
            .unwrap();

        assert_eq!(
            members(&k),
            vec![
                ("bob".to_string(), KeyringRole::MAINTAINER),
                ("carol".to_string(), KeyringRole::EDITOR),
                ("founder".to_string(), KeyringRole::OWNER),
            ]
        );
    }

    #[test]
    fn a_maintainer_cannot_touch_a_signer() {
        // bob (Maintainer) removing the founder (Owner = a signer) needs Owner authority. Admit-then-
        // resolve: the op is admitted (valid signature) but yields no membership change.
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::MAINTAINER, 2),
        ]);
        let r = k
            .apply(sign_op(
                [1; 32],
                vec![],
                "bob",
                MembershipAction::Remove {
                    member: "founder".to_string(),
                },
                &sk(2),
            ))
            .unwrap();
        assert!(matches!(r, ApplyOutcome::Applied { events } if events.is_empty()));
        assert!(
            k.state().active_members().iter().any(|(m, _)| m == "founder"),
            "founder must survive a Maintainer's unauthorized remove"
        );
    }

    #[test]
    fn only_the_owner_may_promote_into_the_signer_set() {
        // bob (Maintainer) cannot promote carol (Editor) to CoOwner — that touches the signer set.
        let mut k = engine(&[
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::MAINTAINER, 2),
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
            "carol stays an Editor — a Maintainer can't create a signer"
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
}
