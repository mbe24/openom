//! Parity THROUGH the seam (OPE-277): drive the chain and dag `KeyringVerifier` adapters on equivalent
//! operations and assert they resolve the same membership — the executable proof that the two engines are
//! interchangeable behind the seam, per the OPE-276 decision.
//!
//! Green rows compare the resolved `MembershipView` (member ids + roles) — the shared contract. The one
//! honest DIVERGENCE the decision doc flagged is asserted as such: an unauthorized change is REFUSED by
//! the chain (it verifies a candidate) but ADMITTED-as-a-no-op by the dag (admit-then-resolve) — the same
//! EFFECT (no membership change) reached by different mechanisms.

use keyeo::{MemberInit, MembershipAction};
use openom_keyring::verifier::ChainVerifier;
use openom_keyring_dag::verifier::{bootstrap_update, op_update, DagVerifier};
use openom_keyring_dag::{sign_op, KeyringAction, KeyringMemberInit, KeyringRole};
use openom_keyring_seam::{KeyringVerifier, MembershipView, VerifyError};
use openom_protocol::v1::{
    AuthorizedSigner, KeyEpoch, KeyWrap, Keyring, Member, MemberRole, WrapMethod,
};
use openom_protocol::Message;
use openom_roles::{MEMBER_OWNER, SIGNER_FOUNDER};
use openom_sign::SigningKey;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32])
}
fn pk(seed: u8) -> Vec<u8> {
    sk(seed).verifying_key().to_bytes().to_vec()
}
fn vk(seed: u8) -> [u8; 32] {
    sk(seed).verifying_key().to_bytes()
}

/// The shared contract we compare across engines: the resolved (member_id, role) set. Key bytes are
/// engine inputs, not semantic divergence, so they're excluded.
fn semantic(v: &MembershipView) -> Vec<(String, i16)> {
    v.members.iter().map(|m| (m.member_id.clone(), m.role)).collect()
}

// ── chain construction (founder-only genesis + an ordinary "carol" add) ──

fn wrap(id: &str, method: WrapMethod) -> KeyWrap {
    KeyWrap {
        member_id: id.into(),
        wrap_method: method as i32,
        nonce: vec![],
        wrapped_dek: vec![1],
        kdf_params: None,
        ephemeral_public_key: vec![],
    }
}
fn chain_genesis() -> Keyring {
    let mut g = Keyring {
        tree_id: b"tree-uuid-16byte".to_vec(),
        revision: 1,
        layout_version: 1,
        prev_keyring_hash: vec![],
        authorized_signers: vec![AuthorizedSigner {
            public_key: pk(1),
            member_id: "owner".into(),
            role: SIGNER_FOUNDER,
        }],
        members: vec![Member {
            member_id: "owner".into(),
            role: MEMBER_OWNER,
            author_public_key: pk(1),
            hpke_public_key: vec![9; 32],
        }],
        signatures: vec![],
        recovery_keys: vec![],
        epochs: vec![KeyEpoch {
            key_id: vec![0],
            epoch: 0,
            wraps: vec![wrap("owner", WrapMethod::RrkHpke)],
        }],
        ..Default::default()
    };
    openom_keyring::sign_keyring(&mut g, &sk(1));
    g
}
/// Add a Maintainer "dave" (seed 4) — a MEMBER but NOT a signer — to a genesis, founder re-signed.
fn with_maintainer_dave(mut g: Keyring) -> Keyring {
    g.members.push(Member {
        member_id: "dave".into(),
        role: MemberRole::Admin as i32, // UI: "Maintainer"
        author_public_key: pk(4),
        hpke_public_key: vec![9; 32],
    });
    g.epochs[0].wraps.push(wrap("dave", WrapMethod::X25519Hpke));
    g.signatures.clear();
    openom_keyring::sign_keyring(&mut g, &sk(1));
    g
}
/// A rev-2 successor adding ordinary editor "carol", signed by `signer_seed`.
fn chain_add_carol(prior: &Keyring, signer_seed: u8) -> Keyring {
    let mut k = prior.clone();
    k.revision = 2;
    k.prev_keyring_hash = openom_keyring::keyring_hash(prior).to_vec();
    k.members.push(Member {
        member_id: "carol".into(),
        role: MemberRole::Editor as i32,
        author_public_key: pk(3),
        hpke_public_key: vec![9; 32],
    });
    k.epochs[0].wraps.push(wrap("carol", WrapMethod::X25519Hpke));
    k.signatures.clear();
    openom_keyring::sign_keyring(&mut k, &sk(signer_seed));
    k
}

// ── dag construction (the equivalent ops) ──

fn dag_minit(id: &str, role: KeyringRole, seed: u8) -> KeyringMemberInit {
    MemberInit {
        id: id.to_string(),
        role,
        author_public_key: vk(seed),
        hpke_public_key: [seed; 32],
    }
}
fn dag_add(member: &str, role: KeyringRole, seed: u8) -> KeyringAction {
    MembershipAction::Add {
        member: member.to_string(),
        role,
        author_public_key: vk(seed),
        hpke_public_key: [seed; 32],
        member_proof: None,
    }
}

#[test]
fn both_engines_resolve_the_same_membership_for_equivalent_authorized_ops() {
    // Bootstrap a founder-only genesis, then add ordinary editor "carol" signed by the founder — the two
    // verifiers must resolve the same (member_id, role) set at each step.
    let (cv, dv) = (ChainVerifier, DagVerifier);

    // chain
    let cg = chain_genesis();
    let c_boot = cv.admit(None, &cg.encode_to_vec()).unwrap();
    let c_next = cv.admit(Some(&c_boot.state), &chain_add_carol(&cg, 1).encode_to_vec()).unwrap();

    // dag
    let gm = vec![dag_minit("owner", KeyringRole::OWNER, 1)];
    let gop = sign_op([1; 32], vec![], "owner", MembershipAction::Create { initial_members: gm.clone() }, &sk(1));
    let d_boot = dv.admit(None, &bootstrap_update(&gm, None, &gop)).unwrap();
    let add = sign_op([2; 32], vec![[1; 32]], "owner", dag_add("carol", KeyringRole::EDITOR, 3), &sk(1));
    let d_next = dv.admit(Some(&d_boot.state), &op_update(&add)).unwrap();

    assert_eq!(semantic(&c_boot.view), semantic(&d_boot.view), "genesis membership agrees");
    assert_eq!(semantic(&c_next.view), semantic(&d_next.view), "post-add membership agrees");
    assert_eq!(semantic(&c_next.view), vec![("carol".into(), 4), ("owner".into(), 1)]);
    assert!(c_boot.changed && c_next.changed && d_boot.changed && d_next.changed);
}

#[test]
fn an_unauthorized_change_has_no_effect_in_both_by_different_mechanisms() {
    // The documented divergence: an unauthorized party tries to add "carol". Same EFFECT (carol never
    // joins), different MECHANISM — the chain refuses the candidate (Unauthorized), the dag admits the op
    // and resolves it to a no-op (changed=false). Both are honest; the seam surfaces both faithfully.
    let (cv, dv) = (ChainVerifier, DagVerifier);

    // Both genesis have Maintainer "dave" — a known member, but NOT a signer — as the unauthorized actor.
    // chain: a rev-2 adding carol, signed by dave (seed 4) → an unendorsed ordinary change → refused.
    let cg = with_maintainer_dave(chain_genesis());
    let c_boot = cv.admit(None, &cg.encode_to_vec()).unwrap();
    let c_out = cv.admit(Some(&c_boot.state), &chain_add_carol(&cg, 4).encode_to_vec());
    assert_eq!(c_out.unwrap_err(), VerifyError::Unauthorized, "chain REFUSES an unauthorized change");

    // dag: dave (a member, not a signer) authors Add(carol) → admitted (dave is known) but resolved to
    // no effect (dave lacks keyring-write authority).
    let gm = vec![
        dag_minit("owner", KeyringRole::OWNER, 1),
        dag_minit("dave", KeyringRole::MAINTAINER, 4),
    ];
    let gop = sign_op([1; 32], vec![], "owner", MembershipAction::Create { initial_members: gm.clone() }, &sk(1));
    let d_boot = dv.admit(None, &bootstrap_update(&gm, None, &gop)).unwrap();
    let daves_add = sign_op([2; 32], vec![[1; 32]], "dave", dag_add("carol", KeyringRole::EDITOR, 3), &sk(4));
    let d_out = dv.admit(Some(&d_boot.state), &op_update(&daves_add)).unwrap();
    assert!(!d_out.changed, "dag ADMITS the op but resolves it to a no-op (changed=false)");

    // ...and the EFFECT is identical: carol is a member in neither.
    assert!(!d_out.view.members.iter().any(|m| m.member_id == "carol"));
}
