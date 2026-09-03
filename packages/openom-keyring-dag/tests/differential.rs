//! Differential oracle: the DAG keyring (openom-keyring-dag / keyeo) vs the legacy CAS keyring
//! (openom-keyring / chain.rs), on a fork-free sequence — the "CAS = degenerate DAG" acceptance gate.
//!
//! For a shared cast + a single logical mutation, we drive BOTH systems and compare — chain.rs builds
//! the successor `Keyring` + `verify_transition` (accept/reject), keyeo `sign_op`s the equivalent
//! `MembershipAction` + `apply`s it (did the target member change?) — and assert they AGREE, except at
//! the two documented v1 divergences (self-removal widen; unanimity is v2), which are asserted as
//! *expected* divergences so the oracle stays honest.

use keyeo_dag::{Keyeo, MemberInit, MembershipAction, StrongRemove};
use openom_keyring_chain::{keyring_hash, sign_keyring, verify_reset, verify_transition, KeyringAnchor};
use openom_keyring_dag::{
    recovery, sign_op, KeyringAccess, KeyringEngine, KeyringMemberInit, KeyringRole, KeyringState,
};
use openom_protocol::v1::{MemberRole, WrapMethod};
use openom_keyring_chain::wire::{KeyEpoch, KeyWrap, Keyring, Member};
use openom_roles::{MEMBER_CO_OWNER, MEMBER_OWNER};
use edsign::SigningKey;

const TREE: &[u8] = b"tree-uuid-16byte";
const RRK_HPKE: i32 = WrapMethod::RrkHpke as i32;
const HPKE: i32 = WrapMethod::X25519Hpke as i32;
const MAINTAINER: i32 = MemberRole::Admin as i32; // UI: "Maintainer"
const EDITOR: i32 = MemberRole::Editor as i32;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32])
}
fn pubv(k: &SigningKey) -> Vec<u8> {
    k.verifying_key().to_bytes().to_vec()
}
fn pk32(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

// ── one cast description, projected into both systems ──
struct Cast {
    seed: u8,
    id: &'static str,
    /// Proto `MemberRole` value (drives both the chain member role and the keyeo `KeyringRole`). The chain
    /// signer set is DERIVED from this (a member at CO_OWNER or stronger is a signer, OPE-309), so there is
    /// no separate signer-role axis.
    member_role: i32,
}

fn keyed_member(k: &SigningKey, id: &str, role: i32) -> Member {
    Member { member_id: id.into(), role, author_public_key: pubv(k), hpke_public_key: vec![9; 32] }
}
fn wrap(id: &str, method: i32) -> KeyWrap {
    KeyWrap {
        member_id: id.into(),
        wrap_method: method,
        nonce: vec![],
        wrapped_dek: vec![1],
        kdf_params: None,
        ephemeral_public_key: vec![],
        recipient_public_key: vec![],
    }
}

/// The chain.rs genesis keyring for a cast (cast[0] is the founder: RRK-wrapped, FOUNDER signer).
fn chain_genesis(cast: &[Cast]) -> Keyring {
    let mut members = Vec::new();
    let mut wraps = Vec::new();
    for (i, c) in cast.iter().enumerate() {
        let k = sk(c.seed);
        members.push(keyed_member(&k, c.id, c.member_role));
        wraps.push(wrap(c.id, if i == 0 { RRK_HPKE } else { HPKE }));
    }
    let mut g = Keyring {
        tree_id: TREE.to_vec(),
        revision: 1,
        layout_version: 1,
        prev_keyring_hash: vec![],
        members,
        signatures: vec![],
        recovery_keys: vec![],
        epochs: vec![KeyEpoch { key_id: vec![0], epoch: 0, wraps }],
        ..Default::default()
    };
    sign_keyring(&mut g, &sk(cast[0].seed)); // founder signs genesis
    g
}

/// A well-formed chain.rs successor: revision+1, chained hash, `mutate` applied, signed by `sign_with`.
fn chain_next(prior: &Keyring, mutate: impl FnOnce(&mut Keyring), sign_with: &[u8]) -> Keyring {
    let mut k = prior.clone();
    k.revision = prior.revision + 1;
    k.prev_keyring_hash = keyring_hash(prior).to_vec();
    mutate(&mut k);
    k.signatures.clear();
    for &seed in sign_with {
        sign_keyring(&mut k, &sk(seed));
    }
    k
}

/// The keyeo engine for the same cast (constructor genesis; the single-axis `KeyringRole` = MemberRole).
fn keyeo_engine(cast: &[Cast]) -> KeyringEngine {
    let inits: Vec<KeyringMemberInit> = cast
        .iter()
        .map(|c| MemberInit {
            id: c.id.to_string(),
            role: KeyringRole(c.member_role as i16),
            author_public_key: pk32(&sk(c.seed)),
            hpke_public_key: [c.seed; 32],
        })
        .collect();
    Keyeo::new(KeyringState::create(keyeo_dag::GroupId::unscoped(), &inits), KeyringAccess, StrongRemove)
}

fn keyeo_has(k: &KeyringEngine, id: &str) -> bool {
    k.state().active_members().iter().any(|(m, _)| m == id)
}

/// keyeo engine for a cast WITH a pinned recovery authority (RVK) — the recovery differential needs it.
fn keyeo_engine_with_rvk(cast: &[Cast], rvk_pub: [u8; 32]) -> KeyringEngine {
    let inits: Vec<KeyringMemberInit> = cast
        .iter()
        .map(|c| MemberInit {
            id: c.id.to_string(),
            role: KeyringRole(c.member_role as i16),
            author_public_key: pk32(&sk(c.seed)),
            hpke_public_key: [c.seed; 32],
        })
        .collect();
    Keyeo::new(
        KeyringState::create(keyeo_dag::GroupId::unscoped(), &inits).with_reset_authority(Some(rvk_pub)),
        KeyringAccess,
        StrongRemove,
    )
}

fn keyeo_owner_key(k: &KeyringEngine) -> [u8; 32] {
    k.state().members.get("owner").unwrap().author_public_key
}

fn founder() -> Cast {
    Cast { seed: 1, id: "owner", member_role: MEMBER_OWNER }
}
fn co_owner(seed: u8, id: &'static str) -> Cast {
    Cast { seed, id, member_role: MEMBER_CO_OWNER }
}
fn plain(seed: u8, id: &'static str, role: i32) -> Cast {
    Cast { seed, id, member_role: role }
}

// ────────────────────────────── AGREEMENT cases ──────────────────────────────

#[test]
fn founder_adds_a_co_owner_agrees() {
    // A founder-signed signer-set change: both accept and both gain the co-owner.
    let cast = [founder()];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            // A CO_OWNER-role member IS a signer (derived from members) — no separate roster push.
            k.members.push(keyed_member(&sk(5), "erin", MEMBER_CO_OWNER));
            k.epochs[0].wraps.push(wrap("erin", HPKE));
        },
        &[1], // founder signs
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op(
        [2u8; 32],
        vec![],
        "owner",
        MembershipAction::Add {
            member: "erin".into(),
            role: KeyringRole::CO_OWNER,
            author_public_key: pk32(&sk(5)),
            hpke_public_key: [5; 32],
            member_proof: None,
        },
        &sk(1),
    ))
    .unwrap();

    assert!(chain_ok, "chain.rs accepts a founder-signed co-owner add");
    assert!(keyeo_has(&k, "erin"), "keyeo adds the co-owner");
}

#[test]
fn a_co_owner_adds_an_ordinary_member_agrees() {
    // Ordinary change (signer set unchanged) signed by a co-owner: both accept.
    let cast = [founder(), co_owner(2, "bob")];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            k.members.push(keyed_member(&sk(3), "carol", EDITOR));
            k.epochs[0].wraps.push(wrap("carol", HPKE));
        },
        &[2], // co-owner bob signs
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op(
        [2u8; 32],
        vec![],
        "bob",
        MembershipAction::Add {
            member: "carol".into(),
            role: KeyringRole::EDITOR,
            author_public_key: pk32(&sk(3)),
            hpke_public_key: [3; 32],
            member_proof: None,
        },
        &sk(2),
    ))
    .unwrap();

    assert!(chain_ok, "chain.rs accepts a co-owner-signed ordinary add");
    assert!(keyeo_has(&k, "carol"), "keyeo adds the ordinary member");
}

#[test]
fn a_non_signer_cannot_write_agrees() {
    // dave is a keyed Maintainer member but NOT a signer. His attempt to add a member is rejected by
    // chain.rs (UnendorsedOrdinaryChange) and is a no-op in keyeo (unauthorized). Both: carol absent.
    let cast = [founder(), plain(4, "dave", MAINTAINER)];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            k.members.push(keyed_member(&sk(3), "carol", EDITOR));
            k.epochs[0].wraps.push(wrap("carol", HPKE));
        },
        &[4], // dave (a non-signer) signs
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op(
        [2u8; 32],
        vec![],
        "dave",
        MembershipAction::Add {
            member: "carol".into(),
            role: KeyringRole::EDITOR,
            author_public_key: pk32(&sk(3)),
            hpke_public_key: [3; 32],
            member_proof: None,
        },
        &sk(4),
    ))
    .unwrap();

    assert!(!chain_ok, "chain.rs rejects a non-signer's change");
    assert!(!keyeo_has(&k, "carol"), "keyeo: a non-signer's add has no effect");
}

#[test]
fn founder_cannot_self_remove_agrees() {
    // Removing the sole founder empties the founder slot → chain.rs check_structure rejects; keyeo
    // forbids the Owner leaving. Both: the founder remains.
    let cast = [founder()];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            // Removing the owner member removes the derived founder signer too.
            k.members.retain(|m| m.member_id != "owner");
            k.epochs[0].wraps.retain(|w| w.member_id != "owner");
        },
        &[1],
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], "owner", MembershipAction::Remove { member: "owner".into() }, &sk(1)))
        .unwrap();

    assert!(!chain_ok, "chain.rs rejects removing the sole founder");
    assert!(keyeo_has(&k, "owner"), "keyeo: the Owner cannot self-remove");
}

// ────────────────────────────── RECOVERY (OPE-269) ──────────────────────────────

#[test]
fn recovery_re_establishes_the_owner_in_both_and_preserves_membership() {
    // OUTCOME parity: a recovery re-founds the Owner under a fresh key while keeping every other member.
    // chain.rs does it with verify_reset (a self-signed re-founding keyring); keyeo with an RVK-signed
    // ReFound (a minimal delta). Different mechanisms, same result — the Q5 convergence claim.
    let new_owner = 7u8; // the recovered Owner's fresh identity

    // chain.rs: a reset keyring whose Owner is re-keyed to `new_owner`, self-signed by that new key.
    let reset_cast = [
        Cast { seed: new_owner, id: "owner", member_role: MEMBER_OWNER },
        co_owner(2, "bob"),
    ];
    let reset = chain_genesis(&reset_cast); // chain_genesis self-signs with cast[0] = the new Owner key
    let chain_anchor = verify_reset(None, &reset).expect("chain.rs accepts a self-signed re-founding");
    assert_eq!(chain_anchor.revision, 1);
    let chain_owner_key = reset
        .members
        .iter()
        .find(|m| m.member_id == "owner")
        .unwrap()
        .author_public_key
        .clone();
    assert_eq!(chain_owner_key, pubv(&sk(new_owner)), "chain: Owner re-keyed");
    assert!(reset.members.iter().any(|m| m.member_id == "bob"), "chain: bob preserved");

    // keyeo: the same recovery as an RVK-signed ReFound over the original cast.
    let rvk = recovery::derive_rvk(&[42u8; 32]);
    let mut k = keyeo_engine_with_rvk(&[founder(), co_owner(2, "bob")], rvk.verifying_key().to_bytes());
    k.apply(sign_op(
        [9u8; 32],
        vec![],
        "owner",
        MembershipAction::ReFound {
            member: "owner".into(),
            new_author_public_key: pk32(&sk(new_owner)),
            new_hpke_public_key: [new_owner; 32],
            era: 1,
        },
        &rvk,
    ))
    .unwrap();

    // Parity of outcome: both re-key the Owner to the same fresh identity and keep bob.
    assert_eq!(keyeo_owner_key(&k), pk32(&sk(new_owner)), "keyeo: Owner re-keyed to the same identity");
    assert_eq!(keyeo_owner_key(&k).to_vec(), chain_owner_key, "the recovered Owner key agrees across both");
    assert!(keyeo_has(&k, "bob"), "keyeo: bob preserved");
}

#[test]
fn keyeo_reset_requires_the_recovery_authority_where_chain_accepts_a_self_signed_reset() {
    // The Q5 INTENTIONAL divergence, made concrete. The identical self-signed re-founding shape that
    // chain.rs verify_reset ACCEPTS (its trust rests on an out-of-band ceremony) is REJECTED by keyeo
    // unless it carries the pinned recovery authority (RVK) — keyeo's gate is strictly stronger, which is
    // why, when the chain is retired, verify_reset's callers migrate to the RVK-gated path.
    let new_owner = 7u8;

    // chain.rs accepts a reset self-signed by the new Owner key (no RVK anywhere).
    let reset_cast = [
        Cast { seed: new_owner, id: "owner", member_role: MEMBER_OWNER },
    ];
    assert!(
        verify_reset(None, &chain_genesis(&reset_cast)).is_ok(),
        "chain.rs accepts a self-signed reset with no recovery-authority binding"
    );

    // keyeo: the same shape — a ReFound self-signed by the new Owner key (sk(7)), NOT the RVK — is
    // admitted but carries no authority, so the Owner is unchanged.
    let rvk = recovery::derive_rvk(&[42u8; 32]);
    let mut k = keyeo_engine_with_rvk(&[founder()], rvk.verifying_key().to_bytes());
    k.apply(sign_op(
        [9u8; 32],
        vec![],
        "owner",
        MembershipAction::ReFound {
            member: "owner".into(),
            new_author_public_key: pk32(&sk(new_owner)),
            new_hpke_public_key: [new_owner; 32],
            era: 1,
        },
        &sk(new_owner), // self-signed by the new key, NOT the RVK
    ))
    .unwrap();
    assert_eq!(
        keyeo_owner_key(&k),
        pk32(&sk(1)),
        "keyeo: a reset not signed by the pinned recovery authority has no effect (strictly stronger)"
    );
}

// ────────────────────────────── DOCUMENTED DIVERGENCE ──────────────────────────────

#[test]
fn ordinary_self_removal_is_the_documented_v1_widen() {
    // An ordinary member self-removing: chain.rs treats it as an ordinary change needing a SIGNER's
    // endorsement (the member's own key isn't a signer) → REJECT. keyeo v1 deliberately WIDENS this:
    // any non-Owner may self-remove (BYO/offline). Asserted as an EXPECTED divergence (decision B.2).
    let cast = [founder(), plain(6, "ed", EDITOR)];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            k.members.retain(|m| m.member_id != "ed");
            k.epochs[0].wraps.retain(|w| w.member_id != "ed");
        },
        &[6], // ed signs their own removal — but ed is not a signer
    );
    let chain_rejects = verify_transition(&anchor, &cand).is_err();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], "ed", MembershipAction::Remove { member: "ed".into() }, &sk(6)))
        .unwrap();
    let keyeo_removed = !keyeo_has(&k, "ed");

    assert!(chain_rejects, "chain.rs requires a signer to endorse an ordinary member's removal");
    assert!(keyeo_removed, "keyeo v1 widens self-removal to any non-Owner");
}
