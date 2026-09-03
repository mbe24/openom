//! Feature-parity capability matrix: the linear chain keyring (openom-keyring / chain.rs) vs the DAG
//! keyring (openom-keyring-dag / keyeo), across both backend classes (OPE-267).
//!
//! The honest answer to "what does each version actually offer" is a MATRIX, not prose. Both keyrings
//! ride the same `blobstore::Blob` seam, so the backend axis is {managed-CAS, BYO-dumb} — and because
//! the seam is the weakest-common-denominator (per-object CAS + list), every capability below behaves
//! IDENTICALLY on both backend classes for a given keyring; a managed backend only *prevents* below the
//! seam what a BYO backend can merely *detect* (the anti-rollback row). So the matrix's live axis is the
//! keyring, and the backend axis collapses to one behavioural note (rollback: prevent vs detect).
//!
//! ```text
//! capability                          | chain (CAS/linear)          | dag (keyeo)                | proven in
//! ------------------------------------+-----------------------------+----------------------------+------------------------
//! membership: add/remove/change role  | ✅                          | ✅                         | differential.rs
//! governance: founder-signed          | ✅                          | ✅                         | keyring.rs / lib.rs
//! governance: founder-or-unanimity    | ✅ (verify_keyring_all)     | ✅ (KeyringQuorum)         | keyring.rs / lib.rs
//! governance: threshold m-of-n        | ✅ (verify_keyring_threshold)| ✅ (QuorumRule::Threshold)| chain.rs / lib.rs
//! recovery: provision / recover       | ✅ (verify_reset)           | ✅ (RVK-gated ReFound)     | differential.rs
//!   └ authorization strength          | self-signed + OOB ceremony  | RVK-signed (STRICTLY >)    | differential.rs
//! recovery: rotate recovery authority | ⚠️ RRK re-wrap only (no     | ✅ (RotateRecoveryAuthority| lib.rs (OPE-272)
//!                                      |    keypair rotation in v1)  |    revokes prior holder)   |
//! recovery: change-passphrase         | ✅ (re-wrap DEK)            | ⏳ sealer-integration      | OPE-273 (deferred)
//! concurrency: non-conflicting edits  | ⚠️ CAS serializes; loser    | ✅ MERGES both            | THIS FILE + blob_sync.rs
//!                                      |    safely re-proposes       |    deterministically       |
//! concurrency: conflicting (mutual)   | n/a (signer-gated,          | n/a for openom keyring     | keyeo integration.rs
//!                                      |     serialized)             | (generic keyeo: 1-survivor)|
//! concurrency: multi-signer N-of-M    | ⚠️ draft-exchange; a        | ✅ quorum merges           | blob_sync (chain) / lib.rs
//!   collection under concurrency      |    competing rev = re-propose|    across a fork           |
//! anti-rollback                       | ✅ revision+prev_hash       | ✅ op-set monotonicity     | chain.rs / blob_sync.rs
//!   └ managed vs BYO backend          | prevent (server) / detect   | prevent (server) / detect  | (backend note above)
//! ```
//!
//! Rows already covered by `differential.rs` (membership, governance parity, recovery parity + the
//! authorization-strength divergence) and by the crate suites (governance, anti-rollback withholding) are
//! not duplicated here. THIS file adds the concurrency axis — the DAG's signature capability the linear
//! chain structurally cannot offer — as executable assertions, so the ✅/⚠️ cells above are backed by
//! tests, not claims.

use keyeo_dag::{Keyeo, MemberInit, MembershipAction, StrongRemove};
use openom_keyring_dag::{
    sign_op, KeyringAccess, KeyringEngine, KeyringMemberInit, KeyringRole, KeyringState,
};
use edsign::SigningKey;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32])
}
fn pk32(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn minit(id: &str, role: KeyringRole, seed: u8) -> KeyringMemberInit {
    MemberInit {
        id: id.to_string(),
        role,
        author_public_key: pk32(&sk(seed)),
        hpke_public_key: [seed; 32],
    }
}
fn engine(members: &[KeyringMemberInit]) -> KeyringEngine {
    Keyeo::new(KeyringState::create(keyeo_dag::GroupId::unscoped(), members), KeyringAccess, StrongRemove)
}
fn add(member: &str, role: KeyringRole, seed: u8) -> MembershipAction<String, KeyringRole, openom_keyring_dag::Ed25519> {
    MembershipAction::Add {
        member: member.to_string(),
        role,
        author_public_key: pk32(&sk(seed)),
        hpke_public_key: [seed; 32],
        member_proof: None,
    }
}
fn has(k: &KeyringEngine, id: &str) -> bool {
    k.state().active_members().iter().any(|(m, _)| m == id)
}

/// Concurrency row (non-conflicting): two co-owners, offline on different branches, each add a DIFFERENT
/// ordinary member — a genuine fork. The DAG merges both branches deterministically and keeps both adds.
/// This is the row the linear chain cannot match: its single-head CAS serializes the two writes, so the
/// second writer's revision is stale and must be rebuilt + re-proposed (safe, but not a merge).
#[test]
fn dag_merges_non_conflicting_concurrent_edits_where_the_chain_would_serialize() {
    let cast = [
        minit("founder", KeyringRole::OWNER, 1),
        minit("bob", KeyringRole::CO_OWNER, 2),
        minit("carol", KeyringRole::CO_OWNER, 3),
    ];
    // Two engines diverge from the same genesis, each learning one side of the fork, then exchange.
    let mut ea = engine(&cast);
    let mut eb = engine(&cast);
    let g = sign_op(
        [1; 32],
        vec![],
        "founder",
        MembershipAction::Create { initial_members: cast.to_vec() },
        &sk(1),
    );
    ea.apply(g.clone()).unwrap();
    eb.apply(g.clone()).unwrap();

    // bob adds dave on A; carol adds erin on B — concurrent children of genesis, different authors.
    let dave = sign_op([2; 32], vec![[1; 32]], "bob", add("dave", KeyringRole::EDITOR, 4), &sk(2));
    let erin = sign_op([3; 32], vec![[1; 32]], "carol", add("erin", KeyringRole::EDITOR, 5), &sk(3));
    ea.apply(dave.clone()).unwrap();
    eb.apply(erin.clone()).unwrap();
    // exchange the other side of the fork
    ea.apply(erin).unwrap();
    eb.apply(dave).unwrap();

    for e in [&ea, &eb] {
        assert!(has(e, "dave") && has(e, "erin"), "the DAG merges both concurrent adds — neither is lost");
    }
    assert_eq!(ea.state().active_members(), eb.state().active_members(), "and both replicas converge");
}

/// Concurrency row (multi-signer under a fork): a quorum threshold is met by approvals that arrive on a
/// FORK — the proposer proposes on one branch, an approver approves on a concurrent branch, and the DAG
/// still tallies them once merged. The chain's draft-exchange can collect the same signatures but a
/// competing head revision forces a re-propose; the DAG merges the approvals across the fork.
#[test]
fn dag_tallies_quorum_approvals_that_arrive_on_a_fork() {
    use openom_keyring_dag::{KeyringQuorum, KeyringQuorumEngine};
    let cast = [
        minit("founder", KeyringRole::OWNER, 1),
        minit("bob", KeyringRole::CO_OWNER, 2),
        minit("carol", KeyringRole::CO_OWNER, 3),
        minit("ed", KeyringRole::EDITOR, 6),
    ];
    let mut k: KeyringQuorumEngine = Keyeo::with_quorum(
        KeyringState::create(keyeo_dag::GroupId::unscoped(), &cast),
        KeyringAccess,
        StrongRemove,
        KeyringQuorum::threshold(3),
    );
    let sign = |id: u8, parents: Vec<[u8; 32]>, author: &str, seed: u8, act| {
        sign_op([id; 32], parents, author, act, &sk(seed))
    };
    k.apply(sign(1, vec![], "founder", 1, MembershipAction::Create { initial_members: cast.to_vec() }))
        .unwrap();
    let promote = MembershipAction::ChangeRole { member: "ed".into(), new_role: KeyringRole::CO_OWNER };
    // propose on the main line, then TWO approvals on concurrent branches off the proposal.
    k.apply(sign(2, vec![[1; 32]], "bob", 2, MembershipAction::Propose { proposal_id: [7; 32], target: Box::new(promote) })).unwrap();
    k.apply(sign(3, vec![[2; 32]], "carol", 3, MembershipAction::Approve { proposal_id: [7; 32] })).unwrap();
    k.apply(sign(4, vec![[2; 32]], "founder", 1, MembershipAction::Approve { proposal_id: [7; 32] })).unwrap();
    // commit references both concurrent approvals in its causal past.
    k.apply(sign(5, vec![[3; 32], [4; 32]], "bob", 2, MembershipAction::Commit { proposal_id: [7; 32] })).unwrap();

    assert_eq!(
        k.state().members.get("ed").filter(|m| m.is_active()).map(|m| m.role),
        Some(KeyringRole::CO_OWNER),
        "3-of-4 approvals arriving across a fork are tallied and the promotion takes effect"
    );
}
