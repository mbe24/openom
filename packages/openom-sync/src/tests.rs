//! Two devices, one shared store + DEK, editing concurrently and syncing — end to end through
//! treelog → sealer (E2EE) → store → sealer → treelog. Convergence is inherited all the way down.

use super::*;
use openom_crypto::generate_dek;
use openom_sealer::Sealer;
use openom_store::memory::MemoryStore;
use openom_treelog::{Pedigree, Tree, TreeOp};
use std::sync::Arc;

fn rid(i: u8) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[0] = i;
    r
}

fn client(replica: u8, sealer_replica: &[u8], dek: openom_crypto::Key32, store: Arc<MemoryStore>) -> SyncClient<Arc<MemoryStore>> {
    let sealer = Sealer::from_unwrapped(1, dek, b"tree-uuid-16byte".to_vec(), b"epoch-0".to_vec(), sealer_replica.to_vec());
    SyncClient::new(Tree::new(rid(replica)), sealer, store, "tree")
}

#[test]
fn two_devices_converge_through_the_full_stack() {
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut a = client(1, b"replica-a", dek.clone(), store.clone());
    let mut b = client(2, b"replica-b", dek, store.clone());

    // Concurrent edits on both devices (each pushes its sealed delta to the shared log).
    a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
    a.apply(TreeOp::AddClaim { person: vec![1], field: "birth.date".into(), claim: vec![9], value: "1901".into(), source: Some("parish".into()) }).unwrap();
    b.apply_batch(vec![
        TreeOp::AddFamily { id: vec![0xF0] },
        TreeOp::LinkChild { family: vec![0xF0], person: vec![1], pedi: Pedigree::Birth },
    ])
    .unwrap();

    // Each device pulls the other's work.
    a.pull().unwrap();
    b.pull().unwrap();

    // Byte-identical convergence, and each sees the other's edits.
    assert_eq!(a.tree().doc().snapshot(), b.tree().doc().snapshot());
    assert!(a.tree().has_person(&[1]));
    assert_eq!(a.tree().families(), vec![vec![0xF0]]);
    assert_eq!(b.tree().fact(&[1], "birth.date").preferred.unwrap().value, "1901");
    assert_eq!(b.tree().children_of(&[0xF0]), vec![(vec![1], Pedigree::Birth)]);
}

#[test]
fn a_second_round_of_edits_syncs_and_pull_is_idempotent() {
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut a = client(1, b"replica-a", dek.clone(), store.clone());
    let mut b = client(2, b"replica-b", dek, store.clone());

    a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
    b.pull().unwrap();
    // A second round: B edits, A catches up.
    b.apply(TreeOp::AddClaim { person: vec![1], field: "name.given".into(), claim: vec![7], value: "Mary".into(), source: None }).unwrap();
    a.pull().unwrap();
    assert_eq!(a.tree().doc().snapshot(), b.tree().doc().snapshot());

    // Pulling again with nothing new changes nothing.
    let before = a.tree().doc().snapshot();
    assert_eq!(a.pull().unwrap(), 0);
    assert_eq!(a.tree().doc().snapshot(), before);
}

#[test]
fn a_proposal_travels_through_the_store_and_is_approved() {
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut owner = client(1, b"replica-o", dek.clone(), store.clone());
    let mut editor = client(2, b"replica-e", dek, store.clone());

    // Owner creates a person; editor syncs it.
    owner.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
    editor.pull().unwrap();

    // Editor drafts + pushes a proposal — NOT applied to its own tree.
    let drafted = editor
        .push_proposal(vec![TreeOp::AddClaim { person: vec![1], field: "birth.date".into(), claim: vec![9], value: "1901".into(), source: Some("record".into()) }])
        .unwrap();
    assert!(editor.tree().fact(&[1], "birth.date").claims.is_empty(), "a proposal is not applied locally");

    // Owner pulls the proposal, reviews it (no conflict), approves.
    let pending = owner.pull_proposals().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0], drafted);
    let review = owner.tree().review(&pending[0]);
    assert!(review.conflicts.is_empty());
    assert_eq!(review.changes.len(), 1);
    owner.commit_proposal(&pending[0]).unwrap();

    // Editor pulls the committed result; both converge with the claim present.
    editor.pull().unwrap();
    assert_eq!(owner.tree().doc().snapshot(), editor.tree().doc().snapshot());
    assert_eq!(editor.tree().fact(&[1], "birth.date").preferred.unwrap().value, "1901");
    // The proposal lived only in its own channel, never on the tree's append log.
    assert_eq!(store.read_updates("tree:proposals", None).unwrap().0.len(), 1);
    assert_eq!(store.read_updates("tree", None).unwrap().0.len(), 2, "person add + approved claim only");
}

#[test]
fn a_crashed_client_rebuilds_its_tree_from_the_durable_log() {
    // The tree is not separately durable — it is derived from the sealed log. A crash (the in-memory
    // client vanishing) loses nothing that was pushed: a fresh client replays the log and recovers.
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let before = {
        let mut a = client(1, b"replica-a", dek.clone(), store.clone());
        a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
        a.apply_batch(vec![
            TreeOp::AddFamily { id: vec![0xF0] },
            TreeOp::LinkChild { family: vec![0xF0], person: vec![1], pedi: Pedigree::Birth },
        ])
        .unwrap();
        a.apply(TreeOp::AddClaim { person: vec![1], field: "name.given".into(), claim: vec![7], value: "Ada".into(), source: None }).unwrap();
        a.tree().doc().snapshot()
        // a drops here — the crash.
    };

    let mut restarted = client(1, b"replica-a", dek, store.clone());
    restarted.pull().unwrap();
    assert_eq!(restarted.tree().doc().snapshot(), before, "the tree is fully recovered from the durable log");
}

#[test]
fn a_wrong_key_cannot_open_the_log() {
    // A device with a different DEK pulls the same log — the sealer refuses to open it.
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut a = client(1, b"replica-a", dek, store.clone());
    a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();

    let wrong = generate_dek().unwrap();
    let mut intruder = client(9, b"replica-x", wrong, store.clone());
    assert!(intruder.pull().is_err(), "a wrong DEK must not decrypt the log");
}
