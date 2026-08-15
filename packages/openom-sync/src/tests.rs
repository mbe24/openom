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
