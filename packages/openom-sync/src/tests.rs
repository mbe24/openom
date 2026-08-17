//! Two devices, one shared store + DEK, editing concurrently and syncing — end to end through
//! treelog → sealer (E2EE) → store → sealer → treelog. Convergence is inherited all the way down.

use super::*;
use openom_crypto::generate_dek;
use openom_sealer::Sealer;
use journal::memory::MemoryStore;
use journal::{Caps, DocStore, Snapshot, StoreError, Update};
use openom_treelog::{Pedigree, Tree, TreeOp};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A store that fails the next `fail_appends` append calls, then behaves normally — to exercise the
/// sync WAL's retry path. Everything else delegates to the wrapped store.
struct FaultStore {
    inner: Arc<MemoryStore>,
    fail_appends: AtomicUsize,
}
impl DocStore for FaultStore {
    fn caps(&self) -> Caps {
        self.inner.caps()
    }
    fn list(&self) -> journal::Result<Vec<String>> {
        self.inner.list()
    }
    fn read_snapshot(&self, doc: &str) -> journal::Result<Option<Snapshot>> {
        self.inner.read_snapshot(doc)
    }
    fn read_updates(&self, doc: &str, since: Option<u64>) -> journal::Result<(Vec<Update>, u64)> {
        self.inner.read_updates(doc, since)
    }
    fn append(&self, doc: &str, updates: &[Update]) -> journal::Result<u64> {
        if self.fail_appends.load(Ordering::SeqCst) > 0 {
            self.fail_appends.fetch_sub(1, Ordering::SeqCst);
            return Err(StoreError::Backend("injected append failure".into()));
        }
        self.inner.append(doc, updates)
    }
    fn put_snapshot(&self, doc: &str, bytes: &[u8], expected: Option<&str>) -> journal::Result<String> {
        self.inner.put_snapshot(doc, bytes, expected)
    }
    fn delete(&self, doc: &str) -> journal::Result<()> {
        self.inner.delete(doc)
    }
}

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
    a.apply(TreeOp::AddClaim { subject: vec![1], field: "birth.date".into(), claim: vec![9], value: "1901".into(), source: Some("parish".into()) }).unwrap();
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
    b.apply(TreeOp::AddClaim { subject: vec![1], field: "name.given".into(), claim: vec![7], value: "Mary".into(), source: None }).unwrap();
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
        .push_proposal(vec![TreeOp::AddClaim { subject: vec![1], field: "birth.date".into(), claim: vec![9], value: "1901".into(), source: Some("record".into()) }])
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
        a.apply(TreeOp::AddClaim { subject: vec![1], field: "name.given".into(), claim: vec![7], value: "Ada".into(), source: None }).unwrap();
        a.tree().doc().snapshot()
        // a drops here — the crash.
    };

    let mut restarted = client(1, b"replica-a", dek, store.clone());
    restarted.pull().unwrap();
    assert_eq!(restarted.tree().doc().snapshot(), before, "the tree is fully recovered from the durable log");
}

#[test]
fn a_fresh_client_bootstraps_from_a_snapshot_plus_the_tail() {
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut a = client(1, b"replica-a", dek.clone(), store.clone());
    a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
    a.apply(TreeOp::AddPerson { id: vec![2] }).unwrap();
    a.compact().unwrap(); // the snapshot covers the two people
                          // A tail edit after the snapshot.
    a.apply(TreeOp::AddClaim { subject: vec![1], field: "birth.date".into(), claim: vec![9], value: "1901".into(), source: None }).unwrap();

    // A fresh client bootstraps: the snapshot (two people) + only the tail (the claim).
    let mut c = client(3, b"replica-c", dek, store.clone());
    c.bootstrap().unwrap();
    assert_eq!(c.tree().doc().snapshot(), a.tree().doc().snapshot());
    assert_eq!(c.tree().persons().len(), 2);
    assert_eq!(c.tree().fact(&[1], "birth.date").preferred.unwrap().value, "1901");
}

#[test]
fn bootstrap_without_a_snapshot_replays_the_whole_log() {
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut a = client(1, b"replica-a", dek.clone(), store.clone());
    a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
    a.apply(TreeOp::AddFamily { id: vec![0xF0] }).unwrap();

    let mut c = client(2, b"replica-c", dek, store.clone());
    c.bootstrap().unwrap(); // no snapshot → full log replay
    assert_eq!(c.tree().doc().snapshot(), a.tree().doc().snapshot());
}

#[test]
fn a_transient_append_failure_queues_and_retries_without_loss() {
    let inner = Arc::new(MemoryStore::new());
    let store = Arc::new(FaultStore { inner, fail_appends: AtomicUsize::new(2) });
    let dek = generate_dek().unwrap();
    let sealer = Sealer::from_unwrapped(1, dek.clone(), b"tree-uuid-16byte".to_vec(), b"epoch-0".to_vec(), b"replica-a".to_vec());
    let mut a = SyncClient::new(Tree::new(rid(1)), sealer, store.clone(), "tree");

    // Two edits while appends are failing → sealed once, queued, not lost.
    assert!(a.apply(TreeOp::AddPerson { id: vec![1] }).is_err());
    assert!(a.apply(TreeOp::AddPerson { id: vec![2] }).is_err());
    assert_eq!(a.pending_count(), 2);

    // Failures exhausted → an explicit flush drains the queue (re-uploading the same sealed bytes).
    a.flush().unwrap();
    assert_eq!(a.pending_count(), 0);

    // A peer over the same store sees both edits and converges.
    let sealer_b = Sealer::from_unwrapped(1, dek, b"tree-uuid-16byte".to_vec(), b"epoch-0".to_vec(), b"replica-b".to_vec());
    let mut b = SyncClient::new(Tree::new(rid(2)), sealer_b, store.clone(), "tree");
    b.pull().unwrap();
    assert_eq!(b.tree().persons().len(), 2);
    assert_eq!(a.tree().doc().snapshot(), b.tree().doc().snapshot());
}

#[test]
fn a_duplicate_appended_delta_is_harmless() {
    // A lost-ack retry can land the same sealed delta twice; commute's idempotent merge absorbs it.
    let store = Arc::new(MemoryStore::new());
    let dek = generate_dek().unwrap();
    let mut a = client(1, b"replica-a", dek.clone(), store.clone());
    a.apply(TreeOp::AddPerson { id: vec![1] }).unwrap();
    // Re-append the existing log entry verbatim (the duplicate).
    let (updates, _) = store.read_updates("tree", None).unwrap();
    store.append("tree", &updates).unwrap();

    let mut b = client(2, b"replica-b", dek, store.clone());
    b.pull().unwrap();
    assert_eq!(b.tree().persons(), vec![vec![1u8]], "the duplicate must not create a second person");
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
