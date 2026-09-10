//! Self-contained proof the generic loop works with a trivial engine: a grow-only set of lines.
//! Convergence + compaction + bootstrap, no domain types.

use super::*;
use store_log::memory::MemoryStore;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;

/// A grow-only set of strings — the simplest commutative/idempotent engine.
#[derive(Default)]
struct GrowSet {
    lines: BTreeSet<String>,
}

impl Engine for GrowSet {
    type Edit = String;
    type Error = Infallible;

    fn apply_local(&mut self, edit: String) -> Vec<u8> {
        if self.lines.insert(edit.clone()) {
            edit.into_bytes() // one line = one delta
        } else {
            Vec::new() // already present ⇒ no-op
        }
    }

    fn merge(&mut self, delta: &[u8]) -> std::result::Result<(), Infallible> {
        if !delta.is_empty() {
            self.lines.insert(String::from_utf8_lossy(delta).into_owned());
        }
        Ok(())
    }

    fn snapshot(&self) -> Vec<u8> {
        self.lines.iter().cloned().collect::<Vec<_>>().join("\n").into_bytes()
    }

    fn merge_snapshot(&mut self, bytes: &[u8]) -> std::result::Result<(), Infallible> {
        for l in String::from_utf8_lossy(bytes).split('\n').filter(|s| !s.is_empty()) {
            self.lines.insert(l.to_string());
        }
        Ok(())
    }
}

fn client(store: Arc<MemoryStore>) -> SyncClient<GrowSet, PassthroughSealer, Arc<MemoryStore>> {
    SyncClient::new(GrowSet::default(), PassthroughSealer, store, "doc")
}

#[test]
fn two_replicas_converge_and_a_third_bootstraps() {
    let store = Arc::new(MemoryStore::new());
    let mut a = client(store.clone());
    let mut b = client(store.clone());

    // Concurrent edits on two replicas, interleaved pulls.
    a.apply("alpha".into()).unwrap();
    b.apply("beta".into()).unwrap();
    a.pull().unwrap();
    b.pull().unwrap();
    a.apply("gamma".into()).unwrap();
    a.pull().unwrap();
    b.pull().unwrap();

    let expected: BTreeSet<String> = ["alpha", "beta", "gamma"].iter().map(|s| s.to_string()).collect();
    assert_eq!(a.engine().lines, expected);
    assert_eq!(b.engine().lines, expected, "two replicas converge");

    // Compact to a snapshot, add a tail delta, then a fresh replica bootstraps
    // from snapshot + tail and matches.
    a.compact().unwrap();
    a.apply("delta".into()).unwrap();

    let mut c = client(store.clone());
    c.bootstrap().unwrap();
    let mut expected2 = expected.clone();
    expected2.insert("delta".into());
    assert_eq!(c.engine().lines, expected2, "bootstrap = snapshot + tail");

    // Re-pulling one's own pushes is a no-op (idempotent).
    let n = a.pull().unwrap();
    a.pull().unwrap();
    assert!(a.engine().lines.contains("delta"));
    let _ = n;
}

#[test]
fn snapshot_policy_triggers_compaction_by_length() {
    let store = Arc::new(MemoryStore::new());
    let mut a = client(store.clone());
    a.apply("one".into()).unwrap();
    a.apply("two".into()).unwrap();
    a.apply("three".into()).unwrap();
    a.pull().unwrap(); // advance the length view to 3

    // Below threshold: 3 >= 4 is false → no compaction.
    assert_eq!(a.maybe_compact(&EveryNUpdates(4)).unwrap(), None);
    // At threshold: compacts, covering seq 3.
    assert_eq!(a.maybe_compact(&EveryNUpdates(3)).unwrap(), Some(3));
    // Nothing new accrued since → no second compaction.
    assert_eq!(a.maybe_compact(&EveryNUpdates(3)).unwrap(), None);

    // A fresh replica bootstraps from the policy-made snapshot.
    let mut c = client(store.clone());
    c.bootstrap().unwrap();
    let expected: BTreeSet<String> = ["one", "two", "three"].iter().map(|s| s.to_string()).collect();
    assert_eq!(c.engine().lines, expected, "bootstrap from the policy-made snapshot");
}

// --- BlobSyncClient (OPE-397): the BlobStore-native, per-replica-frontier delta path ---

use store_blob::MemoryBlob;

fn blob_client(
    store: Arc<MemoryBlob>,
    replica: &str,
) -> BlobSyncClient<GrowSet, PassthroughSealer, Arc<MemoryBlob>> {
    BlobSyncClient::new(GrowSet::default(), PassthroughSealer, store, "doc", replica)
}

#[test]
fn blob_two_replicas_converge_over_one_store_no_server() {
    // Two SyncClients over ONE shared MemoryBlob — the contract-freezing proof, no server present.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    let mut b = blob_client(store.clone(), "replica-B");

    // Concurrent edits on two replicas, interleaved pulls.
    a.apply("alpha".into()).unwrap();
    b.apply("beta".into()).unwrap();
    a.pull().unwrap();
    b.pull().unwrap();
    a.apply("gamma".into()).unwrap();
    a.pull().unwrap();
    b.pull().unwrap();

    let expected: BTreeSet<String> =
        ["alpha", "beta", "gamma"].iter().map(|s| s.to_string()).collect();
    assert_eq!(a.engine().lines, expected);
    assert_eq!(b.engine().lines, expected, "two replicas converge over the blob store, no server");

    // The inbound frontier reflects both replicas' entry counts (A: alpha+gamma=2, B: beta=1).
    assert_eq!(b.frontier().get("replica-A").copied(), Some(2));
    assert_eq!(b.frontier().get("replica-B").copied(), Some(1));
}

#[test]
fn blob_fresh_replica_pulls_all_history() {
    // A third replica with an empty frontier pulls the whole per-replica keyspace and converges.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    let mut b = blob_client(store.clone(), "replica-B");
    a.apply("one".into()).unwrap();
    b.apply("two".into()).unwrap();
    a.apply("three".into()).unwrap();

    let mut c = blob_client(store.clone(), "replica-C");
    c.pull().unwrap();
    let expected: BTreeSet<String> = ["one", "two", "three"].iter().map(|s| s.to_string()).collect();
    assert_eq!(c.engine().lines, expected, "a fresh replica pulls all history from the keyspace");

    // Re-pulling is an idempotent no-op — nothing past the advanced frontier.
    assert_eq!(c.pull().unwrap(), 0, "re-pull merges nothing new");
}

#[test]
fn blob_own_pushes_are_not_refetched() {
    // Pushing advances the self-frontier, so pull() never re-merges this replica's own deltas.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("x".into()).unwrap();
    a.apply("y".into()).unwrap();
    assert_eq!(a.pull().unwrap(), 0, "own entries are already seen");
    assert_eq!(a.frontier().get("replica-A").copied(), Some(2));
}

#[test]
fn blob_bootstrap_from_snapshot_plus_tail() {
    // A snapshot covers a per-replica FRONTIER (carried inside the sealed body); a fresh replica adopts it
    // and pulls only the tail past it.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("one".into()).unwrap();
    a.apply("two".into()).unwrap();
    a.compact().unwrap(); // snapshot covers {replica-A: 2}
    a.apply("three".into()).unwrap(); // tail delta A:2, past the snapshot

    let mut c = blob_client(store.clone(), "replica-C");
    c.bootstrap().unwrap();
    let expected: BTreeSet<String> = ["one", "two", "three"].iter().map(|s| s.to_string()).collect();
    assert_eq!(c.engine().lines, expected, "bootstrap = snapshot + tail");
    // The covered frontier (A:2) was adopted, then the tail (A:2) pulled → A:3.
    assert_eq!(c.frontier().get("replica-A").copied(), Some(3));
}

#[test]
fn blob_bootstrap_covers_multiple_replicas() {
    // The covered frontier spans every replica the snapshotting client had folded.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    let mut b = blob_client(store.clone(), "replica-B");
    a.apply("a1".into()).unwrap();
    b.apply("b1".into()).unwrap();
    a.pull().unwrap(); // a now holds {A:1, B:1}
    a.compact().unwrap(); // snapshot covers {A:1, B:1}
    b.apply("b2".into()).unwrap(); // tail past the snapshot

    let mut c = blob_client(store.clone(), "replica-C");
    c.bootstrap().unwrap();
    let expected: BTreeSet<String> = ["a1", "b1", "b2"].iter().map(|s| s.to_string()).collect();
    assert_eq!(c.engine().lines, expected, "bootstrap adopts a multi-replica covered frontier + tail");
    assert_eq!(c.frontier().get("replica-A").copied(), Some(1));
    assert_eq!(c.frontier().get("replica-B").copied(), Some(2));
}

#[test]
fn blob_verified_pull_holds_then_drains() {
    // The §B3 crux: a peer delta the classifier can't verify YET is HELD (not merged, frontier still
    // advances), then folded on a later pull once it verifies — e.g. after the author's membership op lands.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("secret".into()).unwrap();

    let no_cover = |_b: &[u8], _r: &str, _c: u64| {};
    let mut b = blob_client(store.clone(), "replica-B");
    let merged = b
        .pull_verified(
            |_env, _pt, replica, _c| {
                if replica == "replica-A" { Verdict::Hold } else { Verdict::Accept }
            },
            no_cover,
        )
        .unwrap();
    assert_eq!(merged, 0, "the held delta is not merged");
    assert_eq!(b.held_count(), 1, "it is parked as held");
    assert!(!b.engine().lines.contains("secret"), "not folded while held");
    assert_eq!(b.frontier().get("replica-A").copied(), Some(1), "the frontier still advanced past it");

    // A membership op has since arrived → the same dot now verifies; the drain folds it.
    let merged = b
        .pull_verified(|_env, _pt, _replica, _c| Verdict::Accept, no_cover)
        .unwrap();
    assert_eq!(merged, 1, "the drain merges the un-held delta");
    assert_eq!(b.held_count(), 0);
    assert!(b.engine().lines.contains("secret"), "folded after un-hold");
}

#[test]
fn blob_verified_pull_reject_is_final() {
    // A rejected (forged / unattributed) delta is dropped, not held, and the frontier advances past it — a
    // later accept-all pull never re-offers it.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("forged".into()).unwrap();

    let no_cover = |_b: &[u8], _r: &str, _c: u64| {};
    let mut b = blob_client(store.clone(), "replica-B");
    assert_eq!(b.pull_verified(|_e, _p, _r, _c| Verdict::Reject, no_cover).unwrap(), 0);
    assert_eq!(b.held_count(), 0, "rejected, not held");
    assert!(!b.engine().lines.contains("forged"));
    assert_eq!(
        b.pull_verified(|_e, _p, _r, _c| Verdict::Accept, no_cover).unwrap(),
        0,
        "a reject is final — the frontier advanced, so it is not re-offered"
    );
    assert!(!b.engine().lines.contains("forged"));
}

#[test]
fn blob_mirror_two_local_stores_converge_through_a_remote() {
    // The production topology: each device runs BlobSyncClient over its OWN local store; a shared remote is
    // reached only by the mirror. Prove two replicas on SEPARATE local stores converge through the remote.
    let local_a = Arc::new(MemoryBlob::new());
    let local_b = Arc::new(MemoryBlob::new());
    let remote = Arc::new(MemoryBlob::new());
    let mut a = blob_client(local_a.clone(), "replica-A");
    let mut b = blob_client(local_b.clone(), "replica-B");

    a.apply("x".into()).unwrap();
    b.apply("y".into()).unwrap();

    // Push each local up to the remote, then pull the remote down to each local (both directions).
    mirror(local_a.as_ref(), remote.as_ref(), "doc").unwrap();
    mirror(local_b.as_ref(), remote.as_ref(), "doc").unwrap();
    mirror(remote.as_ref(), local_a.as_ref(), "doc").unwrap();
    mirror(remote.as_ref(), local_b.as_ref(), "doc").unwrap();

    // Each client now folds its own local store (which the mirror filled with the peer's entries).
    a.pull().unwrap();
    b.pull().unwrap();

    let expected: BTreeSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
    assert_eq!(a.engine().lines, expected);
    assert_eq!(b.engine().lines, expected, "separate local stores converge via a remote object mirror");

    // Mirroring again is an idempotent no-op (everything already present).
    assert_eq!(mirror(remote.as_ref(), local_a.as_ref(), "doc").unwrap(), 0);
}

#[test]
fn blob_verified_pull_folds_a_cover_that_un_holds_a_delta() {
    // The self-heal case: an unattributed delta is HELD; a Cover marker blessing it folds into the caller's
    // covered set; the next drain re-classifies the delta as covered → Accept. Proves covers route through
    // pull_verified (never merged as claims, never held) and drive the hold/drain the same way membership does.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("blessed".into()).unwrap(); // A:0 — an (initially) unattributed delta
    a.push_cover(b"cover-for-blessed").unwrap(); // A:1 — a cover blessing it

    let covered = std::cell::RefCell::new(false);
    let classify = |_env: &[u8], pt: &[u8], _r: &str, _c: u64| {
        // Hold the "blessed" delta until a cover for it has folded; accept anything else.
        if pt == b"blessed" && !*covered.borrow() { Verdict::Hold } else { Verdict::Accept }
    };
    let fold_cover = |body: &[u8], _r: &str, _c: u64| {
        if body == b"cover-for-blessed" {
            *covered.borrow_mut() = true;
        }
    };

    let mut b = blob_client(store.clone(), "replica-B");
    // Pass 1: the delta is scanned before its cover, so it holds; the cover then folds (covered = true).
    let merged = b.pull_verified(classify, fold_cover).unwrap();
    assert_eq!(merged, 0, "the unattributed delta holds this tick");
    assert_eq!(b.held_count(), 1);
    assert!(*covered.borrow(), "the cover folded (routed, not merged, not held)");
    assert!(!b.engine().lines.contains("blessed"));

    // Pass 2: the drain re-classifies the held delta — now covered → Accept.
    let merged = b.pull_verified(classify, fold_cover).unwrap();
    assert_eq!(merged, 1, "the cover un-holds the delta on the next drain");
    assert_eq!(b.held_count(), 0);
    assert!(b.engine().lines.contains("blessed"), "the blessed delta is folded once covered");
}
