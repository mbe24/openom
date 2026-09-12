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

    let expected: BTreeSet<String> = ["alpha", "beta", "gamma"].iter().map(ToString::to_string).collect();
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
    let expected: BTreeSet<String> = ["one", "two", "three"].iter().map(ToString::to_string).collect();
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
        ["alpha", "beta", "gamma"].iter().map(ToString::to_string).collect();
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
    let expected: BTreeSet<String> = ["one", "two", "three"].iter().map(ToString::to_string).collect();
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
    let expected: BTreeSet<String> = ["one", "two", "three"].iter().map(ToString::to_string).collect();
    assert_eq!(c.engine().lines, expected, "bootstrap = snapshot + tail");
    // The covered frontier (A:2) was adopted, then the tail (A:2) pulled → A:3.
    assert_eq!(c.frontier().get("replica-A").copied(), Some(3));
}

#[test]
fn blob_bootstrap_rejects_an_inflated_covered_frontier_that_would_suppress_a_present_dot() {
    // OPE-421 anti-suppression: a snapshot claiming a replica is covered PAST a still-present dot must not
    // skip that dot. Replica A writes one real dot; a forged snapshot claims covered {A:1} (past it) with
    // empty state. A fresh replica must STILL pull the present dot, not silently drop it.
    // (Pre-fix, `adopt_snapshot_baseline` did `pull_frontier = max(f, claimed)` unconditionally, so the fresh
    // replica's engine came up EMPTY — the suppression this test pins closed.)
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("keep-me".into()).unwrap(); // A:0, present; heads/A = 1

    // Forge a snapshot: covered {A:1} (inflated one past the present A:0) + empty engine state.
    let mut inflated = Frontier::default();
    inflated.insert("replica-A".to_string(), 1);
    let mut body = encode_frontier(&inflated);
    body.extend_from_slice(&GrowSet::default().snapshot()); // empty state — the "poison"
    let ctx = SealCtx {
        kind: EntryKind::Snapshot,
        replica_counter: 0,
        prev_ciphertext_hash: Vec::new(),
        covers_through_seq: 0,
    };
    let mut ps = PassthroughSealer;
    let sealed = ps.seal(&ctx, &body).unwrap();
    store
        .put(&snapshot_key("doc"), &sealed.envelope, store_blob::Precondition::Any)
        .unwrap();

    let mut c = blob_client(store.clone(), "replica-C");
    c.bootstrap().unwrap();
    assert!(
        c.engine().lines.contains("keep-me"),
        "the present dot A:0 must be pulled, not suppressed by the inflated covered frontier"
    );
}

#[test]
fn a_rejected_snapshot_is_overwritten_by_an_honest_recompaction() {
    // OPE-421 self-heal: a client that REJECTS a poisoned snapshot must not let its claimed coverage block an
    // honest re-compaction — it re-publishes the pointer with real state, collapsing the poison window to one
    // sync interval (needs_snapshot_adoption + maybe_compact both stop trusting a rejected pointer's coverage).
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("real-dot".into()).unwrap(); // A:0

    // Forge a poison snapshot: inflated covered {A:5} + a recognizable poison state.
    let mut inflated = Frontier::default();
    inflated.insert("replica-A".to_string(), 5);
    let mut body = encode_frontier(&inflated);
    body.extend_from_slice(b"poison-state");
    let ctx = SealCtx {
        kind: EntryKind::Snapshot,
        replica_counter: 0,
        prev_ciphertext_hash: Vec::new(),
        covers_through_seq: 0,
    };
    let mut ps = PassthroughSealer;
    let sealed = ps.seal(&ctx, &body).unwrap();
    store
        .put(&snapshot_key("doc"), &sealed.envelope, store_blob::Precondition::Any)
        .unwrap();

    // A syncs with a classify_snapshot that REJECTS the poison (as the auth gate would for a bad author).
    let reject_poison = |_e: &[u8], body: &[u8]| {
        if body.ends_with(b"poison-state") { Verdict::Reject } else { Verdict::Accept }
    };
    a.bootstrap_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER, reject_poison)
        .unwrap();
    assert!(a.engine().lines.contains("real-dot"), "the poison did not suppress the real dot");

    // maybe_compact must NOT be fooled by the rejected poison's coverage — it re-compacts, overwriting it.
    assert!(
        a.maybe_compact(&EveryNUpdates(1)).unwrap(),
        "an honest re-compaction overwrote the poisoned pointer"
    );

    // A fresh client now sees an HONEST snapshot (real covered A:1), not the poison's inflated A:5.
    let fresh = blob_client(store.clone(), "replica-Z");
    let covered = fresh.snapshot_covered_frontier().unwrap().unwrap();
    assert_eq!(
        covered.get("replica-A").copied(),
        Some(1),
        "the honest snapshot covers A:1, not the poison's A:5"
    );
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
    let expected: BTreeSet<String> = ["a1", "b1", "b2"].iter().map(ToString::to_string).collect();
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

    let no_cover = |_e: &[u8], _b: &[u8], _r: &str, _c: u64| {};
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

    let no_cover = |_e: &[u8], _b: &[u8], _r: &str, _c: u64| {};
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

    let expected: BTreeSet<String> = ["x", "y"].iter().map(ToString::to_string).collect();
    assert_eq!(a.engine().lines, expected);
    assert_eq!(b.engine().lines, expected, "separate local stores converge via a remote object mirror");

    // Mirroring again is an idempotent no-op (everything already present).
    assert_eq!(mirror(remote.as_ref(), local_a.as_ref(), "doc").unwrap(), 0);
}

#[test]
fn blob_verified_pull_folds_a_cover_before_classifying_the_delta_it_blesses() {
    // The self-heal case, covers-first within a tick: a delta whose author is covered by a Cover marker is
    // accepted in the SAME pull, because every cover in the gap folds BEFORE any delta is classified. This is
    // load-bearing: a since-removed member's delta classifies as Reject (not Hold), so it is NOT retried on a
    // later drain — the cover MUST already have folded when the delta is classified. Here the delta's replica
    // (A) sorts before the cover author's would in a naive inline scan, yet covers-first still blesses it.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("blessed".into()).unwrap(); // A:0 — a delta whose author is (only) legitimized by a cover
    a.push_cover(b"cover-for-blessed").unwrap(); // A:1 — the cover blessing it

    let covered = std::cell::RefCell::new(false);
    let classify = |_env: &[u8], pt: &[u8], _r: &str, _c: u64| {
        // Model a removed-member delta: Reject unless a cover for it has already folded (never Hold).
        if pt == b"blessed" && !*covered.borrow() { Verdict::Reject } else { Verdict::Accept }
    };
    let fold_cover = |_env: &[u8], body: &[u8], _r: &str, _c: u64| {
        if body == b"cover-for-blessed" {
            *covered.borrow_mut() = true;
        }
    };

    let mut b = blob_client(store.clone(), "replica-B");
    // One tick: the cover folds first (covered = true), THEN the delta is classified — now covered → Accept.
    let merged = b.pull_verified(classify, fold_cover).unwrap();
    assert_eq!(merged, 1, "the cover folds before the delta, so the delta is accepted this same tick");
    assert_eq!(b.held_count(), 0, "the delta is never held — it was accepted outright");
    assert!(*covered.borrow(), "the cover folded (routed, not merged, not held)");
    assert!(b.engine().lines.contains("blessed"), "the blessed delta is folded once the cover blesses it");
}

// --- C3 (OPE-409): the SUBSUMED frontier — a compactor may publish only coverage its snapshot actually holds ---

use store_blob::{BlobStore, Precondition};

const NO_COVER: fn(&[u8], &[u8], &str, u64) = |_e, _b, _r, _c| {};

#[test]
fn blob_subsumed_frontier_clamps_to_a_held_dot() {
    // A held dot at A:1 pins subsumed[A]=1 even though pull_frontier advances to 3 (A:2 merged BEHIND the hole).
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();
    a.apply("a1".into()).unwrap();
    a.apply("a2".into()).unwrap();

    let mut b = blob_client(store.clone(), "replica-B");
    b.pull_verified(|_e, _p, _r, c| if c == 1 { Verdict::Hold } else { Verdict::Accept }, NO_COVER)
        .unwrap();

    assert_eq!(b.frontier().get("replica-A").copied(), Some(3), "the fetch frontier advanced past all three");
    assert_eq!(b.held_count(), 1);
    assert_eq!(
        b.subsumed_frontier().get("replica-A").copied(),
        Some(1),
        "subsumed stops at the held hole (A:1), NOT the fetch frontier (3)"
    );
}

#[test]
fn blob_subsumed_frontier_pins_at_a_reject() {
    // The C3 crux: a Rejected dot PINS subsumed (never advances past it), so a compactor can't claim coverage
    // over a dot it never folded. Holds for an ARBITRARY classify — GC safety needs zero trust in it.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();
    a.apply("forged".into()).unwrap(); // A:1
    a.apply("a2".into()).unwrap();

    let mut b = blob_client(store.clone(), "replica-B");
    b.pull_verified(
        |_e, pt, _r, _c| if pt == b"forged" { Verdict::Reject } else { Verdict::Accept },
        NO_COVER,
    )
    .unwrap();

    assert_eq!(b.frontier().get("replica-A").copied(), Some(3));
    assert_eq!(b.held_count(), 0, "a reject is not held");
    assert_eq!(b.stalled_count(), 1, "it is stalled (pinned)");
    assert_eq!(
        b.subsumed_frontier().get("replica-A").copied(),
        Some(1),
        "subsumed pins at the rejected dot (A:1) — the compactor may not cover past it"
    );
}

#[test]
fn blob_compact_publishes_subsumed_not_pull_frontier() {
    // COVERED-SUBSUMED: the snapshot's PUBLISHED covered frontier equals subsumed_frontier(), never pull_frontier.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();
    a.apply("held1".into()).unwrap(); // A:1

    let mut b = blob_client(store.clone(), "replica-B");
    b.pull_verified(
        |_e, pt, _r, _c| if pt == b"held1" { Verdict::Hold } else { Verdict::Accept },
        NO_COVER,
    )
    .unwrap();
    b.compact().unwrap();

    let subsumed = b.subsumed_frontier();
    assert_eq!(subsumed.get("replica-A").copied(), Some(1));
    // Decode exactly what compact() sealed into the snapshot body.
    let (env, _) = store.get(&snapshot_key("doc")).unwrap().unwrap();
    let body = PassthroughSealer.open(EntryKind::Snapshot, &env).unwrap();
    let (published, _) = decode_frontier(&body).unwrap();
    assert_eq!(published, subsumed, "compact() publishes the SUBSUMED frontier, not pull_frontier");
}

#[test]
fn blob_bootstrap_verified_does_not_merge_a_rejected_tail() {
    // BOOTSTRAP-REJECTS (review #1): bootstrap_verified re-classifies its tail — a Rejected TAIL entry is NOT
    // merged (contrast: plain bootstrap would merge it unconditionally).
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("keep".into()).unwrap();
    a.compact().unwrap(); // snapshot covers {A:1}, contains "keep"
    let mut bwriter = blob_client(store.clone(), "replica-B");
    bwriter.apply("forged".into()).unwrap(); // B:0 — a tail past the snapshot

    let mut c = blob_client(store.clone(), "replica-C");
    c.bootstrap_verified(
        |_e, pt, _r, _co| if pt == b"forged" { Verdict::Reject } else { Verdict::Accept },
        NO_COVER,
        |_e, _b| Verdict::Accept,
    )
    .unwrap();
    assert!(c.engine().lines.contains("keep"), "snapshot content is adopted");
    assert!(!c.engine().lines.contains("forged"), "the rejected TAIL entry is NOT merged by bootstrap_verified");
    assert_eq!(c.stalled_count(), 1, "the rejected tail dot is pinned");
}

#[test]
fn blob_gc_simulation_subsumed_frontier_prevents_loss() {
    // The end-to-end security proof: deleting every log object below the PUBLISHED (subsumed) covered frontier —
    // the maximal sweep gate 1 permits — never loses data. Had the compactor published pull_frontier (which
    // advanced past a held dot), the sweep would have deleted B:0, an entry NO snapshot contains → silent loss.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    let mut b = blob_client(store.clone(), "replica-B");
    a.apply("a0".into()).unwrap(); // A:0
    a.apply("a1".into()).unwrap(); // A:1
    b.apply("held".into()).unwrap(); // B:0 — A will HOLD it (its membership op hasn't landed)

    // A pulls B's entry but HOLDS it → A's subsumed excludes B, so its snapshot cannot cover B:0.
    a.pull_verified(|_e, _p, r, _c| if r == "replica-B" { Verdict::Hold } else { Verdict::Accept }, NO_COVER)
        .unwrap();
    a.compact().unwrap();
    let covered = a.subsumed_frontier();
    assert_eq!(covered.get("replica-A").copied(), Some(2));
    assert_eq!(covered.get("replica-B").copied(), Some(0), "A held B:0, so subsumed can't cover it");

    // The maximal gate-1 sweep: delete every log/{r}/{c} with c < covered[r]. A:0,A:1 go; B:0 is protected.
    for c in 0..2 {
        store.delete(&log_key("doc", "replica-A", c), Precondition::Any).unwrap();
    }

    // A fresh replica bootstraps: snapshot (a0,a1 — A's folded state, NOT "held") + the surviving tail (B:0).
    let mut c = blob_client(store.clone(), "replica-C");
    c.bootstrap_verified(|_e, _p, _r, _co| Verdict::Accept, NO_COVER, |_e, _b| Verdict::Accept).unwrap();
    let expected: BTreeSet<String> = ["a0", "a1", "held"].into_iter().map(String::from).collect();
    assert_eq!(
        c.engine().lines,
        expected,
        "no loss: the snapshot covers A:0-1, and B:0 survived GC (subsumed never covered it) to be re-pulled"
    );
}

#[test]
fn blob_drain_vanished_dot_is_stalled_not_leaked() {
    // The drain-leak fix: a held dot whose object VANISHES (a GC reclaim) becomes STALLED (still pinning
    // subsumed), never silently dropped — dropping would forge coverage over a dot never folded.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("v0".into()).unwrap(); // A:0
    a.apply("a1".into()).unwrap(); // A:1

    let mut b = blob_client(store.clone(), "replica-B");
    b.pull_verified(|_e, pt, _r, _c| if pt == b"v0" { Verdict::Hold } else { Verdict::Accept }, NO_COVER)
        .unwrap();
    assert_eq!(b.held_count(), 1);

    // The held object vanishes (reclaimed below a GC floor); a later drain runs.
    store.delete(&log_key("doc", "replica-A", 0), Precondition::Any).unwrap();
    b.pull_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER).unwrap();
    assert_eq!(b.held_count(), 0, "no longer held");
    assert_eq!(b.stalled_count(), 1, "moved to stalled (Vanished), not dropped");
    assert_eq!(
        b.subsumed_frontier().get("replica-A").copied(),
        Some(0),
        "the vanished dot still pins subsumed — coverage never advances over it"
    );
}

#[test]
fn blob_a_dropped_pre_demote_delta_is_recovered_from_the_authenticated_snapshot() {
    // OPE-421 F2 (the frontier split): a legit pre-demote delta HELD then DROPPED under a new (demoted) head
    // must NOT be lost. The admin's authenticated snapshot pinned it (Slice 3 compact-before-demote), so the
    // dropped-below-covered dot triggers `needs_snapshot_adoption` and adoption recovers its content. Proves
    // `dropped` is NON-pinning for GC (subsumed advances past it) yet ADOPTION-triggering (so no divergence).
    let store = Arc::new(MemoryBlob::new());

    // Member B writes a legit pre-demote delta; admin A folds it + compacts (the Slice-3 pin covers B:0).
    let mut b = blob_client(store.clone(), "replica-B");
    b.apply("legit".into()).unwrap(); // B:0
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("owner-write".into()).unwrap(); // A:0
    a.pull_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER).unwrap(); // A folds B:0
    a.compact().unwrap(); // snapshot covers {A:1, B:1}, contains "legit" + "owner-write"

    // Replica X first HOLDS B:0 (keyring behind), then — after the demote lands — the drain re-classifies it to
    // DROP (B's author is demoted at head). The Cell flips the verdict between the two drains.
    let demoted = std::cell::Cell::new(false);
    let classify = |_e: &[u8], pt: &[u8], r: &str, _c: u64| {
        if r == "replica-B" && pt == b"legit" {
            if demoted.get() { Verdict::Drop } else { Verdict::Hold }
        } else {
            Verdict::Accept
        }
    };
    let mut x = blob_client(store.clone(), "replica-X");
    x.pull_verified(&classify, NO_COVER).unwrap(); // holds B:0, merges owner-write
    assert_eq!(x.held_count(), 1, "B:0 is held pre-demote");

    // The demote lands: the drain re-classifies B:0 → Drop.
    demoted.set(true);
    x.pull_verified(&classify, NO_COVER).unwrap();
    assert_eq!(x.held_count(), 0, "no longer held");
    assert_eq!(x.dropped_count(), 1, "B:0 dropped");
    assert_eq!(x.stalled_count(), 0, "a Drop does not stall/pin (unlike Reject/Vanished)");
    assert_eq!(
        x.subsumed_frontier().get("replica-B").copied(),
        Some(1),
        "dropped is NON-pinning — subsumed advanced past B:0"
    );
    assert!(!x.engine().lines.contains("legit"), "X did not merge the dropped delta directly");
    assert!(
        x.needs_snapshot_adoption().unwrap(),
        "a dropped dot below covered MUST trigger adoption (else legit history is lost)"
    );

    // Adopt the authenticated pin: recovers "legit", purges the drop, converges.
    x.bootstrap_verified(&classify, NO_COVER, |_e, _b| Verdict::Accept).unwrap();
    assert!(x.engine().lines.contains("legit"), "the pin recovered the dropped pre-demote delta");
    assert!(x.engine().lines.contains("owner-write"));
    assert_eq!(x.dropped_count(), 0, "the drop is purged below covered — no adoption churn");
    assert!(!x.needs_snapshot_adoption().unwrap(), "converged — no further adoption needed");
}

#[test]
fn blob_a_forge_above_covered_stays_dropped_without_adoption_churn() {
    // A demoted member's NEW forge (past the admin's pinned covered frontier) is dropped and stays INERT: it is
    // non-pinning AND does not trigger adoption (its counter >= covered), so there is no re-adoption churn —
    // while the legit pre-demote dot BELOW covered is still recovered. The two cases split exactly at covered.
    let store = Arc::new(MemoryBlob::new());
    let mut b = blob_client(store.clone(), "replica-B");
    b.apply("legit".into()).unwrap(); // B:0 — legit pre-demote
    let mut a = blob_client(store.clone(), "replica-A");
    a.pull_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER).unwrap(); // A folds B:0
    a.compact().unwrap(); // covered {B:1} — covers B:0 only
    b.apply("forge".into()).unwrap(); // B:1 — a post-demote forge, ABOVE covered

    // X drops every B entry (author demoted): B:0 (below covered) and B:1 (above covered).
    let drop_b =
        |_e: &[u8], _p: &[u8], r: &str, _c: u64| if r == "replica-B" { Verdict::Drop } else { Verdict::Accept };
    let mut x = blob_client(store.clone(), "replica-X");
    x.pull_verified(&drop_b, NO_COVER).unwrap();
    assert_eq!(x.dropped_count(), 2, "both B dots dropped");
    assert!(x.needs_snapshot_adoption().unwrap(), "B:0 (< covered) triggers adoption");

    x.bootstrap_verified(&drop_b, NO_COVER, |_e, _b| Verdict::Accept).unwrap();
    assert!(x.engine().lines.contains("legit"), "the below-covered legit dot recovered from the pin");
    assert!(!x.engine().lines.contains("forge"), "the forge is never merged");
    assert_eq!(x.dropped_count(), 1, "only the below-covered drop is purged; the forge (>= covered) stays dropped");
    assert!(!x.needs_snapshot_adoption().unwrap(), "no churn: the remaining forge is at/above covered");
}

#[test]
fn blob_compact_does_not_regress_a_peer_snapshots_covered() {
    // BYO covered-monotonicity (the client analog of the server's M6 guard): a compactor whose frontier is
    // INCOMPARABLE to the current snapshot must not clobber it to a lower coordinate — that would un-pin history
    // the peer covered. A's snapshot covers {A:2}; B (which folded only its own write, not A's) must NOT
    // overwrite it down to {B:1}. After B adopts A's snapshot it dominates, and its compact lands.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap(); // A:0
    a.apply("a1".into()).unwrap(); // A:1
    a.compact().unwrap(); // snapshot covers {A:2}
    assert_eq!(
        a.snapshot_covered_frontier().unwrap().unwrap().get("replica-A").copied(),
        Some(2)
    );

    // B has its own write but has NOT pulled A. A naive compact would overwrite the snapshot to {B:1},
    // regressing A:2 -> absent. The guard skips it.
    let mut b = blob_client(store.clone(), "replica-B");
    b.apply("b0".into()).unwrap(); // B:0
    b.compact().unwrap(); // guard: would regress A → no-op
    assert_eq!(
        a.snapshot_covered_frontier().unwrap().unwrap().get("replica-A").copied(),
        Some(2),
        "B's incomparable compact did not regress A's covered"
    );
    assert_eq!(
        a.snapshot_covered_frontier().unwrap().unwrap().get("replica-B").copied(),
        None,
        "and it did not publish B's coordinate either (the whole write was skipped)"
    );

    // After B adopts A's snapshot + folds the tail, B's subsumed dominates → its compact lands (both covered).
    b.bootstrap_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER, |_e, _b| Verdict::Accept).unwrap();
    b.compact().unwrap();
    let cov = b.snapshot_covered_frontier().unwrap().unwrap();
    assert_eq!(cov.get("replica-A").copied(), Some(2), "A still covered after B dominates");
    assert!(cov.get("replica-B").copied().unwrap_or(0) >= 1, "B now covered too");
}

#[test]
fn blob_readmit_and_forget_a_dropped_dot() {
    // The two mechanisms openom's soft-removal review is built on: a dropped dot can be RE-ADMITTED into engine
    // state (gate → merge + un-track, so the next compaction pins it) or FORGOTTEN (un-track, stays suppressed).
    // docsync stays domain-agnostic — the admit decision is the caller's `gate` closure.
    let store = Arc::new(MemoryBlob::new());
    let mut b = blob_client(store.clone(), "replica-B");
    b.apply("keep-me".into()).unwrap(); // B:0
    b.apply("drop-me".into()).unwrap(); // B:1

    // X drops both of B's entries (B is a since-departed member at X's head).
    let mut x = blob_client(store.clone(), "replica-X");
    x.pull_verified(|_e, _p, r, _c| if r == "replica-B" { Verdict::Drop } else { Verdict::Accept }, NO_COVER)
        .unwrap();
    assert_eq!(x.dropped_count(), 2);
    assert_eq!(x.dropped_dots().len(), 2, "both trailing edits are in the review queue");
    assert!(!x.engine().lines.contains("keep-me"), "a dropped dot is not folded");
    assert!(x.read_dropped("replica-B", 0).unwrap().is_some(), "the raw envelope is readable for review");

    // RE-ADMIT B:0 (gate passes) → merged + un-tracked.
    assert!(x.readmit_dropped("replica-B", 0, |_env, _pt| true).unwrap());
    assert!(x.engine().lines.contains("keep-me"), "a re-admitted trailing edit is folded");
    assert_eq!(x.dropped_count(), 1, "the re-admitted dot leaves the queue");

    // A gate that DECLINES leaves the dot dropped + unmerged.
    assert!(!x.readmit_dropped("replica-B", 1, |_e, _p| false).unwrap());
    assert!(!x.engine().lines.contains("drop-me"));
    assert_eq!(x.dropped_count(), 1);

    // FORGET B:1 → un-tracked, never folded; a subsequent re-admit is a no-op (unknown dot).
    assert!(x.forget_dropped("replica-B", 1));
    assert!(!x.engine().lines.contains("drop-me"));
    assert_eq!(x.dropped_count(), 0);
    assert!(!x.readmit_dropped("replica-B", 1, |_e, _p| true).unwrap(), "forgotten dot is no longer admittable");
}

/// A `MemoryBlob` whose named keys return `BlobError::Gone` from `get` — models a GC-reaped remote object
/// (distinct from a plain absent key). Everything else delegates.
struct GoneFor {
    inner: Arc<MemoryBlob>,
    gone: BTreeSet<String>,
}
impl BlobStore for GoneFor {
    fn get(&self, key: &str) -> store_blob::Result<Option<(Vec<u8>, store_blob::Etag)>> {
        if self.gone.contains(key) {
            return Err(store_blob::BlobError::Gone);
        }
        self.inner.get(key)
    }
    fn put(&self, key: &str, bytes: &[u8], pre: Precondition) -> store_blob::Result<store_blob::Etag> {
        self.inner.put(key, bytes, pre)
    }
    fn list(&self, prefix: &str) -> store_blob::Result<Vec<(String, store_blob::Etag)>> {
        self.inner.list(prefix)
    }
    fn delete(&self, key: &str, pre: Precondition) -> store_blob::Result<()> {
        self.inner.delete(key, pre)
    }
}

#[test]
fn blob_mirror_skips_gone_objects_and_carries_the_snapshot() {
    // C2: a GC-reaped source object returns Gone; mirror SKIPS it (the carried snapshot backs it) and keeps
    // copying the above-floor tail, instead of aborting — and carries the source snapshot so a client can
    // bootstrap over the hole.
    let src = Arc::new(MemoryBlob::new());
    let mut a = blob_client(src.clone(), "replica-A");
    a.apply("a0".into()).unwrap(); // A:0
    a.apply("a1".into()).unwrap(); // A:1
    a.apply("a2".into()).unwrap(); // A:2
    a.compact().unwrap(); // a snapshot covering {A:3}, so A:0 is below the covered frontier

    // Model the sweep having reaped A:0 (below the floor): the remote get() returns Gone for it.
    let gone_src = GoneFor {
        inner: src.clone(),
        gone: [log_key("doc", "replica-A", 0)].into_iter().collect(),
    };
    let dst = Arc::new(MemoryBlob::new());
    let copied = mirror(&gone_src, dst.as_ref(), "doc").unwrap();

    assert_eq!(copied, 2, "A:1 and A:2 copied; the reaped A:0 skipped; mirror did not abort");
    assert!(dst.get(&log_key("doc", "replica-A", 0)).unwrap().is_none(), "the reaped object was not copied");
    assert!(dst.get(&log_key("doc", "replica-A", 1)).unwrap().is_some());
    assert!(dst.get(&log_key("doc", "replica-A", 2)).unwrap().is_some());
    assert_eq!(
        dst.get(&head_key("doc", "replica-A")).unwrap().and_then(|(b, _)| decode_count(&b)),
        Some(3),
        "the head advanced past the Gone gap (snapshot-backed), not capped"
    );
    assert!(dst.get(&snapshot_key("doc")).unwrap().is_some(), "the source snapshot was carried");

    // A fresh replica bootstraps from the mirrored store: snapshot (a0,a1,a2) + tail (empty above A:3) = complete.
    let mut c = blob_client(dst.clone(), "replica-C");
    c.bootstrap_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER, |_e, _b| Verdict::Accept).unwrap();
    let expected: BTreeSet<String> = ["a0", "a1", "a2"].into_iter().map(String::from).collect();
    assert_eq!(c.engine().lines, expected, "no loss: bootstrap over the reaped hole via the carried snapshot");
}

#[test]
fn blob_maybe_compact_fires_at_k_then_resets() {
    // The compaction-trigger seam bound by K log objects since the last snapshot: below K no compaction; at K
    // it compacts; the baseline resets so it does not re-fire until K more accrue.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();
    a.apply("a1".into()).unwrap();
    assert!(!a.maybe_compact(&EveryNUpdates(3)).unwrap(), "below K: no compaction");
    assert!(store.get(&snapshot_key("doc")).unwrap().is_none(), "no snapshot yet");

    a.apply("a2".into()).unwrap();
    assert!(a.maybe_compact(&EveryNUpdates(3)).unwrap(), "at K: compacts");
    assert!(store.get(&snapshot_key("doc")).unwrap().is_some(), "snapshot written");

    assert!(!a.maybe_compact(&EveryNUpdates(3)).unwrap(), "baseline reset — no re-fire right after");
}

#[test]
fn blob_maybe_compact_skips_when_a_peer_snapshot_already_covers_us() {
    // Check-before-compact (OPE-409): if the current snapshot already covers our subsumed frontier (a peer
    // compacted it), maybe_compact SKIPS — no redundant snapshot write / concurrent-compaction churn.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();
    a.apply("a1".into()).unwrap();
    a.compact().unwrap(); // A's snapshot covers {A:2}
    let etag_before = store.get(&snapshot_key("doc")).unwrap().unwrap().1;

    let mut b = blob_client(store.clone(), "replica-B");
    b.pull_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER).unwrap(); // B's subsumed = {A:2}
    assert!(!b.maybe_compact(&EveryNUpdates(1)).unwrap(), "skips — the snapshot already covers B's subsumed");
    assert_eq!(
        store.get(&snapshot_key("doc")).unwrap().unwrap().1,
        etag_before,
        "the snapshot is untouched — B did not redundantly overwrite it"
    );
}

#[test]
fn blob_needs_snapshot_adoption_signals_missing_state() {
    // A fresh client whose subsumed is behind the snapshot's coverage needs to ADOPT it (bootstrap), not just
    // fold — else it misses the reaped-below-floor state that lives only in the snapshot (OPE-409 layer 3).
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();
    a.apply("a1".into()).unwrap();
    a.compact().unwrap(); // snapshot covers {A:2}

    let mut c = blob_client(store.clone(), "replica-C");
    assert!(c.needs_snapshot_adoption().unwrap(), "a fresh client (subsumed 0) must adopt the {{A:2}} snapshot");
    c.bootstrap_verified(|_e, _p, _r, _c| Verdict::Accept, NO_COVER, |_e, _b| Verdict::Accept).unwrap();
    assert!(!c.needs_snapshot_adoption().unwrap(), "after adoption it holds the snapshot's coverage");
}

#[test]
fn blob_retry_stalled_clears_a_now_acceptable_dot() {
    // review #4: a dot Rejected on first pull is stalled (pinning subsumed); retry_stalled with a classify
    // that now Accepts it (its membership op has since landed) merges it and unpins — the only heal for a pin.
    let store = Arc::new(MemoryBlob::new());
    let mut a = blob_client(store.clone(), "replica-A");
    a.apply("a0".into()).unwrap();

    let mut b = blob_client(store.clone(), "replica-B");
    b.pull_verified(|_e, _p, _r, _c| Verdict::Reject, NO_COVER).unwrap();
    assert_eq!(b.stalled_count(), 1);
    assert_eq!(b.subsumed_frontier().get("replica-A").copied(), Some(0), "pinned at the rejected dot");

    let cleared = b.retry_stalled(|_e, _p, _r, _c| Verdict::Accept, NO_COVER).unwrap();
    assert_eq!(cleared, 1);
    assert_eq!(b.stalled_count(), 0, "the stall cleared");
    assert!(b.engine().lines.contains("a0"), "the dot is now merged");
    assert_eq!(
        b.subsumed_frontier().get("replica-A").copied(),
        Some(1),
        "subsumed unpinned to the fetch frontier"
    );
}
