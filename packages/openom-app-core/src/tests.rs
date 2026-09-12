//! Core tests over `MemoryBlob`, driven through the production topology: each core owns its OWN local
//! `BlobStore` and the only meeting point is a shared REMOTE `BlobStore` (R2 / BYO), reached by dumb
//! anti-entropy — `docsync::mirror(local, remote)` to push, `mirror(remote, local)` + `fold()` to pull.
//! Unlike the docsync tests (which may share one store), here nothing is shared but the remote, exactly as
//! the deployed client-server topology works. The §B3 verify gate runs at FOLD time over the mirrored-in
//! objects (not at store time): the local store is a dumb cache of the remote, so it may hold a forgery —
//! the invariant is that a forgery never FOLDS into the tree, now or after a reload.

use super::AppCore;
use docsync::mirror;
use openom_crypto::{generate_dek, Dek};
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_sealer::{Sealer, SealerSet};
use openom_vault::{Governing, MembershipResolver};
use std::collections::BTreeSet;
use std::sync::Arc;
use store_blob::{BlobStore, MemoryBlob};

/// A scripted [`MembershipResolver`] double for the §B3 routing tests — it forces one disposition for every
/// entry via the neutral policy's *crypto-free* arms (no keyring, no signature check), so the routing
/// (Accept ⇒ fold, Hold ⇒ park, Reject ⇒ anomaly + never-fold) can be exercised in isolation. The real
/// crypto decisions are proven against `ChainMembershipResolver`/`DagMembershipResolver` below and in
/// openom-vault.
enum Route {
    Accept,
    Hold,
    Reject,
}
struct Fake(Route);
impl MembershipResolver for Fake {
    fn shared(&self) -> bool {
        // Accept routes through the never-shared arm; Hold/Reject through the shared arm.
        !matches!(self.0, Route::Accept)
    }
    fn resolve(&self, _governing_ref: &[u8], _key_id: &[u8]) -> Governing {
        match self.0 {
            // (false, Unattributed) ⇒ Accept; (true, Unattributed) ⇒ Reject — neither opens the entry.
            Route::Accept | Route::Reject => Governing::Unattributed,
            // (true, NotYetRetained) ⇒ Hold.
            Route::Hold => Governing::NotYetRetained,
        }
    }
}

const DEVICE: &str = "did:key:z6MkDevice";
const PERSON: &str = "openom.org/core/person/v1";
const NAME: &str = "openom.org/core/name/v1";
const DOC: &str = "tree";

fn core(replica: &[u8], dek: Dek, store: Arc<MemoryBlob>) -> AppCore<MemoryBlob> {
    let sealer = Sealer::from_unwrapped(
        1,
        dek.into_inner(),
        TreeId::new(b"tree-uuid-16byte".to_vec()),
        KeyId::new(b"epoch-0".to_vec()),
        ReplicaId::new(replica.to_vec()),
    );
    AppCore::new(DEVICE, SealerSet::single(sealer), store, DOC, replica)
}

/// Push: mirror this core's local store UP to the shared remote (dumb anti-entropy — copies the log gap,
/// advances the remote's heads). Returns the number of log objects copied.
fn push(core: &AppCore<MemoryBlob>, remote: &Arc<MemoryBlob>) -> usize {
    mirror(core.store(), remote, DOC).unwrap()
}

/// Pull: mirror the shared remote DOWN into this core's local store, then fold the arrivals through the §B3
/// gate. Returns how many entries folded into the tree.
fn pull(core: &mut AppCore<MemoryBlob>, remote: &Arc<MemoryBlob>) -> usize {
    mirror(remote, core.store(), DOC).unwrap();
    core.fold().unwrap()
}

/// How many immutable delta/cover log objects a store holds under this doc's keyspace.
fn log_len(store: &Arc<MemoryBlob>) -> usize {
    store.list("tree/log/").unwrap().len()
}

#[test]
fn compact_writes_a_snapshot_and_publishes_the_subsumed_frontier() {
    // Layer-1 compaction over the REAL crypto sealer (not the passthrough): a committed edit compacts to a
    // snapshot object, and subsumed_frontier() covers this replica's own (folded) entry — the map the worker
    // sends as the x-openom-covered header (OPE-409 C3).
    let dek = generate_dek().unwrap();
    let store = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-A", dek, store.clone());
    a.tree_mut().assert_anchor("p1", PERSON, 1).unwrap();
    a.commit().unwrap();

    a.compact().unwrap();
    assert!(store.get("tree/snapshot").unwrap().is_some(), "compaction wrote a snapshot object");
    let covered = a.subsumed_frontier();
    assert!(!covered.is_empty(), "subsumed frontier is non-empty after compaction");
    // Own entries are always coverable (folded on commit), so the frontier covers this replica.
    let replica_hex = super::replica_key(b"replica-A");
    assert_eq!(covered.get(&replica_hex).copied(), Some(1), "covers this replica's own committed entry");
}

#[test]
fn sync_against_compacts_and_surfaces_the_snapshot_in_uploads() {
    // The worker's tick contract: sync_against with compact_k=1 compacts after the fold, so the fresh snapshot
    // object is in the returned uploads (the worker sends it with the x-openom-covered header).
    let dek = generate_dek().unwrap();
    let store = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-A", dek, store.clone());
    a.tree_mut().assert_anchor("p1", PERSON, 1).unwrap();
    a.commit().unwrap();

    let (uploads, _folded) = a.sync_against(&[], 1).unwrap();
    assert!(uploads.iter().any(|(k, _)| k.ends_with("/snapshot")), "the fresh snapshot is in the uploads");
    assert!(!a.subsumed_frontier().is_empty(), "the covered frontier for the header is available");

    // A fresh core with compaction disabled (0) produces no snapshot.
    let mut b = core(b"replica-B", generate_dek().unwrap(), Arc::new(MemoryBlob::new()));
    b.tree_mut().assert_anchor("p2", PERSON, 2).unwrap();
    b.commit().unwrap();
    let (ub, _) = b.sync_against(&[], 0).unwrap();
    assert!(!ub.iter().any(|(k, _)| k.ends_with("/snapshot")), "no snapshot when compaction is off");
}

#[test]
fn a_straggler_adopts_a_snapshot_when_the_covered_log_was_reaped() {
    // OPE-409 layer 3. After compaction the below-floor log can be REAPED server-side. A fresh/straggler
    // client that only folded the tail would miss that state — it must ADOPT the snapshot (bootstrap_verified).
    // Here the remote carries the snapshot + heads but NOT the covered (reaped) log object; the straggler
    // still recovers the person — proving sync_against took the adopt branch, since a plain fold sees no log.
    let dek = generate_dek().unwrap();
    let local = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek.clone(), local.clone());
    a.tree_mut().assert_anchor("pReaped", PERSON, 1).unwrap();
    a.commit().unwrap();
    a.compact().unwrap(); // snapshot covers {a:1}

    // The remote view the straggler pulls: snapshot + heads only — the covered log object is gone (reaped).
    let mut remote_view = Vec::new();
    for (key, _etag) in local.list("tree/").unwrap() {
        if key.starts_with("tree/log/") {
            continue; // below the floor → reaped
        }
        if let Some((bytes, _etag)) = local.get(&key).unwrap() {
            remote_view.push((key, bytes));
        }
    }
    assert!(remote_view.iter().any(|(k, _)| k.ends_with("/snapshot")), "the remote carries the snapshot");
    assert!(!remote_view.iter().any(|(k, _)| k.starts_with("tree/log/")), "the covered log is reaped");

    // A fresh straggler over its own empty store, same DEK. Fold alone sees no log; adoption recovers p.
    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));
    b.sync_against(&remote_view, 0).unwrap();
    assert!(
        live_ids(&b).contains("pReaped"),
        "the straggler adopted the snapshot and recovered the reaped-below-floor state"
    );
}

fn live_ids(core: &AppCore<MemoryBlob>) -> BTreeSet<String> {
    core.live_records()
        .unwrap()
        .into_iter()
        .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_owned))
        .collect()
}

/// Drive one sync tick the way the worker does: fetch the remote's whole snapshot, `sync_against` it, upload
/// the returned diff back to the remote. Returns how many entries folded.
fn tick(core: &mut AppCore<MemoryBlob>, remote: &Arc<MemoryBlob>) -> usize {
    let mut snapshot = Vec::new();
    for (key, _etag) in remote.list("tree/").unwrap() {
        if let Some((bytes, _etag)) = remote.get(&key).unwrap() {
            snapshot.push((key, bytes));
        }
    }
    let (uploads, folded) = core.sync_against(&snapshot, 0).unwrap(); // 0 = no compaction in these tests
    for (key, bytes) in uploads {
        let pre = if key.contains("/heads/") || key.ends_with("/snapshot") {
            store_blob::Precondition::Any
        } else {
            store_blob::Precondition::IfAbsent
        };
        match remote.put(&key, &bytes, pre) {
            Ok(_) | Err(store_blob::BlobError::PreconditionFailed) => {}
            Err(e) => panic!("remote put failed: {e}"),
        }
    }
    folded
}

#[test]
fn two_cores_converge_through_a_ferried_snapshot() {
    // The worker's real contract: each core owns a local store, converges through a shared remote by ferrying
    // a whole-snapshot in and an upload-diff out (AppCore::sync_against). Head-monotonicity is Rust's job — a
    // peer's head is never rolled back even though both cores push their stale view of it each tick.
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));

    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    b.tree_mut().assert_anchor("pB", PERSON, 2).unwrap();
    b.commit().unwrap();

    // Interleave ticks (A up, B up+down, A down) — order-free set-union convergence.
    tick(&mut a, &remote);
    tick(&mut b, &remote);
    tick(&mut a, &remote);
    tick(&mut b, &remote);

    assert_eq!(live_ids(&a), live_ids(&b), "both devices converge through the ferried snapshot");
    assert!(live_ids(&a).contains("pA") && live_ids(&a).contains("pB"));

    // Idempotent: a further tick with nothing new folds nothing and uploads nothing.
    assert_eq!(tick(&mut a, &remote), 0, "a quiescent tick is a no-op");
}

#[test]
fn two_cores_converge_through_the_remote() {
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));

    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.tree_mut().assert_claim("pA", NAME, json_name("Ada"), 1).unwrap();
    a.commit().unwrap();
    b.tree_mut().assert_anchor("pB", PERSON, 2).unwrap();
    b.commit().unwrap();

    // Each pushes its own up to the remote; each pulls the other's down. Order-free (set-union).
    push(&a, &remote);
    push(&b, &remote);
    pull(&mut a, &remote);
    pull(&mut b, &remote);

    assert_eq!(live_ids(&a), live_ids(&b), "both devices converge");
    assert!(live_ids(&a).contains("pA") && live_ids(&a).contains("pB"));
}

#[test]
fn an_offline_mint_survives_a_reload() {
    // THE durable-outbox proof. A mints offline and commits (durable in the local store) but never pushes;
    // the whole core is dropped and rebuilt from the local store alone; the mint re-enters the engine on
    // bootstrap, still reaches the remote, and a peer sees it.
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());
    let store = Arc::new(MemoryBlob::new());

    {
        let mut a = core(b"replica-a", dek.clone(), Arc::clone(&store));
        a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
        a.commit().unwrap(); // durable locally — but a is dropped before any push
    }

    // "Reload": a fresh core over the SAME local store, its in-memory frontier reset.
    let mut a2 = core(b"replica-a", dek.clone(), Arc::clone(&store));
    a2.bootstrap().unwrap();
    assert!(live_ids(&a2).contains("pA"), "the offline mint is back in the engine after reload");

    // The un-pushed mint is still in the local store, so a push mirrors it up to the remote.
    assert_eq!(push(&a2, &remote), 1, "the un-pushed offline mint reaches the remote");

    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));
    pull(&mut b, &remote);
    assert!(live_ids(&b).contains("pA"), "the peer receives the mint that survived the reload");
}

#[test]
fn our_own_entries_are_not_re_folded_or_re_pushed() {
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());
    let store = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek, Arc::clone(&store));

    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&a, &remote);
    assert_eq!(log_len(&remote), 1);

    // A pulls the remote tail — which holds only its own entry. The mirror is an IfAbsent no-op (already
    // present), and the fold skips our own entry (past the frontier), so nothing folds.
    let before = log_len(&store);
    assert_eq!(pull(&mut a, &remote), 0, "our own entry pulled back does not re-fold");
    assert_eq!(log_len(&store), before, "our own entry pulled back is not re-appended locally");

    // ...nor re-pushed (the remote already has it; the mirror is a no-op).
    assert_eq!(push(&a, &remote), 0, "no echo back to the remote");
    assert_eq!(log_len(&remote), 1);
}

#[test]
fn export_then_import_reconstructs_the_core_on_a_fresh_store() {
    // Mirrors what the worker does across a reload: `export` the local store objects to the host (IndexedDB),
    // then on open a FRESH core `import`s them into a new store + bootstraps — the data and the un-pushed
    // outbound both come back. The durable-outbox guarantee via the persistence seam (no shared Arc, unlike
    // `an_offline_mint_survives_a_reload`).
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());

    // Device A mints offline and commits; the "host" captures the exported store objects.
    let exported: Vec<(String, Vec<u8>)> = {
        let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
        a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
        a.commit().unwrap();
        a.export().unwrap()
    };
    assert!(!exported.is_empty(), "the committed batch is captured for persistence");

    // "Reload": a brand-new core over a fresh store, hydrated only from the persisted bytes.
    let mut a2 = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    a2.import(&exported).unwrap();
    a2.bootstrap().unwrap();
    assert!(live_ids(&a2).contains("pA"), "the persisted mint is back after reload");

    // ...and it's still in the local store, so it reaches a peer through the remote.
    assert_eq!(push(&a2, &remote), 1);
    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));
    pull(&mut b, &remote);
    assert!(live_ids(&b).contains("pA"), "the peer receives the reloaded mint");
}

#[test]
fn fold_is_idempotent() {
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&a, &remote);

    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));
    assert_eq!(pull(&mut b, &remote), 1);
    let before = live_ids(&b);
    // Re-pull: the mirror brings nothing new and the frontier has advanced, so nothing folds.
    assert_eq!(pull(&mut b, &remote), 0, "re-folding the same entries is a no-op");
    assert_eq!(live_ids(&b), before);
}

#[test]
fn a_reload_does_not_re_append_peer_entries() {
    // With the frontier reset on reload, re-pulling the remote tail must NOT duplicate peer entries in the
    // local store (the mirror is IfAbsent on immutable log keys), or storage grows without bound.
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());

    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&a, &remote);

    let b_store = Arc::new(MemoryBlob::new());
    let mut b = core(b"replica-b", dek.clone(), Arc::clone(&b_store));
    pull(&mut b, &remote);
    assert_eq!(log_len(&b_store), 1);

    // "Reload" B from its persisted objects (fresh core, frontier reset), then re-pull the same tail.
    let exported = b.export().unwrap();
    let reload_store = Arc::new(MemoryBlob::new());
    let mut b2 = core(b"replica-b", dek, Arc::clone(&reload_store));
    b2.import(&exported).unwrap();
    b2.bootstrap().unwrap();
    pull(&mut b2, &remote); // frontier is empty → re-mirrors, but IfAbsent dedups

    assert_eq!(log_len(&reload_store), 1, "the peer entry is deduped, not re-appended on a reload re-pull");
    assert!(live_ids(&b2).contains("pA"));
}

#[test]
fn a_poison_entry_is_quarantined_not_wedged() {
    // A wrong-key / corrupt entry on the shared log must not wedge the fold for everyone — it is quarantined
    // (surfaced via `anomalies`), and valid entries still merge.
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());

    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    a.tree_mut().assert_anchor("pGood", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&a, &remote);

    // An intruder writes an entry sealed under a DIFFERENT DEK to the same log.
    let wrong = generate_dek().unwrap();
    let mut x = core(b"replica-x", wrong, Arc::new(MemoryBlob::new()));
    x.tree_mut().assert_anchor("pEvil", PERSON, 1).unwrap();
    x.commit().unwrap();
    push(&x, &remote);

    let mut b = core(b"replica-b", dek, Arc::new(MemoryBlob::new()));
    pull(&mut b, &remote); // must not wedge

    assert!(live_ids(&b).contains("pGood"), "the valid entry still merges");
    assert!(!live_ids(&b).contains("pEvil"), "the wrong-key entry never decrypts into the tree");
    assert!(b.anomalies() >= 1, "the poison entry is surfaced as an anomaly, not silently dropped or wedging");
}

#[test]
fn reset_clears_the_tree_and_store_then_reseeds_cleanly() {
    let dek = generate_dek().unwrap();
    let store = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek, Arc::clone(&store));

    a.tree_mut().assert_anchor("pOld", PERSON, 1).unwrap();
    a.commit().unwrap();
    assert!(live_ids(&a).contains("pOld"));
    assert_eq!(log_len(&store), 1);

    a.reset().unwrap();
    assert!(live_ids(&a).is_empty(), "the tree is empty after reset");
    assert_eq!(log_len(&store), 0, "the durable store is cleared");

    // Re-seed cleanly — the new record is there, the old id is not resurrected.
    a.tree_mut().assert_anchor("pNew", PERSON, 2).unwrap();
    a.commit().unwrap();
    assert!(live_ids(&a).contains("pNew"));
    assert!(!live_ids(&a).contains("pOld"), "no resurrected old id after reset+reseed");
}

/// Set up a remote holding ONE peer entry (anchor `pA`, authored by replica-a) plus a fresh core B over its
/// own store, sharing the DEK so B can open it. B installs `route` as its §B3 membership before pulling.
fn peer_entry_and_core_b(route: Route) -> (Arc<MemoryBlob>, AppCore<MemoryBlob>, Arc<MemoryBlob>) {
    let dek = generate_dek().unwrap();
    let remote = Arc::new(MemoryBlob::new());
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryBlob::new()));
    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&a, &remote);

    let b_store = Arc::new(MemoryBlob::new());
    let mut b = core(b"replica-b", dek, Arc::clone(&b_store));
    b.set_membership(Box::new(Fake(route))).unwrap();
    (remote, b, b_store)
}

#[test]
fn a_rejected_peer_entry_never_folds_now_or_after_a_reload() {
    // The anti-forgery gate under the mirror model: a §B3-rejected entry lands in the durable local store
    // (the mirror is dumb — it copies whatever the remote holds), but it never FOLDS into the tree, it is
    // surfaced as an anomaly, and — the recovery invariant — a reload re-verifies the persisted forgery and
    // re-rejects it: it never leaks into the tree, no matter how many times it is re-folded.
    let (remote, mut b, b_store) = peer_entry_and_core_b(Route::Reject);
    pull(&mut b, &remote);

    assert!(!live_ids(&b).contains("pA"), "a rejected entry never folds into the tree");
    assert!(b.anomalies() >= 1, "a rejected forgery is surfaced as an anomaly");
    assert_eq!(log_len(&b_store), 1, "the mirror is a dumb cache — the forgery IS in the local store");

    // Recovery invariant: reload from the persisted objects and re-fold — still rejected, never folds.
    let exported = b.export().unwrap();
    let reload_store = Arc::new(MemoryBlob::new());
    let mut b2 = core(b"replica-b", generate_dek().unwrap(), Arc::clone(&reload_store));
    b2.set_membership(Box::new(Fake(Route::Reject))).unwrap();
    b2.import(&exported).unwrap();
    b2.bootstrap().unwrap();
    assert!(!live_ids(&b2).contains("pA"), "the persisted forgery still never folds after a reload");
    assert!(b2.anomalies() >= 1, "the reload re-verifies and re-rejects the forgery");
}

#[test]
fn a_held_peer_entry_is_buffered_then_released_on_set_membership() {
    // Hold ⇒ parked, un-folded, and NOT an anomaly; a later set_membership whose resolver now accepts the
    // entry releases it into the tree. (The mirror still places the entry in the local store — the hold is a
    // fold-time state, not a store-time one.)
    let (remote, mut b, b_store) = peer_entry_and_core_b(Route::Hold);
    pull(&mut b, &remote);
    assert!(!live_ids(&b).contains("pA"), "a held entry is not folded");
    assert_eq!(b.anomalies(), 0, "a hold is not an anomaly");
    assert_eq!(log_len(&b_store), 1, "the mirror still cached the entry locally");

    let folded = b.set_membership(Box::new(Fake(Route::Accept))).unwrap();
    assert_eq!(folded, 1, "the released entry folds in on set_membership");
    assert!(live_ids(&b).contains("pA"), "the released entry is now in the tree");
}

#[test]
fn an_accepting_membership_folds_peer_entries_like_the_solo_path() {
    let (remote, mut b, _b_store) = peer_entry_and_core_b(Route::Accept);
    assert_eq!(pull(&mut b, &remote), 1);
    assert!(live_ids(&b).contains("pA"));
}

#[test]
fn a_shared_tree_accepts_a_signed_member_write_and_rejects_an_unsigned_forgery() {
    // The Half-B payoff: provision a chain tree, SHARE it (add a member), and prove verify-on-fold goes live
    // end-to-end. A signed write from a member of the shared keyring is accepted on a peer's fold; an UNSIGNED
    // write on the same shared tree (same DEK, no author signature) is rejected and surfaced.
    use openom_crypto::Passphrase;
    use openom_keyring_api::EngineKind;
    use openom_protocol::ids::MemberId;
    use openom_vault::{sharing, vault, ChainMembershipResolver, MembershipResolver};

    const TREE: &[u8] = b"tree-uuid-16byte";
    let tree = TreeId::new(TREE.to_vec());
    let owner_id = MemberId::new("acct-owner");
    let owner_pass = Passphrase::new(b"owner passphrase".to_vec());

    // 1. Owner provisions a solo chain tree (genesis revision 1).
    let prov = vault::provision(&owner_pass, &tree, &owner_id, &ReplicaId::new(b"ro".to_vec())).unwrap();
    let owner_author = prov.did_key.to_public_key();
    let rev1 = prov.keyring.clone();

    // 2. Bob mints his member account keys (kdf + author + hpke publics).
    let bob_pass = Passphrase::new(b"bob passphrase".to_vec());
    let bob = vault::provision_member(&bob_pass).unwrap();

    // 3. Owner admits bob (Editor) → a SHARED keyring, revision 2.
    let added = sharing::add_member(
        EngineKind::Chain,
        &rev1,
        &owner_pass,
        TREE,
        "acct-owner",
        b"ro",
        1,
        "acct-bob",
        "editor",
        &bob.author_public_key,
        &bob.hpke_public_key,
    )
    .unwrap();
    let rev2 = added.keyring.clone();

    // A chain resolver retaining both governing revisions: rev 2 (the shared head, which governs the member's
    // signed writes) and rev 1 (the pre-share genesis). The unsigned forgery below carries an EMPTY
    // governing_ref (rev 0), so it is Unattributed→Reject regardless of retention.
    let resolver = || -> Box<dyn MembershipResolver> {
        Box::new(ChainMembershipResolver::new(&rev2, &[(1u32, rev1.clone()), (2u32, rev2.clone())]).unwrap())
    };

    let remote = Arc::new(MemoryBlob::new());

    // 4. Owner re-unlocks the SHARED keyring → a signing sealer, and writes a signed delta.
    let ou = vault::unlock(&rev2, &owner_pass, &tree, &owner_id, &ReplicaId::new(b"ro".to_vec())).unwrap();
    let mut owner = AppCore::new(ou.did_key.into_string(), ou.sealer, Arc::new(MemoryBlob::new()), DOC, b"ro");
    owner.set_membership(resolver()).unwrap();
    owner.tree_mut().assert_anchor("pSigned", PERSON, 1).unwrap();
    owner.commit().unwrap();
    push(&owner, &remote);

    // 5. THE FORGERY: unlock the pre-share genesis (rev 1) on a DISTINCT replica → a sealer with the shared
    //    DEK that does NOT sign (solo era). Its write is unsigned with an empty governing_ref — a backdate
    //    forgery that, on a shared tree, must be rejected.
    let fu = vault::unlock(&rev1, &owner_pass, &tree, &owner_id, &ReplicaId::new(b"rf".to_vec())).unwrap();
    let mut forger = AppCore::new(fu.did_key.into_string(), fu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rf");
    forger.tree_mut().assert_anchor("pForged", PERSON, 2).unwrap();
    forger.commit().unwrap();
    push(&forger, &remote);

    // 6. Bob unlocks as a member (his passphrase + kdf, pinning the owner's author key) and verifies rev 2.
    let bu = sharing::unlock_as_member(
        EngineKind::Chain,
        &rev2,
        &bob_pass,
        &keyeo_crypto::codec::encode_kdf_params(&bob.kdf_params),
        TREE,
        "acct-bob",
        &owner_author,
        b"rb",
        2,
    )
    .unwrap();
    let mut bob_core = AppCore::new(bu.did_key, bu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rb");
    bob_core.set_membership(resolver()).unwrap();
    pull(&mut bob_core, &remote);

    assert!(live_ids(&bob_core).contains("pSigned"), "a signed member write on the shared tree is accepted");
    assert!(!live_ids(&bob_core).contains("pForged"), "an unsigned write on the shared tree is rejected");
    assert!(bob_core.anomalies() >= 1, "the rejected forgery is surfaced as an anomaly");
}

#[test]
fn a_shared_dag_tree_accepts_a_signed_member_write_and_rejects_an_unsigned_forgery() {
    // The dag counterpart of the chain share→verify proof: exercise the DAG arms of
    // sharing::add_member / unlock_as_member + DagMembershipResolver end-to-end.
    use openom_crypto::Passphrase;
    use openom_keyring_api::EngineKind;
    use openom_protocol::ids::MemberId;
    use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
    use openom_vault::{resolver_from, sharing, vault, DagVault, MembershipResolver};

    const TREE: &[u8] = b"tree-uuid-16byte";
    let tree = TreeId::new(TREE.to_vec());
    let owner_id = MemberId::new("acct-owner");
    let owner_pass = Passphrase::new(b"owner passphrase".to_vec());
    let ro = ReplicaId::new(b"ro".to_vec());

    // 1. Owner provisions a solo dag tree.
    let prov = DagVault
        .provision(&VaultContext { tree_id: &tree, member_id: &owner_id, replica_id: &ro }, &owner_pass)
        .unwrap();
    let solo = prov.anchor.clone();

    // 2. Bob's member account keys.
    let bob_pass = Passphrase::new(b"bob passphrase".to_vec());
    let bob = vault::provision_member(&bob_pass).unwrap();

    // 3. Owner admits bob (Editor) → a shared anchor (dag ignores min_revision).
    let added = sharing::add_member(
        EngineKind::Dag,
        &solo,
        &owner_pass,
        TREE,
        "acct-owner",
        b"ro",
        0,
        "acct-bob",
        "editor",
        &bob.author_public_key,
        &bob.hpke_public_key,
    )
    .unwrap();
    let shared = added.keyring.clone();

    // The dag resolver comes from the single shared anchor (no per-revision retention).
    let resolver = || -> Box<dyn MembershipResolver> { resolver_from(EngineKind::Dag, &shared, &[]).unwrap() };

    let remote = Arc::new(MemoryBlob::new());

    // 4. Owner re-unlocks the shared anchor → a signing sealer, and writes a signed delta.
    let ou = DagVault
        .unlock(&VaultContext { tree_id: &tree, member_id: &owner_id, replica_id: &ro }, &shared, &owner_pass)
        .unwrap();
    let mut owner = AppCore::new(ou.did_key.into_string(), ou.sealer, Arc::new(MemoryBlob::new()), DOC, b"ro");
    owner.set_membership(resolver()).unwrap();
    owner.tree_mut().assert_anchor("pSigned", PERSON, 1).unwrap();
    owner.commit().unwrap();
    push(&owner, &remote);

    // 5. Forgery: unlock the SOLO (pre-share) anchor on a distinct replica → a non-signing sealer with the
    //    shared DEK; its write is unsigned/unattributed and must be rejected on the shared tree.
    let rf = ReplicaId::new(b"rf".to_vec());
    let fu = DagVault
        .unlock(&VaultContext { tree_id: &tree, member_id: &owner_id, replica_id: &rf }, &solo, &owner_pass)
        .unwrap();
    let mut forger = AppCore::new(fu.did_key.into_string(), fu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rf");
    forger.tree_mut().assert_anchor("pForged", PERSON, 2).unwrap();
    forger.commit().unwrap();
    push(&forger, &remote);

    // 6. Bob unlocks as a member (dag ignores trusted_signers) and verifies against the shared anchor.
    let bu = sharing::unlock_as_member(
        EngineKind::Dag,
        &shared,
        &bob_pass,
        &keyeo_crypto::codec::encode_kdf_params(&bob.kdf_params),
        TREE,
        "acct-bob",
        &[],
        b"rb",
        0,
    )
    .unwrap();
    let mut bob_core = AppCore::new(bu.did_key, bu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rb");
    bob_core.set_membership(resolver()).unwrap();
    pull(&mut bob_core, &remote);

    assert!(live_ids(&bob_core).contains("pSigned"), "a signed member write on the shared dag tree is accepted");
    assert!(!live_ids(&bob_core).contains("pForged"), "an unsigned write on the shared dag tree is rejected");
    assert!(bob_core.anomalies() >= 1, "the rejected forgery is surfaced as an anomaly");
}

#[test]
fn a_cover_lets_a_removed_members_history_verify_on_a_fresh_replica() {
    // SH-2: the data-channel self-heal, end-to-end through the remote. A member writes a signed entry, is
    // removed, and a Maintainer authors a Cover blessing that entry. A fresh replica resolving the ROTATED
    // anchor (member gone) drops the entry as UnknownAuthor UNLESS the cover, folded first, lets it verify. A
    // control replica that pulls BEFORE the cover is published drops it, proving the cover is load-bearing.
    use openom_crypto::Passphrase;
    use openom_keyring_api::EngineKind;
    use openom_protocol::ids::MemberId;
    use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
    use openom_vault::{resolver_from, sharing, vault, DagVault, MembershipResolver};

    const TREE: &[u8] = b"tree-uuid-16byte";
    let tree = TreeId::new(TREE.to_vec());
    let owner_id = MemberId::new("acct-owner");
    let owner_pass = Passphrase::new(b"owner passphrase".to_vec());
    let ro = ReplicaId::new(b"ro".to_vec());
    let ctx_ro = VaultContext { tree_id: &tree, member_id: &owner_id, replica_id: &ro };

    // Provision, share (add bob as Maintainer — the role that commits deltas directly), bob writes a signed
    // entry.
    let solo = DagVault.provision(&ctx_ro, &owner_pass).unwrap().anchor;
    let bob_pass = Passphrase::new(b"bob passphrase".to_vec());
    let bob = vault::provision_member(&bob_pass).unwrap();
    let shared = sharing::add_member(
        EngineKind::Dag, &solo, &owner_pass, TREE, "acct-owner", b"ro", 0, "acct-bob", "maintainer",
        &bob.author_public_key, &bob.hpke_public_key,
    )
    .unwrap()
    .keyring;

    let remote = Arc::new(MemoryBlob::new());
    let bu = sharing::unlock_as_member(
        EngineKind::Dag, &shared, &bob_pass, &keyeo_crypto::codec::encode_kdf_params(&bob.kdf_params),
        TREE, "acct-bob", &[], b"rb", 0,
    )
    .unwrap();
    let mut bob_core = AppCore::new(bu.did_key, bu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rb");
    bob_core.tree_mut().assert_anchor("pBob", PERSON, 1).unwrap();
    bob_core.commit().unwrap();
    push(&bob_core, &remote);

    // The owner opens the shared tree, pulls + accepts bob's entry (bob is a current member), then removes bob.
    let ou = DagVault.unlock(&ctx_ro, &shared, &owner_pass).unwrap();
    let mut owner = AppCore::new(ou.did_key.into_string(), ou.sealer, Arc::new(MemoryBlob::new()), DOC, b"ro");
    owner.set_membership(resolver_from(EngineKind::Dag, &shared, &[]).unwrap()).unwrap();
    pull(&mut owner, &remote);
    assert!(live_ids(&owner).contains("pBob"), "owner accepted bob's entry while bob was a member");

    let rotated = DagVault.remove_member(&ctx_ro, &shared, &owner_pass, "acct-bob").unwrap();
    owner.set_membership(resolver_from(EngineKind::Dag, &rotated, &[]).unwrap()).unwrap();

    // A resolver over the ROTATED anchor (bob is no longer a member).
    let resolver = || -> Box<dyn MembershipResolver> { resolver_from(EngineKind::Dag, &rotated, &[]).unwrap() };

    // Control: a fresh replica pulls the remote BEFORE the cover exists → bob's now-unattributed entry drops.
    let mut control = fresh_owner_replica(&rotated, &owner_pass, &tree, b"r1");
    control.set_membership(resolver()).unwrap();
    pull(&mut control, &remote);
    assert!(!live_ids(&control).contains("pBob"), "without a cover, a removed member's entry is dropped");
    assert!(control.anomalies() >= 1);

    // The owner (a Maintainer) authors a Cover over bob's entry and publishes it to the remote.
    assert!(owner.author_cover().unwrap(), "a cover is authored for the removed member");
    push(&owner, &remote);

    // Healed: a fresh replica pulls the remote WITH the cover → the cover folds first and blesses bob's entry.
    let mut healed = fresh_owner_replica(&rotated, &owner_pass, &tree, b"r2");
    healed.set_membership(resolver()).unwrap();
    pull(&mut healed, &remote);
    assert!(live_ids(&healed).contains("pBob"), "the cover lets the removed member's history verify");
    assert_eq!(healed.anomalies(), 0, "nothing is rejected — the cover is honored, and it is not a forgery");
    // The cover itself is projection-inert: it is not a claim.
    assert!(!live_ids(&healed).contains("acct-bob"));

    // Pin P6 — the covered-accept gate distinguishes a legitimately-removed member (whose Add is effective, so
    // their history MAY be covered) from someone who was NEVER a legitimate member (never coverable).
    let r = resolver();
    assert!(r.ever_member_info("acct-bob").is_some(), "a legitimately added-then-removed member is an ever-member");
    assert!(r.ever_member_info("acct-never").is_none(), "someone never admitted is not an ever-member → not coverable");
}

#[test]
fn the_writer_authors_a_cover_that_heals_a_removed_members_history() {
    // SH-3: the self-heal WRITER, idempotence. An owner holds a member's entry, removes the member, and
    // author_cover() mints a signed Cover over it — a second sweep finds nothing left to cover.
    use openom_crypto::Passphrase;
    use openom_keyring_api::EngineKind;
    use openom_protocol::ids::MemberId;
    use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
    use openom_vault::{resolver_from, sharing, vault, DagVault, MembershipResolver};

    const TREE: &[u8] = b"tree-uuid-16byte";
    let tree = TreeId::new(TREE.to_vec());
    let owner = MemberId::new("acct-owner");
    let owner_pass = Passphrase::new(b"owner passphrase".to_vec());
    let ro = ReplicaId::new(b"ro".to_vec());
    let ctx_ro = VaultContext { tree_id: &tree, member_id: &owner, replica_id: &ro };

    // Provision, share (add bob as Maintainer — the role that commits deltas directly); bob writes an entry.
    let solo = DagVault.provision(&ctx_ro, &owner_pass).unwrap().anchor;
    let bob_pass = Passphrase::new(b"bob passphrase".to_vec());
    let bob = vault::provision_member(&bob_pass).unwrap();
    let shared = sharing::add_member(
        EngineKind::Dag, &solo, &owner_pass, TREE, "acct-owner", b"ro", 0, "acct-bob", "maintainer",
        &bob.author_public_key, &bob.hpke_public_key,
    )
    .unwrap()
    .keyring;

    let remote = Arc::new(MemoryBlob::new());
    let bu = sharing::unlock_as_member(
        EngineKind::Dag, &shared, &bob_pass, &keyeo_crypto::codec::encode_kdf_params(&bob.kdf_params),
        TREE, "acct-bob", &[], b"rb", 0,
    )
    .unwrap();
    let mut bob_core = AppCore::new(bu.did_key, bu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rb");
    bob_core.tree_mut().assert_anchor("pBob", PERSON, 1).unwrap();
    bob_core.commit().unwrap();
    push(&bob_core, &remote);

    // The OWNER opens the shared tree, pulls + accepts + stores bob's entry (bob is a current member).
    let ou = DagVault.unlock(&ctx_ro, &shared, &owner_pass).unwrap();
    let mut owner_core = AppCore::new(ou.did_key.into_string(), ou.sealer, Arc::new(MemoryBlob::new()), DOC, b"ro");
    owner_core.set_membership(resolver_from(EngineKind::Dag, &shared, &[]).unwrap()).unwrap();
    pull(&mut owner_core, &remote);
    assert!(live_ids(&owner_core).contains("pBob"), "owner accepted bob's entry while bob was a member");

    // Owner removes bob, refreshes its resolver → bob is no longer current (but is an ever-member).
    let rotated = DagVault.remove_member(&ctx_ro, &shared, &owner_pass, "acct-bob").unwrap();
    owner_core.set_membership(resolver_from(EngineKind::Dag, &rotated, &[]).unwrap()).unwrap();

    // THE WRITER: author a cover over bob's (now-removed) entry, then confirm a second sweep is idempotent.
    assert!(owner_core.author_cover().unwrap(), "a cover is authored for the removed member");
    assert!(!owner_core.author_cover().unwrap(), "a second sweep is idempotent — nothing left to cover");
    push(&owner_core, &remote);

    // A fresh replica on the rotated anchor honors the authored cover — bob's history verifies.
    let resolver = || -> Box<dyn MembershipResolver> { resolver_from(EngineKind::Dag, &rotated, &[]).unwrap() };
    let mut healed = fresh_owner_replica(&rotated, &owner_pass, &tree, b"r9");
    healed.set_membership(resolver()).unwrap();
    pull(&mut healed, &remote);
    assert!(live_ids(&healed).contains("pBob"), "the authored cover heals the removed member's history");
    assert_eq!(healed.anomalies(), 0, "the authored cover is honored, nothing rejected");
}

/// The `H(ciphertext)` of the (first) `Delta` in `store` authored by `author` — for a test to bind a cover to
/// a specific entry without going through the writer's gate.
fn delta_hash_by_author(store: &Arc<MemoryBlob>, author: &str) -> Vec<u8> {
    use openom_protocol::v1::Envelope;
    use openom_protocol::Message;
    use sha2::Digest;
    for (k, _e) in store.list("tree/log/").unwrap() {
        let (bytes, _e) = store.get(&k).unwrap().unwrap();
        let env = Envelope::decode(bytes.as_slice()).unwrap();
        if env.header.as_ref().is_some_and(|h| h.author_member_id == author) {
            return sha2::Sha256::digest(&env.ciphertext).to_vec();
        }
    }
    panic!("no delta by {author} in the store");
}

/// Share a dag tree with `bob` at `role`, have bob write a signed `pBob` Delta and push it to a fresh remote,
/// then have the owner open + remove bob. Returns `(remote, owner_core_on_rotated, rotated_anchor, owner_pass,
/// tree_id)` — the common prelude for the two below-role self-heal regressions.
fn shared_then_bob_removed(
    role: &str,
) -> (Arc<MemoryBlob>, AppCore<MemoryBlob>, Vec<u8>, openom_crypto::Passphrase, TreeId) {
    use openom_crypto::Passphrase;
    use openom_keyring_api::EngineKind;
    use openom_protocol::ids::MemberId;
    use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
    use openom_vault::{resolver_from, sharing, vault, DagVault};

    const TREE: &[u8] = b"tree-uuid-16byte";
    let tree = TreeId::new(TREE.to_vec());
    let owner = MemberId::new("acct-owner");
    let owner_pass = Passphrase::new(b"owner passphrase".to_vec());
    let ro = ReplicaId::new(b"ro".to_vec());
    let ctx_ro = VaultContext { tree_id: &tree, member_id: &owner, replica_id: &ro };

    let solo = DagVault.provision(&ctx_ro, &owner_pass).unwrap().anchor;
    let bob_pass = Passphrase::new(b"bob passphrase".to_vec());
    let bob = vault::provision_member(&bob_pass).unwrap();
    let shared = sharing::add_member(
        EngineKind::Dag, &solo, &owner_pass, TREE, "acct-owner", b"ro", 0, "acct-bob", role,
        &bob.author_public_key, &bob.hpke_public_key,
    )
    .unwrap()
    .keyring;

    let remote = Arc::new(MemoryBlob::new());
    let bu = sharing::unlock_as_member(
        EngineKind::Dag, &shared, &bob_pass, &keyeo_crypto::codec::encode_kdf_params(&bob.kdf_params),
        TREE, "acct-bob", &[], b"rb", 0,
    )
    .unwrap();
    let mut bob_core = AppCore::new(bu.did_key, bu.sealer, Arc::new(MemoryBlob::new()), DOC, b"rb");
    bob_core.tree_mut().assert_anchor("pBob", PERSON, 1).unwrap();
    bob_core.commit().unwrap();
    push(&bob_core, &remote);

    let ou = DagVault.unlock(&ctx_ro, &shared, &owner_pass).unwrap();
    let mut owner_core = AppCore::new(ou.did_key.into_string(), ou.sealer, Arc::new(MemoryBlob::new()), DOC, b"ro");
    owner_core.set_membership(resolver_from(EngineKind::Dag, &shared, &[]).unwrap()).unwrap();
    pull(&mut owner_core, &remote);

    let rotated = DagVault.remove_member(&ctx_ro, &shared, &owner_pass, "acct-bob").unwrap();
    owner_core.set_membership(resolver_from(EngineKind::Dag, &rotated, &[]).unwrap()).unwrap();
    (remote, owner_core, rotated, owner_pass, tree)
}

#[test]
fn a_removed_editors_planted_delta_is_refused_by_the_cover_writer() {
    // H1, writer side: an Editor is below the Maintainer a Delta requires, so their direct delta is §B3-rejected
    // (never folded) — yet it sits in the dumb-mirror store. author_cover must REFUSE to bless it (it covers only
    // what the reader would accept), so a routine removal can't activate a below-role member's planted write.
    let (_remote, mut owner_core, _rotated, _pass, _tree) = shared_then_bob_removed("editor");
    assert!(!live_ids(&owner_core).contains("pBob"), "an editor's direct delta is role-rejected, never folded");
    assert!(
        !owner_core.author_cover().unwrap(),
        "author_cover refuses to bless a below-Maintainer's planted delta — the writer/reader coupling holds"
    );
}

#[test]
fn a_compromised_maintainers_cover_cannot_heal_a_removed_editors_delta() {
    // H1, reader side (defense in depth): even a COMPROMISED but currently-legitimate Maintainer who force-mints
    // a cover over a removed Editor's planted delta cannot make a fresh replica accept it — the reader resolves
    // the author's STRONGEST role (Editor) from its own membership, not the cover, and rejects on role.
    use openom_keyring_api::EngineKind;
    use openom_protocol::v1::{CoverBody, CoveredEntry};
    use openom_vault::{resolver_from, MembershipResolver};

    let (remote, mut owner_core, rotated, owner_pass, tree) = shared_then_bob_removed("editor");

    // A compromised Maintainer force-covers the editor's plant (author_cover itself would refuse — proven above).
    let hash = delta_hash_by_author(&remote, "acct-bob");
    owner_core
        .push_raw_cover_for_test(&CoverBody {
            entries: vec![CoveredEntry {
                ciphertext_hash: hash,
                author_member_id: "acct-bob".into(),
            }],
        })
        .unwrap();
    push(&owner_core, &remote);

    let resolver = || -> Box<dyn MembershipResolver> { resolver_from(EngineKind::Dag, &rotated, &[]).unwrap() };
    // Sanity: bob is a genuine ever-member (so the rejection is the ROLE gate, not the P6 ever-member gate).
    assert!(resolver().ever_member_info("acct-bob").is_some());

    let mut fresh = fresh_owner_replica(&rotated, &owner_pass, &tree, b"r7");
    fresh.set_membership(resolver()).unwrap();
    pull(&mut fresh, &remote);
    assert!(!live_ids(&fresh).contains("pBob"), "the reader rejects a below-role author's entry despite a cover");
    assert!(fresh.anomalies() >= 1, "the forced cover doesn't launder the role check — the plant is still rejected");
}

/// A fresh owner replica over the rotated dag anchor (a new device: owner unlock + a fresh store/replica).
fn fresh_owner_replica(
    anchor: &[u8],
    pass: &openom_crypto::Passphrase,
    tree: &TreeId,
    replica: &'static [u8],
) -> AppCore<MemoryBlob> {
    use openom_protocol::ids::MemberId;
    use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
    let u = openom_vault::DagVault
        .unlock(
            &VaultContext {
                tree_id: tree,
                member_id: &MemberId::new("acct-owner"),
                replica_id: &ReplicaId::new(replica.to_vec()),
            },
            anchor,
            pass,
        )
        .unwrap();
    AppCore::new(u.did_key.into_string(), u.sealer, Arc::new(MemoryBlob::new()), DOC, replica)
}

fn json_name(given: &str) -> serde_json::Value {
    serde_json::json!({ "parts": { "given": given } })
}
