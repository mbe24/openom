//! Core + replicator tests over `MemoryStore`, driven through a fake server that mimics the real
//! delta-log endpoint (seq assignment + idempotent dedup on the replica dot + `?since` paging). Unlike
//! the docsync tests — which share ONE store between peers — here each core has its OWN local store and
//! the ONLY meeting point is the server, exactly as the deployed client-server topology works.

use super::AppCore;
use openom_crypto::{generate_dek, Dek};
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_protocol::v1::Envelope;
use openom_protocol::Message;
use openom_sealer::{Sealer, SealerSet};
use openom_vault::{Governing, MembershipResolver};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use store_log::memory::MemoryStore;
use store_log::DocStore;

/// A scripted [`MembershipResolver`] double for the ingest-routing tests — it forces one disposition for every
/// entry via the neutral policy's *crypto-free* arms (no keyring, no signature check), so the routing
/// (Accept ⇒ store+fold, Hold ⇒ buffer, Reject ⇒ anomaly+drop) and the Hold-release path can be exercised
/// in isolation. The real crypto decisions are proven against `ChainMembershipResolver`/`DagMembershipResolver` in
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

fn core(replica: &[u8], dek: Dek, store: Arc<MemoryStore>) -> AppCore<MemoryStore> {
    let sealer = Sealer::from_unwrapped(
        1,
        dek.into_inner(),
        TreeId::new(b"tree-uuid-16byte".to_vec()),
        KeyId::new(b"epoch-0".to_vec()),
        ReplicaId::new(replica.to_vec()),
    );
    AppCore::new(DEVICE, SealerSet::single(sealer), store, "tree", replica.to_vec())
}

/// The replica dot `(replica_id, replica_counter)` from a sealed envelope — the server's idempotency key.
fn dot(env: &[u8]) -> (Vec<u8>, u64) {
    let h = Envelope::decode(env).unwrap().header.unwrap();
    (h.replica_id, h.replica_counter)
}

/// A stand-in for the server's `POST/GET /trees/{id}/log`: an append-only log with seq = index+1,
/// idempotent on the replica dot, served by `?since`.
#[derive(Default)]
struct FakeServer {
    log: Vec<Vec<u8>>,
    seq_of: BTreeMap<(Vec<u8>, u64), i64>,
}

impl FakeServer {
    fn append(&mut self, env: Vec<u8>) -> i64 {
        let key = dot(&env);
        if let Some(&seq) = self.seq_of.get(&key) {
            return seq; // idempotent re-delivery: original seq, nothing added
        }
        self.log.push(env);
        let seq = self.log.len() as i64;
        self.seq_of.insert(key, seq);
        seq
    }

    /// Entries with seq > since, plus the new cursor (head seq).
    fn read_log(&self, since: Option<i64>) -> (Vec<Vec<u8>>, i64) {
        let start = usize::try_from(since.unwrap_or(0).max(0)).unwrap();
        let entries = self.log.get(start..).unwrap_or(&[]).to_vec();
        (entries, self.log.len() as i64)
    }
}

/// Push every outbound entry to the server, then advance the cursor (mimics a successful tick).
fn push(core: &mut AppCore<MemoryStore>, server: &mut FakeServer) {
    let out = core.outbound().unwrap();
    for env in out.entries {
        server.append(env);
    }
    core.mark_pushed(out.through);
}

/// Pull the server tail from the core's cursor and fold it in. Returns how many entries folded.
fn pull(core: &mut AppCore<MemoryStore>, server: &FakeServer) -> usize {
    let (entries, next) = server.read_log(core.server_since());
    core.ingest(&entries, next).unwrap()
}

fn live_ids(core: &AppCore<MemoryStore>) -> BTreeSet<String> {
    core.live_records()
        .unwrap()
        .into_iter()
        .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_owned))
        .collect()
}

#[test]
fn two_cores_converge_through_the_server() {
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
    let mut b = core(b"replica-b", dek, Arc::new(MemoryStore::new()));

    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.tree_mut().assert_claim("pA", NAME, json_name("Ada"), 1).unwrap();
    a.commit().unwrap();
    b.tree_mut().assert_anchor("pB", PERSON, 2).unwrap();
    b.commit().unwrap();

    // Each pushes its own; each pulls the other's. Order-free (set-union).
    push(&mut a, &mut server);
    push(&mut b, &mut server);
    pull(&mut a, &server);
    pull(&mut b, &server);

    assert_eq!(live_ids(&a), live_ids(&b), "both devices converge");
    assert!(live_ids(&a).contains("pA") && live_ids(&a).contains("pB"));
}

#[test]
fn an_offline_mint_survives_a_reload() {
    // THE durable-outbox proof. A mints offline and commits (durable in the local store) but never
    // pushes; the whole core is dropped and rebuilt from the local store alone; the mint is still
    // offered outbound, reaches the server, and a peer sees it.
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();
    let store = Arc::new(MemoryStore::new());

    {
        let mut a = core(b"replica-a", dek.clone(), Arc::clone(&store));
        a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
        a.commit().unwrap(); // durable locally — but a is dropped before any push
    }

    // "Reload": a fresh core over the SAME local store, its in-memory push cursor reset.
    let mut a2 = core(b"replica-a", dek.clone(), Arc::clone(&store));
    a2.bootstrap().unwrap();
    assert!(live_ids(&a2).contains("pA"), "the offline mint is back in the engine after reload");

    let out = a2.outbound().unwrap();
    assert!(!out.entries.is_empty(), "the un-pushed offline mint is still offered");
    push(&mut a2, &mut server);

    let mut b = core(b"replica-b", dek, Arc::new(MemoryStore::new()));
    pull(&mut b, &server);
    assert!(live_ids(&b).contains("pA"), "the peer receives the mint that survived the reload");
}

#[test]
fn our_own_entries_are_not_echoed_back_up_or_restored() {
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();
    let store = Arc::new(MemoryStore::new());
    let mut a = core(b"replica-a", dek, Arc::clone(&store));

    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&mut a, &mut server);
    assert_eq!(server.log.len(), 1);

    // A pulls the server tail — which contains only its own entry. It must not re-store it locally...
    let local_before = store.read_updates("tree", None).unwrap().0;
    pull(&mut a, &server);
    let local_after = store.read_updates("tree", None).unwrap().0;
    assert_eq!(local_before, local_after, "our own entry pulled back is not re-appended locally");

    // ...nor re-push it (the server would dedup anyway, but the scan must skip it).
    push(&mut a, &mut server);
    assert_eq!(server.log.len(), 1, "no echo back to the server");
}

#[test]
fn export_then_import_reconstructs_the_core_on_a_fresh_store() {
    // Mirrors what the worker does across a reload: `exportSince` the log to the host (IndexedDB), then
    // on open a FRESH core `importLog`s it into a new store + bootstraps — the data and the un-pushed
    // outbound both come back. This is the durable-outbox guarantee via the persistence seam (no shared
    // Arc, unlike `an_offline_mint_survives_a_reload`).
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();

    // Device A mints offline and commits; the "host" captures the exported log bytes.
    let exported: Vec<Vec<u8>> = {
        let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
        a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
        a.commit().unwrap();
        a.export_since(None).unwrap().0
    };
    assert_eq!(exported.len(), 1, "one committed batch to persist");

    // "Reload": a brand-new core over a fresh store, hydrated only from the persisted bytes.
    let mut a2 = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
    a2.import_log(&exported).unwrap();
    a2.bootstrap().unwrap();
    assert!(live_ids(&a2).contains("pA"), "the persisted mint is back after reload");

    // ...and it's still offered outbound, so it reaches a peer.
    assert!(!a2.outbound().unwrap().entries.is_empty());
    push(&mut a2, &mut server);
    let mut b = core(b"replica-b", dek, Arc::new(MemoryStore::new()));
    pull(&mut b, &server);
    assert!(live_ids(&b).contains("pA"), "the peer receives the reloaded mint");
}

#[test]
fn ingest_is_idempotent() {
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&mut a, &mut server);

    let mut b = core(b"replica-b", dek, Arc::new(MemoryStore::new()));
    assert_eq!(pull(&mut b, &server), 1);
    let before = live_ids(&b);
    // Re-pull from the beginning: nothing new folds, the set is unchanged.
    b.ingest(&server.read_log(None).0, server.read_log(None).1).unwrap();
    assert_eq!(live_ids(&b), before, "re-ingesting the same entries is a no-op");
}

#[test]
fn a_reload_does_not_re_append_peer_entries() {
    // C2 regression: with cursors reset on reload, re-pulling the server tail must NOT re-append peer
    // entries into the local store (dedup on the replica dot), or storage grows without bound.
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();

    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&mut a, &mut server);

    let b_store = Arc::new(MemoryStore::new());
    let mut b = core(b"replica-b", dek.clone(), Arc::clone(&b_store));
    pull(&mut b, &server);
    assert_eq!(b_store.read_updates("tree", None).unwrap().0.len(), 1);

    // "Reload" B from its persisted log (fresh core, cursors reset), then re-pull the same page.
    let exported = b.export_since(None).unwrap().0;
    let reload_store = Arc::new(MemoryStore::new());
    let mut b2 = core(b"replica-b", dek, Arc::clone(&reload_store));
    b2.import_log(&exported).unwrap();
    b2.bootstrap().unwrap();
    pull(&mut b2, &server); // server_cursor is None → re-reads from 0

    assert_eq!(
        reload_store.read_updates("tree", None).unwrap().0.len(),
        1,
        "the peer entry is deduped, not re-appended on a reload re-pull"
    );
    assert!(live_ids(&b2).contains("pA"));
}

#[test]
fn a_poison_entry_is_quarantined_not_wedged() {
    // C3 regression: a wrong-key / corrupt entry on the shared log must not wedge pull for everyone —
    // it is quarantined (surfaced via `anomalies`), and valid entries still merge.
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();

    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
    a.tree_mut().assert_anchor("pGood", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&mut a, &mut server);

    // An intruder writes an entry sealed under a DIFFERENT DEK to the same log.
    let wrong = generate_dek().unwrap();
    let mut x = core(b"replica-x", wrong, Arc::new(MemoryStore::new()));
    x.tree_mut().assert_anchor("pEvil", PERSON, 1).unwrap();
    x.commit().unwrap();
    push(&mut x, &mut server);

    let mut b = core(b"replica-b", dek, Arc::new(MemoryStore::new()));
    pull(&mut b, &server); // must not wedge

    assert!(live_ids(&b).contains("pGood"), "the valid entry still merges");
    assert!(!live_ids(&b).contains("pEvil"), "the wrong-key entry never decrypts into the tree");
    assert!(
        b.anomalies() >= 1,
        "the poison entry is surfaced as an anomaly, not silently dropped or wedging"
    );
}

#[test]
fn reset_clears_the_tree_and_store_then_reseeds_cleanly() {
    let dek = generate_dek().unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut a = core(b"replica-a", dek, Arc::clone(&store));

    a.tree_mut().assert_anchor("pOld", PERSON, 1).unwrap();
    a.commit().unwrap();
    assert!(live_ids(&a).contains("pOld"));
    assert_eq!(store.read_updates("tree", None).unwrap().0.len(), 1);

    a.reset().unwrap();
    assert!(live_ids(&a).is_empty(), "the tree is empty after reset");
    assert_eq!(store.read_updates("tree", None).unwrap().0.len(), 0, "the durable store is cleared");

    // Re-seed cleanly — the new record is there, the old id is not resurrected.
    a.tree_mut().assert_anchor("pNew", PERSON, 2).unwrap();
    a.commit().unwrap();
    assert!(live_ids(&a).contains("pNew"));
    assert!(!live_ids(&a).contains("pOld"), "no resurrected old id after reset+reseed");
}

/// Set up a server holding ONE peer entry (anchor `pA`, authored by replica-a) plus a fresh core B over its
/// own store, sharing the DEK so B can open it. B installs `route` as its §B3 membership before pulling.
fn peer_entry_and_core_b(route: Route) -> (FakeServer, AppCore<MemoryStore>, Arc<MemoryStore>) {
    let dek = generate_dek().unwrap();
    let mut server = FakeServer::default();
    let mut a = core(b"replica-a", dek.clone(), Arc::new(MemoryStore::new()));
    a.tree_mut().assert_anchor("pA", PERSON, 1).unwrap();
    a.commit().unwrap();
    push(&mut a, &mut server);

    let b_store = Arc::new(MemoryStore::new());
    let mut b = core(b"replica-b", dek, Arc::clone(&b_store));
    b.set_membership(Box::new(Fake(route))).unwrap();
    (server, b, b_store)
}

#[test]
fn a_rejected_peer_entry_is_never_stored_folded_or_persisted() {
    // The recovery invariant + the anti-forgery gate: a §B3-rejected entry must not reach the tree, the
    // durable store, or the persistence export — yet the cursor still advances so a forgery can't stall the
    // tail (a reload re-pulls it from the un-pruned server log and re-verifies).
    let (server, mut b, b_store) = peer_entry_and_core_b(Route::Reject);
    pull(&mut b, &server);

    assert!(!live_ids(&b).contains("pA"), "a rejected entry never folds into the tree");
    assert_eq!(
        b_store.read_updates("tree", None).unwrap().0.len(),
        0,
        "a rejected entry is never stored"
    );
    assert_eq!(
        b.export_since(None).unwrap().0.len(),
        0,
        "a rejected entry is never persisted (recovery invariant)"
    );
    assert!(b.anomalies() >= 1, "a rejected forgery is surfaced as an anomaly");
    assert!(b.server_since().is_some(), "the cursor advanced past the forgery");
}

#[test]
fn a_held_peer_entry_is_buffered_then_released_on_set_membership() {
    // Hold ⇒ buffered, unstored, un-folded, and NOT an anomaly; a later set_membership whose resolver now
    // accepts the entry releases it into the store and the tree.
    let (server, mut b, b_store) = peer_entry_and_core_b(Route::Hold);
    pull(&mut b, &server);
    assert!(!live_ids(&b).contains("pA"), "a held entry is not folded");
    assert_eq!(
        b_store.read_updates("tree", None).unwrap().0.len(),
        0,
        "a held entry is not stored"
    );
    assert_eq!(b.anomalies(), 0, "a hold is not an anomaly");

    let folded = b.set_membership(Box::new(Fake(Route::Accept))).unwrap();
    assert_eq!(folded, 1, "the released entry folds in on set_membership");
    assert!(live_ids(&b).contains("pA"), "the released entry is now in the tree");
    assert_eq!(
        b_store.read_updates("tree", None).unwrap().0.len(),
        1,
        "the released entry is now durably stored"
    );
}

#[test]
fn an_accepting_membership_folds_peer_entries_like_the_solo_path() {
    let (server, mut b, _b_store) = peer_entry_and_core_b(Route::Accept);
    assert_eq!(pull(&mut b, &server), 1);
    assert!(live_ids(&b).contains("pA"));
}

#[test]
fn a_shared_tree_accepts_a_signed_member_write_and_rejects_an_unsigned_forgery() {
    // The Half-B payoff: provision a chain tree, SHARE it (add a member), and prove verify-on-ingest goes
    // live end-to-end. A signed write from a member of the shared keyring is accepted on a peer's ingest; an
    // UNSIGNED write on the same shared tree (same DEK, no author signature) is rejected and surfaced.
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

    // A chain resolver over BOTH retained governing revisions: rev 2 (the shared head, which governs the
    // member's signed writes) and rev 1 (the pre-share genesis, which governs the unsigned forgery so it is
    // rejected rather than perpetually held for a not-yet-retained keyring).
    let resolver = || -> Box<dyn MembershipResolver> {
        Box::new(ChainMembershipResolver::new(&rev2, &[(1u32, rev1.clone()), (2u32, rev2.clone())]).unwrap())
    };

    let mut server = FakeServer::default();

    // 4. Owner re-unlocks the SHARED keyring → a sealer that signs (has_been_shared), and writes a signed delta.
    let ou = vault::unlock(&rev2, &owner_pass, &tree, &owner_id, &ReplicaId::new(b"ro".to_vec())).unwrap();
    let mut owner = AppCore::new(
        ou.did_key.into_string(),
        ou.sealer,
        Arc::new(MemoryStore::new()),
        "tree",
        b"ro".to_vec(),
    );
    owner.set_membership(resolver()).unwrap();
    owner.tree_mut().assert_anchor("pSigned", PERSON, 1).unwrap();
    owner.commit().unwrap();
    push(&mut owner, &mut server);

    // 5. THE FORGERY: unlock the pre-share genesis (rev 1) on a DISTINCT replica → a sealer with the shared
    //    DEK that does NOT sign (solo era). Its write is unsigned with an empty governing_ref — a backdate
    //    forgery that, on a shared tree, must be rejected.
    let fu = vault::unlock(&rev1, &owner_pass, &tree, &owner_id, &ReplicaId::new(b"rf".to_vec())).unwrap();
    let mut forger = AppCore::new(
        fu.did_key.into_string(),
        fu.sealer,
        Arc::new(MemoryStore::new()),
        "tree",
        b"rf".to_vec(),
    );
    forger.tree_mut().assert_anchor("pForged", PERSON, 2).unwrap();
    forger.commit().unwrap();
    push(&mut forger, &mut server);

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
    let b_store = Arc::new(MemoryStore::new());
    let mut bob_core = AppCore::new(
        bu.did_key,
        bu.sealer,
        Arc::clone(&b_store),
        "tree",
        b"rb".to_vec(),
    );
    bob_core.set_membership(resolver()).unwrap();
    pull(&mut bob_core, &server);

    assert!(live_ids(&bob_core).contains("pSigned"), "a signed member write on the shared tree is accepted");
    assert!(!live_ids(&bob_core).contains("pForged"), "an unsigned write on the shared tree is rejected");
    assert!(bob_core.anomalies() >= 1, "the rejected forgery is surfaced as an anomaly");
    assert_eq!(
        b_store.read_updates("tree", None).unwrap().0.len(),
        1,
        "only the accepted entry is durably stored"
    );
}

fn json_name(given: &str) -> serde_json::Value {
    serde_json::json!({ "parts": { "given": given } })
}
