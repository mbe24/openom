//! The claim-model sync client — openom's binding of the generic [`docsync`] loop.
//!
//! A claim update **is** a delta — an op-based change — so it seals as a `Kind::Delta` entry with
//! `Format::OpenomOps`, appends to the tree's one log, and is deduped by the replica dot like any other
//! delta. The payload is a batch of [`ChannelItem`]s (from `openom-data-crdt`); inbound, they accumulate into
//! the engine's set and its `materialize` fold produces the live record set the projection reads.
//!
//! The push / pull / compact / bootstrap loop itself lives in [`docsync`]; openom supplies two seams:
//!  - [`SyncTree`] — `impl docsync::Engine`, a THIN newtype that **delegates to [`openom_data_tree::Tree`]**,
//!    the one claim engine (mint + set + fold + read model). No second op-set, no second fold: `Tree` owns
//!    the HLC clock and observes it on `merge`, so the receive rule holds — which is exactly why the engine
//!    lives in `Tree` and not here.
//!  - [`SealerAdapter`] — `impl docsync::Sealer` over `openom-sealer`, mapping the generic entry kind to
//!    openom's `Format` and reading `covers_through_seq` back out of a snapshot header (openom-data-tree is
//!    keyless, so this bridge has no equivalent there — it is genuinely this crate's job).
//!
//! **Single-engine-per-app-instance:** the whole app runs the claim engine, so this client's log carries
//! only claim entries — no mixed-kind routing.

use std::collections::BTreeSet;

use store_log::DocStore;
use openom_data_crdt::ChannelItem;
use openom_protocol::v1::{Compression, Envelope, Format};
use openom_protocol::Message;
use openom_sealer::{EntryKind, SealContext, SealerError, SealerSet};
use openom_data_tree::{Tree, TreeError};
use serde_json::Value;

use crate::Result;

/// Transport-side codec bits: the wire [`FORMAT`](codec::FORMAT) tag, plus the batch `encode` re-exported
/// from [`openom_data_crdt::codec`] — the one place the op-batch codec lives, shared with the `openom-data-tree`
/// engine so both emit byte-identical bytes (and a CBOR swap, OPE-199, touches it once). Decoding is the
/// engine's job now (Tree's clock-observing `merge`), so only the local-encode + the tag live here.
pub mod codec {
    /// The wire `Format` tag for claim entries (`FORMAT_OPENOM_OPS` = "JSON op-log entries").
    pub const FORMAT: openom_protocol::v1::Format = openom_protocol::v1::Format::OpenomOps;

    pub use openom_data_crdt::codec::encode;
}

/// The [`docsync::Engine`] seam for the claim model — a thin newtype over [`openom_data_tree::Tree`] that the
/// generic loop drives. It holds NO state of its own: the op-set, the moderator-honoring `materialize`
/// fold, the byte-preserving snapshot, and — crucially — the HLC clock (observed on every `merge`) all
/// live in `Tree`.
pub struct SyncTree(Tree);

impl docsync::Engine for SyncTree {
    /// A local edit is a pre-minted batch of channel items (minting — id + HLC + author — is `Tree`'s job,
    /// done before the batch reaches the transport).
    type Edit = Vec<ChannelItem>;
    type Error = TreeError;

    fn apply_local(&mut self, edit: Vec<ChannelItem>) -> Vec<u8> {
        if edit.is_empty() {
            return Vec::new();
        }
        // Encode the batch as the delta, then apply it through `Tree::merge` so the clock observes the ops
        // and the live view reflects them immediately; the bytes are what the transport seals.
        let bytes = codec::encode(&edit).expect("op-batch JSON encoding is infallible for valid items");
        self.0
            .merge(&bytes)
            .expect("re-merging a freshly-encoded local batch is infallible");
        bytes
    }

    fn merge(&mut self, delta: &[u8]) -> std::result::Result<(), TreeError> {
        self.0.merge(delta).map(|_| ())
    }

    fn snapshot(&self) -> Vec<u8> {
        self.0
            .snapshot()
            .expect("snapshot JSON encoding is infallible for valid records")
    }

    fn merge_snapshot(&mut self, bytes: &[u8]) -> std::result::Result<(), TreeError> {
        self.0.load_snapshot(bytes)
    }
}

/// Adapts openom's DEK [`SealerSet`] to the [`docsync::Sealer`] seam: maps the generic entry kind to
/// openom's `Format` (op-log for deltas, JSON for snapshots), fills the openom-only
/// `compression`/`blob_id` fields, and reads `covers_through_seq` back out of a snapshot envelope's
/// header. A `SealerSet` (not a single `Sealer`) so reads route across epochs after a key rotation while
/// writes always target the latest epoch.
struct SealerAdapter(SealerSet);

impl docsync::Sealer for SealerAdapter {
    type Error = SealerError;

    fn seal(
        &mut self,
        ctx: &docsync::SealCtx,
        plaintext: &[u8],
    ) -> std::result::Result<docsync::Sealed, SealerError> {
        let (kind, format) = match ctx.kind {
            docsync::EntryKind::Delta => (EntryKind::Delta, codec::FORMAT),
            docsync::EntryKind::Snapshot => (EntryKind::Snapshot, Format::OpenomJson),
            // A Cover body is a proto CoverBody (same op-batch codec framing as a delta plaintext).
            docsync::EntryKind::Cover => (EntryKind::Cover, codec::FORMAT),
        };
        let oc = SealContext {
            kind,
            format,
            compression: Compression::None,
            replica_counter: ctx.replica_counter,
            prev_ciphertext_hash: ctx.prev_ciphertext_hash.clone(),
            covers_through_seq: ctx.covers_through_seq,
            blob_id: Vec::new(),
        };
        let out = self.0.seal_entry(&oc, plaintext)?;
        Ok(docsync::Sealed {
            envelope: out.envelope,
            ciphertext_hash: out.ciphertext_hash,
        })
    }

    fn open(
        &self,
        kind: docsync::EntryKind,
        envelope: &[u8],
    ) -> std::result::Result<Vec<u8>, SealerError> {
        let k = match kind {
            docsync::EntryKind::Delta => EntryKind::Delta,
            docsync::EntryKind::Snapshot => EntryKind::Snapshot,
            docsync::EntryKind::Cover => EntryKind::Cover,
        };
        self.0.open_entry(k, envelope)
    }

    fn covers_through_seq(&self, snapshot_envelope: &[u8]) -> u64 {
        Envelope::decode(snapshot_envelope)
            .ok()
            .and_then(|e| e.header)
            .map_or(0, |h| h.covers_through_seq)
    }
}

/// One device's view of a claim-model tree — a facade over [`docsync::SyncClient`] wired with a
/// [`SyncTree`] (delegating to [`openom_data_tree::Tree`]) and openom's sealer.
///
/// Preserves the claim-model API (`push_claims` / `pull_claims` / `compact_claims` / `bootstrap_claims` /
/// `set_moderators`), and exposes the wrapped [`Tree`] for the app's mint + projection paths.
pub struct SyncClient<S: DocStore> {
    inner: docsync::SyncClient<SyncTree, SealerAdapter, S>,
}

impl<S: DocStore> SyncClient<S> {
    /// Wrap a freshly-unlocked claim tree. `created_by` is this device's author `did:key` (the [`Tree`]'s
    /// mint author); `doc` is the store key for this tree's log.
    pub fn new(
        created_by: impl Into<String>,
        sealer: SealerSet,
        store: S,
        doc: impl Into<String>,
    ) -> Self {
        Self {
            inner: docsync::SyncClient::new(
                SyncTree(Tree::new(created_by)),
                SealerAdapter(sealer),
                store,
                doc,
            ),
        }
    }

    /// The wrapped engine (for the app's mint / projection paths — `assert_claim`, `project`, …).
    pub const fn tree(&self) -> &Tree {
        &self.inner.engine().0
    }

    /// The wrapped engine, mutably (mint through it; the transport picks the ops up on `flush`).
    pub const fn tree_mut(&mut self) -> &mut Tree {
        &mut self.inner.engine_mut().0
    }

    /// Set the moderator `did:key`s (members currently at Maintainer or above) whose
    /// Remove/Supersede/Revoke ops the fold honors — from the governing keyring.
    pub fn set_moderators(&mut self, moderators: BTreeSet<String>) {
        self.inner.engine_mut().0.set_moderators(moderators);
    }

    /// Splice newly-reachable epoch DEKs into the running sealer after a rotation — a member's epoch ADOPT
    /// (OPE-393). Delegates to [`openom_sealer::SealerSet::adopt_epochs`]. Returns how many NEW epochs were
    /// added (0 if the sealer already held them all — idempotent).
    pub fn adopt_epochs(
        &mut self,
        epochs: Vec<(Vec<u8>, openom_sealer::Key32)>,
        write_key_id: Vec<u8>,
        governing_ref: Vec<u8>,
    ) -> usize {
        self.inner
            .sealer_mut()
            .0
            .adopt_epochs(epochs, write_key_id, governing_ref)
    }

    /// The live record set as JSON — the fold's output the projection reads.
    ///
    /// # Errors
    /// Returns a [`TreeError`] if the live set can't be serialized.
    pub fn live_records(&self) -> std::result::Result<Vec<Value>, TreeError> {
        self.inner.engine().0.live_records()
    }

    /// Seal a batch of channel items as one `Kind::Delta` / `Format::OpenomOps` entry, apply it to the
    /// local set, queue it, and flush. Seal + chain-advance happen exactly once; a failed flush leaves the
    /// sealed envelope queued for a byte-identical retry.
    ///
    /// # Errors
    /// Returns an error if sealing or the store append fails.
    pub fn push_claims(&mut self, items: &[ChannelItem]) -> Result<()> {
        self.inner.apply(items.to_vec())
    }

    /// Seal an already-encoded op-batch (from [`Tree::flush`](openom_data_tree::Tree::flush)) and append
    /// it, without re-merging — the engine minted and folded the batch itself. This is the app's mint
    /// path: mint through [`tree_mut`](Self::tree_mut), `flush` to bytes, then `push_delta`. An empty
    /// batch (nothing minted) is a no-op.
    ///
    /// # Errors
    /// Returns an error if sealing or the store append fails.
    pub fn push_delta(&mut self, batch: &[u8]) -> Result<()> {
        self.inner.push_delta(batch)
    }

    /// Append every queued sealed envelope, oldest first. A failed append leaves it (and the rest) queued;
    /// call again to retry — a re-appended entry dedups on the dot and re-folds idempotently.
    ///
    /// # Errors
    /// Returns an error if the store push fails (the entry stays queued for a later retry).
    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    /// How many sealed batches are queued but not yet confirmed appended (0 == fully synced up).
    pub const fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// How many log entries have been quarantined (skipped as un-openable / un-mergeable) — a corrupt
    /// or wrong-key entry that would otherwise wedge the pull. A caller surfaces a non-zero count.
    pub const fn quarantined_count(&self) -> usize {
        self.inner.quarantined_count()
    }

    /// Open a `Delta` envelope to its plaintext without merging — for §B3 author verification before
    /// the entry is accepted into the store.
    ///
    /// # Errors
    /// Returns an error if the sealer can't open the envelope.
    pub fn try_open_delta(&self, envelope: &[u8]) -> Result<Vec<u8>> {
        self.inner.try_open_delta(envelope)
    }

    /// Open a `Cover` (self-heal marker) envelope to its plaintext without merging — to verify + fold its
    /// body into the covered set.
    ///
    /// # Errors
    /// Returns an error if the sealer can't open the envelope.
    pub fn try_open_cover(&self, envelope: &[u8]) -> Result<Vec<u8>> {
        self.inner.try_open_cover(envelope)
    }

    /// Seal a self-heal `Cover` marker (advancing this replica's chain, not stored locally) — the caller
    /// pushes the returned envelope to the server's log.
    ///
    /// # Errors
    /// Returns an error if sealing fails.
    pub fn seal_cover(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.seal_cover(plaintext)
    }

    /// Pull every log entry newer than the last pull, decode each into channel items, and merge them.
    /// Returns how many **log entries** were pulled. Idempotent — re-reading our own or a duplicate entry
    /// re-inserts by id. From a fresh client this replays the whole log (the journal is authority).
    ///
    /// # Errors
    /// Returns an error if the store read or a decode fails.
    pub fn pull_claims(&mut self) -> Result<usize> {
        self.inner.pull()
    }

    /// Publish a snapshot of the live record set (the byte-preserving fold), CAS'd on the prior snapshot
    /// version and stamped with the log seq it covers. Pull first so the snapshot reflects the whole log.
    /// Returns the covered seq.
    ///
    /// # Errors
    /// Returns an error if snapshotting or the store write fails.
    pub fn compact_claims(&mut self) -> Result<u64> {
        self.inner.compact()
    }

    /// Bring a fresh client up to date: load the stored snapshot (if any) into the set, then pull only the
    /// ops after the seq it covers. Falls back to a full log replay when there is no snapshot.
    ///
    /// # Errors
    /// Returns an error if the store read or a decode fails.
    pub fn bootstrap_claims(&mut self) -> Result<()> {
        self.inner.bootstrap()
    }
}

impl<S: DocStore> std::fmt::Debug for SyncClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncClient")
            .field("pending", &self.inner.pending_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::SyncClient;
    use store_log::memory::MemoryStore;
    use store_log::DocStore;
    use openom_data_model::envelope::{Claim, Record};
    use openom_data_model::Hlc;
    use openom_data_crdt::{ChannelItem, Op, OpKind};
    use openom_crypto::{generate_dek, Dek};
    use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
    use openom_sealer::{Sealer, SealerSet};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    // The Tree's `created_by` is this device's author did:key. It is irrelevant to these tests: they push
    // PRE-BUILT items that carry their own explicit `createdBy`, so the device author never authors anything.
    const DEVICE: &str = "did:key:z6MkDevice";

    fn client(replica: &[u8], dek: Dek, store: Arc<MemoryStore>) -> SyncClient<Arc<MemoryStore>> {
        let sealer = Sealer::from_unwrapped(
            1,
            dek.into_inner(),
            TreeId::new(b"tree-uuid-16byte".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
            ReplicaId::new(replica.to_vec()),
        );
        SyncClient::new(DEVICE, SealerSet::single(sealer), store, "tree")
    }

    /// A logical-counter-zero HLC at `ms` epoch-milliseconds, for test fixtures.
    fn hlc(ms: i64) -> Hlc {
        Hlc::new(ms, 0)
    }

    fn person(id: &str, author: &str) -> ChannelItem {
        ChannelItem::Assert(
            Record::try_from(json!({
                "id": id, "type": "openom.org/core/person/v1",
                "createdAt": hlc(1).to_string(), "createdBy": author,
            }))
            .unwrap(),
        )
    }

    fn name_claim(target: &str, given: &str, author: &str, at: i64) -> ChannelItem {
        let mut c = Claim::new(
            target,
            "openom.org/core/name/v1",
            json!({ "given": given }),
            author,
            hlc(at),
        );
        c.compute_id().unwrap();
        ChannelItem::Assert(Record::Claim(c))
    }

    fn remove(target: &ChannelItem, author: &str) -> ChannelItem {
        ChannelItem::Op(
            Op::new(
                hlc(2),
                author,
                OpKind::Remove {
                    target: target.id().to_owned(),
                },
            )
            .unwrap(),
        )
    }

    /// The live record ids after the fold — read through the wrapped Tree.
    fn live(c: &SyncClient<Arc<MemoryStore>>) -> BTreeSet<String> {
        c.live_records()
            .unwrap()
            .into_iter()
            .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_owned))
            .collect()
    }

    fn empty(c: &SyncClient<Arc<MemoryStore>>) -> bool {
        c.live_records().unwrap().is_empty()
    }

    fn set(items: &[&ChannelItem]) -> BTreeSet<String> {
        items.iter().map(|i| i.id().to_owned()).collect()
    }

    #[test]
    fn two_devices_converge_through_the_claim_stack() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        let mut b = client(b"replica-b", dek, store.clone());

        let pa = person("pA", "did:key:z6MkA");
        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        let nb = name_claim("pA", "Ada Lovelace", "did:key:z6MkB", 2);

        a.push_claims(&[pa.clone(), na.clone()]).unwrap();
        b.push_claims(std::slice::from_ref(&nb)).unwrap();
        a.pull_claims().unwrap();
        b.pull_claims().unwrap();

        assert_eq!(live(&a), live(&b), "both devices converge");
        assert_eq!(live(&a), set(&[&pa, &na, &nb]));
    }

    #[test]
    fn pull_is_idempotent() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        a.push_claims(&[name_claim("pA", "Ada", "did:key:z6MkA", 1)])
            .unwrap();

        let mut b = client(b"replica-b", dek, store.clone());
        assert_eq!(b.pull_claims().unwrap(), 1);
        let before = live(&b);
        assert_eq!(b.pull_claims().unwrap(), 0, "nothing new the second time");
        assert_eq!(live(&b), before);
    }

    #[test]
    fn a_moderator_remove_syncs_and_drops_the_record() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        let mut b = client(b"replica-b", dek, store.clone());
        let mods = BTreeSet::from(["did:key:z6MkA".to_string()]);
        a.set_moderators(mods.clone());
        b.set_moderators(mods);

        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        a.push_claims(std::slice::from_ref(&na)).unwrap();
        b.pull_claims().unwrap();
        assert_eq!(live(&b), set(&[&na]));

        a.push_claims(&[remove(&na, "did:key:z6MkA")]).unwrap();
        b.pull_claims().unwrap();
        assert!(empty(&b), "the remove propagated");
        assert!(empty(&a));
    }

    #[test]
    fn a_crashed_client_rebuilds_from_the_durable_log() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let pa = person("pA", "did:key:z6MkA");
        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        {
            let mut a = client(b"replica-a", dek.clone(), store.clone());
            a.push_claims(&[pa.clone(), na.clone()]).unwrap();
            // a drops here — the crash. Nothing pushed is lost; it's in the durable log.
        }
        let mut restarted = client(b"replica-a", dek, store.clone());
        restarted.pull_claims().unwrap(); // replays the whole log
        assert_eq!(live(&restarted), set(&[&pa, &na]));
    }

    #[test]
    fn a_duplicate_appended_entry_is_harmless() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        a.push_claims(std::slice::from_ref(&na)).unwrap();
        // A lost-ack retry lands the same sealed entry twice.
        let (updates, _) = store.read_updates("tree", None).unwrap();
        store.append("tree", &updates).unwrap();

        let mut b = client(b"replica-b", dek, store.clone());
        b.pull_claims().unwrap();
        assert_eq!(live(&b), set(&[&na]), "the duplicate must not double the record");
    }

    #[test]
    fn a_wrong_key_quarantines_the_log_instead_of_wedging() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek, store.clone());
        a.push_claims(&[name_claim("pA", "Ada", "did:key:z6MkA", 1)])
            .unwrap();

        // A wrong DEK reveals nothing — and, crucially, does not wedge the pull: the unopenable entry
        // is quarantined and counted, not returned as a fatal error (one bad entry can't brick sync).
        let wrong = generate_dek().unwrap();
        let mut intruder = client(b"replica-x", wrong, store.clone());
        assert_eq!(intruder.pull_claims().unwrap(), 0, "a wrong DEK merges nothing");
        assert!(empty(&intruder), "the wrong key reveals no data");
        assert!(
            intruder.quarantined_count() >= 1,
            "the unopenable entry is quarantined, not fatal"
        );
    }

    #[test]
    fn a_fresh_client_bootstraps_from_a_snapshot_plus_the_tail() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());

        let pa = person("pA", "did:key:z6MkA");
        let pb = person("pB", "did:key:z6MkA");
        a.push_claims(&[pa.clone(), pb.clone()]).unwrap();
        a.compact_claims().unwrap(); // snapshot covers the two people
        let na = name_claim("pA", "Ada", "did:key:z6MkA", 2); // a tail op after the snapshot
        a.push_claims(std::slice::from_ref(&na)).unwrap();

        let mut c = client(b"replica-c", dek, store.clone());
        c.bootstrap_claims().unwrap(); // snapshot (two people) + only the tail (the name)
        assert_eq!(live(&c), live(&a));
        assert_eq!(live(&c), set(&[&pa, &pb, &na]));
    }

    #[test]
    fn bootstrap_without_a_snapshot_replays_the_whole_log() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        let pa = person("pA", "did:key:z6MkA");
        a.push_claims(std::slice::from_ref(&pa)).unwrap();

        let mut c = client(b"replica-c", dek, store.clone());
        c.bootstrap_claims().unwrap(); // no snapshot → full log replay
        assert_eq!(live(&c), set(&[&pa]));
    }

    #[test]
    fn compaction_folds_out_removed_records() {
        // The snapshot is the live set: a moderator-removed record is folded out and never reaches a
        // bootstrapping client (the structural GC horizon — the compaction horizon the owner accepted),
        // while a live record survives.
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        a.set_moderators(BTreeSet::from(["did:key:z6MkA".to_string()]));
        let keep = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        let gone = name_claim("pB", "Zzz", "did:key:z6MkA", 1);
        a.push_claims(&[keep.clone(), gone.clone()]).unwrap();
        a.push_claims(&[remove(&gone, "did:key:z6MkA")]).unwrap();
        a.compact_claims().unwrap();

        // A fresh client bootstraps only from the snapshot (the tail is empty) — the removed record is
        // absent, and the record it never touched survives.
        let mut c = client(b"replica-c", dek, store.clone());
        c.bootstrap_claims().unwrap();
        assert_eq!(live(&c), set(&[&keep]), "removed record folded out of the snapshot");
    }
}
