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

use store_blob::BlobStore;
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
pub struct SyncClient<S: BlobStore> {
    inner: docsync::BlobSyncClient<SyncTree, SealerAdapter, S>,
}

impl<S: BlobStore> SyncClient<S> {
    /// Wrap a freshly-unlocked claim tree over the Blob seam. `created_by` is this device's author `did:key`
    /// (the [`Tree`]'s mint author); `doc` is the tree's keyspace prefix; `replica` is this device's stable
    /// replica id (the first coordinate of the per-replica dot / the keyspace it owns).
    pub fn new(
        created_by: impl Into<String>,
        sealer: SealerSet,
        store: S,
        doc: impl Into<String>,
        replica: impl Into<String>,
    ) -> Self {
        Self {
            inner: docsync::BlobSyncClient::new(
                SyncTree(Tree::new(created_by)),
                SealerAdapter(sealer),
                store,
                doc,
                replica,
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

    /// Seal a self-heal `Cover` marker as this replica's next log object (OPE-382) — a peer routes it to its
    /// cover-fold on [`pull_verified`](Self::pull_verified) rather than merging it as a claim. Unlike the old
    /// remote model, the cover is WRITTEN here (the object IS the publish); the caller no longer pushes it.
    ///
    /// # Errors
    /// Returns an error if sealing or the blob write fails.
    pub fn push_cover(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.push_cover(plaintext)
    }

    /// Always 0 — a `BlobSyncClient` writes each entry immediately (no seal queue). Kept for the app's
    /// diagnostic surface.
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        0
    }

    /// How many log entries have been quarantined (skipped as un-openable / un-mergeable).
    #[must_use]
    pub const fn quarantined_count(&self) -> usize {
        self.inner.quarantined_count()
    }

    /// How many peer dots are currently HELD (classified un-verifiable, awaiting a re-verify on a later
    /// [`pull_verified`](Self::pull_verified)).
    #[must_use]
    pub fn held_count(&self) -> usize {
        self.inner.held_count()
    }

    /// Open a `Delta` envelope to its plaintext without merging — for §B3 author verification.
    ///
    /// # Errors
    /// Returns an error if the sealer can't open the envelope.
    pub fn try_open_delta(&self, envelope: &[u8]) -> Result<Vec<u8>> {
        self.inner.try_open_delta(envelope)
    }

    /// Open a `Cover` (self-heal marker) envelope to its plaintext without merging.
    ///
    /// # Errors
    /// Returns an error if the sealer can't open the envelope.
    pub fn try_open_cover(&self, envelope: &[u8]) -> Result<Vec<u8>> {
        self.inner.try_open_cover(envelope)
    }

    /// Pull + fold every log object past the inbound frontier (across replicas): each peer `Delta` is gated
    /// by the caller's `classify` (§B3 attribution — `docsync` stays ignorant of it), each `Cover` is routed
    /// to `fold_cover`. A held delta is retried on every later call so a later membership/cover un-holds it,
    /// without blocking the frontier. Returns how many entries folded this call. See
    /// [`docsync::BlobSyncClient::pull_verified`].
    ///
    /// # Errors
    /// Returns an error if a blob read fails.
    pub fn pull_verified(
        &mut self,
        classify: impl FnMut(&[u8], &[u8], &str, u64) -> docsync::Verdict,
        fold_cover: impl FnMut(&[u8], &[u8], &str, u64),
    ) -> Result<usize> {
        self.inner.pull_verified(classify, fold_cover)
    }

    /// Fold current engine state into a snapshot covering this client's SUBSUMED frontier, and write it to
    /// `{doc}/snapshot` (OPE-409 C3). The covered frontier the snapshot publishes is `subsumed_frontier()` —
    /// only entries actually folded into state — so a GC deleting below it can never delete an entry no
    /// snapshot holds. The app plumbs the same map as the plaintext `x-openom-covered` header on the snapshot
    /// PUT. See [`docsync::BlobSyncClient::compact`].
    ///
    /// # Errors
    /// Returns an error if sealing or the blob write fails.
    pub fn compact(&mut self) -> Result<()> {
        self.inner.compact()
    }

    /// Compact iff the [`SnapshotPolicy`](docsync::SnapshotPolicy) says so, given the `log/*` objects accrued
    /// since the last snapshot (all replicas — the whole reclaimable tail). Returns whether it compacted. The
    /// initial policy bounds the log by a fixed count K ([`docsync::EveryNUpdates`]).
    ///
    /// # Errors
    /// Returns an error if a triggered compaction or the store scan fails.
    pub fn maybe_compact(&mut self, policy: &impl docsync::SnapshotPolicy) -> Result<bool> {
        self.inner.maybe_compact(policy)
    }

    /// Like [`pull_verified`](Self::pull_verified) but the post-snapshot tail is re-classified after adopting
    /// the snapshot's covered baseline — the shared data channel's cold-start / `Gone`-recovery path (OPE-409
    /// C3). A plain `bootstrap` (fold only) merges the tail WITHOUT the §B3 gate, so the verified channel MUST
    /// use this once compaction/snapshots are wired. See [`docsync::BlobSyncClient::bootstrap_verified`].
    ///
    /// # Errors
    /// Returns an error if a blob read, open, or merge fails.
    pub fn bootstrap_verified(
        &mut self,
        classify: impl FnMut(&[u8], &[u8], &str, u64) -> docsync::Verdict,
        fold_cover: impl FnMut(&[u8], &[u8], &str, u64),
    ) -> Result<()> {
        self.inner.bootstrap_verified(classify, fold_cover)
    }

    /// Re-attempt every STALLED dot — app-invoked on a version upgrade / membership change, NEVER per tick.
    /// The only heal for a pinned subsumed frontier (OPE-409 review #4). See
    /// [`docsync::BlobSyncClient::retry_stalled`].
    ///
    /// # Errors
    /// Returns an error if a blob read fails.
    pub fn retry_stalled(
        &mut self,
        classify: impl FnMut(&[u8], &[u8], &str, u64) -> docsync::Verdict,
        fold_cover: impl FnMut(&[u8], &[u8], &str, u64),
    ) -> Result<usize> {
        self.inner.retry_stalled(classify, fold_cover)
    }

    /// The SUBSUMED frontier — the ONLY coverage a compaction may honestly publish (the contiguous per-replica
    /// prefix actually folded into the engine, OPE-409 C3). The app plumbs this as the plaintext `x-openom-covered`
    /// header on the snapshot PUT. `{replica: counter}`.
    #[must_use]
    pub fn subsumed_frontier(&self) -> docsync::Frontier {
        self.inner.subsumed_frontier()
    }

    /// How many dots are currently STALLED (dispositioned without absorption; each pins the subsumed frontier).
    /// A nonzero `Unopenable` count on newer-than-build entries is the "this device is a version straggler" signal.
    #[must_use]
    pub fn stalled_count(&self) -> usize {
        self.inner.stalled_count()
    }
}

impl<S: BlobStore> std::fmt::Debug for SyncClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncClient")
            .field("held", &self.inner.held_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use openom_data_model::envelope::{Claim, Record};
    use openom_data_model::Hlc;
    use openom_data_crdt::{ChannelItem, Op, OpKind};
    use openom_crypto::{generate_dek, Dek};
    use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
    use openom_sealer::{Sealer, SealerSet};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    // The BlobStore-native path (docsync::BlobSyncClient) over a local MemoryBlob.
    use docsync::{BlobSyncClient, Verdict};
    use openom_data_tree::Tree;
    use store_blob::MemoryBlob;

    /// Pull with no §B3 gate (accept every peer delta; ignore covers) — the trusted-DEK path used where a
    /// facade test isn't exercising membership verification (that lives in the app-core tests).
    fn pull_all(c: &mut BlobClient) -> usize {
        c.pull_verified(|_e, _p, _r, _c| Verdict::Accept, |_e, _b, _r, _c| {})
            .unwrap()
    }

    fn blob_empty(c: &BlobClient) -> bool {
        c.engine().0.live_records().unwrap().is_empty()
    }

    type BlobClient = BlobSyncClient<super::SyncTree, super::SealerAdapter, Arc<MemoryBlob>>;

    fn blob_client(replica: &[u8], dek: Dek, store: Arc<MemoryBlob>) -> BlobClient {
        let sealer = Sealer::from_unwrapped(
            1,
            dek.into_inner(),
            TreeId::new(b"tree-uuid-16byte".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
            ReplicaId::new(replica.to_vec()),
        );
        BlobSyncClient::new(
            super::SyncTree(Tree::new(DEVICE)),
            super::SealerAdapter(SealerSet::single(sealer)),
            store,
            "tree",
            String::from_utf8_lossy(replica).into_owned(),
        )
    }

    fn blob_live(c: &BlobClient) -> BTreeSet<String> {
        c.engine()
            .0
            .live_records()
            .unwrap()
            .into_iter()
            .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_owned))
            .collect()
    }

    // The Tree's `created_by` is this device's author did:key. It is irrelevant to these tests: they push
    // PRE-BUILT items that carry their own explicit `createdBy`, so the device author never authors anything.
    const DEVICE: &str = "did:key:z6MkDevice";

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

    fn set(items: &[&ChannelItem]) -> BTreeSet<String> {
        items.iter().map(|i| i.id().to_owned()).collect()
    }

    #[test]
    fn blob_two_devices_converge_through_the_claim_stack() {
        // The SAME convergence, but the REAL claim stack (Tree engine + real DEK SealerAdapter + real
        // ChannelItems) over docsync::BlobSyncClient on the Blob seam — proving the binding, not just the
        // GrowSet/Passthrough spikes.
        let store = Arc::new(MemoryBlob::new());
        let dek = generate_dek().unwrap();
        let mut a = blob_client(b"replica-a", dek.clone(), store.clone());
        let mut b = blob_client(b"replica-b", dek, store.clone());

        let pa = person("pA", "did:key:z6MkA");
        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        let nb = name_claim("pA", "Ada Lovelace", "did:key:z6MkB", 2);

        a.apply(vec![pa.clone(), na.clone()]).unwrap();
        b.apply(vec![nb.clone()]).unwrap();
        a.pull().unwrap();
        b.pull().unwrap();

        assert_eq!(blob_live(&a), blob_live(&b), "both devices converge over the blob seam");
        assert_eq!(blob_live(&a), set(&[&pa, &na, &nb]));
    }

    #[test]
    fn blob_a_moderator_remove_syncs_and_drops_the_record() {
        let store = Arc::new(MemoryBlob::new());
        let dek = generate_dek().unwrap();
        let mut a = blob_client(b"replica-a", dek.clone(), store.clone());
        let mut b = blob_client(b"replica-b", dek, store.clone());
        let mods = BTreeSet::from(["did:key:z6MkA".to_string()]);
        a.engine_mut().0.set_moderators(mods.clone());
        b.engine_mut().0.set_moderators(mods);

        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        a.apply(vec![na.clone()]).unwrap();
        pull_all(&mut b);
        assert_eq!(blob_live(&b), set(&[&na]));

        a.apply(vec![remove(&na, "did:key:z6MkA")]).unwrap();
        pull_all(&mut b);
        assert!(blob_empty(&b), "the remove propagated");
        assert!(blob_empty(&a));
    }

    #[test]
    fn blob_a_wrong_key_quarantines_instead_of_wedging() {
        let store = Arc::new(MemoryBlob::new());
        let dek = generate_dek().unwrap();
        let mut a = blob_client(b"replica-a", dek, store.clone());
        a.apply(vec![name_claim("pA", "Ada", "did:key:z6MkA", 1)]).unwrap();

        // A wrong DEK reveals nothing and does not wedge: the unopenable object is quarantined + counted.
        let wrong = generate_dek().unwrap();
        let mut intruder = blob_client(b"replica-x", wrong, store.clone());
        assert_eq!(pull_all(&mut intruder), 0, "a wrong DEK merges nothing");
        assert!(blob_empty(&intruder), "the wrong key reveals no data");
        assert!(
            intruder.quarantined_count() >= 1,
            "the unopenable object is quarantined, not fatal"
        );
    }
}
