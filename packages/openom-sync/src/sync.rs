//! The claim-model sync client — the openom adapter over the generic [`docsync`] loop.
//!
//! A claim update **is** a delta — an op-based change — so it seals as a `Kind::Delta` entry with
//! `Format::OpenomOps`, appends to the tree's one log, and is deduped by the replica dot like any other
//! delta. The payload is a batch of [`ChannelItem`]s (from `openom-crdt`); inbound, they accumulate into
//! a set that [`materialize`] folds into the live record set — the snapshot the projection reads.
//!
//! The push / pull / compact / bootstrap loop itself lives in [`docsync`]; openom supplies only the two
//! seams: a [`ClaimEngine`] (`impl docsync::Engine` — the op-set + fold + codec) and a sealer adapter
//! (`impl docsync::Sealer` over `openom-sealer`, mapping the entry kind to openom's `Format`). All
//! claim-specific logic — `materialize`, `moderators`, the `ChannelItem` codec — stays here, caller-side.
//!
//! **Single-engine-per-app-instance:** the whole app runs the claim engine, so this client's log carries
//! only claim entries — no mixed-kind routing.

use std::collections::{BTreeMap, BTreeSet};

use journal::DocStore;
use openom_claim::envelope::Record;
use openom_crdt::{materialize, ChannelItem};
use openom_protocol::v1::{Compression, Envelope, Format};
use openom_protocol::Message;
use openom_sealer::{EntryKind, SealContext, Sealer, SealerError};

use crate::Result;

/// Transport-side codec bits: the wire [`FORMAT`](codec::FORMAT) tag, plus the batch `encode`/`decode`
/// re-exported from [`openom_crdt::codec`] — the one place the op-batch codec lives, shared with the
/// `openom-tree` engine so both emit byte-identical bytes (and a CBOR swap, OPE-199, touches it once).
pub mod codec {
    /// The wire `Format` tag for claim entries (`FORMAT_OPENOM_OPS` = "JSON op-log entries").
    pub const FORMAT: openom_protocol::v1::Format = openom_protocol::v1::Format::OpenomOps;

    pub use openom_crdt::codec::{decode, encode};
}

/// The claim-model merge engine: the accumulated channel items (keyed by content id — a set, idempotent
/// under re-delivery) plus the moderator set the fold honors. Implements [`docsync::Engine`] so the
/// generic loop drives it; `materialize`/`set_moderators`/`items` are the caller-side extras reached via
/// the client's engine accessors.
pub struct ClaimEngine {
    // The journal is the durable authority; this map is rebuilt by replaying the log. `materialize` folds
    // it into the live records.
    items: BTreeMap<String, ChannelItem>,
    // The did:keys currently at Maintainer+ — the authors whose Remove/Supersede/Revoke ops the fold
    // honors. Empty until set from the governing keyring, so a fresh client folds only asserts.
    moderators: BTreeSet<String>,
}

impl ClaimEngine {
    fn new() -> Self {
        ClaimEngine {
            items: BTreeMap::new(),
            moderators: BTreeSet::new(),
        }
    }

    /// The live record set — [`materialize`] over the accumulated ops. The snapshot the projection reads.
    fn materialize(&self) -> Vec<Record> {
        let items: Vec<ChannelItem> = self.items.values().cloned().collect();
        materialize(&items, &self.moderators)
    }
}

impl docsync::Engine for ClaimEngine {
    type Edit = Vec<ChannelItem>;
    type Error = serde_json::Error;

    fn apply_local(&mut self, edit: Vec<ChannelItem>) -> Vec<u8> {
        if edit.is_empty() {
            return Vec::new();
        }
        // Encode the batch as the delta, then apply it optimistically to the local set.
        let bytes = codec::encode(&edit).expect("op-batch JSON encoding is infallible for valid items");
        for item in edit {
            self.items.insert(item.id().to_owned(), item);
        }
        bytes
    }

    fn merge(&mut self, delta: &[u8]) -> std::result::Result<(), serde_json::Error> {
        for item in codec::decode(delta)? {
            self.items.insert(item.id().to_owned(), item);
        }
        Ok(())
    }

    fn snapshot(&self) -> Vec<u8> {
        // The byte-preserving fold: dead (removed/superseded) records drop out; disputed-yet-live claims
        // and attestations stay. Emitted as a set of `Assert`s.
        let live: Vec<ChannelItem> = self.materialize().into_iter().map(ChannelItem::Assert).collect();
        codec::encode(&live).expect("snapshot JSON encoding is infallible for valid records")
    }
    // merge_snapshot defaults to merge — decode the Asserts and re-insert by id.
}

/// Adapts openom's DEK [`Sealer`] to the [`docsync::Sealer`] seam: maps the generic entry kind to
/// openom's `Format` (op-log for deltas, JSON for snapshots), fills the openom-only `compression`/
/// `blob_id` fields, and reads `covers_through_seq` back out of a snapshot envelope's header.
struct SealerAdapter(Sealer);

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
        };
        self.0.open_entry(k, envelope)
    }

    fn covers_through_seq(&self, snapshot_envelope: &[u8]) -> u64 {
        Envelope::decode(snapshot_envelope)
            .ok()
            .and_then(|e| e.header)
            .map(|h| h.covers_through_seq)
            .unwrap_or(0)
    }
}

/// One device's view of a claim-model tree — a thin facade over [`docsync::SyncClient`] wired with a
/// [`ClaimEngine`] and openom's sealer. Preserves the claim-model API (`push_claims` / `pull_claims` /
/// `compact_claims` / `bootstrap_claims` / `materialize` / `set_moderators`).
pub struct SyncClient<S: DocStore> {
    inner: docsync::SyncClient<ClaimEngine, SealerAdapter, S>,
}

impl<S: DocStore> SyncClient<S> {
    /// Wrap a freshly-unlocked claim tree. `doc` is the store key for this tree's log.
    pub fn new(sealer: Sealer, store: S, doc: impl Into<String>) -> Self {
        SyncClient {
            inner: docsync::SyncClient::new(ClaimEngine::new(), SealerAdapter(sealer), store, doc),
        }
    }

    /// Set the moderator `did:key`s (members currently at Maintainer or above) whose
    /// Remove/Supersede/Revoke ops the fold honors — from the governing keyring.
    pub fn set_moderators(&mut self, moderators: BTreeSet<String>) {
        self.inner.engine_mut().moderators = moderators;
    }

    /// The live record set — [`materialize`] over the accumulated ops. This is the snapshot the
    /// projection reads. (Clones the set once per call; the read-model rebuild, not a hot path.)
    pub fn materialize(&self) -> Vec<Record> {
        self.inner.engine().materialize()
    }

    /// The accumulated channel items (borrowed), for a caller that folds them itself.
    pub fn items(&self) -> impl Iterator<Item = &ChannelItem> {
        self.inner.engine().items.values()
    }

    /// Seal a batch of channel items as one `Kind::Delta` / `Format::OpenomOps` entry, apply it to the
    /// local set, queue it, and flush. Seal + chain-advance happen exactly once; a failed flush leaves
    /// the sealed envelope queued for a byte-identical retry.
    pub fn push_claims(&mut self, items: &[ChannelItem]) -> Result<()> {
        self.inner.apply(items.to_vec())
    }

    /// Append every queued sealed envelope, oldest first. A failed append leaves it (and the rest)
    /// queued; call again to retry — a re-appended entry dedups on the dot and re-folds idempotently.
    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    /// How many sealed batches are queued but not yet confirmed appended (0 == fully synced up).
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// Pull every log entry newer than the last pull, decode each into channel items, and merge them.
    /// Returns how many **log entries** were pulled. Idempotent — re-reading our own or a duplicate
    /// entry re-inserts by id. From a fresh client this replays the whole log (the journal is authority).
    pub fn pull_claims(&mut self) -> Result<usize> {
        self.inner.pull()
    }

    /// Publish a snapshot of the live record set (the byte-preserving fold), CAS'd on the prior snapshot
    /// version and stamped with the log seq it covers. Pull first so the snapshot reflects the whole log.
    /// Returns the covered seq.
    pub fn compact_claims(&mut self) -> Result<u64> {
        self.inner.compact()
    }

    /// Bring a fresh client up to date: load the stored snapshot (if any) into the set, then pull only
    /// the ops after the seq it covers. Falls back to a full log replay when there is no snapshot.
    pub fn bootstrap_claims(&mut self) -> Result<()> {
        self.inner.bootstrap()
    }
}

impl<S: DocStore> std::fmt::Debug for SyncClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncClient")
            .field("items", &self.inner.engine().items.len())
            .field("pending", &self.inner.pending_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::SyncClient;
    use journal::memory::MemoryStore;
    use journal::DocStore;
    use openom_claim::envelope::{Claim, Record};
    use openom_claim::Hlc;
    use openom_crdt::{ChannelItem, Op, OpKind};
    use openom_crypto::{generate_dek, Dek};
    use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
    use openom_sealer::Sealer;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn client(
        replica: &[u8],
        dek: Dek,
        store: Arc<MemoryStore>,
    ) -> SyncClient<Arc<MemoryStore>> {
        let sealer = Sealer::from_unwrapped(
            1,
            dek.into_inner(),
            TreeId::new(b"tree-uuid-16byte".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
            ReplicaId::new(replica.to_vec()),
        );
        SyncClient::new(sealer, store, "tree")
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

    fn live(c: &SyncClient<Arc<MemoryStore>>) -> BTreeSet<String> {
        c.materialize()
            .into_iter()
            .map(|r| r.id().to_owned())
            .collect()
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
        assert!(b.materialize().is_empty(), "the remove propagated");
        assert!(a.materialize().is_empty());
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
        assert_eq!(
            live(&b),
            set(&[&na]),
            "the duplicate must not double the record"
        );
    }

    #[test]
    fn a_wrong_key_cannot_open_the_claim_log() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek, store.clone());
        a.push_claims(&[name_claim("pA", "Ada", "did:key:z6MkA", 1)])
            .unwrap();

        let wrong = generate_dek().unwrap();
        let mut intruder = client(b"replica-x", wrong, store.clone());
        assert!(
            intruder.pull_claims().is_err(),
            "a wrong DEK must not decrypt the log"
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

        // A fresh client bootstraps only from the snapshot (the tail is empty) — the removed record
        // is absent, and the record it never touched survives.
        let mut c = client(b"replica-c", dek, store.clone());
        c.bootstrap_claims().unwrap();
        assert_eq!(
            live(&c),
            set(&[&keep]),
            "removed record folded out of the snapshot"
        );
    }
}
