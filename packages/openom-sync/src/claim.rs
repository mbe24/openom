//! The claim-model sync client — the op-based counterpart to [`SyncClient`](crate::SyncClient),
//! deliberately independent of `openom-treelog`/`commute` so those can be deleted (OPE-210) without
//! touching it.
//!
//! Same transport as the treelog path: a claim update **is** a delta — an op-based change — so it
//! seals as a `Kind::Delta` entry with `Format::OpenomOps`, appends to the tree's one log, and is
//! deduped by the replica dot exactly like any other delta. The payload is a batch of [`ChannelItem`]s
//! (from `openom-crdt`); inbound, they accumulate into a set that [`materialize`] folds into the live
//! record set — the snapshot the projection reads.
//!
//! **Single-engine-per-app-instance:** the whole app runs either treelog or claims, so this client's
//! log carries only claim entries. There is no mixed-kind routing, and the replica dot never collides
//! with a treelog channel (there isn't one). The compaction fold + a real `covers_through_seq` are a
//! later slice (OPE-176 tail / OPE-179); for now a fresh client replays the whole log — trivial before
//! compaction exists.

use std::collections::BTreeMap;

use journal::DocStore;
use openom_claim::envelope::Record;
use openom_crdt::{materialize, ChannelItem};
use openom_protocol::v1::{Compression, Envelope, Format};
use openom_protocol::Message;
use openom_sealer::{EntryKind, SealContext, Sealer};

use crate::Result;

/// Transport-side codec bits: the wire [`FORMAT`](codec::FORMAT) tag, plus the batch `encode`/`decode`
/// re-exported from [`openom_crdt::codec`] — the one place the op-batch codec lives, shared with the
/// `openom-tree` engine so both emit byte-identical bytes (and a CBOR swap, OPE-199, touches it once).
pub mod codec {
    /// The wire `Format` tag for claim entries (`FORMAT_OPENOM_OPS` = "JSON op-log entries").
    pub const FORMAT: openom_protocol::v1::Format = openom_protocol::v1::Format::OpenomOps;

    pub use openom_crdt::codec::{decode, encode};
}

/// One device's view of a claim-model tree: the [`Sealer`] holding its DEK, a shared [`DocStore`], the
/// outbound replica chain (counter + prev hash), the inbound cursor, and the accumulated op set.
pub struct ClaimSyncClient<S: DocStore> {
    sealer: Sealer,
    store: S,
    doc: String,
    next_counter: u64,
    prev_hash: Vec<u8>,
    pull_cursor: Option<u64>,
    // Sealed-but-not-yet-confirmed envelopes (a write-ahead queue). Sealed exactly once; a transient
    // append failure keeps it queued for a byte-identical retry — the dot dedups it server-side, and
    // re-ingesting re-inserts by id, so it is idempotent either way.
    pending: Vec<Vec<u8>>,
    // The accumulated channel items, keyed by content id — a set (idempotent under re-delivery). The
    // journal is its durable authority; this map is rebuilt by replaying the log (`pull_claims` from
    // an unset cursor). `materialize` folds it into the live records.
    items: BTreeMap<String, ChannelItem>,
    // CAS token for this tree's single snapshot slot — the version from the last put/read, passed to
    // the next put_snapshot so a concurrent writer can't silently clobber it.
    snapshot_version: Option<String>,
}

impl<S: DocStore> ClaimSyncClient<S> {
    /// Wrap a freshly-unlocked claim tree. `doc` is the store key for this tree's log.
    pub fn new(sealer: Sealer, store: S, doc: impl Into<String>) -> Self {
        ClaimSyncClient {
            sealer,
            store,
            doc: doc.into(),
            next_counter: 0,
            prev_hash: Vec::new(),
            pull_cursor: None,
            pending: Vec::new(),
            items: BTreeMap::new(),
            snapshot_version: None,
        }
    }

    /// The live record set — [`materialize`] over the accumulated ops. This is the snapshot the
    /// projection reads. (Clones the set once per call; the read-model rebuild, not a hot path.)
    pub fn materialize(&self) -> Vec<Record> {
        let items: Vec<ChannelItem> = self.items.values().cloned().collect();
        materialize(&items)
    }

    /// The accumulated channel items (borrowed), for a caller that folds them itself.
    pub fn items(&self) -> impl Iterator<Item = &ChannelItem> {
        self.items.values()
    }

    /// Seal a batch of channel items as one `Kind::Delta` / `Format::OpenomOps` entry, apply it
    /// optimistically to the local set, queue it, and flush. Seal + chain-advance happen exactly once;
    /// a failed flush leaves the sealed envelope queued for a byte-identical retry.
    pub fn push_claims(&mut self, items: &[ChannelItem]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let ctx = SealContext {
            kind: EntryKind::Delta,
            format: codec::FORMAT,
            compression: Compression::None,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: 0,
            blob_id: Vec::new(),
        };
        let out = self.sealer.seal_entry(&ctx, &codec::encode(items)?)?;
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        for item in items {
            self.items.insert(item.id().to_owned(), item.clone());
        }
        self.pending.push(out.envelope);
        self.flush()
    }

    /// Append every queued sealed envelope, oldest first, dropping each as it lands. A failed append
    /// leaves it (and the rest) queued and returns the error; call again to retry — a re-appended
    /// entry dedups on the dot and re-folds idempotently.
    pub fn flush(&mut self) -> Result<()> {
        while let Some(env) = self.pending.first() {
            self.store.append(&self.doc, std::slice::from_ref(env))?;
            self.pending.remove(0);
        }
        Ok(())
    }

    /// How many sealed batches are queued but not yet confirmed appended (0 == fully synced up).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Pull every log entry newer than the last pull, decode each into channel items, and merge them
    /// into the set. Returns how many items were ingested. Idempotent — re-reading our own or a
    /// duplicate entry re-inserts by id. From a fresh client (cursor unset) this replays the whole
    /// log, rebuilding the set from the journal (its durable authority).
    ///
    /// The log is claim-only (single-engine), so every entry opens as `Kind::Delta` and decodes as a
    /// `ChannelItem` batch; a foreign entry would surface as a decode error rather than corrupt the
    /// set. (A pre-decrypt `Format` check is the belt-and-braces upgrade when/if engines ever mix.)
    pub fn pull_claims(&mut self) -> Result<usize> {
        let (updates, new_cursor) = self.store.read_updates(&self.doc, self.pull_cursor)?;
        let mut ingested = 0;
        for envelope in &updates {
            let bytes = self.sealer.open_entry(EntryKind::Delta, envelope)?;
            for item in codec::decode(&bytes)? {
                self.items.insert(item.id().to_owned(), item);
                ingested += 1;
            }
        }
        self.pull_cursor = Some(new_cursor);
        Ok(ingested)
    }

    /// Publish a snapshot of the live record set — [`materialize`] over the accumulated ops, as a set
    /// of `Assert`s — CAS'd on the prior snapshot version and stamped with the log seq it covers
    /// through. A fresh client then [`bootstrap_claims`](Self::bootstrap_claims) from the snapshot +
    /// only the tail. This is the byte-preserving fold: dead (removed / superseded) records drop out,
    /// but disputed-yet-live claims and attestations stay — refutation memory is preserved. Folding
    /// out a pre-snapshot remove also makes it irrevocable (the structural GC horizon). Pulling first,
    /// so the snapshot reflects the whole log, is the caller's responsibility. Returns the covered seq.
    pub fn compact_claims(&mut self) -> Result<u64> {
        let covered = match self.pull_cursor {
            Some(c) => c,
            None => self.store.read_updates(&self.doc, None)?.1,
        };
        let live: Vec<ChannelItem> = self
            .materialize()
            .into_iter()
            .map(ChannelItem::Assert)
            .collect();
        let ctx = SealContext {
            kind: EntryKind::Snapshot,
            format: Format::OpenomJson,
            compression: Compression::None,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: covered,
            blob_id: Vec::new(),
        };
        let out = self.sealer.seal_entry(&ctx, &codec::encode(&live)?)?;
        let version =
            self.store
                .put_snapshot(&self.doc, &out.envelope, self.snapshot_version.as_deref())?;
        self.snapshot_version = Some(version);
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        Ok(covered)
    }

    /// Bring a fresh client up to date the fast way: load the stored snapshot (if any) into the set,
    /// then pull only the ops after the seq it covers. Falls back to a full log replay when there is
    /// no snapshot. Idempotent — safe even if the snapshot and the tail overlap (re-insert by id).
    pub fn bootstrap_claims(&mut self) -> Result<()> {
        if let Some(snap) = self.store.read_snapshot(&self.doc)? {
            let covered = Envelope::decode(snap.bytes.as_slice())
                .ok()
                .and_then(|e| e.header)
                .map(|h| h.covers_through_seq)
                .unwrap_or(0);
            let plaintext = self.sealer.open_entry(EntryKind::Snapshot, &snap.bytes)?;
            for item in codec::decode(&plaintext)? {
                self.items.insert(item.id().to_owned(), item);
            }
            self.snapshot_version = Some(snap.version);
            self.pull_cursor = Some(covered);
        }
        self.pull_claims()?;
        Ok(())
    }
}

impl<S: DocStore> std::fmt::Debug for ClaimSyncClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimSyncClient")
            .field("doc", &self.doc)
            .field("next_counter", &self.next_counter)
            .field("pending", &self.pending.len())
            .field("items", &self.items.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::ClaimSyncClient;
    use journal::memory::MemoryStore;
    use journal::DocStore;
    use openom_claim::envelope::{Claim, Record};
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
    ) -> ClaimSyncClient<Arc<MemoryStore>> {
        let sealer = Sealer::from_unwrapped(
            1,
            dek.into_inner(),
            TreeId::new(b"tree-uuid-16byte".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
            ReplicaId::new(replica.to_vec()),
        );
        ClaimSyncClient::new(sealer, store, "tree")
    }

    fn person(id: &str, author: &str) -> ChannelItem {
        ChannelItem::Assert(
            Record::try_from(json!({
                "id": id, "type": "openom.org/core/person/v1", "createdAt": 1, "createdBy": author,
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
            at,
        );
        c.compute_id().unwrap();
        ChannelItem::Assert(Record::Claim(c))
    }

    fn remove(target: &ChannelItem, author: &str) -> ChannelItem {
        ChannelItem::Op(
            Op::new(
                2,
                author,
                OpKind::Remove {
                    target: target.id().to_owned(),
                },
            )
            .unwrap(),
        )
    }

    fn live(c: &ClaimSyncClient<Arc<MemoryStore>>) -> BTreeSet<String> {
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
        b.push_claims(&[nb.clone()]).unwrap();
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
    fn a_same_author_remove_syncs_and_drops_the_record() {
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
        let mut b = client(b"replica-b", dek, store.clone());

        let na = name_claim("pA", "Ada", "did:key:z6MkA", 1);
        a.push_claims(&[na.clone()]).unwrap();
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
        a.push_claims(&[na.clone()]).unwrap();
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
        a.push_claims(&[na.clone()]).unwrap();

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
        a.push_claims(&[pa.clone()]).unwrap();

        let mut c = client(b"replica-c", dek, store.clone());
        c.bootstrap_claims().unwrap(); // no snapshot → full log replay
        assert_eq!(live(&c), set(&[&pa]));
    }

    #[test]
    fn compaction_folds_out_removed_records() {
        // The snapshot is the live set: a same-author-removed record is folded out and never reaches
        // a bootstrapping client (the structural GC horizon), while a live record survives.
        let store = Arc::new(MemoryStore::new());
        let dek = generate_dek().unwrap();
        let mut a = client(b"replica-a", dek.clone(), store.clone());
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
