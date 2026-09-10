#![doc = include_str!("../README.md")]

use store_blob::BlobStore;
use store_log::{DocStore, StoreError};

/// Kind of a sealed log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Delta,
    Snapshot,
    /// The self-heal covering marker (OPE-382). Opened for verification only, never merged as a claim.
    Cover,
}

/// Outbound chain state + kind for one entry, handed to the [`Sealer`].
pub struct SealCtx {
    pub kind: EntryKind,
    pub replica_counter: u64,
    pub prev_ciphertext_hash: Vec<u8>,
    pub covers_through_seq: u64,
}

/// A sealed entry: the opaque envelope bytes + the chain hash to thread forward.
pub struct Sealed {
    pub envelope: Vec<u8>,
    pub ciphertext_hash: Vec<u8>,
}

/// The merge-engine seam. Delta-bytes-centric so it fits op- and doc-CRDTs alike.
pub trait Engine {
    /// A local edit request — the caller's own edit type (e.g. a CRDT op or a doc mutation).
    type Edit;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Apply a local edit; return the delta bytes it produced (empty ⇒ no-op).
    fn apply_local(&mut self, edit: Self::Edit) -> Vec<u8>;
    /// Merge a remote delta's bytes into local state.
    ///
    /// # Errors
    /// Returns `Self::Error` if `delta` cannot be applied.
    fn merge(&mut self, delta: &[u8]) -> Result<(), Self::Error>;
    /// Full-state snapshot bytes (for compaction).
    fn snapshot(&self) -> Vec<u8>;
    /// Merge a snapshot's bytes (bootstrap). Defaults to [`merge`](Engine::merge).
    ///
    /// # Errors
    /// Returns `Self::Error` if `bytes` isn't a valid snapshot.
    fn merge_snapshot(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.merge(bytes)
    }
}

/// The envelope seam — seals plaintext into opaque bytes and opens them back.
pub trait Sealer {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Seal `plaintext` into a wire-ready envelope under `ctx`.
    ///
    /// # Errors
    /// Returns `Self::Error` if sealing fails.
    fn seal(&mut self, ctx: &SealCtx, plaintext: &[u8]) -> Result<Sealed, Self::Error>;

    /// Open an envelope of the given `kind`, returning the plaintext.
    ///
    /// # Errors
    /// Returns `Self::Error` if the envelope is out of scope or fails to open.
    fn open(&self, kind: EntryKind, envelope: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// `covers_through_seq` recorded in a snapshot envelope (for bootstrap).
    fn covers_through_seq(&self, snapshot_envelope: &[u8]) -> u64;
}

/// What a [`SnapshotPolicy`] consults to decide whether to compact now. Compaction *timing* is a
/// sync-layer concern (this crate); *what is safe to discard* stays with the caller's engine.
pub struct CompactionState {
    /// Log entries appended since this client's last snapshot (0 if it has never snapshotted).
    pub updates_since_snapshot: u64,
    /// Whether a snapshot exists for this document yet.
    pub has_snapshot: bool,
    // Future: a per-member seen-frontier, so a channel can gate compaction on "≥ X% of members have
    // seen the entries being folded away" — needed for the auth/keyring channel, not the data channel.
    // That requires watermark plumbing this client doesn't yet carry.
}

/// The compaction-trigger seam: given the current [`CompactionState`], should the client compact now?
///
/// Different channels plug in different cadences — a data channel compacts aggressively (short window),
/// an auth channel conservatively (long window, and eventually a %-seen safety gate).
pub trait SnapshotPolicy {
    fn should_compact(&self, state: &CompactionState) -> bool;
}

/// Compact once at least `n` log entries have accrued since the last snapshot. A simple length trigger.
#[derive(Debug, Clone, Copy)]
pub struct EveryNUpdates(pub u64);

impl SnapshotPolicy for EveryNUpdates {
    fn should_compact(&self, state: &CompactionState) -> bool {
        state.updates_since_snapshot >= self.0
    }
}

/// Never auto-compact — the caller drives [`SyncClient::compact`] explicitly. The conservative default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverCompact;

impl SnapshotPolicy for NeverCompact {
    fn should_compact(&self, _state: &CompactionState) -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A blob-store transport failure (the [`BlobSyncClient`] path).
    #[error("blob store: {0}")]
    Blob(#[from] store_blob::BlobError),
    #[error("engine: {0}")]
    Engine(Box<dyn std::error::Error + Send + Sync>),
    #[error("sealer: {0}")]
    Sealer(Box<dyn std::error::Error + Send + Sync>),
}

/// One device's view of one document: a local [`Engine`], a [`Sealer`], and a shared [`DocStore`]. Owns
/// this replica's outbound chain (counter + prev hash) and the inbound cursor.
pub struct SyncClient<E: Engine, K: Sealer, S: DocStore> {
    engine: E,
    sealer: K,
    store: S,
    doc: String,
    next_counter: u64,
    prev_hash: Vec<u8>,
    pull_cursor: Option<u64>,
    snapshot_version: Option<String>,
    /// The log seq this client's last snapshot covered — for [`SnapshotPolicy`] length triggers.
    snapshot_covered: Option<u64>,
    /// Sealed-but-not-yet-appended envelopes (write-ahead queue): sealed once, re-appended on retry
    /// (idempotent on peers).
    pending: Vec<Vec<u8>>,
    /// Count of log entries [`pull`](Self::pull) skipped because they would not open or merge — a
    /// corrupt / wrong-key / future-format envelope. Surfaced (not fatal) so one bad entry from an
    /// untrusted server can't wedge sync for the whole tree.
    quarantined: usize,
}

impl<E: Engine, K: Sealer, S: DocStore> SyncClient<E, K, S> {
    pub fn new(engine: E, sealer: K, store: S, doc: impl Into<String>) -> Self {
        Self {
            engine,
            sealer,
            store,
            doc: doc.into(),
            next_counter: 0,
            prev_hash: Vec::new(),
            pull_cursor: None,
            snapshot_version: None,
            snapshot_covered: None,
            quarantined: 0,
            pending: Vec::new(),
        }
    }

    pub const fn engine(&self) -> &E {
        &self.engine
    }

    /// Mutable access to the engine — for caller-specific operations docsync doesn't generalize (e.g. a
    /// domain version cursor, or a workflow-specific commit).
    pub const fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    /// Mutable access to the sealer — for caller-specific key-material operations docsync doesn't generalize
    /// (e.g. splicing a newly-reachable epoch DEK into a running member's set after a rotation).
    pub const fn sealer_mut(&mut self) -> &mut K {
        &mut self.sealer
    }

    /// Apply a local edit and immediately push it.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the edit cannot be applied or sealed.
    pub fn apply(&mut self, edit: E::Edit) -> Result<(), SyncError> {
        let delta = self.engine.apply_local(edit);
        self.push(EntryKind::Delta, &delta, 0)
    }

    /// Seal an already-encoded delta payload and append it — the same path as [`apply`](Self::apply)
    /// minus `apply_local`. For an engine that mints the batch bytes itself (its own id/clock/author
    /// logic) and has already folded them into its own state, so re-merging here would be redundant.
    /// An empty payload is a no-op.
    ///
    /// # Errors
    /// Returns [`SyncError`] if sealing or the store append fails.
    pub fn push_delta(&mut self, plaintext: &[u8]) -> Result<(), SyncError> {
        self.push(EntryKind::Delta, plaintext, 0)
    }

    /// Seal a self-heal `Cover` marker in this replica's chain (advancing the counter + prev-hash like any
    /// entry, so it never collides with a delta) but do NOT store it locally — a Cover must not enter the
    /// claim log (`pull` would try to open it as a Delta and quarantine it). The caller pushes the returned
    /// envelope to the server's log directly; peers fold it into their covered set on ingest.
    ///
    /// # Errors
    /// Returns [`SyncError`] if sealing fails.
    pub fn seal_cover(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SyncError> {
        let ctx = SealCtx {
            kind: EntryKind::Cover,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: 0,
        };
        let out = self
            .sealer
            .seal(&ctx, plaintext)
            .map_err(|e| SyncError::Sealer(Box::new(e)))?;
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        Ok(out.envelope)
    }

    fn push(&mut self, kind: EntryKind, plaintext: &[u8], covers: u64) -> Result<(), SyncError> {
        if plaintext.is_empty() {
            return Ok(());
        }
        let ctx = SealCtx {
            kind,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: covers,
        };
        let out = self
            .sealer
            .seal(&ctx, plaintext)
            .map_err(|e| SyncError::Sealer(Box::new(e)))?;
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        self.pending.push(out.envelope);
        self.flush()
    }

    /// Append every queued envelope (oldest first); a failed append leaves the rest queued for an
    /// idempotent retry.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the store push fails.
    pub fn flush(&mut self) -> Result<(), SyncError> {
        while let Some(env) = self.pending.first() {
            self.store.append(&self.doc, std::slice::from_ref(env))?;
            self.pending.remove(0);
        }
        Ok(())
    }

    pub const fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Pull + merge every log entry newer than the last pull. Returns the count.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the store read or a merge fails.
    pub fn pull(&mut self) -> Result<usize, SyncError> {
        let (updates, new_cursor) = self.store.read_updates(&self.doc, self.pull_cursor)?;
        let mut merged = 0;
        for env in &updates {
            // Per-entry fault isolation: a single un-openable / un-mergeable entry (corrupt, wrong
            // key, future format, or a malicious write to the untrusted log) is quarantined and the
            // cursor still advances past it — one bad entry can't wedge sync for the whole tree. A
            // *store* read failure above is still fatal (a broken local backend, not one bad entry).
            match self.sealer.open(EntryKind::Delta, env) {
                Ok(bytes) => match self.engine.merge(&bytes) {
                    Ok(()) => merged += 1,
                    Err(_) => self.quarantined += 1,
                },
                Err(_) => self.quarantined += 1,
            }
        }
        self.pull_cursor = Some(new_cursor);
        Ok(merged)
    }

    /// Total log entries [`pull`](Self::pull) has quarantined (skipped as un-openable / un-mergeable)
    /// over this client's life — a caller surfaces a non-zero count as a data-integrity anomaly.
    pub const fn quarantined_count(&self) -> usize {
        self.quarantined
    }

    /// Open a `Delta` envelope to its plaintext WITHOUT merging — for a caller that must inspect an
    /// entry (e.g. §B3 author verification) before deciding whether to accept it into the store.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the sealer can't open the envelope (wrong key / corrupt).
    pub fn try_open_delta(&self, envelope: &[u8]) -> Result<Vec<u8>, SyncError> {
        self.sealer
            .open(EntryKind::Delta, envelope)
            .map_err(|e| SyncError::Sealer(Box::new(e)))
    }

    /// Open a `Cover` envelope (the self-heal marker) to its plaintext without merging — so a caller can
    /// verify + fold its body into the covered set. A Cover is a normal sealed entry under the tree DEK; only
    /// its header `kind` differs, so the sealer must be told to expect `Cover` (a `Delta`-kind open rejects it).
    ///
    /// # Errors
    /// Returns [`SyncError`] if the sealer can't open the envelope (wrong key / corrupt / wrong kind).
    pub fn try_open_cover(&self, envelope: &[u8]) -> Result<Vec<u8>, SyncError> {
        self.sealer
            .open(EntryKind::Cover, envelope)
            .map_err(|e| SyncError::Sealer(Box::new(e)))
    }

    /// Fold state into a snapshot and CAS it, recording the seq it covers.
    ///
    /// # Errors
    /// Returns [`SyncError`] if snapshotting or the store write fails.
    pub fn compact(&mut self) -> Result<u64, SyncError> {
        let covered = match self.pull_cursor {
            Some(c) => c,
            None => self.store.read_updates(&self.doc, None)?.1,
        };
        let snap = self.engine.snapshot();
        let ctx = SealCtx {
            kind: EntryKind::Snapshot,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: covered,
        };
        let out = self
            .sealer
            .seal(&ctx, &snap)
            .map_err(|e| SyncError::Sealer(Box::new(e)))?;
        let version =
            self.store
                .put_snapshot(&self.doc, &out.envelope, self.snapshot_version.as_deref())?;
        self.snapshot_version = Some(version);
        self.snapshot_covered = Some(covered);
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        Ok(covered)
    }

    /// Compact iff the [`SnapshotPolicy`] says so, given how much log has accrued since the last
    /// snapshot. Returns the covered seq if it compacted. The length estimate uses the pull cursor, so
    /// call after [`pull`](Self::pull) for an up-to-date view.
    ///
    /// # Errors
    /// Returns [`SyncError`] if a triggered compaction fails.
    pub fn maybe_compact(
        &mut self,
        policy: &impl SnapshotPolicy,
    ) -> Result<Option<u64>, SyncError> {
        let head = self.pull_cursor.unwrap_or(0);
        let state = CompactionState {
            updates_since_snapshot: head.saturating_sub(self.snapshot_covered.unwrap_or(0)),
            has_snapshot: self.snapshot_version.is_some(),
        };
        if policy.should_compact(&state) {
            Ok(Some(self.compact()?))
        } else {
            Ok(None)
        }
    }

    /// Bring a fresh client current: load the snapshot (if any), then pull only the tail after the seq it
    /// covers. Idempotent.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the store read or a merge fails.
    pub fn bootstrap(&mut self) -> Result<(), SyncError> {
        if let Some(snap) = self.store.read_snapshot(&self.doc)? {
            let covered = self.sealer.covers_through_seq(&snap.bytes);
            let plaintext = self
                .sealer
                .open(EntryKind::Snapshot, &snap.bytes)
                .map_err(|e| SyncError::Sealer(Box::new(e)))?;
            self.engine
                .merge_snapshot(&plaintext)
                .map_err(|e| SyncError::Engine(Box::new(e)))?;
            self.snapshot_version = Some(snap.version);
            self.pull_cursor = Some(covered);
        }
        self.pull()?;
        Ok(())
    }
}

/// A classifier's decision on a fetched peer delta (the caller's §B3 verify/attribution gate lives here —
/// `docsync` stays ignorant of what "valid" means; the client opens the envelope and passes the classifier
/// both the raw envelope, for attribution, and the opened plaintext). `Accept` merges it; `Hold` keeps the
/// dot for a later retry (e.g. its author isn't a known member YET) WITHOUT blocking the frontier; `Reject`
/// drops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Hold,
    Reject,
}

/// A per-replica sync FRONTIER: `replica_id -> the count of that replica's log entries` — i.e. the next
/// counter to pull from it. Exclusive / next-uncovered (the OPE-76 convention): entry `n` from a replica is
/// covered iff `n < frontier[replica]`. This replaces the scalar `pull_cursor: Option<u64>` — there is no
/// store-assigned global order to count, only each replica's own client-assigned counter.
pub type Frontier = std::collections::BTreeMap<String, u64>;

/// `{doc}/log/{replica}/{counter}` — one immutable delta object (the per-replica dot is the delta identity).
fn log_key(doc: &str, replica: &str, counter: u64) -> String {
    format!("{doc}/log/{replica}/{counter}")
}

/// `{doc}/heads/` — the prefix holding one tiny CAS'd pointer per replica. Listing THIS is O(members), not
/// O(all deltas), so a pull discovers who has written + how far without scanning the whole log — the same
/// head-pointer model the keyring port uses. It is what keeps a managed backend efficient WITHOUT any
/// index-in-the-API: the shape works identically on R2 and a dumb folder store, and a managed backend can
/// still accelerate the head-list + gap-gets below the seam.
fn heads_prefix(doc: &str) -> String {
    format!("{doc}/heads/")
}

/// `{doc}/heads/{replica}` — a replica's head pointer, holding its entry count (its exclusive frontier).
fn head_key(doc: &str, replica: &str) -> String {
    format!("{doc}/heads/{replica}")
}

/// Recover the `replica` id from a `{doc}/heads/{replica}` key (given the `{doc}/heads/` prefix).
fn parse_head_key(prefix: &str, key: &str) -> Option<String> {
    let replica = key.strip_prefix(prefix)?;
    if replica.is_empty() || replica.contains('/') {
        return None;
    }
    Some(replica.to_string())
}

/// A head pointer's value is its replica's entry count, as ASCII decimal (small, human-debuggable, and
/// order-preserving enough for the tiny pointer object).
fn encode_count(n: u64) -> Vec<u8> {
    n.to_string().into_bytes()
}

fn decode_count(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// `{doc}/snapshot` — the single CAS'd snapshot object (a fold of state up to a covered frontier).
fn snapshot_key(doc: &str) -> String {
    format!("{doc}/snapshot")
}

/// A snapshot body is `encode_frontier(covered) ‖ engine.snapshot()` — the covered frontier travels INSIDE
/// the sealed plaintext, so the sealer authenticates it for free (a tampered marker fails to open / is
/// detected) with NO change to the `Sealer` seam. Layout: `[u32 n]{ [u32 rlen][replica][u64 counter] }*`.
fn encode_frontier(f: &Frontier) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(f.len()).unwrap_or(u32::MAX).to_be_bytes());
    for (replica, counter) in f {
        out.extend_from_slice(&u32::try_from(replica.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(replica.as_bytes());
        out.extend_from_slice(&counter.to_be_bytes());
    }
    out
}

/// Split a snapshot body back into `(covered_frontier, engine_snapshot_bytes)`. `None` on a malformed body.
fn decode_frontier(bytes: &[u8]) -> Option<(Frontier, &[u8])> {
    // Bite `n` bytes off the front of `rest`, advancing it; `None` if short.
    fn bite<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if rest.len() < n {
            return None;
        }
        let (head, tail) = rest.split_at(n);
        *rest = tail;
        Some(head)
    }
    let mut rest = bytes;
    let count = u32::from_be_bytes(bite(&mut rest, 4)?.try_into().ok()?);
    let mut frontier = Frontier::new();
    for _ in 0..count {
        let rlen = u32::from_be_bytes(bite(&mut rest, 4)?.try_into().ok()?) as usize;
        let replica = std::str::from_utf8(bite(&mut rest, rlen)?).ok()?.to_string();
        let counter = u64::from_be_bytes(bite(&mut rest, 8)?.try_into().ok()?);
        frontier.insert(replica, counter);
    }
    Some((frontier, rest))
}

/// The `BlobStore`-native sync core (OPE-397): one document, one local [`Engine`] + [`Sealer`], over a
/// swappable [`BlobStore`]. Each replica APPENDS immutable delta objects under `{doc}/log/{replica}/{counter}`
/// with `IfAbsent` — contention is intra-replica only (a crash/retry), never inter-replica, so an append needs
/// no coordination and no store-assigned global order. The inbound cursor is a per-replica [`Frontier`], not a
/// scalar: `pull` discovers every replica's objects, fetches only the gap past the frontier, merges, and
/// advances it. Order-independent set-union merge means the fetch order doesn't matter.
///
/// This increment covers DELTA sync (the contract-freezing two-replica convergence). Snapshot / compaction /
/// bootstrap over a covered-frontier snapshot are the next increment; the existing [`SyncClient`] keeps the
/// `DocStore` path until consumers migrate onto this one.
pub struct BlobSyncClient<E: Engine, K: Sealer, S: BlobStore> {
    engine: E,
    sealer: K,
    store: S,
    doc: String,
    /// THIS replica's stable id — the first coordinate of the delta dot, and the keyspace it owns.
    replica: String,
    /// This replica's next outbound log counter.
    next_counter: u64,
    prev_hash: Vec<u8>,
    /// Per-replica inbound frontier (next counter to pull from each replica, including self).
    pull_frontier: Frontier,
    /// Dots the classifier said to HOLD (couldn't verify yet) — retried each verified pull without blocking
    /// the frontier, so a later-arriving membership op can un-hold them (the §B3 hold/drain, OPE-382).
    held: std::collections::BTreeSet<(String, u64)>,
    quarantined: usize,
}

impl<E: Engine, K: Sealer, S: BlobStore> BlobSyncClient<E, K, S> {
    pub fn new(
        engine: E,
        sealer: K,
        store: S,
        doc: impl Into<String>,
        replica: impl Into<String>,
    ) -> Self {
        Self {
            engine,
            sealer,
            store,
            doc: doc.into(),
            replica: replica.into(),
            next_counter: 0,
            prev_hash: Vec::new(),
            pull_frontier: Frontier::new(),
            held: std::collections::BTreeSet::new(),
            quarantined: 0,
        }
    }

    pub const fn engine(&self) -> &E {
        &self.engine
    }

    pub const fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    /// Mutable access to the sealer — for caller-specific key-material operations docsync doesn't generalize
    /// (e.g. splicing a newly-reachable epoch DEK into a running member's set after a rotation).
    pub const fn sealer_mut(&mut self) -> &mut K {
        &mut self.sealer
    }

    /// Open a `Delta` envelope to its plaintext WITHOUT merging — for a caller that must inspect an entry
    /// (e.g. §B3 author verification) before accepting it.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the sealer can't open the envelope.
    pub fn try_open_delta(&self, envelope: &[u8]) -> Result<Vec<u8>, SyncError> {
        self.sealer
            .open(EntryKind::Delta, envelope)
            .map_err(|e| SyncError::Sealer(Box::new(e)))
    }

    /// Open a `Cover` envelope (the self-heal marker) to its plaintext without merging.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the sealer can't open the envelope.
    pub fn try_open_cover(&self, envelope: &[u8]) -> Result<Vec<u8>, SyncError> {
        self.sealer
            .open(EntryKind::Cover, envelope)
            .map_err(|e| SyncError::Sealer(Box::new(e)))
    }

    /// Apply a local edit and push the delta it produced.
    ///
    /// # Errors
    /// Returns [`SyncError`] if the edit cannot be sealed or written.
    pub fn apply(&mut self, edit: E::Edit) -> Result<(), SyncError> {
        let delta = self.engine.apply_local(edit);
        self.push_delta(&delta)
    }

    /// Seal an already-encoded delta payload and append it as this replica's next log object. Empty ⇒ no-op.
    ///
    /// # Errors
    /// Returns [`SyncError`] if sealing or the blob write fails.
    pub fn push_delta(&mut self, plaintext: &[u8]) -> Result<(), SyncError> {
        if plaintext.is_empty() {
            return Ok(());
        }
        let ctx = SealCtx {
            kind: EntryKind::Delta,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: 0, // deltas carry no covered marker; only snapshots do
        };
        let out = self
            .sealer
            .seal(&ctx, plaintext)
            .map_err(|e| SyncError::Sealer(Box::new(e)))?;
        let key = log_key(&self.doc, &self.replica, self.next_counter);
        // IfAbsent: the object is immutable. A crash-retry of the same counter finds it already present
        // (PreconditionFailed) — idempotent, so treat that as success and advance, rather than failing.
        // (A replica id is fresh per open, so no two live clients ever share this keyspace.)
        match self.store.put(&key, &out.envelope, store_blob::Precondition::IfAbsent) {
            Ok(_) | Err(store_blob::BlobError::PreconditionFailed) => {}
            Err(e) => return Err(e.into()),
        }
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        // Advance our head pointer LAST (delta first, then head): a crash between leaves the head lagging,
        // so a peer just doesn't see the newest delta until the next push — a delay, never corruption. Only
        // this replica writes its own head, so an unconditional overwrite is safe.
        self.store.put(
            &head_key(&self.doc, &self.replica),
            &encode_count(self.next_counter),
            store_blob::Precondition::Any,
        )?;
        // We have, by definition, "seen" our own entry — advance the frontier so `pull` doesn't refetch it.
        let f = self.pull_frontier.entry(self.replica.clone()).or_insert(0);
        *f = (*f).max(self.next_counter);
        Ok(())
    }

    /// Pull + merge every delta object newer than the inbound frontier, across all replicas, then advance the
    /// frontier. Returns the count merged. Per-entry fault isolation: an un-openable / un-mergeable object is
    /// quarantined and the frontier still advances past it, so one bad object can't wedge sync.
    ///
    /// # Errors
    /// Returns [`SyncError`] if a blob read fails (a broken backend, as opposed to one bad object).
    pub fn pull(&mut self) -> Result<usize, SyncError> {
        let hp = heads_prefix(&self.doc);
        // O(members): list only the head pointers, not the whole log.
        let mut replicas: Vec<String> = self
            .store
            .list(&hp)?
            .into_iter()
            .filter_map(|(k, _etag)| parse_head_key(&hp, &k))
            .collect();
        replicas.sort(); // deterministic order (set-union is order-independent; stable keeps it reproducible)

        let mut merged = 0;
        for replica in replicas {
            let Some((hb, _etag)) = self.store.get(&head_key(&self.doc, &replica))? else {
                continue; // head vanished (a concurrent delete) — skip
            };
            let Some(head) = decode_count(&hb) else {
                self.quarantined += 1; // a malformed head pointer — skip this replica this tick
                continue;
            };
            // Fetch only this replica's gap: [frontier .. head).
            let mut c = self.pull_frontier.get(&replica).copied().unwrap_or(0);
            while c < head {
                let Some((bytes, _etag)) = self.store.get(&log_key(&self.doc, &replica, c))? else {
                    break; // the head ran ahead of a not-yet-written delta — stop; retry next pull
                };
                match self.sealer.open(EntryKind::Delta, &bytes) {
                    Ok(pt) => match self.engine.merge(&pt) {
                        Ok(()) => merged += 1,
                        Err(_) => self.quarantined += 1,
                    },
                    Err(_) => self.quarantined += 1,
                }
                c += 1;
            }
            self.pull_frontier.insert(replica, c);
        }
        Ok(merged)
    }

    /// Like [`pull`](Self::pull), but each fetched peer delta passes through the caller's `classify` gate
    /// (the §B3 verify/attribution decision — `docsync` stays ignorant of it). The client opens the envelope
    /// and hands `classify` the raw envelope (for the author/attribution) + the opened plaintext + the dot;
    /// `classify` returns [`Verdict`]. `Accept` merges; `Reject` drops; `Hold` parks the dot in a held set,
    /// retried on every later `pull_verified` WITHOUT blocking the frontier — so a membership op that arrives
    /// after a delta can un-hold it (the OPE-382 hold/drain). An un-openable envelope is quarantined (the
    /// classifier never sees it). Returns the count merged this call (drained + fresh).
    ///
    /// # Errors
    /// Returns [`SyncError`] if a blob read fails.
    pub fn pull_verified(
        &mut self,
        mut classify: impl FnMut(&[u8], &[u8], &str, u64) -> Verdict,
    ) -> Result<usize, SyncError> {
        let mut merged = 0;

        // 1. Drain: retry every held dot (a membership op since may now un-hold it). Held dots sit BELOW the
        //    frontier, so the fresh scan below never double-processes them.
        for (replica, counter) in self.held.iter().cloned().collect::<Vec<_>>() {
            let Some((env, _etag)) = self.store.get(&log_key(&self.doc, &replica, counter))? else {
                self.held.remove(&(replica, counter)); // vanished — unrecoverable
                continue;
            };
            let Ok(pt) = self.sealer.open(EntryKind::Delta, &env) else {
                self.quarantined += 1;
                self.held.remove(&(replica, counter)); // un-openable: stop retrying it
                continue;
            };
            match classify(&env, &pt, &replica, counter) {
                Verdict::Accept => {
                    match self.engine.merge(&pt) {
                        Ok(()) => merged += 1,
                        Err(_) => self.quarantined += 1,
                    }
                    self.held.remove(&(replica, counter));
                }
                Verdict::Reject => {
                    self.held.remove(&(replica, counter));
                }
                Verdict::Hold => {} // stays held for the next drain
            }
        }

        // 2. Fresh scan: each replica's gap past the frontier.
        let hp = heads_prefix(&self.doc);
        let mut replicas: Vec<String> = self
            .store
            .list(&hp)?
            .into_iter()
            .filter_map(|(k, _etag)| parse_head_key(&hp, &k))
            .collect();
        replicas.sort();
        for replica in replicas {
            let Some((hb, _etag)) = self.store.get(&head_key(&self.doc, &replica))? else {
                continue;
            };
            let Some(head) = decode_count(&hb) else {
                self.quarantined += 1;
                continue;
            };
            let mut c = self.pull_frontier.get(&replica).copied().unwrap_or(0);
            while c < head {
                let Some((env, _etag)) = self.store.get(&log_key(&self.doc, &replica, c))? else {
                    break;
                };
                match self.sealer.open(EntryKind::Delta, &env) {
                    Ok(pt) => match classify(&env, &pt, &replica, c) {
                        Verdict::Accept => match self.engine.merge(&pt) {
                            Ok(()) => merged += 1,
                            Err(_) => self.quarantined += 1,
                        },
                        Verdict::Hold => {
                            self.held.insert((replica.clone(), c));
                        }
                        Verdict::Reject => {}
                    },
                    Err(_) => self.quarantined += 1,
                }
                c += 1;
            }
            self.pull_frontier.insert(replica, c);
        }
        Ok(merged)
    }

    /// How many peer dots are currently HELD (classified un-verifiable, awaiting a retry).
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Total objects `pull` has quarantined (skipped as un-openable / un-mergeable) over this client's life.
    pub const fn quarantined_count(&self) -> usize {
        self.quarantined
    }

    /// This replica's inbound frontier — the next counter it will pull from each replica.
    pub const fn frontier(&self) -> &Frontier {
        &self.pull_frontier
    }

    /// Fold current state into a snapshot covering this client's frontier, and CAS it to `{doc}/snapshot`.
    /// The covered frontier rides inside the sealed body, so it is authenticated with the state. A snapshot
    /// is out-of-band (not a log entry), so it consumes no replica counter. Concurrent compactions last-win;
    /// completeness is unaffected because [`bootstrap`](Self::bootstrap) always pulls the tail past whatever
    /// snapshot it finds.
    ///
    /// # Errors
    /// Returns [`SyncError`] if sealing or the blob write fails.
    pub fn compact(&mut self) -> Result<(), SyncError> {
        let mut body = encode_frontier(&self.pull_frontier);
        body.extend_from_slice(&self.engine.snapshot());
        let ctx = SealCtx {
            kind: EntryKind::Snapshot,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: self.prev_hash.clone(),
            covers_through_seq: 0, // the covered marker is the frontier inside `body`, not this scalar
        };
        let out = self
            .sealer
            .seal(&ctx, &body)
            .map_err(|e| SyncError::Sealer(Box::new(e)))?;
        self.store
            .put(&snapshot_key(&self.doc), &out.envelope, store_blob::Precondition::Any)?;
        Ok(())
    }

    /// Bring a fresh client current: load `{doc}/snapshot` if present (adopting its covered frontier as the
    /// pull baseline), then [`pull`](Self::pull) only the tail past it. Idempotent — an already-current
    /// client re-runs it harmlessly (the snapshot merges idempotently, the tail is empty).
    ///
    /// # Errors
    /// Returns [`SyncError`] if a blob read, an open, or a merge fails.
    pub fn bootstrap(&mut self) -> Result<(), SyncError> {
        if let Some((env, _etag)) = self.store.get(&snapshot_key(&self.doc))? {
            let body = self
                .sealer
                .open(EntryKind::Snapshot, &env)
                .map_err(|e| SyncError::Sealer(Box::new(e)))?;
            if let Some((covered, engine_bytes)) = decode_frontier(&body) {
                self.engine
                    .merge_snapshot(engine_bytes)
                    .map_err(|e| SyncError::Engine(Box::new(e)))?;
                // Adopt the covered frontier as our baseline (max — we may already hold more from a prior pull).
                for (replica, counter) in covered {
                    let f = self.pull_frontier.entry(replica).or_insert(0);
                    *f = (*f).max(counter);
                }
            }
        }
        self.pull()?;
        Ok(())
    }
}

/// A no-crypto [`Sealer`]: frames `[covers_through_seq: u64 BE][kind: u8][plaintext]`. Enough for tests
/// and single-project spikes; a real deployment supplies an encrypting sealer.
#[derive(Default, Clone, Copy)]
pub struct PassthroughSealer;

impl Sealer for PassthroughSealer {
    type Error = std::convert::Infallible;

    fn seal(&mut self, ctx: &SealCtx, plaintext: &[u8]) -> std::result::Result<Sealed, Self::Error> {
        let mut env = Vec::with_capacity(9 + plaintext.len());
        env.extend_from_slice(&ctx.covers_through_seq.to_be_bytes());
        env.push(match ctx.kind {
            EntryKind::Delta => 0,
            EntryKind::Snapshot => 1,
            EntryKind::Cover => 2,
        });
        env.extend_from_slice(plaintext);
        Ok(Sealed {
            envelope: env,
            ciphertext_hash: Vec::new(),
        })
    }

    fn open(&self, _kind: EntryKind, envelope: &[u8]) -> std::result::Result<Vec<u8>, Self::Error> {
        Ok(envelope.get(9..).unwrap_or(&[]).to_vec())
    }

    fn covers_through_seq(&self, envelope: &[u8]) -> u64 {
        envelope
            .get(0..8)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_be_bytes)
    }
}

#[cfg(test)]
mod tests;
