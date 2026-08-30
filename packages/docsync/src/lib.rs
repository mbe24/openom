//! `docsync` — a generic local-first client sync loop.
//!
//! The push / pull / compact / bootstrap loop over a [`journal::DocStore`], abstracted over a merge
//! [`Engine`] and an envelope [`Sealer`] so it isn't tied to any one CRDT or crypto. A caller re-imports
//! it by `impl Engine` for its CRDT (encode a local edit → delta bytes; merge delta/snapshot bytes;
//! snapshot) and `impl Sealer` for its envelope format. All domain logic — the concrete op/state model,
//! the encryption — stays caller-side behind those two seams; this crate carries none of it.
//!
//! The [`Engine`] seam is **delta-bytes-centric**, which fits both op-CRDTs (`encode(state.apply(op))`)
//! and doc-CRDTs (`export(update, from = before)`). Because merges are idempotent/commutative, delivery
//! order and at-least-once redelivery don't matter — re-pulling one's own pushes is a no-op. (Causally
//! *dependent* workflows such as propose/approve are intentionally not generalized here: they only stay
//! clean for causally-independent ops, so a caller layers them above this loop.)

use journal::{DocStore, StoreError};

/// Kind of a sealed log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Delta,
    Snapshot,
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
    fn merge(&mut self, delta: &[u8]) -> Result<(), Self::Error>;
    /// Full-state snapshot bytes (for compaction).
    fn snapshot(&self) -> Vec<u8>;
    /// Merge a snapshot's bytes (bootstrap). Defaults to [`merge`](Engine::merge).
    fn merge_snapshot(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.merge(bytes)
    }
}

/// The envelope seam — seals plaintext into opaque bytes and opens them back.
pub trait Sealer {
    type Error: std::error::Error + Send + Sync + 'static;

    fn seal(&mut self, ctx: &SealCtx, plaintext: &[u8]) -> Result<Sealed, Self::Error>;
    fn open(&self, kind: EntryKind, envelope: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// `covers_through_seq` recorded in a snapshot envelope (for bootstrap).
    fn covers_through_seq(&self, snapshot_envelope: &[u8]) -> u64;
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Store(#[from] StoreError),
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
    /// Sealed-but-not-yet-appended envelopes (write-ahead queue): sealed once, re-appended on retry
    /// (idempotent on peers).
    pending: Vec<Vec<u8>>,
}

impl<E: Engine, K: Sealer, S: DocStore> SyncClient<E, K, S> {
    pub fn new(engine: E, sealer: K, store: S, doc: impl Into<String>) -> Self {
        SyncClient {
            engine,
            sealer,
            store,
            doc: doc.into(),
            next_counter: 0,
            prev_hash: Vec::new(),
            pull_cursor: None,
            snapshot_version: None,
            pending: Vec::new(),
        }
    }

    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Mutable access to the engine — for caller-specific operations docsync doesn't generalize (e.g. a
    /// domain version cursor, or a workflow-specific commit).
    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    /// Apply a local edit and immediately push it.
    pub fn apply(&mut self, edit: E::Edit) -> Result<(), SyncError> {
        let delta = self.engine.apply_local(edit);
        self.push(EntryKind::Delta, &delta, 0)
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
    pub fn flush(&mut self) -> Result<(), SyncError> {
        while let Some(env) = self.pending.first() {
            self.store.append(&self.doc, std::slice::from_ref(env))?;
            self.pending.remove(0);
        }
        Ok(())
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Pull + merge every log entry newer than the last pull. Returns the count.
    pub fn pull(&mut self) -> Result<usize, SyncError> {
        let (updates, new_cursor) = self.store.read_updates(&self.doc, self.pull_cursor)?;
        for env in &updates {
            let bytes = self
                .sealer
                .open(EntryKind::Delta, env)
                .map_err(|e| SyncError::Sealer(Box::new(e)))?;
            self.engine
                .merge(&bytes)
                .map_err(|e| SyncError::Engine(Box::new(e)))?;
        }
        self.pull_cursor = Some(new_cursor);
        Ok(updates.len())
    }

    /// Fold state into a snapshot and CAS it, recording the seq it covers.
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
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        Ok(covered)
    }

    /// Bring a fresh client current: load the snapshot (if any), then pull only the tail after the seq it
    /// covers. Idempotent.
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
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests;
