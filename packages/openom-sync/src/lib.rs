//! The client sync loop — the piece that makes a [`Tree`](openom_treelog::Tree) multi-device.
//!
//! It ties three layers that each deliberately know nothing of the others: `openom-treelog` produces
//! and consumes `commute` op bytes; `openom-sealer` seals those bytes into E2EE envelopes; a
//! `DocStore` persists opaque envelopes as an append log. A [`SyncClient`] wraps all three:
//!
//! - **push** — a local edit's ops are encoded, sealed as a `KIND_DELTA` / `FORMAT_OPENOM_TREELOG`
//!   entry, and appended to the store's log;
//! - **pull** — new log entries are opened and `merge_bytes`-d into the tree.
//!
//! Because `commute` ops are self-contained, commutative, and idempotent, delivery order and
//! at-least-once redelivery don't matter — re-pulling one's own pushes is a no-op, and any interleave
//! of two clients' pushes converges. The log carries deltas only; full snapshots are a separate
//! compaction concern (the store's snapshot slot), so the receive path always opens a delta.

use commute::codec::encode_ops;
use commute::Op;
use openom_protocol::v1::{Compression, Envelope, Format};
use openom_protocol::Message;
use openom_sealer::{EntryKind, SealContext, Sealer, SealerError};
use openom_store::{DocStore, StoreError};
use openom_treelog::{Proposal, ProposalError, Tree, TreeOp};

/// A sync failure — one of the three layers said no.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sealer(#[from] SealerError),
    /// A pulled delta's decrypted bytes didn't decode as a commute op run.
    #[error("delta decode failed: {0:?}")]
    Decode(commute::DecodeError),
    /// A pulled proposal's decrypted bytes didn't decode as a proposal bundle.
    #[error("proposal decode failed: {0:?}")]
    ProposalDecode(ProposalError),
}

impl From<commute::DecodeError> for SyncError {
    fn from(e: commute::DecodeError) -> Self {
        SyncError::Decode(e)
    }
}

type Result<T> = std::result::Result<T, SyncError>;

/// A single device's view of one tree: the local [`Tree`], the [`Sealer`] holding its DEK, and a
/// shared [`DocStore`]. Owns this replica's outbound chain state (counter + prev hash) and the
/// inbound cursor.
pub struct SyncClient<S: DocStore> {
    tree: Tree,
    sealer: Sealer,
    store: S,
    doc: String,
    next_counter: u64,
    prev_hash: Vec<u8>,
    pull_cursor: Option<u64>,
    // The proposals channel — a SEPARATE store doc, so a proposal is never on the tree's append
    // log (a server can't replay an editor's proposal into the tree). Its own chain + cursor.
    prop_counter: u64,
    prop_prev: Vec<u8>,
    proposals_cursor: Option<u64>,
    snapshot_version: Option<String>,
}

impl<S: DocStore> SyncClient<S> {
    /// Wrap a freshly-unlocked tree. `doc` is the store key for this tree's log.
    pub fn new(tree: Tree, sealer: Sealer, store: S, doc: impl Into<String>) -> Self {
        SyncClient {
            tree,
            sealer,
            store,
            doc: doc.into(),
            next_counter: 0,
            prev_hash: Vec::new(),
            pull_cursor: None,
            prop_counter: 0,
            prop_prev: Vec::new(),
            proposals_cursor: None,
            snapshot_version: None,
        }
    }

    fn proposals_doc(&self) -> String {
        format!("{}:proposals", self.doc)
    }

    /// The local tree (read model, queries).
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Apply a local edit and immediately push it. The tree updates optimistically; the sealed
    /// delta is appended to the log for peers.
    pub fn apply(&mut self, op: TreeOp) -> Result<()> {
        let ops = self.tree.apply(op);
        self.push(&ops)
    }

    /// Apply a multi-record action atomically and push it as one delta.
    pub fn apply_batch(&mut self, ops: Vec<TreeOp>) -> Result<()> {
        let produced = self.tree.apply_batch(ops);
        self.push(&produced)
    }

    /// Seal a run of ops as one delta entry and append it to the log.
    fn push(&mut self, ops: &[Op]) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let ctx = SealContext {
            kind: EntryKind::Delta,
            format: Format::OpenomTreelog,
            compression: Compression::None,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: 0,
            blob_id: Vec::new(),
        };
        let out = self.sealer.seal_entry(&ctx, &encode_ops(ops))?;
        self.store.append(&self.doc, std::slice::from_ref(&out.envelope))?;
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        Ok(())
    }

    /// Pull every log entry newer than the last pull, opening and merging each into the tree.
    /// Returns how many were applied. Merging one's own or a duplicate entry is a harmless no-op.
    pub fn pull(&mut self) -> Result<usize> {
        let (updates, new_cursor) = self.store.read_updates(&self.doc, self.pull_cursor)?;
        for envelope in &updates {
            let bytes = self.sealer.open_entry(EntryKind::Delta, envelope)?;
            self.tree.doc_mut().merge_bytes(&bytes)?;
        }
        self.pull_cursor = Some(new_cursor);
        Ok(updates.len())
    }

    /// Fold the tree into a snapshot and store it (CAS on the prior snapshot version), recording
    /// the log seq it covers through. A fresh client can then [`bootstrap`](Self::bootstrap) from
    /// the snapshot + only the tail, instead of replaying the whole log. Returns the covered seq.
    /// The caller should be current (pull first) so the snapshot reflects the whole log.
    pub fn compact(&mut self) -> Result<u64> {
        let covered = match self.pull_cursor {
            Some(c) => c,
            None => self.store.read_updates(&self.doc, None)?.1,
        };
        let ctx = SealContext {
            kind: EntryKind::Snapshot,
            format: Format::OpenomTreelog,
            compression: Compression::None,
            replica_counter: self.next_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prev_hash),
            covers_through_seq: covered,
            blob_id: Vec::new(),
        };
        let out = self.sealer.seal_entry(&ctx, &self.tree.doc().snapshot())?;
        let version = self.store.put_snapshot(&self.doc, &out.envelope, self.snapshot_version.as_deref())?;
        self.snapshot_version = Some(version);
        self.next_counter += 1;
        self.prev_hash = out.ciphertext_hash;
        Ok(covered)
    }

    /// Bring a fresh client up to date the fast way: load the stored snapshot (if any), then pull
    /// only the deltas after the seq it covers. Falls back to a full log replay when there is no
    /// snapshot. Idempotent — safe even if the snapshot and the log tail overlap.
    pub fn bootstrap(&mut self) -> Result<()> {
        if let Some(snap) = self.store.read_snapshot(&self.doc)? {
            let covered = Envelope::decode(snap.bytes.as_slice())
                .ok()
                .and_then(|e| e.header)
                .map(|h| h.covers_through_seq)
                .unwrap_or(0);
            let plaintext = self.sealer.open_entry(EntryKind::Snapshot, &snap.bytes)?;
            self.tree.doc_mut().merge_bytes(&plaintext)?;
            self.snapshot_version = Some(snap.version);
            self.pull_cursor = Some(covered);
        }
        self.pull()?;
        Ok(())
    }

    /// Draft a proposal against the current head and push it to the proposals channel — sealed as
    /// `KIND_PROPOSAL`, NOT applied to the local tree (an editor proposes; an approver commits).
    pub fn push_proposal(&mut self, ops: Vec<TreeOp>) -> Result<Proposal> {
        let proposal = Proposal { base: self.tree.version_cursor(), ops };
        let ctx = SealContext {
            kind: EntryKind::Proposal,
            format: Format::OpenomTreelog,
            compression: Compression::None,
            replica_counter: self.prop_counter,
            prev_ciphertext_hash: std::mem::take(&mut self.prop_prev),
            covers_through_seq: 0,
            blob_id: Vec::new(),
        };
        let out = self.sealer.seal_entry(&ctx, &proposal.encode())?;
        self.store.append(&self.proposals_doc(), std::slice::from_ref(&out.envelope))?;
        self.prop_counter += 1;
        self.prop_prev = out.ciphertext_hash;
        Ok(proposal)
    }

    /// Pull newly-staged proposals for review (open + decode). Read-only w.r.t. the tree.
    pub fn pull_proposals(&mut self) -> Result<Vec<Proposal>> {
        let (updates, new_cursor) = self.store.read_updates(&self.proposals_doc(), self.proposals_cursor)?;
        let mut out = Vec::with_capacity(updates.len());
        for envelope in &updates {
            let bytes = self.sealer.open_entry(EntryKind::Proposal, envelope)?;
            out.push(Proposal::decode(&bytes).map_err(SyncError::ProposalDecode)?);
        }
        self.proposals_cursor = Some(new_cursor);
        Ok(out)
    }

    /// Approve a proposal: apply its bundle to the tree and push the resulting delta. The caller is
    /// responsible for the role check (only an approver reaches this) and for having reviewed it.
    pub fn commit_proposal(&mut self, proposal: &Proposal) -> Result<()> {
        let ops = self.tree.commit_proposal(proposal);
        self.push(&ops)
    }
}

#[cfg(test)]
mod tests;
