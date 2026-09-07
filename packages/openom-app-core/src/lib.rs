#![doc = include_str!("../README.md")]

use std::collections::BTreeSet;
use std::sync::Arc;

use openom_data_tree::{OpView, Tree, TreeError};
use openom_docsync::SyncClient;
use openom_protocol::v1::Envelope;
use openom_protocol::Message;
use openom_sealer::SealerSet;
use serde_json::Value;
use store_log::DocStore;

#[cfg(feature = "wasm")]
mod wasm;

/// Anything that can go wrong in the core.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A sync-loop / sealer error from the docsync layer.
    #[error(transparent)]
    Sync(#[from] openom_docsync::SyncError),
    /// An engine (mint / flush / read) error.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// A local durable-store error (the replicator's direct append / read).
    #[error(transparent)]
    Store(#[from] store_log::StoreError),
}

/// The local-origin sealed deltas awaiting a server push, and the local-store cursor they cover.
///
/// The worker driver POSTs each entry to the server, and on success calls
/// [`AppCore::mark_pushed`] with `through` — so a failed push simply re-scans the same range next
/// tick (the server dedups a re-sent entry on its replica dot, so a retry is harmless).
#[derive(Debug, Clone)]
pub struct Outbound {
    /// The sealed `Envelope` bytes to POST to the server's log, oldest first.
    pub entries: Vec<Vec<u8>>,
    /// The local-store seq the scan reached — pass to [`AppCore::mark_pushed`] once every entry lands.
    pub through: u64,
}

/// One tree's Rust core: the engine + sealer + docsync loop over a local durable store, plus the
/// local⇄server [`Replicator`](self) cursors. Every method is **synchronous**; the worker driver
/// wraps them with `fetch`.
///
/// The store is held as `Arc<S>` so the docsync client and the replicator share one underlying log:
/// docsync appends this replica's mints and folds the local tail into the engine, while the replicator
/// pushes this replica's own entries up and appends peers' entries down.
pub struct AppCore<S: DocStore> {
    client: SyncClient<Arc<S>>,
    store: Arc<S>,
    doc: String,
    /// This replica's id (the sealer's `replica_id`) — the discriminator that keeps the replicator
    /// from echoing peers' entries back up or re-storing our own on the way down.
    replica: Vec<u8>,
    /// Every peer replica-dot `(replica_id, counter)` already in the local store — so re-pulling the
    /// server tail on a reload (when `server_cursor` has reset) does NOT re-append peer entries. Built
    /// from the store on [`import_log`](Self::import_log); grown on [`ingest`](Self::ingest).
    seen: std::collections::BTreeSet<(Vec<u8>, u64)>,
    /// Server log entries whose header wouldn't even decode (can't attribute or dedup them) — skipped
    /// at ingest and surfaced via [`anomalies`](Self::anomalies), not silently dropped.
    undecodable: usize,
    /// Local-store seq already scanned for outbound push.
    push_scan: Option<u64>,
    /// Local-store seq already mirrored to durable storage (the persist cursor lives in Rust, not the
    /// worker — the host just executes the append and confirms with [`mark_persisted`](Self::mark_persisted)).
    persisted: Option<u64>,
    /// The server log `?since` cursor — the seq of the newest server entry already pulled.
    server_cursor: Option<i64>,
}

impl<S: DocStore> AppCore<S> {
    /// Wrap a freshly-unlocked tree. `created_by` is this device's author `did:key`; `sealer` carries
    /// the DEK and this replica's id; `store` is the local durable log; `doc` is its store key.
    pub fn new(
        created_by: impl Into<String>,
        sealer: SealerSet,
        store: Arc<S>,
        doc: impl Into<String>,
        replica: Vec<u8>,
    ) -> Self {
        let doc = doc.into();
        Self {
            client: SyncClient::new(created_by, sealer, Arc::clone(&store), doc.clone()),
            store,
            doc,
            replica,
            seen: std::collections::BTreeSet::new(),
            undecodable: 0,
            push_scan: None,
            persisted: None,
            server_cursor: None,
        }
    }

    /// Rebuild the engine from the local durable log (snapshot + tail) — call once on open, after a
    /// reload. This is what makes an offline mint survive a reload: the mint is durable in the local
    /// store, so it re-enters the engine here and is re-offered by [`outbound`](Self::outbound).
    ///
    /// # Errors
    /// Returns [`CoreError`] if the store read or a merge fails.
    pub fn bootstrap(&mut self) -> Result<(), CoreError> {
        self.client.bootstrap_claims()?;
        Ok(())
    }

    /// The moderator `did:key`s (Maintainer+) whose Remove/Supersede/Revoke ops the fold honors.
    pub fn set_moderators(&mut self, moderators: BTreeSet<String>) {
        self.client.set_moderators(moderators);
    }

    /// The engine, mutably — mint through it (`assert_anchor`, `assert_claim`, `remove`, …); the batch
    /// reaches the durable store on the next [`commit`](Self::commit).
    pub const fn tree_mut(&mut self) -> &mut Tree {
        self.client.tree_mut()
    }

    /// The engine, read-only — for the app's projection / op-log reads.
    #[must_use]
    pub const fn tree(&self) -> &Tree {
        self.client.tree()
    }

    /// Seal everything minted since the last commit as ONE op-batch and append it to the local durable
    /// log (one settled intention = one entry). A no-op if nothing was minted.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the batch can't be encoded, sealed, or appended.
    pub fn commit(&mut self) -> Result<(), CoreError> {
        let batch = self.client.tree_mut().flush()?;
        self.client.push_delta(&batch)?;
        Ok(())
    }

    // --- the replicator: local log ⇄ server ----------------------------------------------------

    /// This replica's own sealed deltas the server hasn't seen yet (see [`Outbound`]). Peers' entries
    /// that reached the local store via [`ingest`](Self::ingest) are filtered out by replica id.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the local store read fails.
    pub fn outbound(&self) -> Result<Outbound, CoreError> {
        let (updates, through) = self.store.read_updates(&self.doc, self.push_scan)?;
        let entries = updates
            .into_iter()
            .filter(|env| envelope_dot(env).is_some_and(|(r, _)| r == self.replica))
            .collect();
        Ok(Outbound { entries, through })
    }

    /// Advance the outbound cursor after every entry from an [`outbound`](Self::outbound) batch has
    /// been accepted by the server.
    pub const fn mark_pushed(&mut self, through: u64) {
        self.push_scan = Some(through);
    }

    // --- durable persistence: the core owns the log; the host executes the plan --------------------
    //
    // The core computes *what* to persist synchronously (opaque sealed byte-batches + the log cursor);
    // the host (worker JS) executes the writes against a dumb async blob store (IndexedDB on web,
    // rusqlite on Tauri) OUTSIDE these sync steps. No storage engine lives in Rust-wasm — persisting
    // encrypted blobs is plumbing the platform already handles.

    /// Every local-log entry after `since` (the whole log if `None`) plus the new cursor — the batch the
    /// host should append to durable storage. Unlike [`outbound`](Self::outbound), this is NOT filtered
    /// by replica: durability mirrors the *whole* local log (ours + peers'), so a reload rebuilds the
    /// full set without re-pulling everything from the server.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the local store read fails.
    pub fn export_since(&self, since: Option<u64>) -> Result<(Vec<Vec<u8>>, u64), CoreError> {
        Ok(self.store.read_updates(&self.doc, since)?)
    }

    /// Load durably-persisted log entries back into the local store on open (before
    /// [`bootstrap`](Self::bootstrap) replays them into the engine). Idempotent at the engine level
    /// (merge dedups by content id), but the host should load each entry once (it tracks its own
    /// persisted cursor).
    ///
    /// # Errors
    /// Returns [`CoreError`] if the local store append fails.
    pub fn import_log(&mut self, entries: &[Vec<u8>]) -> Result<(), CoreError> {
        for env in entries {
            if let Some((replica, counter)) = envelope_dot(env) {
                if replica != self.replica {
                    self.seen.insert((replica, counter)); // so a later re-pull doesn't re-append these
                }
            }
        }
        if !entries.is_empty() {
            self.store.append(&self.doc, entries)?;
        }
        // Everything imported is already durable (it came FROM durable storage), so the persist cursor
        // starts past it — the host won't re-mirror the reloaded log.
        self.persisted = Some(self.store.read_updates(&self.doc, None)?.1);
        Ok(())
    }

    /// Local-log entries not yet mirrored to durable storage, plus the cursor to confirm afterwards
    /// with [`mark_persisted`](Self::mark_persisted). The persist cursor lives here, in the core — the
    /// host just runs the append and confirms.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the local store read fails.
    pub fn export_unpersisted(&self) -> Result<(Vec<Vec<u8>>, u64), CoreError> {
        self.export_since(self.persisted)
    }

    /// Advance the persist cursor after the host has durably written an [`export_unpersisted`] batch.
    pub const fn mark_persisted(&mut self, through: u64) {
        self.persisted = Some(through);
    }

    /// Data-integrity anomalies observed so far: server entries whose header wouldn't decode plus the
    /// pull's quarantined (un-openable / un-mergeable) entries. A caller surfaces a non-zero count as a
    /// warning — these are never silently swallowed.
    #[must_use]
    pub fn anomalies(&self) -> usize {
        self.undecodable + self.client.quarantined_count()
    }

    /// The server log `?since` cursor for the next pull (`None` ⇒ from the beginning).
    #[must_use]
    pub const fn server_since(&self) -> Option<i64> {
        self.server_cursor
    }

    /// Fold a page of server log entries into the tree, then advance the server cursor. Each peer entry
    /// is appended to the local log **once** — deduped on its replica dot against [`seen`](Self) — so a
    /// reload that re-pulls the tail (cursor reset) does not re-append peer history. Our own entries
    /// (echoed back) are skipped; an entry whose header won't decode is counted (see
    /// [`anomalies`](Self::anomalies)), never blindly stored. The merge is fault-isolated in `pull`, so
    /// one bad entry can't wedge. Returns how many entries the merge folded in.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a local store append or read fails (a broken backend — not one bad entry).
    pub fn ingest(&mut self, payloads: &[Vec<u8>], next_cursor: i64) -> Result<usize, CoreError> {
        for env in payloads {
            match envelope_dot(env) {
                None => self.undecodable += 1, // can't attribute or dedup — skip, surface via anomalies
                Some((replica, _)) if replica == self.replica => {} // our own, echoed back
                Some(dot) => {
                    if self.seen.insert(dot) {
                        self.store.append(&self.doc, std::slice::from_ref(env))?;
                    }
                }
            }
        }
        // Monotonic: never rewind the cursor (a smaller value would re-pull; dedup makes that safe but
        // wasteful — a rewind loop is not). Only ever move forward.
        self.server_cursor = Some(self.server_cursor.map_or(next_cursor, |c| c.max(next_cursor)));
        Ok(self.client.pull_claims()?)
    }

    /// How many sealed batches docsync has queued but not yet appended locally (0 == the local write is
    /// fully durable). A diagnostic for the driver.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.client.pending_count()
    }

    // --- reads --------------------------------------------------------------------------------

    /// The materialized read model as JSON — what the UI renders.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the projection can't be serialized.
    pub fn project_json(&self) -> Result<String, CoreError> {
        Ok(self.client.tree().project_json()?)
    }

    /// The operations log — every op with its author and whether the fold currently honors it (see
    /// [`OpView`]). The below-Maintainer moderation ops are the inert (non-`effective`) ones.
    #[must_use]
    pub fn oplog(&self) -> Vec<OpView> {
        self.client.tree().oplog()
    }

    /// The operations log as JSON — for the wasm boundary.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the log can't be serialized.
    pub fn oplog_json(&self) -> Result<String, CoreError> {
        Ok(self.client.tree().oplog_json()?)
    }

    /// Every live record as JSON — the granular set the app's undo/redo diff reads.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a record can't be serialized.
    pub fn live_records(&self) -> Result<Vec<Value>, CoreError> {
        Ok(self.client.live_records()?)
    }

    /// The live claims about `target` under `predicate` (each as its JSON record) — the granular reader
    /// the editor uses to decide supersede-vs-assert.
    #[must_use]
    pub fn live_claims_of(&self, target: &str, predicate: &str) -> Vec<Value> {
        self.client.tree().live_claims_of(target, predicate)
    }

    /// Every live claim about `target`, whatever the predicate — the predicate-less reader (e.g. delete).
    #[must_use]
    pub fn live_claims_of_any(&self, target: &str) -> Vec<Value> {
        self.client.tree().live_claims_of_any(target)
    }

    /// The canonical person id an anchor resolves to (its cluster's minimum-anchor id), or `None`.
    #[must_use]
    pub fn resolve_id(&self, anchor: &str) -> Option<String> {
        self.client.tree().resolve_id(anchor)
    }
}

/// The replica dot `(replica_id, replica_counter)` from a sealed `Envelope`'s (plaintext) header — the
/// replicator's echo discriminator and its idempotency key. `None` if the bytes don't decode as an
/// `Envelope` with a header (never our own freshly-sealed entry; a peer entry that returns `None` is
/// counted as an anomaly rather than misattributed).
fn envelope_dot(envelope: &[u8]) -> Option<(Vec<u8>, u64)> {
    let header = Envelope::decode(envelope).ok()?.header?;
    Some((header.replica_id, header.replica_counter))
}

#[cfg(test)]
mod tests;
