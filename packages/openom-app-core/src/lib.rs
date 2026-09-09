#![doc = include_str!("../README.md")]

use std::collections::BTreeSet;
use std::sync::Arc;

use openom_data_tree::{OpView, Tree, TreeError};
use openom_docsync::SyncClient;
use openom_protocol::v1::Envelope;
use openom_protocol::Message;
use openom_sealer::SealerSet;
use openom_vault::{Disposition, MembershipResolver};
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
    /// The §B3 governing membership for verify-on-ingest. `None` ⇒ a solo / never-shared tree (no keyring):
    /// AEAD-only is safe there (only the DEK holder can write), so ingest accepts without attribution. The
    /// worker installs `Some(..)` via [`set_membership`](Self::set_membership) once the tree is shared, after
    /// which every peer entry is verified against the resolved roles before it is stored or folded.
    membership: Option<Box<dyn MembershipResolver>>,
    /// Peer entries HELD because their governing keyring/epoch isn't retained locally yet (the data channel
    /// outran the keyring channel). Re-verified on the next [`set_membership`](Self::set_membership); never
    /// folded until they verify. Bounded by [`HELD_CAP`](Self::HELD_CAP) — an overflow is dropped (counted in
    /// [`anomalies`](Self::anomalies)) and recovered on a reload's full re-pull, since the server log is never
    /// pruned below an un-subsumed entry.
    held: Vec<Vec<u8>>,
    /// Peer entries REJECTED by §B3 verification (forged / unattributed-on-shared / illegitimate), plus any
    /// hold-buffer overflow — never stored, and the cursor still advances so a forgery can't stall the tail.
    /// Surfaced via [`anomalies`](Self::anomalies), never silently swallowed.
    rejected: usize,
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
            membership: None,
            held: Vec::new(),
            rejected: 0,
        }
    }

    /// The hold buffer's cap — entries awaiting a not-yet-synced governing keyring. Beyond this an overflow is
    /// dropped (recovered on a reload's full re-pull), so a peer withholding a keyring can't grow memory
    /// without bound.
    const HELD_CAP: usize = 1024;

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

    /// Clear the tree AND the local durable store — the engine side of a demo reseed / hard local reset.
    /// Keeps the sealer (DEK) + author; a subsequent seed writes a fresh set. Demo/dev flow: a synced
    /// tree never resets, so docsync's own read cursor is left as-is (a reload re-bootstraps it anyway).
    ///
    /// # Errors
    /// Returns [`CoreError`] if clearing the local store fails.
    pub fn reset(&mut self) -> Result<(), CoreError> {
        self.client.tree_mut().clear();
        self.store.delete(&self.doc)?;
        self.push_scan = None;
        self.server_cursor = None;
        self.persisted = None;
        self.seen.clear();
        self.undecodable = 0;
        self.held.clear();
        self.rejected = 0;
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

    /// Data-integrity anomalies observed so far: server entries whose header wouldn't decode, the pull's
    /// quarantined (un-openable / un-mergeable) entries, and the §B3-rejected forgeries (+ hold overflow). A
    /// caller surfaces a non-zero count as a warning — these are never silently swallowed.
    #[must_use]
    pub fn anomalies(&self) -> usize {
        self.undecodable + self.client.quarantined_count() + self.rejected
    }

    /// Install (or refresh) the §B3 governing membership. The worker calls this on unlock and after every
    /// keyring sync, passing a resolver ([`openom_vault::ChainMembershipResolver`] /
    /// [`openom_vault::DagMembershipResolver`])
    /// built from the freshly-verified keyring. Once set, every peer entry [`ingest`](Self::ingest) sees is
    /// verified against the resolved roles before it is stored or folded.
    ///
    /// Re-runs verification on the Held buffer: entries whose governing keyring/epoch is now retained are
    /// stored + folded; the rest stay held (up to the cap) or are rejected. Returns how many newly-released
    /// held entries the fold took in.
    ///
    /// # Errors
    /// Returns [`CoreError`] if releasing a now-valid held entry fails to append to the local store or fold.
    pub fn set_membership(&mut self, membership: Box<dyn MembershipResolver>) -> Result<usize, CoreError> {
        // NOTE (follow-up): a sticky-shared guard here — refuse a resolver that reports `!shared()` when the
        // current one reports `shared()`, so a worker bug feeding a stale pre-share keyring can't downgrade
        // mid-session to accept-all — is worth adding, but must be threaded as a separate `was_shared` flag
        // consulted in the verify path (not a guard here) so it doesn't collide with the crypto-free test
        // double that encodes its route via `shared()`. Primary defense is installing the resolver at unlock.
        self.membership = Some(membership);
        self.drain_held()
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
                Some(dot) if self.seen.contains(&dot) => {} // already stored (a re-pulled tail)
                Some(dot) => self.admit(env, dot)?,
            }
        }
        // Monotonic: never rewind the cursor (a smaller value would re-pull; dedup makes that safe but
        // wasteful — a rewind loop is not). Only ever move forward.
        self.server_cursor = Some(self.server_cursor.map_or(next_cursor, |c| c.max(next_cursor)));
        Ok(self.client.pull_claims()?)
    }

    /// Route one deduped, attributable peer entry through §B3 verification. Accept ⇒ store it (the next
    /// `pull_claims` folds it, and a reload re-folds it from the durable log). Hold ⇒ buffer it, unstored, for
    /// re-verification after the next [`set_membership`](Self::set_membership). Reject ⇒ count it as an
    /// anomaly and drop it — never stored, so a forgery can neither be folded nor stall the tail.
    fn admit(&mut self, env: &[u8], dot: (Vec<u8>, u64)) -> Result<(), CoreError> {
        match self.classify(env) {
            Disposition::Accept => {
                self.seen.insert(dot);
                self.store.append(&self.doc, &[env.to_vec()])?;
            }
            Disposition::Hold => self.hold(env),
            Disposition::Reject => self.rejected += 1,
        }
        Ok(())
    }

    /// The §B3 disposition for one peer entry. With no shared membership installed (a solo / never-shared
    /// tree) every entry is accepted — AEAD-only is safe because only the DEK holder can write. Otherwise the
    /// entry is opened ONLY if a signature must actually be checked (`verify_ingest` calls `open` lazily), and
    /// an entry whose envelope/header won't even decode on a shared tree is rejected as untrustworthy.
    fn classify(&self, env: &[u8]) -> Disposition {
        let Some(membership) = self.membership.as_deref() else {
            return Disposition::Accept;
        };
        let Ok(envelope) = Envelope::decode(env) else {
            return Disposition::Reject;
        };
        let Some(header) = envelope.header.as_ref() else {
            return Disposition::Reject;
        };
        openom_vault::verify_ingest(
            envelope.version,
            membership,
            header,
            &header.governing_ref,
            &header.key_id,
            || self.client.try_open_delta(env),
        )
    }

    /// Buffer a held entry, bounded by [`HELD_CAP`](Self::HELD_CAP). An overflow is dropped and counted as an
    /// anomaly (recovered on a reload's full re-pull), so a peer withholding a keyring can't exhaust memory.
    fn hold(&mut self, env: &[u8]) {
        if self.held.len() < Self::HELD_CAP {
            self.held.push(env.to_vec());
        } else {
            self.rejected += 1;
        }
    }

    /// Re-verify the Held buffer after a [`set_membership`](Self::set_membership): a now-retained governing
    /// keyring/epoch releases its entries into the store, the rest stay held or are rejected. Folds the
    /// released entries and returns the fold count.
    fn drain_held(&mut self) -> Result<usize, CoreError> {
        if self.held.is_empty() {
            return Ok(0);
        }
        let held = std::mem::take(&mut self.held);
        for (i, env) in held.iter().enumerate() {
            match envelope_dot(env) {
                Some(dot) if !self.seen.contains(&dot) => {
                    if let Err(e) = self.admit(env, dot) {
                        // A local-store append failed — keep the failed entry AND the un-visited remainder
                        // for a later retry rather than silently dropping them.
                        self.held.extend_from_slice(&held[i..]);
                        return Err(e);
                    }
                }
                _ => {} // undecodable dots never entered the buffer; a since-stored dot needs no replay
            }
        }
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
