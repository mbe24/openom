//! The `#[wasm_bindgen]` veneer over [`AppCore`] — the surface the Web Worker calls. Every method is
//! synchronous (the worker's async driver wraps them with `fetch`); the DEK lives in this module's
//! linear memory and never crosses to JS. The worker keeps a `Map<docId, AppCoreHandle>`; each handle
//! owns one tree's engine + sealer + local store + replicator.
//!
//! Marshalling: ids and sealed envelopes cross as `Uint8Array`; claim values and the read model as JSON
//! strings; the `u64`/`i64` cursors as range-checked `f64` (JS numbers). The flat argument lists are the
//! JS calling convention, hence the documented `too_many_arguments` allow.

use std::collections::BTreeSet;
use std::sync::Arc;

use js_sys::{Array, Object, Reflect, Uint8Array};
use openom_crypto::{Passphrase, RecoveryCode};
use openom_keyring_api::EngineKind;
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_sealer::{Sealer, SealerSet};
use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
use openom_vault::AppVault;
use store_log::memory::MemoryStore;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::AppCore;

/// The local durable store the worker core runs over. `MemoryStore` for now (functional, not durable
/// across a reload); an OPFS-backed `DocStore` swaps in here to make an offline mint survive a reload.
type Store = MemoryStore;

/// One tree's core, as the worker sees it. Owns the engine + sealer (DEK) + local store + replicator.
#[wasm_bindgen]
pub struct AppCoreHandle {
    inner: AppCore<Store>,
}

#[wasm_bindgen]
impl AppCoreHandle {
    /// A local-development core (§16 reserved dev key: the full seal/open path, no unlock flow) — for
    /// the demo datasets and the sync e2e. Production refuses this key id, so this never ships data.
    #[wasm_bindgen(js_name = dev)]
    #[must_use]
    pub fn dev(tree_id: &[u8], replica_id: &[u8], created_by: String, doc: String) -> Self {
        let sealer = SealerSet::single(Sealer::dev(
            TreeId::new(tree_id.to_vec()),
            ReplicaId::new(replica_id.to_vec()),
        ));
        let store = Arc::new(MemoryStore::new());
        Self {
            inner: AppCore::new(created_by, sealer, store, doc, replica_id.to_vec()),
        }
    }

    /// Rebuild the engine from the local durable log — call once on open (a no-op on a fresh store).
    ///
    /// # Errors
    /// Returns a [`JsError`] if the store read or a merge fails.
    #[wasm_bindgen]
    pub fn bootstrap(&mut self) -> Result<(), JsError> {
        self.inner.bootstrap().map_err(to_js)
    }

    /// Set the moderator `did:key`s (Maintainer+) whose Remove/Supersede/Revoke ops the fold honors.
    #[wasm_bindgen(js_name = setModerators)]
    pub fn set_moderators(&mut self, dids: Vec<String>) {
        self.inner.set_moderators(dids.into_iter().collect::<BTreeSet<_>>());
    }

    // --- mint (buffer into the current intention; `commit` seals + persists the batch) --------------

    /// Assert an identity anchor (with its existence claim) — see `Tree::assert_anchor`.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the anchor can't be canonicalized.
    #[wasm_bindgen(js_name = assertAnchor)]
    pub fn assert_anchor(&mut self, id: &str, type_uri: &str) -> Result<(), JsError> {
        self.inner
            .tree_mut()
            .assert_anchor(id, type_uri, now_millis())
            .map_err(to_js)
    }

    /// Assert a claim about `target` — `value_json` is the claim value as a JSON string.
    ///
    /// # Errors
    /// Returns a [`JsError`] if `value_json` is invalid or the claim can't be canonicalized.
    #[wasm_bindgen(js_name = assertClaim)]
    pub fn assert_claim(
        &mut self,
        target: &str,
        predicate: &str,
        value_json: &str,
    ) -> Result<(), JsError> {
        let value = serde_json::from_str(value_json).map_err(to_js)?;
        self.inner
            .tree_mut()
            .assert_claim(target, predicate, value, now_millis())
            .map_err(to_js)
    }

    /// Supersede `prior` with a fresh claim value (an atomic edit).
    ///
    /// # Errors
    /// Returns a [`JsError`] if `value_json` is invalid or the op can't be canonicalized.
    #[wasm_bindgen(js_name = supersedeClaim)]
    pub fn supersede_claim(
        &mut self,
        prior: &str,
        target: &str,
        predicate: &str,
        value_json: &str,
    ) -> Result<(), JsError> {
        let value = serde_json::from_str(value_json).map_err(to_js)?;
        self.inner
            .tree_mut()
            .supersede_claim(prior, target, predicate, value, now_millis())
            .map_err(to_js)
    }

    /// Remove one of this author's records by id — returns the Remove op's own id (for a later revoke).
    ///
    /// # Errors
    /// Returns a [`JsError`] if the op can't be canonicalized.
    #[wasm_bindgen(js_name = removeRecord)]
    pub fn remove_record(&mut self, target: &str) -> Result<String, JsError> {
        self.inner
            .tree_mut()
            .remove(target, now_millis())
            .map_err(to_js)
    }

    /// Undo a same-author Remove by its op id.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the op can't be canonicalized.
    #[wasm_bindgen]
    pub fn revoke(&mut self, removal_op_id: &str) -> Result<(), JsError> {
        self.inner
            .tree_mut()
            .revoke(removal_op_id, now_millis())
            .map_err(to_js)
    }

    /// Seal everything minted since the last commit as one op-batch and append it to the local durable
    /// log (a no-op if nothing was minted).
    ///
    /// # Errors
    /// Returns a [`JsError`] if the batch can't be encoded, sealed, or appended.
    #[wasm_bindgen]
    pub fn commit(&mut self) -> Result<(), JsError> {
        self.inner.commit().map_err(to_js)
    }

    /// Clear the tree + the local durable store (demo reseed / hard local reset). Keeps the DEK.
    ///
    /// # Errors
    /// Returns a [`JsError`] if clearing the local store fails.
    #[wasm_bindgen]
    pub fn reset(&mut self) -> Result<(), JsError> {
        self.inner.reset().map_err(to_js)
    }

    // --- the replicator's synchronous steps (the worker driver does the `fetch` between them) --------

    /// This replica's own sealed deltas the server hasn't seen, as `{ entries: Uint8Array[], through:
    /// number }`. POST each entry, then call [`markPushed`](Self::mark_pushed) with `through`.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the local store read fails, or the result object can't be built.
    #[wasm_bindgen]
    pub fn outbound(&self) -> Result<JsValue, JsError> {
        let out = self.inner.outbound().map_err(to_js)?;
        let entries = Array::new();
        for env in &out.entries {
            entries.push(&Uint8Array::from(env.as_slice()));
        }
        let obj = Object::new();
        set(&obj, "entries", &entries)?;
        set(&obj, "through", &JsValue::from_f64(u64_to_f64(out.through)))?;
        Ok(obj.into())
    }

    /// Advance the outbound cursor after every entry from an [`outbound`](Self::outbound) batch landed.
    #[wasm_bindgen(js_name = markPushed)]
    pub fn mark_pushed(&mut self, through: f64) -> Result<(), JsError> {
        self.inner.mark_pushed(as_u64(through, "through")?);
        Ok(())
    }

    /// The server log `?since` cursor for the next pull (`undefined` ⇒ from the beginning).
    #[wasm_bindgen(js_name = serverSince)]
    #[must_use]
    pub fn server_since(&self) -> Option<f64> {
        self.inner.server_since().map(i64_to_f64)
    }

    /// Fold a page of server log entries (an array of `Uint8Array`) into the tree, advance the server
    /// cursor to `next_cursor`, and merge the new local tail into the engine. Returns how many entries
    /// the merge folded in.
    ///
    /// # Errors
    /// Returns a [`JsError`] if an element isn't a `Uint8Array`, or the store/merge fails.
    #[wasm_bindgen]
    pub fn ingest(&mut self, payloads: &Array, next_cursor: f64) -> Result<usize, JsError> {
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(payloads.length() as usize);
        for v in payloads.iter() {
            let bytes: Uint8Array = v
                .dyn_into()
                .map_err(|_| JsError::new("each server log entry must be a Uint8Array"))?;
            batch.push(bytes.to_vec());
        }
        self.inner
            .ingest(&batch, as_i64(next_cursor, "nextCursor")?)
            .map_err(to_js)
    }

    /// Install (or refresh) the §B3 governing membership so [`ingest`](Self::ingest) verifies peer entries
    /// against the resolved roles. The worker calls this on unlock of a shared tree and after every keyring
    /// sync, passing the engine tag, the current head keyring/anchor, and — chain only — the retained
    /// per-revision keyrings as `[revision, Uint8Array][]` (empty for the dag, which resolves from the single
    /// anchor). Returns how many held entries the refresh released into the tree.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the engine is unknown, a keyring blob is malformed, or releasing a now-valid
    /// held entry fails.
    #[wasm_bindgen(js_name = setMembership)]
    pub fn set_membership(
        &mut self,
        engine: &str,
        head: &[u8],
        retained: &Array,
    ) -> Result<usize, JsError> {
        let mut pairs: Vec<(u32, Vec<u8>)> = Vec::with_capacity(retained.length() as usize);
        for item in retained.iter() {
            let pair: Array = item
                .dyn_into()
                .map_err(|_| JsError::new("each retained keyring must be [revision, Uint8Array]"))?;
            let rev = pair
                .get(0)
                .as_f64()
                .ok_or_else(|| JsError::new("retained revision must be a number"))?;
            let rev = u32::try_from(as_i64(rev, "retained revision")?)
                .map_err(|_| JsError::new("retained revision out of range"))?;
            let bytes: Uint8Array = pair
                .get(1)
                .dyn_into()
                .map_err(|_| JsError::new("retained keyring bytes must be a Uint8Array"))?;
            pairs.push((rev, bytes.to_vec()));
        }
        let resolver =
            openom_vault::resolver_from(parse_engine(engine)?, head, &pairs).map_err(to_js)?;
        self.inner.set_membership(resolver).map_err(to_js)
    }

    /// Author a self-heal **cover** over this device's stored entries whose author was a legitimate member but
    /// is no longer current — the OPE-382 writer sweep. Call after a removal (once
    /// [`setMembership`](Self::set_membership) has refreshed the resolver): returns the sealed `Cover` envelope
    /// to push to the server data channel, or `undefined` when there is nothing to cover. The cover is NOT
    /// stored locally (a Cover must not enter the claim log) but IS folded into the local covered set, so a
    /// re-sweep is idempotent. Dag-only in practice (the chain retains per-revision history, so its removed
    /// members' entries verify without a cover).
    ///
    /// # Errors
    /// Returns a [`JsError`] if the store read or the seal fails.
    #[wasm_bindgen(js_name = authorCover)]
    pub fn author_cover(&mut self) -> Result<Option<Uint8Array>, JsError> {
        Ok(self
            .inner
            .author_cover()
            .map_err(to_js)?
            .map(|bytes| Uint8Array::from(bytes.as_slice())))
    }

    /// Adopt a rotated write epoch after a keyring sync (OPE-393) — a member's counterpart to the owner
    /// re-unlock. Given the freshly-synced keyring/anchor, the core unwraps its newly-reachable epoch DEK with
    /// the retained member secret (no passphrase) and splices it into the running sealer, so it can now OPEN
    /// content sealed under the new epoch (the self-heal cover included) and SEAL under it. A no-op (0) on a
    /// core with no retained member secret (owner / solo). Returns how many NEW epochs were spliced in.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the keyring is malformed or the member now reaches no epoch.
    #[wasm_bindgen(js_name = adoptEpochs)]
    pub fn adopt_epochs(&mut self, keyring: &[u8]) -> Result<usize, JsError> {
        self.inner.adopt_epochs(keyring).map_err(to_js)
    }

    /// How many sealed batches are queued but not yet appended locally (0 == the local write is durable).
    #[wasm_bindgen(js_name = pendingCount)]
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    // --- durable persistence: the worker mirrors this to IndexedDB (web) / rusqlite (Tauri) ----------

    /// The local-log entries not yet mirrored to durable storage, as `{ entries: Uint8Array[], through:
    /// number }`. The worker appends `entries` to `IndexedDB`, then confirms with
    /// [`markPersisted`](Self::mark_persisted)`(through)`. The persist cursor lives in the core (not the
    /// worker) — the host only executes the append.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the local store read fails, or the result object can't be built.
    #[wasm_bindgen(js_name = exportUnpersisted)]
    pub fn export_unpersisted(&self) -> Result<JsValue, JsError> {
        let (updates, through) = self.inner.export_unpersisted().map_err(to_js)?;
        let entries = Array::new();
        for env in &updates {
            entries.push(&Uint8Array::from(env.as_slice()));
        }
        let obj = Object::new();
        set(&obj, "entries", &entries)?;
        set(&obj, "through", &JsValue::from_f64(u64_to_f64(through)))?;
        Ok(obj.into())
    }

    /// Advance the persist cursor after the host has durably written an
    /// [`exportUnpersisted`](Self::export_unpersisted) batch.
    #[wasm_bindgen(js_name = markPersisted)]
    pub fn mark_persisted(&mut self, through: f64) -> Result<(), JsError> {
        self.inner.mark_persisted(as_u64(through, "through")?);
        Ok(())
    }

    /// Data-integrity anomalies observed (server entries that wouldn't decode + quarantined pull
    /// entries). A non-zero count is surfaced to the user, never silently swallowed.
    #[wasm_bindgen]
    #[must_use]
    pub fn anomalies(&self) -> usize {
        self.inner.anomalies()
    }

    /// Load durably-persisted log entries back into the local store on open (call before
    /// [`bootstrap`](Self::bootstrap)). `entries` is an array of `Uint8Array`.
    ///
    /// # Errors
    /// Returns a [`JsError`] if an element isn't a `Uint8Array`, or the store append fails.
    #[wasm_bindgen(js_name = importLog)]
    pub fn import_log(&mut self, entries: &Array) -> Result<(), JsError> {
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(entries.length() as usize);
        for v in entries.iter() {
            let bytes: Uint8Array = v
                .dyn_into()
                .map_err(|_| JsError::new("each persisted entry must be a Uint8Array"))?;
            batch.push(bytes.to_vec());
        }
        self.inner.import_log(&batch).map_err(to_js)
    }

    // --- reads -------------------------------------------------------------------------------------

    /// The materialized read model as a JSON string.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the projection can't be serialized.
    #[wasm_bindgen]
    pub fn project(&self) -> Result<String, JsError> {
        self.inner.project_json().map_err(to_js)
    }

    /// The operations log as a JSON string (each op with its author + `effective` flag).
    ///
    /// # Errors
    /// Returns a [`JsError`] if the log can't be serialized.
    #[wasm_bindgen]
    pub fn oplog(&self) -> Result<String, JsError> {
        self.inner.oplog_json().map_err(to_js)
    }

    /// Every live record as a JSON-array string — the granular set the undo/redo diff reads.
    ///
    /// # Errors
    /// Returns a [`JsError`] if a record can't be serialized.
    #[wasm_bindgen(js_name = liveRecords)]
    pub fn live_records(&self) -> Result<String, JsError> {
        let recs = self.inner.live_records().map_err(to_js)?;
        serde_json::to_string(&recs).map_err(to_js)
    }

    /// The live claims about `target` under `predicate`, as a JSON-array string (supersede-vs-assert).
    ///
    /// # Errors
    /// Returns a [`JsError`] if the claims can't be serialized.
    #[wasm_bindgen(js_name = liveClaimsOf)]
    pub fn live_claims_of(&self, target: &str, predicate: &str) -> Result<String, JsError> {
        serde_json::to_string(&self.inner.live_claims_of(target, predicate)).map_err(to_js)
    }

    /// Every live claim about `target`, whatever the predicate, as a JSON-array string.
    ///
    /// # Errors
    /// Returns a [`JsError`] if the claims can't be serialized.
    #[wasm_bindgen(js_name = liveClaimsOfAny)]
    pub fn live_claims_of_any(&self, target: &str) -> Result<String, JsError> {
        serde_json::to_string(&self.inner.live_claims_of_any(target)).map_err(to_js)
    }

    /// The canonical person id an anchor resolves to, or `undefined`.
    #[wasm_bindgen(js_name = resolveId)]
    #[must_use]
    pub fn resolve_id(&self, anchor: &str) -> Option<String> {
        self.inner.resolve_id(anchor)
    }
}

/// The result of a lifecycle flow (`provision` / `unlock`): the ready core `handle` plus the non-secret
/// outputs the caller persists — the keyring `anchor` to store, the one-time `recoveryCode` (provision
/// only), the author `didKey`, and the engine-opaque `watermark`. No secret key material crosses to JS;
/// the DEK lives inside the handle's `SealerSet` in this module's memory. Mirrors the vault's
/// `VaultResult`, but hands back an [`AppCoreHandle`] instead of a bare sealer.
#[wasm_bindgen]
// The four advisory flags are independent repair signals the worker acts on separately, not a state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct OpenResult {
    handle: Option<AppCoreHandle>,
    keyring: Vec<u8>,
    recovery_code: String,
    did_key: String,
    watermark: Vec<u8>,
    needs_reseal: bool,
    needs_backfill: bool,
    needs_rrk_backfill: bool,
    write_epoch_unreachable: bool,
}

#[wasm_bindgen]
impl OpenResult {
    /// The encoded keyring anchor to persist (empty for unlock).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }

    /// The one-time recovery code to show once (empty for unlock).
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    #[must_use]
    pub fn recovery_code(&self) -> String {
        self.recovery_code.clone()
    }

    /// The author `did:key` (the claim `createdBy`).
    #[wasm_bindgen(getter, js_name = didKey)]
    #[must_use]
    pub fn did_key(&self) -> String {
        self.did_key.clone()
    }

    /// The engine-opaque anti-rollback cursor to persist and pass back as the floor.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }

    /// Advisory: the dag write epoch is stale after a concurrent membership merge and a reseal is due
    /// (always `false` for the chain). Never blocks; the client repairs it out-of-band (OPE-282).
    #[wasm_bindgen(getter, js_name = needsReseal)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn needs_reseal(&self) -> bool {
        self.needs_reseal
    }

    /// Advisory: some retained epoch lacks a resolved member's wrap, so the owner should backfill
    /// historical read access (always `false` for the chain). Never blocks; repaired out-of-band (OPE-288).
    #[wasm_bindgen(getter, js_name = needsBackfill)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn needs_backfill(&self) -> bool {
        self.needs_backfill
    }

    /// Advisory: a retained epoch's RRK wrap doesn't bind the current recovery escrow — a rotation orphan the
    /// owner can't read until a MEMBER re-wraps it (`backfillRrk`). Always `false` for the chain (OPE-381 / F3).
    #[wasm_bindgen(getter, js_name = needsRrkBackfill)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn needs_rrk_backfill(&self) -> bool {
        self.needs_rrk_backfill
    }

    /// Advisory: this unlocker's own DEK bag didn't reach the current write epoch — locally derived, so it
    /// holds even when a malicious wrap forges the (unauthenticated) `needsReseal` coverage hint. The worker
    /// responds with a forced reseal (always `false` for the chain / a fresh tree) (OPE-299).
    #[wasm_bindgen(getter, js_name = writeEpochUnreachable)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn write_epoch_unreachable(&self) -> bool {
        self.write_epoch_unreachable
    }

    /// Take the ready core out to the worker (once).
    #[wasm_bindgen(js_name = takeHandle)]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn take_handle(&mut self) -> Option<AppCoreHandle> {
        self.handle.take()
    }
}

/// Create a brand-new encrypted tree: provision the keyring, then wrap its `SealerSet` in a ready core.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown or provisioning fails.
#[wasm_bindgen]
pub fn provision(
    engine: &str,
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    doc: String,
) -> Result<OpenResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let p = vault
        .provision(&ctx, &Passphrase::new(passphrase.into_bytes()))
        .map_err(to_js)?;
    let did = p.did_key.into_string();
    let handle = AppCoreHandle {
        inner: AppCore::new(did.clone(), p.sealer, Arc::new(MemoryStore::new()), doc, replica_id.to_vec()),
    };
    Ok(OpenResult {
        handle: Some(handle),
        keyring: p.anchor,
        recovery_code: p.recovery_code.into_string(),
        did_key: did,
        watermark: p.watermark,
        needs_reseal: false, // a fresh tree's single genesis epoch is never stale
        needs_backfill: false,
        needs_rrk_backfill: false, // a fresh tree has no rotation orphan
        write_epoch_unreachable: false, // the founder reaches the genesis epoch via the RRK (OPE-299)
    })
}

/// Re-open an existing tree from its trusted keyring `anchor` + passphrase (a returning / new device).
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown, or unlock fails (wrong passphrase / stale keyring).
#[wasm_bindgen]
pub fn unlock(
    engine: &str,
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    doc: String,
) -> Result<OpenResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let u = vault
        .unlock(&ctx, anchor, &Passphrase::new(passphrase.into_bytes()))
        .map_err(to_js)?;
    let did = u.did_key.into_string();
    // No bootstrap here — hydration is host-driven and uniform: the worker `importLog`s the durably
    // persisted log, THEN `bootstrap`s. Bootstrapping the fresh empty store here would be dead work
    // and would conflate a bad passphrase with one corrupt log entry.
    let handle = AppCoreHandle {
        inner: AppCore::new(did.clone(), u.sealer, Arc::new(MemoryStore::new()), doc, replica_id.to_vec()),
    };
    Ok(OpenResult {
        handle: Some(handle),
        keyring: Vec::new(),
        recovery_code: String::new(),
        did_key: did,
        watermark: u.watermark,
        needs_reseal: u.needs_reseal,
        needs_backfill: u.needs_backfill,
        needs_rrk_backfill: u.needs_rrk_backfill,
        write_epoch_unreachable: u.write_epoch_unreachable,
    })
}

/// Recover owner access with the recovery code under a new passphrase, then wrap the fresh `SealerSet`
/// in a ready core (recovery mints a new identity, so a new `didKey`). `anchor` is the stored keyring;
/// `floor` is the persisted anti-rollback watermark. Returns the new keyring + a NEW recovery code.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown, or recovery fails (wrong code / stale keyring).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn recover(
    engine: &str,
    recovery_code: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    floor: &[u8],
    doc: String,
) -> Result<OpenResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let r = vault
        .recover(
            &ctx,
            anchor,
            &RecoveryCode::new(recovery_code),
            &Passphrase::new(new_passphrase.into_bytes()),
            floor,
        )
        .map_err(to_js)?;
    let did = r.did_key.into_string();
    let handle = AppCoreHandle {
        inner: AppCore::new(did.clone(), r.sealer, Arc::new(MemoryStore::new()), doc, replica_id.to_vec()),
    };
    Ok(OpenResult {
        handle: Some(handle),
        keyring: r.anchor,
        recovery_code: r.recovery_code.into_string(),
        did_key: did,
        watermark: r.watermark,
        needs_reseal: r.needs_reseal,
        needs_backfill: r.needs_backfill,
        // recovery mints a fresh owner escrow, so no rotation orphan is introduced (OPE-381).
        needs_rrk_backfill: false,
        // recovery re-wraps every DEK to the (re-derived) owner, so the write epoch is reachable (OPE-299).
        write_epoch_unreachable: false,
    })
}

/// Change the passphrase (re-wrap the keyring under a new KEK, rotate the recovery code). The DEK is
/// unchanged, so the RUNNING core keeps working — this returns NO handle, just the new keyring + code +
/// watermark to persist. `anchor` is the stored keyring; `floor` is the persisted watermark.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown, or the change fails (wrong current passphrase).
#[wasm_bindgen(js_name = changePassphrase)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn change_passphrase(
    engine: &str,
    old_passphrase: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    floor: &[u8],
) -> Result<OpenResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let re = vault
        .change_passphrase(
            &ctx,
            anchor,
            &Passphrase::new(old_passphrase.into_bytes()),
            &Passphrase::new(new_passphrase.into_bytes()),
            floor,
        )
        .map_err(to_js)?;
    Ok(OpenResult {
        handle: None, // the DEK is unchanged — the running core keeps working
        keyring: re.anchor,
        recovery_code: re.recovery_code.into_string(),
        did_key: String::new(),
        watermark: re.watermark,
        needs_reseal: false,
        needs_backfill: false,
        needs_rrk_backfill: false,
        write_epoch_unreachable: false, // the DEK is unchanged, so the running core still reaches it (OPE-299)
    })
}

/// Result of [`rotate_recovery`]: the new keyring anchor to persist, the fresh recovery code, the new
/// recovery authority to record for confirmation, and the watermark. The code is PROVISIONAL until
/// [`rotation_confirmed`] returns `true` against the synced anchor (OPE-381 / §11.2).
#[wasm_bindgen]
pub struct DagRotated {
    keyring: Vec<u8>,
    recovery_code: String,
    reset_authority: Vec<u8>,
    watermark: Vec<u8>,
}

#[wasm_bindgen]
impl DagRotated {
    /// The rotated keyring anchor to persist.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }
    /// The one-time NEW recovery code to show once — provisional until confirmed.
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn recovery_code(&self) -> String {
        self.recovery_code.clone()
    }
    /// The new recovery authority (RVK) to hand back to [`rotation_confirmed`] after syncing.
    #[wasm_bindgen(getter, js_name = resetAuthority)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn reset_authority(&self) -> Vec<u8> {
        self.reset_authority.clone()
    }
    /// The anti-rollback cursor to persist.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }
}

/// Result of [`backfill_rrk`]: the (possibly unchanged) keyring anchor + watermark to persist, and whether a
/// heal was actually appended (`false` = no reachable orphan, an idempotent no-op).
#[wasm_bindgen]
pub struct DagBackfilled {
    keyring: Vec<u8>,
    watermark: Vec<u8>,
    backfilled: bool,
}

#[wasm_bindgen]
impl DagBackfilled {
    /// The keyring anchor to persist (unchanged when `backfilled` is false).
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }
    /// The anti-rollback cursor to persist.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }
    /// Whether an RRK-backfill op was actually appended.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn backfilled(&self) -> bool {
        self.backfilled
    }
}

/// Rotate the recovery authority (OPE-381): the owner retires the current recovery code for a fresh one so a
/// holder of the old code can no longer take over. Authorized by the owner's passphrase-derived identity.
/// Returns the rotated keyring + new code + the authority to confirm. The code is PROVISIONAL — the worker
/// keeps the OLD code live until [`rotation_confirmed`] returns `true` against the synced anchor.
///
/// # Errors
/// Returns a [`JsError`] if the engine isn't the dag keyring, the passphrase isn't the resolved owner's, or
/// the rotation fails.
#[wasm_bindgen(js_name = rotateRecovery)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn rotate_recovery(
    engine: &str,
    owner_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    floor: &[u8],
) -> Result<DagRotated, JsError> {
    let dag = AppVault::from_kind(parse_engine(engine)?)
        .as_dag()
        .ok_or_else(|| JsError::new("this operation requires the dag keyring engine"))?;
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let r = dag
        .rotate_recovery(&ctx, anchor, &Passphrase::new(owner_passphrase.into_bytes()), floor)
        .map_err(to_js)?;
    let reset_authority = dag
        .resolved_reset_authority(&r.anchor)
        .map_err(to_js)?
        .map(|a| a.to_vec())
        .unwrap_or_default();
    Ok(DagRotated {
        keyring: r.anchor,
        recovery_code: r.recovery_code.into_string(),
        reset_authority,
        watermark: r.watermark,
    })
}

/// Confirm a rotation survived the merge (OPE-381 / §11.2): `expected_reset_authority` is what
/// [`rotate_recovery`] returned; re-resolves `synced_anchor` and reports whether that authority is now the
/// resolved one. `false` means the rotation was superseded — the new code is void and the OLD code is still
/// live, so the worker must re-rotate.
///
/// # Errors
/// Returns a [`JsError`] if the engine isn't the dag keyring, the authority isn't 32 bytes, or resolve fails.
#[wasm_bindgen(js_name = rotationConfirmed)]
pub fn rotation_confirmed(
    engine: &str,
    synced_anchor: &[u8],
    expected_reset_authority: &[u8],
) -> Result<bool, JsError> {
    let dag = AppVault::from_kind(parse_engine(engine)?)
        .as_dag()
        .ok_or_else(|| JsError::new("this operation requires the dag keyring engine"))?;
    let expected: [u8; 32] = expected_reset_authority
        .try_into()
        .map_err(|_| JsError::new("reset authority must be 32 bytes"))?;
    dag.rotation_confirmed(synced_anchor, &expected).map_err(to_js)
}

/// Member-side heal of a rotation-orphaned epoch (OPE-381 / F3): an active member opens an epoch the owner
/// can't read and re-wraps its DEK to the current escrow. Authorized by the member's passphrase + account
/// KDF. Idempotent (`backfilled=false` when no orphan is reachable) — safe to call opportunistically.
///
/// # Errors
/// Returns a [`JsError`] if the engine isn't the dag keyring, the KDF params are malformed, or the heal fails.
#[wasm_bindgen(js_name = backfillRrk)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn backfill_rrk(
    engine: &str,
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    floor: &[u8],
) -> Result<DagBackfilled, JsError> {
    let dag = AppVault::from_kind(parse_engine(engine)?)
        .as_dag()
        .ok_or_else(|| JsError::new("this operation requires the dag keyring engine"))?;
    let kdf = keyeo_crypto::codec::decode_kdf_params(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let r = dag
        .backfill_rrk(&ctx, anchor, &Passphrase::new(passphrase.into_bytes()), &kdf, floor)
        .map_err(to_js)?;
    Ok(DagBackfilled {
        keyring: r.anchor,
        watermark: r.watermark,
        backfilled: r.backfilled,
    })
}

/// The resolved Owner's identity key at `anchor` — recorded right after a recovery so
/// [`recovery_confirmed`] can later check the recovery survived. Empty if the roster has no owner.
///
/// # Errors
/// Returns a [`JsError`] if the engine isn't the dag keyring or resolve fails.
#[wasm_bindgen(js_name = resolvedOwnerKey)]
pub fn resolved_owner_key(engine: &str, anchor: &[u8]) -> Result<Vec<u8>, JsError> {
    let dag = AppVault::from_kind(parse_engine(engine)?)
        .as_dag()
        .ok_or_else(|| JsError::new("this operation requires the dag keyring engine"))?;
    Ok(dag.resolved_owner_key(anchor).map_err(to_js)?.unwrap_or_default())
}

/// Confirm a recovery survived the merge (OPE-381 / §11.2, the superseded-recovery signal):
/// `expected_owner_key` is what [`resolved_owner_key`] returned right after the recovery; re-resolves
/// `synced_anchor` and reports whether that owner is still the resolved Owner. `false` means a concurrent
/// rotation voided the recovery's `ReFound` — the owner is locked out and must recover again.
///
/// # Errors
/// Returns a [`JsError`] if the engine isn't the dag keyring or resolve fails.
#[wasm_bindgen(js_name = recoveryConfirmed)]
pub fn recovery_confirmed(
    engine: &str,
    synced_anchor: &[u8],
    expected_owner_key: &[u8],
) -> Result<bool, JsError> {
    let dag = AppVault::from_kind(parse_engine(engine)?)
        .as_dag()
        .ok_or_else(|| JsError::new("this operation requires the dag keyring engine"))?;
    dag.recovery_confirmed(synced_anchor, expected_owner_key)
        .map_err(to_js)
}

/// A joining member's freshly-minted account identity (before they claim an invite): the KDF params to
/// persist locally + the two public keys to hand the owner OOB for `addMember`. The secrets never leave the
/// worker — they re-derive from the passphrase on `unlockAsMember`.
#[wasm_bindgen]
pub struct MemberIdentity {
    kdf_params: Vec<u8>,
    author_public_key: Vec<u8>,
    hpke_public_key: Vec<u8>,
}

#[wasm_bindgen]
impl MemberIdentity {
    /// The account's KDF params (persist locally; replay on `unlockAsMember`).
    #[wasm_bindgen(getter, js_name = kdfParams)]
    #[must_use]
    pub fn kdf_params(&self) -> Vec<u8> {
        self.kdf_params.clone()
    }
    /// The Ed25519 author public key (hand to the owner for `addMember`).
    #[wasm_bindgen(getter, js_name = authorPublicKey)]
    #[must_use]
    pub fn author_public_key(&self) -> Vec<u8> {
        self.author_public_key.clone()
    }
    /// The X25519 HPKE public key (hand to the owner for `addMember`).
    #[wasm_bindgen(getter, js_name = hpkePublicKey)]
    #[must_use]
    pub fn hpke_public_key(&self) -> Vec<u8> {
        self.hpke_public_key.clone()
    }
}

/// Mint a joining member's account identity from their passphrase — the first step of the member flow (before
/// the owner admits them). Returns the KDF params + the OOB-shareable public keys.
///
/// # Errors
/// Returns a [`JsError`] if the member secret derivation fails.
#[wasm_bindgen(js_name = provisionMember)]
pub fn provision_member(passphrase: String) -> Result<MemberIdentity, JsError> {
    let m = openom_vault::sharing::provision_member(&Passphrase::new(passphrase.into_bytes()))
        .map_err(to_js)?;
    Ok(MemberIdentity {
        kdf_params: m.kdf_params,
        author_public_key: m.author_public_key,
        hpke_public_key: m.hpke_public_key,
    })
}

/// The result of an owner membership change (add/remove) — the new keyring/anchor to persist + its watermark.
/// No handle: the owner's running core keeps its DEK and just re-reads membership via
/// [`setMembership`](AppCoreHandle::set_membership) after the caller persists the new keyring.
#[wasm_bindgen]
pub struct MembershipChange {
    keyring: Vec<u8>,
    watermark: Vec<u8>,
}

#[wasm_bindgen]
impl MembershipChange {
    /// The new keyring/anchor bytes to persist as the head (chain also retains it per revision).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }

    /// The engine-opaque anti-rollback watermark to persist.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }
}

/// Add a member (owner action) — HPKE-wrap the tree DEK to the OOB-verified joiner keys + record them in a
/// new keyring revision. Returns the new keyring + watermark to persist; the owner then calls
/// [`setMembership`](AppCoreHandle::set_membership) so ingest verifies the now-shared tree.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown, the owner passphrase is wrong, a joiner key is malformed,
/// or the add is unauthorized.
#[wasm_bindgen(js_name = addMember)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn add_member(
    engine: &str,
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
    new_member_id: &str,
    role: &str,
    member_author_public: &[u8],
    member_hpke_public: &[u8],
) -> Result<MembershipChange, JsError> {
    let changed = openom_vault::sharing::add_member(
        parse_engine(engine)?,
        keyring,
        &Passphrase::new(owner_passphrase.into_bytes()),
        tree_id,
        owner_member_id,
        replica_id,
        min_revision,
        new_member_id,
        role,
        member_author_public,
        member_hpke_public,
    )
    .map_err(to_js)?;
    Ok(MembershipChange {
        keyring: changed.keyring,
        watermark: changed.watermark,
    })
}

/// Remove a member (owner action) — forward-secret re-epoch that drops the member and re-wraps the fresh DEK
/// only for those who remain. Returns the new keyring + watermark to persist. The removal ROTATES the write
/// epoch, so the owner's running core must be re-opened via [`unlock`] on the new keyring (its old sealer can
/// no longer sign), then [`authorCover`](AppCoreHandle::author_cover) mints the self-heal cover.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown, the owner passphrase is wrong, the target is the owner or
/// not a member, or the removal is unauthorized.
#[wasm_bindgen(js_name = removeMember)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn remove_member(
    engine: &str,
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
    remove_member_id: &str,
) -> Result<MembershipChange, JsError> {
    let changed = openom_vault::sharing::remove_member(
        parse_engine(engine)?,
        keyring,
        &Passphrase::new(owner_passphrase.into_bytes()),
        tree_id,
        owner_member_id,
        replica_id,
        min_revision,
        remove_member_id,
    )
    .map_err(to_js)?;
    Ok(MembershipChange {
        keyring: changed.keyring,
        watermark: changed.watermark,
    })
}

/// Unlock a shared tree as a non-owner member — verify against the pinned `trusted_signers` (chain) / resolve
/// the anchor (dag), HPKE-unwrap the member's DEKs with their passphrase + account KDF, and wrap the sealer in
/// a ready core. Returns an [`OpenResult`] like [`unlock`], whose handle the worker drives.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown, or member unlock fails (wrong passphrase / unpinned signer
/// / removed member).
#[wasm_bindgen(js_name = unlockAsMember)]
#[allow(clippy::too_many_arguments)] // wasm-bindgen JS export: the flat argument list IS the JS calling convention
pub fn unlock_as_member(
    engine: &str,
    keyring: &[u8],
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    trusted_signers: &[u8],
    replica_id: &[u8],
    min_revision: u32,
    doc: String,
) -> Result<OpenResult, JsError> {
    let u = openom_vault::sharing::unlock_as_member(
        parse_engine(engine)?,
        keyring,
        &Passphrase::new(passphrase.into_bytes()),
        member_kdf_params,
        tree_id,
        member_id,
        trusted_signers,
        replica_id,
        min_revision,
    )
    .map_err(to_js)?;
    let mut inner = AppCore::new(
        u.did_key.clone(),
        u.sealer,
        Arc::new(MemoryStore::new()),
        doc,
        replica_id.to_vec(),
    );
    // Retain the member's epoch-adopt secret so a keyring sync that rotates the write epoch (a removal) can
    // splice the new epoch DEK into this running core WITHOUT a passphrase (OPE-393). Stays inside the core.
    inner.set_member_epoch_secret(u.epoch_secret);
    // A member-unlocked core is a SHARED tree by definition, so install a §B3 resolver AT CONSTRUCTION —
    // never leave it in the accept-all `membership: None` state where a sync tick before the worker's first
    // setMembership would fold forgeries. The dag anchor is self-sufficient; the chain gets the head with an
    // empty retained set (older governing revisions Hold — fail-closed — until the worker supplies them).
    let resolver =
        openom_vault::resolver_from(parse_engine(engine)?, keyring, &[]).map_err(to_js)?;
    inner.set_membership(resolver).map_err(to_js)?;
    Ok(OpenResult {
        handle: Some(AppCoreHandle { inner }),
        keyring: Vec::new(),
        recovery_code: String::new(),
        did_key: u.did_key,
        watermark: u.watermark,
        needs_reseal: false,
        needs_backfill: false,
        // The member-unlock wrapper (sharing::unlock_as_member) doesn't thread the coverage advisories through
        // yet — the member drives backfill_rrk opportunistically (idempotent) rather than off this flag.
        needs_rrk_backfill: false,
        // The member's own local lockout signal — the one a malicious coverage hint can't suppress (OPE-299).
        write_epoch_unreachable: u.write_epoch_unreachable,
    })
}

/// Whether this tree HAS BEEN SHARED — a non-founder member was ever admitted. The worker calls this on
/// unlock to decide whether to install a §B3 resolver (a solo tree needs none).
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown or the keyring is malformed.
#[wasm_bindgen(js_name = keyringHasBeenShared)]
pub fn keyring_has_been_shared(engine: &str, keyring: &[u8]) -> Result<bool, JsError> {
    openom_vault::sharing::keyring_has_been_shared(parse_engine(engine)?, keyring).map_err(to_js)
}

/// The advisory membership + basis for a keyring, as JSON `{"members":[{"memberId","role"}],"basis":[...]}`
/// — what the worker pushes to the server's /access channel.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown or the keyring is malformed.
#[wasm_bindgen(js_name = keyringSummary)]
pub fn keyring_summary(engine: &str, keyring: &[u8]) -> Result<String, JsError> {
    openom_vault::sharing::keyring_summary(parse_engine(engine)?, keyring).map_err(to_js)
}

/// The moderator `did:key`s (Maintainer+ members) resolved from a keyring — the worker feeds these to the
/// core's `setModerators` on unlock and after every keyring change, so the claim fold honors the current
/// moderator authority.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown or the keyring is malformed.
#[wasm_bindgen(js_name = moderatorsFromKeyring)]
pub fn moderators_from_keyring(engine: &str, keyring: &[u8]) -> Result<Vec<String>, JsError> {
    openom_vault::sharing::moderators_from_keyring(parse_engine(engine)?, keyring).map_err(to_js)
}

/// Whether this keyring's trust state COVERS `stored_basis` — the worker's pre-push staleness guard.
///
/// # Errors
/// Returns a [`JsError`] if the engine is unknown or the keyring is malformed.
#[wasm_bindgen(js_name = keyringCovers)]
#[allow(clippy::needless_pass_by_value)] // wasm-bindgen marshals a JS string array as an owned Vec
pub fn keyring_covers(
    engine: &str,
    keyring: &[u8],
    stored_basis: Vec<String>,
) -> Result<bool, JsError> {
    openom_vault::sharing::keyring_covers(parse_engine(engine)?, keyring, &stored_basis).map_err(to_js)
}

/// A joining member's verified whole-history walk (`verifyKeyringWalk`): the head revision + RAW head body,
/// the head's signers (JSON, for the worker's out-of-band fingerprint cross-check), and every RAW per-revision
/// body (length-prefix framed) for the member to retain.
#[wasm_bindgen]
pub struct KeyringWalk {
    revision: u32,
    head_keyring: Vec<u8>,
    signers_json: String,
    bodies_framed: Vec<u8>,
}

#[wasm_bindgen]
impl KeyringWalk {
    /// The verified head revision.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // wasm-bindgen exports can't be const
    pub fn revision(&self) -> u32 {
        self.revision
    }
    /// The RAW head `Keyring` body — stored as the head and fed to `unlockAsMember`.
    #[wasm_bindgen(getter, js_name = headKeyring)]
    #[must_use]
    pub fn head_keyring(&self) -> Vec<u8> {
        self.head_keyring.clone()
    }
    /// The head's authorized signers as JSON `[{"memberId","authorPublicKey"(hex)}]`.
    #[wasm_bindgen(getter, js_name = signersJson)]
    #[must_use]
    pub fn signers_json(&self) -> String {
        self.signers_json.clone()
    }
    /// Every RAW per-revision body 1..=head, ascending, length-prefix framed.
    #[wasm_bindgen(getter, js_name = bodiesFramed)]
    #[must_use]
    pub fn bodies_framed(&self) -> Vec<u8> {
        self.bodies_framed.clone()
    }
}

/// Verify a tree's WHOLE keyring history from genesis (a joining member's read-side bootstrap): TOFU the
/// genesis founder, walk to the head, and pin it to the invite's `(revision, keyring_hash)`. Returns the
/// verified head + signers + every per-revision body to retain.
///
/// # Errors
/// Returns a [`JsError`] on any fail-closed condition (empty/forked history, wrong tree, pin mismatch).
#[wasm_bindgen(js_name = verifyKeyringWalk)]
pub fn verify_keyring_walk(
    tree_id: &[u8],
    hops: &[u8],
    pinned_revision: u32,
    pinned_hash: &[u8],
) -> Result<KeyringWalk, JsError> {
    let w = openom_vault::sharing::verify_keyring_walk(tree_id, hops, pinned_revision, pinned_hash)
        .map_err(to_js)?;
    Ok(KeyringWalk {
        revision: w.revision,
        head_keyring: w.head_keyring,
        signers_json: w.signers_json,
        bodies_framed: w.bodies_framed,
    })
}

/// Accept a keyring run pulled from the untrusted network (the chain-walk read-side). Returns the new head +
/// watermark to persist (an empty keyring signals a no-op at the current head).
///
/// # Errors
/// Returns a [`JsError`] on a malformed anchor/hop, a tree mismatch, or a rejected transition.
#[wasm_bindgen(js_name = syncKeyring)]
pub fn sync_keyring(
    anchor: &[u8],
    tree_id: &[u8],
    hops: &[u8],
) -> Result<MembershipChange, JsError> {
    let a = openom_vault::sharing::accept_remote_keyring(anchor, tree_id, hops).map_err(to_js)?;
    Ok(MembershipChange {
        keyring: a.keyring,
        watermark: a.watermark,
    })
}

/// Frame a produced chain keyring revision as the wire `KeyringUpdate` the server's `PUT /keyring` accepts —
/// the outbound publish (`reconcileKeyring`).
///
/// # Errors
/// Returns a [`JsError`] if the keyring isn't a decodable chain keyring.
#[wasm_bindgen(js_name = wrapChainKeyringUpdate)]
pub fn wrap_chain_keyring_update(keyring: &[u8]) -> Result<Vec<u8>, JsError> {
    openom_vault::sharing::wrap_chain_keyring_update(keyring).map_err(to_js)
}

/// Unwrap a served `MembershipEnvelope` to its RAW chain `Keyring` body — the format the client retains per
/// revision (a member's `syncKeyring` unwraps each successor before retaining it, since §B3 verify decodes a
/// raw `Keyring`, not the wrapped envelope).
///
/// # Errors
/// Returns a [`JsError`] if the bytes aren't a chain-tagged membership envelope.
#[wasm_bindgen(js_name = unwrapChainKeyring)]
pub fn unwrap_chain_keyring(bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    openom_vault::sharing::unwrap_chain_keyring(bytes).map_err(to_js)
}

// --- dag keyring distribution (OPE-392): the dag counterparts of the chain walk/hash/wrap veneers. The
//     worker uses these to publish an anchor, first-sight-JOIN against an OOB pin, and adopt newer anchors. --

/// Mint the OOB trust pin for a dag tree's CURRENT anchor (owner, invite time) — the dag analog of
/// [`keyring_hash`]. Opaque bytes: the genesis-op id + recovery authority + invite-time frontier the joiner
/// binds to.
///
/// # Errors
/// Returns a [`JsError`] if the anchor is malformed.
#[wasm_bindgen(js_name = dagAnchorPin)]
pub fn dag_anchor_pin(anchor: &[u8]) -> Result<Vec<u8>, JsError> {
    openom_vault::sharing::dag_anchor_pin(anchor).map_err(to_js)
}

/// Verify a dag anchor served by the untrusted network against an OOB pin — a member's first-sight JOIN, the
/// dag analog of [`verify_keyring_walk`]. Returns the validated anchor + watermark to persist; the worker then
/// calls [`unlock_as_member`] to open the member core. Throws on any failed trust check.
///
/// # Errors
/// Returns a [`JsError`] on a malformed anchor/pin or a failed trust check.
#[wasm_bindgen(js_name = verifyDagAnchor)]
pub fn verify_dag_anchor(anchor: &[u8], tree_id: &[u8], pin: &[u8]) -> Result<MembershipChange, JsError> {
    let a = openom_vault::sharing::verify_dag_anchor(anchor, tree_id, pin).map_err(to_js)?;
    Ok(MembershipChange {
        keyring: a.keyring,
        watermark: a.watermark,
    })
}

/// Adopt a newer dag anchor pulled from the untrusted network onto the local one (a member's SYNC), enforcing
/// the persisted pin + anti-rollback `floor`. Returns the merged anchor + its new watermark.
///
/// # Errors
/// Returns a [`JsError`] on a malformed input or a failed verify / rollback check.
#[wasm_bindgen(js_name = acceptRemoteDagAnchor)]
pub fn accept_remote_dag_anchor(
    local: &[u8],
    remote: &[u8],
    tree_id: &[u8],
    pin: &[u8],
    floor: &[u8],
) -> Result<MembershipChange, JsError> {
    let a = openom_vault::sharing::accept_remote_dag_anchor(local, remote, tree_id, pin, floor)
        .map_err(to_js)?;
    Ok(MembershipChange {
        keyring: a.keyring,
        watermark: a.watermark,
    })
}

/// Frame a full dag anchor as the wire `KeyringUpdate` the server's keyring channel accepts (the dag mirror of
/// [`wrap_chain_keyring_update`]). `revision` = the target server slot (server-head + 1); `tree_id` is a
/// routing hint.
///
/// # Errors
/// Returns a [`JsError`] if framing fails.
#[wasm_bindgen(js_name = wrapDagKeyringUpdate)]
pub fn wrap_dag_keyring_update(anchor: &[u8], tree_id: &[u8], revision: u32) -> Result<Vec<u8>, JsError> {
    openom_vault::sharing::wrap_dag_keyring_update(anchor, tree_id, revision).map_err(to_js)
}

/// Unwrap a served dag `MembershipEnvelope` payload to the raw anchor bytes (the dag mirror of
/// [`unwrap_chain_keyring`]).
///
/// # Errors
/// Returns a [`JsError`] if the bytes aren't a dag-tagged membership envelope.
#[wasm_bindgen(js_name = unwrapDagKeyring)]
pub fn unwrap_dag_keyring(bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    openom_vault::sharing::unwrap_dag_keyring(bytes).map_err(to_js)
}

/// The content hash of a raw chain keyring revision — what an invite pins so a joiner's genesis-walk binds
/// the verified history to the owner's published revision.
///
/// # Errors
/// Returns a [`JsError`] if the bytes aren't a decodable chain keyring.
#[wasm_bindgen(js_name = keyringHash)]
pub fn keyring_hash(keyring: &[u8]) -> Result<Vec<u8>, JsError> {
    openom_vault::sharing::chain_keyring_hash(keyring).map_err(to_js)
}

/// Adopt a recovery/succession reset keyring against the trusted anchor (the caller must have shown the new
/// signer fingerprints for out-of-band confirmation first). Returns the validated keyring + watermark.
///
/// # Errors
/// Returns a [`JsError`] on a malformed keyring, a tree mismatch, a non-next revision, or a rejected reset.
#[wasm_bindgen(js_name = adoptReset)]
pub fn adopt_reset(
    anchor: &[u8],
    tree_id: &[u8],
    candidate: &[u8],
) -> Result<MembershipChange, JsError> {
    let a = openom_vault::sharing::accept_reset_keyring(anchor, tree_id, candidate).map_err(to_js)?;
    Ok(MembershipChange {
        keyring: a.keyring,
        watermark: a.watermark,
    })
}

/// The engine tag mapping ([`EngineKind`]'s own `FromStr`, so this and the vault host can't drift).
fn parse_engine(s: &str) -> Result<EngineKind, JsError> {
    s.parse::<EngineKind>()
        .map_err(|_| JsError::new("unknown keyring engine (expected chain|dag)"))
}

/// The wall clock the engine's HLC sanitizes (`Date.now()` epoch ms).
fn now_millis() -> i64 {
    // Date.now() is a non-negative integer count of ms within 2^53; the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let ms = js_sys::Date::now() as i64;
    ms
}

fn set(obj: &Object, key: &str, value: &JsValue) -> Result<(), JsError> {
    Reflect::set(obj, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|_| JsError::new("failed to set a result field"))
}

fn to_js(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0; // 2^53 - 1

fn as_u64(n: f64, field: &str) -> Result<u64, JsError> {
    if n.is_nan() || n < 0.0 || n.fract() != 0.0 || n > MAX_SAFE {
        return Err(JsError::new(&format!(
            "{field} must be a non-negative integer within 2^53"
        )));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let v = n as u64;
    Ok(v)
}

fn as_i64(n: f64, field: &str) -> Result<i64, JsError> {
    if n.is_nan() || n.fract() != 0.0 || n.abs() > MAX_SAFE {
        return Err(JsError::new(&format!(
            "{field} must be an integer within 2^53"
        )));
    }
    #[allow(clippy::cast_possible_truncation)]
    let v = n as i64;
    Ok(v)
}

fn u64_to_f64(n: u64) -> f64 {
    // Local-log seq; far below 2^53 in practice.
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    f
}

fn i64_to_f64(n: i64) -> f64 {
    // Server seq; far below 2^53 in practice.
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    f
}
