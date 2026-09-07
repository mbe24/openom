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
use openom_crypto::Passphrase;
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
pub struct OpenResult {
    handle: Option<AppCoreHandle>,
    keyring: Vec<u8>,
    recovery_code: String,
    did_key: String,
    watermark: Vec<u8>,
    needs_reseal: bool,
    needs_backfill: bool,
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
