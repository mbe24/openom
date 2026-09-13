#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use openom_crypto::{Passphrase, RecoveryCode};
use openom_data_tree::{OpView, Tree, TreeError};
use openom_docsync::{EveryNUpdates, SnapshotPolicy, SyncClient, Verdict};
use openom_keyring_api::EngineKind;
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_protocol::v1::{CoverBody, CoveredEntry, Envelope, Kind};
use openom_protocol::Message;
use openom_sealer::SealerSet;
use openom_vault::lifecycle::{KeyringLifecycle, VaultContext};
use openom_vault::{AppVault, Disposition, MembershipResolver};
// Re-export so the native host (and other rlib consumers) can name the lifecycle API's error type.
pub use openom_vault::VaultError;
use sha2::{Digest, Sha256};
use serde_json::Value;
use store_blob::{BlobError, BlobStore, MemoryBlob, Precondition};

/// One stored object: its keyspace key and its opaque sealed bytes. The unit of [`AppCore::export`] /
/// [`AppCore::import`] / [`AppCore::sync_against`] — a `(key, bytes)` pair the host ferries verbatim.
pub type StoredObject = (String, Vec<u8>);

/// One object a sync tick must upload: its key, bytes, and whether it is a POINTER (heads/snapshot — overwrites)
/// vs an immutable log object (writes If-None-Match). The CORE decides `pointer` from the key (`is_pointer_key`),
/// so the caller never inspects a key to choose a write precondition.
pub struct Upload {
    pub key: String,
    pub bytes: Vec<u8>,
    pub pointer: bool,
}

/// The full result of one [`AppCore::sync_tick`]: the objects to upload (each with its `pointer` flag), how many
/// entries folded, and the covered frontier the caller sends as the snapshot's `x-openom-covered` GC header.
pub struct SyncTick {
    pub uploads: Vec<Upload>,
    pub folded: usize,
    pub covered: BTreeMap<String, u64>,
}

#[cfg(feature = "wasm")]
mod wasm;

/// The wasm-core mirror of the unified error-code registry (generated; see `plan/design.error-model.md`).
/// Ready for the in-core error path to emit `AppError`s once 9457 parsing moves into Rust (B3).
pub mod error_codes;

/// Anything that can go wrong in the core.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A sync-loop / sealer error from the docsync layer.
    #[error(transparent)]
    Sync(#[from] openom_docsync::SyncError),
    /// An engine (mint / flush / read) error.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// A local durable-store (Blob seam) error.
    #[error(transparent)]
    Store(#[from] BlobError),
    /// A vault crypto error — e.g. a member's epoch adopt over a malformed keyring (OPE-393).
    #[error(transparent)]
    Vault(#[from] openom_vault::VaultError),
}

/// One tree's Rust core: the engine + sealer + the `docsync::BlobSyncClient` loop over a LOCAL device
/// `BlobStore`. Every method is **synchronous**. The device-local ⇄ shared-remote replication is the
/// `docsync::mirror` anti-entropy the caller drives (the test harness directly; the worker's async JS wraps
/// it): mirror the remote's objects into the local store, then [`fold`](Self::fold) them through the §B3 gate.
///
/// The store is `Arc<S>` so the client and the mirror share one local log: the client writes this replica's
/// mints as immutable per-replica log objects + folds peers' (mirrored-in) objects into the engine.
pub struct AppCore<S: BlobStore> {
    client: SyncClient<Arc<S>>,
    store: Arc<S>,
    doc: String,
    /// Peer entries whose envelope/header wouldn't decode (can't verify) — surfaced via
    /// [`anomalies`](Self::anomalies), never blindly folded.
    undecodable: usize,
    /// Peer entries REJECTED by §B3 verification (forged / unattributed-on-shared / illegitimate). Never
    /// folded; surfaced via [`anomalies`](Self::anomalies), never silently swallowed. (Hold is the client's
    /// frontier-held set — see [`fold`](Self::fold).)
    rejected: usize,
    /// The §B3 governing membership for verify-on-fold. `None` ⇒ a solo / never-shared tree (AEAD-only is safe:
    /// only the DEK holder can write). The worker installs `Some(..)` via [`set_membership`](Self::set_membership)
    /// once shared, after which every peer entry is verified before it folds.
    membership: Option<Box<dyn MembershipResolver>>,
    /// The self-heal covered set (OPE-382 SH-2): `H(ciphertext) → author_member_id` for every entry a
    /// currently-valid Cover blesses. Only the author ID is stored — the author's KEY and ROLE are resolved from
    /// the membership at accept time via [`MembershipResolver::ever_member_info`], NEVER taken from the
    /// (untrusted) cover, so a forged cover can't bind an attacker key or waive the role check. Rebuilt from
    /// [`cover_envelopes`](Self) on every [`set_membership`](Self) (pin P3), and not durable: a fresh fold
    /// re-scans the whole local store.
    covered: BTreeMap<Vec<u8>, String>,
    /// The raw `Cover` envelopes folded this session, retained so [`covered`](Self) can be REBUILT against the
    /// current membership on each [`set_membership`](Self).
    cover_envelopes: Vec<Vec<u8>>,
    /// A MEMBER core retains its epoch-adopt secret so a keyring sync that rotated the write epoch can splice
    /// the new epoch DEK into the running sealer WITHOUT a passphrase (OPE-393). `None` on an owner / solo core.
    member_epoch_secret: Option<openom_vault::sharing::MemberEpochSecret>,
}

// OPE-429 compile-time guard: `AppCore<S>` must stay `Send + Sync` whenever `S` is, so the native (Tauri)
// host can hold it in a `Mutex<AppCore>` accessed from Tauri's invoke thread pool. This function is never
// called — it exists only so the build FAILS if a future field (or a resolver without the `Send + Sync`
// supertrait) breaks the bound. No-op for the single-threaded wasm worker.
#[allow(dead_code)]
fn _assert_app_core_send_sync<S: BlobStore + Send + Sync + 'static>() {
    const fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<AppCore<S>>();
}

// ── Keyring lifecycle (store-generic rlib API) ─────────────────────────────────────────────────────────
// The ONE implementation of provision/unlock the wasm veneer AND the native (Tauri) host both call, so the two
// runtimes can't drift (OPE-429). `store` is the caller's local device BlobStore — MemoryBlob for the wasm
// worker, FsBlob/SQLite for the native host. Membership + the other lifecycle ops follow this shape.

/// The result of [`provision`]: a ready [`AppCore`] + the durable outputs the host persists (keyring anchor +
/// anti-rollback watermark) and shows the user (recovery code + the author `did:key`).
pub struct Provisioned<S: BlobStore> {
    pub core: AppCore<S>,
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub did_key: String,
    pub watermark: Vec<u8>,
}

/// The result of [`unlock`]: a ready [`AppCore`] + the watermark and the four advisory repair flags the host
/// surfaces.
// The four flags are INDEPENDENT repair signals (reseal / backfill / rrk-backfill / write-epoch-unreachable),
// mirroring `OpenResult` — not a state enum, so keep them separate.
#[allow(clippy::struct_excessive_bools)]
pub struct Unlocked<S: BlobStore> {
    pub core: AppCore<S>,
    pub did_key: String,
    pub watermark: Vec<u8>,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
    pub needs_rrk_backfill: bool,
    pub write_epoch_unreachable: bool,
}

/// Map a [`VaultError`] to its stable UI error-code (the [`error_codes`] registry). Shared by the wasm veneer
/// and the native (Tauri) host so their two error channels — and thus the gate's tamper/rollback/wrong-pass
/// distinctions — can't drift.
#[must_use]
pub fn vault_error_code(e: &VaultError) -> &'static str {
    use error_codes as ec;
    use openom_crypto::CryptoError;
    match e {
        VaultError::RevisionRollback { .. } | VaultError::WatermarkRollback { .. } => ec::REVISION_ROLLBACK,
        VaultError::Crypto(CryptoError::Open) | VaultError::MissingWrap => ec::WRONG_PASSPHRASE,
        VaultError::Crypto(CryptoError::RecoveryFormat | CryptoError::RecoveryChecksum) => {
            ec::RECOVERY_CODE_INVALID
        }
        VaultError::Crypto(CryptoError::Signature)
        | VaultError::BadKeyring(_)
        | VaultError::BadKdfParams
        | VaultError::RevisionOverflow
        | VaultError::Sharing(_) => ec::KEYRING_VERIFY_FAILED,
        VaultError::Crypto(_) | VaultError::Sealer(_) => ec::DECRYPT_FAILED,
        VaultError::TreeMismatch => ec::TAMPERED_ANCHOR,
        VaultError::NotAuthorized => ec::ACCESS_DENIED,
        VaultError::MemberExists | VaultError::MemberNotFound | VaultError::CannotRemoveOwner => {
            ec::INVALID_REQUEST
        }
        VaultError::MalformedWatermark => ec::INTERNAL,
    }
}

/// Provision a fresh tree (genesis) and open a ready core over `store`.
///
/// # Errors
/// Returns [`VaultError`] if the keyring engine provisioning fails.
pub fn provision<S: BlobStore>(
    store: S,
    engine: EngineKind,
    passphrase: &Passphrase,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    doc: impl Into<String>,
) -> Result<Provisioned<S>, VaultError> {
    let (tree, member, replica) =
        (TreeId::new(tree_id), MemberId::new(member_id), ReplicaId::new(replica_id));
    let ctx = VaultContext { tree_id: &tree, member_id: &member, replica_id: &replica };
    let p = AppVault::from_kind(engine).provision(&ctx, passphrase)?;
    let did = p.did_key.into_string();
    Ok(Provisioned {
        core: AppCore::new(did.clone(), p.sealer, Arc::new(store), doc, replica_id),
        keyring: p.anchor,
        recovery_code: p.recovery_code.into_string(),
        did_key: did,
        watermark: p.watermark,
    })
}

/// Re-open an existing tree from its trusted keyring `anchor` + passphrase, over `store`. No bootstrap here —
/// the host imports the durably-persisted log THEN calls [`AppCore::bootstrap`].
///
/// # Errors
/// Returns [`VaultError`] if the engine can't unlock the anchor (wrong passphrase / stale keyring).
// The flat lifecycle argument list (engine + passphrase + the three ids + anchor + doc) is the veneer/host
// calling convention shared with the wasm export, not a struct to bundle.
#[allow(clippy::too_many_arguments)]
pub fn unlock<S: BlobStore>(
    store: S,
    engine: EngineKind,
    passphrase: &Passphrase,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    doc: impl Into<String>,
) -> Result<Unlocked<S>, VaultError> {
    let (tree, member, replica) =
        (TreeId::new(tree_id), MemberId::new(member_id), ReplicaId::new(replica_id));
    let ctx = VaultContext { tree_id: &tree, member_id: &member, replica_id: &replica };
    let u = AppVault::from_kind(engine).unlock(&ctx, anchor, passphrase)?;
    let did = u.did_key.into_string();
    Ok(Unlocked {
        core: AppCore::new(did.clone(), u.sealer, Arc::new(store), doc, replica_id),
        did_key: did,
        watermark: u.watermark,
        needs_reseal: u.needs_reseal,
        needs_backfill: u.needs_backfill,
        needs_rrk_backfill: u.needs_rrk_backfill,
        write_epoch_unreachable: u.write_epoch_unreachable,
    })
}

/// The result of [`recover`]: a ready [`AppCore`] under a freshly-minted owner identity, plus the NEW keyring
/// anchor + recovery code the host persists/shows and the two advisory repair flags.
pub struct Recovered<S: BlobStore> {
    pub core: AppCore<S>,
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub did_key: String,
    pub watermark: Vec<u8>,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
}

/// Recover owner access with the recovery code under a NEW passphrase (mints a fresh owner identity and
/// re-wraps every DEK to it), and open a ready core over `store`. `anchor` is the stored keyring; `floor` is
/// the persisted anti-rollback watermark. Returns the new keyring + a new recovery code to persist. Recovery
/// mints a fresh escrow and reaches every epoch, so it introduces no rotation orphan and no unreachable write
/// epoch (hence only the reseal/backfill flags surface).
///
/// # Errors
/// Returns [`VaultError`] if the engine can't recover the anchor (wrong recovery code / stale keyring).
#[allow(clippy::too_many_arguments)]
pub fn recover<S: BlobStore>(
    store: S,
    engine: EngineKind,
    recovery_code: &RecoveryCode,
    new_passphrase: &Passphrase,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    floor: &[u8],
    doc: impl Into<String>,
) -> Result<Recovered<S>, VaultError> {
    let (tree, member, replica) =
        (TreeId::new(tree_id), MemberId::new(member_id), ReplicaId::new(replica_id));
    let ctx = VaultContext { tree_id: &tree, member_id: &member, replica_id: &replica };
    let r = AppVault::from_kind(engine).recover(&ctx, anchor, recovery_code, new_passphrase, floor)?;
    let did = r.did_key.into_string();
    Ok(Recovered {
        core: AppCore::new(did.clone(), r.sealer, Arc::new(store), doc, replica_id),
        keyring: r.anchor,
        recovery_code: r.recovery_code.into_string(),
        did_key: did,
        watermark: r.watermark,
        needs_reseal: r.needs_reseal,
        needs_backfill: r.needs_backfill,
    })
}

/// The result of [`change_passphrase`]: the re-wrapped keyring anchor + rotated recovery code + watermark to
/// persist. The DEK is unchanged, so there is no new core — the running core keeps working.
pub struct PassphraseChanged {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub watermark: Vec<u8>,
}

/// Change the passphrase: re-wrap the keyring under a new KEK and rotate the recovery code. The DEK is
/// unchanged (the running core keeps working), so this returns no core — just the new keyring + code +
/// watermark to persist. `anchor` is the stored keyring; `floor` is the persisted watermark.
///
/// # Errors
/// Returns [`VaultError`] if the engine can't re-key the anchor (wrong current passphrase / stale keyring).
#[allow(clippy::too_many_arguments)]
pub fn change_passphrase(
    engine: EngineKind,
    old_passphrase: &Passphrase,
    new_passphrase: &Passphrase,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    anchor: &[u8],
    floor: &[u8],
) -> Result<PassphraseChanged, VaultError> {
    let (tree, member, replica) =
        (TreeId::new(tree_id), MemberId::new(member_id), ReplicaId::new(replica_id));
    let ctx = VaultContext { tree_id: &tree, member_id: &member, replica_id: &replica };
    let re = AppVault::from_kind(engine)
        .change_passphrase(&ctx, anchor, old_passphrase, new_passphrase, floor)?;
    Ok(PassphraseChanged {
        keyring: re.anchor,
        recovery_code: re.recovery_code.into_string(),
        watermark: re.watermark,
    })
}

/// The result of [`unlock_as_member`]: a ready member [`AppCore`] (already carrying its epoch-adopt secret and
/// a §B3 resolver installed at construction) + the author identity + watermark.
pub struct MemberUnlocked<S: BlobStore> {
    pub core: AppCore<S>,
    pub did_key: String,
    pub watermark: Vec<u8>,
}

/// Unlock a shared tree as a NON-owner member over `store`: verify against the pinned `trusted_signers` (chain)
/// / resolve the anchor (dag), HPKE-unwrap the member DEKs with the passphrase + account KDF, and wrap a ready
/// core that (a) retains the member's epoch-adopt secret so a later write-epoch rotation splices in without a
/// passphrase (OPE-393) and (b) carries a §B3 resolver AT CONSTRUCTION — never the accept-all state where a
/// sync before the first membership install would fold forgeries. `keyring` is the trusted member keyring head;
/// `retained` is the prior-revision set for the look-behind (empty ⇒ older governing revisions Hold, fail-
/// closed, until supplied); `trusted_signers` is the flat concatenated signer keys (empty for dag).
///
/// # Errors
/// [`CoreError::Vault`] if member unlock fails (wrong passphrase / unpinned signer / removed member) or the
/// resolver can't be built; [`CoreError`] if installing the resolver faults.
#[allow(clippy::too_many_arguments)]
pub fn unlock_as_member<S: BlobStore>(
    store: S,
    engine: EngineKind,
    keyring: &[u8],
    passphrase: &Passphrase,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    trusted_signers: &[u8],
    replica_id: &[u8],
    min_revision: u32,
    retained: &[(u32, Vec<u8>)],
    doc: impl Into<String>,
) -> Result<MemberUnlocked<S>, CoreError> {
    let u = openom_vault::sharing::unlock_as_member(
        engine,
        keyring,
        passphrase,
        member_kdf_params,
        tree_id,
        member_id,
        trusted_signers,
        replica_id,
        min_revision,
    )?;
    let mut core = AppCore::new(u.did_key.clone(), u.sealer, Arc::new(store), doc, replica_id);
    core.set_member_epoch_secret(u.epoch_secret);
    let resolver = openom_vault::resolver_from(engine, keyring, retained)?;
    core.set_membership(resolver)?;
    Ok(MemberUnlocked { core, did_key: u.did_key, watermark: u.watermark })
}

#[cfg(test)]
mod lifecycle_tests {
    use openom_crypto::Passphrase;
    use openom_keyring_api::EngineKind;
    use std::sync::atomic::{AtomicU64, Ordering};
    use store_blob::FsBlob;

    // A unique temp dir per test run (no tempfile dep) — the native local BlobStore both provision + unlock
    // share so the committed log persists across the re-open, exactly as the native (Tauri) host will.
    fn temp_dir() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "openom-appcore-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn provision_then_unlock_roundtrips_natively_over_fsblob() {
        // OPE-429: the store-generic rlib lifecycle drives a REAL provision/unlock over a native FsBlob store
        // (the wasm veneer uses the same fns over MemoryBlob) — the "one core, two runtimes" foundation.
        let dir = temp_dir();
        let (tree_id, replica_id) = ([7u8; 16], [1u8; 16]);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());

        // provision yields a working core over the native store: mint + commit + project round-trips in-core.
        let mut p = super::provision(
            FsBlob::new(dir.clone()), EngineKind::Chain, &pass, &tree_id, "acct-owner", &replica_id, "doc",
        )
        .unwrap();
        assert!(!p.keyring.is_empty(), "provision yields a keyring anchor");
        assert!(!p.recovery_code.is_empty(), "and a recovery code");
        assert!(!p.did_key.is_empty(), "and the author did:key");
        p.core.tree_mut().assert_anchor("pAlice", "https://openom.example/person", 1_000_000).unwrap();
        p.core.commit().unwrap();
        // Own entries fold on commit, so the subsumed frontier now covers this replica — proof the provisioned
        // core is fully wired (engine + sealer + local store), not just constructed.
        assert!(!p.core.subsumed_frontier().is_empty(), "the provisioned core folds its own committed mint");
        let (did, keyring) = (p.did_key.clone(), p.keyring.clone());
        drop(p); // release the FsBlob handle before re-opening the dir

        // unlock reconstructs the SAME identity from the keyring anchor over a fresh native store, and
        // bootstrap runs clean. (Recovering a committed-but-unsynced mint across a native re-open needs the
        // host's persist step — the heads pointer — which is the native-host slice's job, like the wasm
        // worker's import+bootstrap; the e2e reload tests already prove that flow in the wasm topology.)
        let mut u = super::unlock(
            FsBlob::new(dir.clone()), EngineKind::Chain, &pass, &tree_id, "acct-owner", &replica_id, &keyring, "doc",
        )
        .unwrap();
        assert_eq!(u.did_key, did, "same identity across provision + unlock");
        u.core.bootstrap().unwrap();

        assert!(
            super::unlock(
                FsBlob::new(dir.clone()), EngineKind::Chain, &Passphrase::new(b"wrong".to_vec()),
                &tree_id, "acct-owner", &replica_id, &keyring, "doc",
            )
            .is_err(),
            "a wrong passphrase is refused"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}

/// This replica's keyspace folder — the raw id as lowercase hex, so a random binary replica id maps to a
/// valid, injective object-key segment (the sealer keeps the raw bytes for attribution).
fn replica_key(replica: &[u8]) -> String {
    use std::fmt::Write as _;
    replica.iter().fold(String::with_capacity(replica.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl<S: BlobStore> AppCore<S> {
    /// Wrap a freshly-unlocked tree over a local `BlobStore`. `created_by` is this device's author `did:key`;
    /// `sealer` carries the DEK + this replica's id; `store` is the local durable `BlobStore`; `doc` is its
    /// keyspace prefix; `replica` is this replica's raw id.
    pub fn new(
        created_by: impl Into<String>,
        sealer: SealerSet,
        store: Arc<S>,
        doc: impl Into<String>,
        replica: &[u8],
    ) -> Self {
        let doc = doc.into();
        Self {
            client: SyncClient::new(
                created_by,
                sealer,
                Arc::clone(&store),
                doc.clone(),
                replica_key(replica),
            ),
            store,
            doc,
            undecodable: 0,
            rejected: 0,
            membership: None,
            covered: BTreeMap::new(),
            cover_envelopes: Vec::new(),
            member_epoch_secret: None,
        }
    }

    /// The local device `BlobStore` — the caller mirrors it against the shared remote (`docsync::mirror`)
    /// before/after [`fold`](Self::fold).
    #[must_use]
    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Retain the member's epoch-adopt secret (OPE-393) — set by the wasm veneer at a MEMBER unlock so the
    /// running core can adopt a later epoch on sync. Never exposed to JS.
    pub fn set_member_epoch_secret(&mut self, secret: openom_vault::sharing::MemberEpochSecret) {
        self.member_epoch_secret = Some(secret);
    }

    /// Adopt a rotated write epoch after a keyring sync — a member's counterpart to the owner re-unlock. Uses
    /// the retained epoch-adopt secret to unwrap the freshly-synced keyring's reachable epochs (no passphrase)
    /// and splices any new one into the running sealer, so the core can now OPEN content sealed under the new
    /// epoch (the self-heal cover included) and SEAL under it. Returns how many NEW epochs were spliced in.
    ///
    /// A NO-OP (returns 0) when: this core retains no member secret (an owner / solo core); OR the member now
    /// reaches no epoch at all — a REMOVED member. That last case is deliberately not an error: a removal is
    /// exactly the sync where a member discovers it was removed, and the sync tick must not throw over it
    /// ("reconcile = one tick, never throws"). Their old-epoch DEKs already cover the history they can read.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the keyring/anchor is malformed (a genuine data fault, distinct from an
    /// empty-reach removed member).
    pub fn adopt_epochs(&mut self, keyring: &[u8]) -> Result<usize, CoreError> {
        let adopted = match self.member_epoch_secret.as_ref() {
            None => return Ok(0),
            Some(secret) => match secret.adopt(keyring) {
                Ok(a) => a, // owned result — the borrow of `self` ends here
                // A removed member reaches no epoch → nothing to adopt. Fail SOFT (0), never throw on the tick.
                Err(openom_vault::VaultError::MissingWrap) => return Ok(0),
                Err(e) => return Err(e.into()),
            },
        };
        Ok(self
            .client
            .adopt_epochs(adopted.epochs, adopted.write_key_id, adopted.governing_ref))
    }

    /// Rebuild the engine from the local durable log on open/reload — adopt the snapshot's covered baseline,
    /// purge the held/stalled dots it subsumes, then re-classify the tail through the §B3 gate
    /// (`bootstrap_verified`, OPE-409 review #1). With no snapshot present (the pre-compaction state) this
    /// degrades to a plain verified fold, so an offline mint still survives a reload. NEVER a plain fold: a
    /// `Gone`-triggered re-bootstrap over a GC-reaped hole must RE-VERIFY the tail, not merge it unauthorized.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the store read or a merge fails.
    pub fn bootstrap(&mut self) -> Result<(), CoreError> {
        self.verify_gated(|client, classify, fold_cover, classify_snapshot| {
            client.bootstrap_verified(classify, fold_cover, classify_snapshot)
        })?;
        Ok(())
    }

    /// Fold current engine state into a snapshot at `{doc}/snapshot`, publishing the SUBSUMED frontier
    /// (OPE-409 C3) as the covered marker — only entries actually folded, so a GC deleting below it never
    /// deletes an entry no snapshot holds. Held/rejected/quarantined dots (a not-yet-covered removed member's
    /// tail, a version-skew entry) PIN the frontier, so compaction cannot cover them until they resolve. The
    /// app sends the SAME map as the plaintext `x-openom-covered` header on the snapshot PUT
    /// ([`subsumed_frontier`](Self::subsumed_frontier)).
    ///
    /// # Errors
    /// Returns [`CoreError`] if sealing or the blob write fails.
    pub fn compact(&mut self) -> Result<(), CoreError> {
        self.client.compact()?;
        Ok(())
    }

    /// Compact iff `policy` says so, given the `log/*` objects accrued since the last snapshot. Returns whether
    /// it compacted — if so, the worker uploads the fresh snapshot with the `x-openom-covered` header
    /// ([`subsumed_frontier`](Self::subsumed_frontier)). The policy is the seam; the app drives it with a fixed
    /// log-count K ([`openom_docsync::EveryNUpdates`]).
    ///
    /// # Errors
    /// Returns [`CoreError`] if a triggered compaction fails.
    pub fn maybe_compact(&mut self, policy: &impl SnapshotPolicy) -> Result<bool, CoreError> {
        Ok(self.client.maybe_compact(policy)?)
    }

    /// The SUBSUMED frontier — the ONLY coverage this device may honestly publish (OPE-409 C3), sent as the
    /// plaintext `x-openom-covered` header on the snapshot PUT so the server's GC gate 1 can trust it.
    /// `{replica_hex: counter}`.
    #[must_use]
    pub fn subsumed_frontier(&self) -> BTreeMap<String, u64> {
        self.client.subsumed_frontier()
    }

    /// The PULL frontier — the per-replica counter this device has FETCHED up to (`{replica_hex: counter}`).
    /// The worker reports it to `PUT /frontier` so the server's GC gate 2 pins the reclamation floor down to
    /// the slowest current member's pull point — a member's un-pulled log tail is never reaped before it can
    /// pull it (OPE-409 gate 2). Distinct from [`subsumed_frontier`](Self::subsumed_frontier).
    #[must_use]
    pub fn pull_frontier(&self) -> BTreeMap<String, u64> {
        self.client.pull_frontier()
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
        // Delete every object under this doc's keyspace (log/heads/snapshot).
        let prefix = format!("{}/", self.doc);
        for (key, _etag) in self.store.list(&prefix)? {
            self.store.delete(&key, Precondition::Any)?;
        }
        self.undecodable = 0;
        self.rejected = 0;
        self.covered.clear();
        self.cover_envelopes.clear();
        Ok(())
    }

    // --- fold: the §B3 verify gate over the (mirrored) local store ------------------------------

    /// Fold every log object past the client's inbound frontier through the §B3 gate: each peer `Delta` is
    /// verified ([`classify_entry`]) — accepted → merged, held → parked for a later fold (a later membership
    /// op / cover un-holds it), rejected → dropped + counted — and each `Cover` is verified + folded into
    /// [`covered`](Self) ([`fold_cover_entry`]). The caller mirrors the shared remote into the local store
    /// first; this then folds the arrivals. Returns how many entries merged this call.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a local store read fails (a broken backend — not one bad entry).
    pub fn fold(&mut self) -> Result<usize, CoreError> {
        Ok(self.verify_gated(|client, classify, fold_cover, _cs| client.pull_verified(classify, fold_cover))?)
    }

    /// Re-attempt every STALLED dot (a pinned blocker: `Unopenable`/`MergeFailed`/`Rejected`/`Vanished`)
    /// through the §B3 gate — the only heal for a stuck pin, since stalls are deliberately NOT auto-retried
    /// per tick (that would recreate the retry loop the terminal `Rejected` disposition avoids). Invoke on
    /// discrete events only: a membership change ([`set_membership`](Self::set_membership) does this) or an
    /// explicit user "retry". Safe by construction — it can only REMOVE a blocker, never merge unverified
    /// content: each re-attempt re-runs the full crypto + role gate, so a forgery never flips to Accept, but a
    /// peer write that the OLD membership rejected and the NEW membership authorizes (a retroactive grant) is
    /// legitimately released. Returns how many stalls cleared or re-parked to `held`.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a local store read fails.
    pub fn retry_stalled(&mut self) -> Result<usize, CoreError> {
        Ok(self.verify_gated(|client, classify, fold_cover, _cs| client.retry_stalled(classify, fold_cover))?)
    }

    /// Run a verified-pull op (`pull_verified` / `bootstrap_verified`) behind the §B3 gate closures, shared by
    /// [`fold`](Self::fold) and [`bootstrap`](Self::bootstrap). `classify` verifies each peer `Delta`
    /// (accept/hold/reject + the SH-2 covered-accept rescue); `fold_cover` verifies and folds each `Cover`.
    /// The two closures share `covered`/`cover_envelopes`, taken into interior-mutable locals for the call and
    /// restored after; `membership` is a disjoint field borrowed shared while `self.client` is borrowed mut.
    fn verify_gated<R>(
        &mut self,
        run: impl FnOnce(
            &mut SyncClient<Arc<S>>,
            &mut dyn FnMut(&[u8], &[u8], &str, u64) -> Verdict,
            &mut dyn FnMut(&[u8], &[u8], &str, u64),
            &mut dyn FnMut(&[u8], &[u8]) -> Verdict,
        ) -> R,
    ) -> R {
        use std::cell::{Cell, RefCell};
        let membership = self.membership.as_deref();
        let covered = RefCell::new(std::mem::take(&mut self.covered));
        let cover_envs = RefCell::new(std::mem::take(&mut self.cover_envelopes));
        let rejected = Cell::new(0_usize);
        let out = {
            let mut classify = |env: &[u8], pt: &[u8], _r: &str, _c: u64| {
                let v = classify_entry(membership, &covered.borrow(), env, pt);
                if v == Verdict::Reject {
                    rejected.set(rejected.get() + 1);
                }
                v
            };
            let mut fold_cover = |env: &[u8], body: &[u8], _r: &str, _c: u64| {
                if fold_cover_entry(membership, &mut covered.borrow_mut(), env, body) {
                    cover_envs.borrow_mut().push(env.to_vec());
                } else {
                    rejected.set(rejected.get() + 1);
                }
            };
            // OPE-421: the snapshot-adoption gate — a snapshot's bulk state is trusted only if its author held
            // the role at head (the same §B3 look-behind, no covered-accept). A rejection counts as an anomaly.
            let mut classify_snapshot = |env: &[u8], body: &[u8]| {
                let v = classify_snapshot_entry(membership, env, body);
                if v == Verdict::Reject {
                    rejected.set(rejected.get() + 1);
                }
                v
            };
            run(&mut self.client, &mut classify, &mut fold_cover, &mut classify_snapshot)
        };
        self.covered = covered.into_inner();
        self.cover_envelopes = cover_envs.into_inner();
        self.rejected += rejected.get();
        out
    }

    // --- durable persistence: the local BlobStore mirrored to a durable tier -----------------------
    //
    // The local BlobStore is the device-local durable cache. Where it is in-memory (tests), the host
    // persists it to a durable tier (IndexedDB / rusqlite) as opaque (key, bytes) objects: `export` lists
    // them; `import` puts them back on open. The core computes WHAT to persist synchronously; the host runs
    // the async writes outside these steps.

    /// Every object under this doc's keyspace, as `(key, bytes)` — the batch the host writes to durable
    /// storage. Not filtered by replica: durability mirrors the WHOLE local store (ours + peers'), so a
    /// reload rebuilds the full set without re-pulling from the remote.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a local store read fails.
    pub fn export(&self) -> Result<Vec<(String, Vec<u8>)>, CoreError> {
        let prefix = format!("{}/", self.doc);
        let mut out = Vec::new();
        for (key, _etag) in self.store.list(&prefix)? {
            if let Some((bytes, _etag)) = self.store.get(&key)? {
                out.push((key, bytes));
            }
        }
        Ok(out)
    }

    /// Load durably-persisted objects back into the local store on open (before [`bootstrap`](Self::bootstrap)
    /// folds them). Idempotent: immutable log objects go in `IfAbsent`, head/snapshot pointers overwrite.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a local store write fails.
    pub fn import(&mut self, objects: &[(String, Vec<u8>)]) -> Result<(), CoreError> {
        for (key, bytes) in objects {
            let pre = if is_pointer_key(key) {
                Precondition::Any
            } else {
                Precondition::IfAbsent
            };
            match self.store.put(key, bytes, pre) {
                Ok(_) | Err(BlobError::PreconditionFailed) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    // --- remote sync: reconcile against a snapshot of the shared remote --------------------------------

    /// Reconcile against a snapshot of the shared remote's objects, and return what the remote is missing.
    ///
    /// The caller (the worker) lists every object the shared remote holds under this doc and passes them here.
    /// This mirrors them into the local store (PULL), folds the arrivals through the §B3 gate, then mirrors the
    /// local store back into an in-memory copy of the remote (PUSH) and returns the objects that copy has which
    /// the input snapshot lacked — exactly the set the caller must upload. `docsync::mirror` owns the whole
    /// keyspace + frontier + head-monotonicity decision (a peer's head is only ever advanced, never rolled
    /// back), so the caller stays a dumb ferry that never parses, builds, or compares a key.
    ///
    /// `compact_k` triggers compaction as part of the tick: after the fold, if at least `compact_k` `log/*`
    /// objects have accrued since the last snapshot (`EveryNUpdates`, OPE-409 C3), fold state into a fresh
    /// snapshot BEFORE the push — so the snapshot object is in the returned uploads. `0` disables compaction.
    /// When a snapshot was (re)written, the caller sends [`subsumed_frontier`](Self::subsumed_frontier) as the
    /// `x-openom-covered` header on the snapshot upload.
    ///
    /// Returns `(objects_to_upload, folded_count)`.
    ///
    /// # Errors
    /// Returns [`CoreError`] if a store read/write, a mirror step, or a triggered compaction fails.
    pub fn sync_against(
        &mut self,
        remote: &[StoredObject],
        compact_k: u32,
    ) -> Result<(Vec<StoredObject>, usize), CoreError> {
        // An in-memory view of the remote, seeded from the caller's snapshot.
        let view = MemoryBlob::new();
        for (key, bytes) in remote {
            view.put(key, bytes, Precondition::Any)?;
        }
        // PULL remote → local (monotonic). Then ADOPT a newer snapshot if it covers state we lack (a
        // fresh/straggler client gets the reaped-below-floor state that lives ONLY in the snapshot — OPE-409
        // layer 3); otherwise just fold the tail. MAYBE compact (which itself skips if a peer already covered
        // us), then PUSH local → the view.
        docsync::mirror(&view, &self.store, &self.doc)?;
        let folded = if self.client.needs_snapshot_adoption()? {
            self.bootstrap()?; // adopt the snapshot + re-verify the tail (bootstrap_verified)
            0 // bootstrap's tail count isn't surfaced; the diagnostic `folded` is a fold-tick count only
        } else {
            self.fold()?
        };
        if compact_k > 0 {
            self.client.maybe_compact(&EveryNUpdates(u64::from(compact_k)))?;
        }
        docsync::mirror(&self.store, &view, &self.doc)?;
        // The view now holds the union; whatever it has that the input snapshot didn't (a fresh log object, or
        // an advanced head/snapshot pointer) is what the remote must be sent.
        let had: std::collections::HashMap<&str, &[u8]> =
            remote.iter().map(|(k, b)| (k.as_str(), b.as_slice())).collect();
        let mut uploads = Vec::new();
        for (key, _etag) in view.list(&format!("{}/", self.doc))? {
            let Some((bytes, _etag)) = view.get(&key)? else {
                continue;
            };
            if had.get(key.as_str()) != Some(&bytes.as_slice()) {
                uploads.push((key, bytes));
            }
        }
        Ok((uploads, folded))
    }

    /// One sync tick with the FULL per-object write metadata the transport needs: [`sync_against`](Self::sync_against)
    /// plus each upload's `pointer` flag (from the core's `is_pointer_key`) and the covered frontier (from
    /// [`subsumed_frontier`](Self::subsumed_frontier)). The wasm veneer AND the native host both call THIS, so the
    /// pointer/covered logic lives in exactly one place and the two runtimes can't drift.
    ///
    /// # Errors
    /// As [`sync_against`](Self::sync_against).
    pub fn sync_tick(&mut self, remote: &[StoredObject], compact_k: u32) -> Result<SyncTick, CoreError> {
        let (uploads, folded) = self.sync_against(remote, compact_k)?;
        let uploads = uploads
            .into_iter()
            .map(|(key, bytes)| {
                let pointer = is_pointer_key(&key);
                Upload { key, bytes, pointer }
            })
            .collect();
        Ok(SyncTick { uploads, folded, covered: self.subsumed_frontier() })
    }

    /// Data-integrity anomalies observed so far: entries whose header wouldn't decode, the fold's quarantined
    /// (un-openable / un-mergeable) objects, and the §B3-rejected forgeries. A caller surfaces a non-zero
    /// count as a warning — these are never silently swallowed.
    #[must_use]
    pub fn anomalies(&self) -> usize {
        self.undecodable + self.client.quarantined_count() + self.rejected
    }

    /// The pending soft-removal review queue (OPE-426), as JSON `[{replica, counter, authorMemberId, kind}]`.
    /// These are a departed member's trailing edits the head look-behind refused (dropped): valid at their
    /// governing revision but authored by someone since demoted/removed. An administrator reviews them and
    /// either [`approve_pending`](Self::approve_pending) (keep — the reactive analog of compact-before-remove)
    /// or [`discard_pending`](Self::discard_pending). Never contains a generic forgery (those are rejected, not
    /// dropped). The UI drives this; the core just surfaces the queue + the two decisions.
    #[must_use]
    pub fn pending_reviews(&self) -> String {
        let items: Vec<Value> = self
            .client
            .dropped_dots()
            .into_iter()
            .filter_map(|(replica, counter)| {
                let env = self.client.read_dropped(&replica, counter).ok()??;
                let envelope = Envelope::decode(env.as_slice()).ok()?;
                let header = envelope.header.as_ref()?;
                Some(serde_json::json!({
                    "replica": replica,
                    "counter": counter,
                    "authorMemberId": header.author_member_id,
                    "kind": header.kind,
                }))
            })
            .collect();
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
    }

    /// Approve a pending trailing edit (OPE-426): a current administrator VOUCHES for it. The delta is merged
    /// iff it passes the covered-accept predicate — a valid signature by a key the author ACTUALLY held and a
    /// kind their strongest-ever role permits, resolved from OUR membership ([`MembershipResolver::ever_member_info`]),
    /// never the entry — the same gate the self-heal cover reader applies. Once merged, the next compaction pins
    /// it, so every replica recovers it via snapshot adoption. Returns whether it was approved (false if the dot
    /// is unknown, gone, or fails the vouch). Idempotent.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the store read fails.
    pub fn approve_pending(&mut self, replica: &str, counter: u64) -> Result<bool, CoreError> {
        let membership = self.membership.as_deref();
        let approved = self.client.readmit_dropped(replica, counter, |env, pt| {
            let Some(m) = membership else {
                return true; // solo/unshared — only the DEK holder writes, so an opened entry is trusted
            };
            let Ok(envelope) = Envelope::decode(env) else {
                return false;
            };
            let Some(header) = envelope.header.as_ref() else {
                return false;
            };
            // Re-run §B3 and accept iff the disposition is Accept OR Drop. A dropped dot is governing-valid but
            // head-invalid, so Drop is the expected verdict; both Accept and Drop mean the signature verifies
            // against the author's key at the governing revision — engine-neutral (the chain resolves the
            // retained governing keyring; it has no dag-style `ever_member_info`). This re-checks the signature
            // (guarding a BYO store where the object could be swapped), while the administrator supplies the
            // head-authority override by choosing to approve. A Reject (forgery) or Hold declines.
            matches!(
                openom_vault::verify_ingest(
                    envelope.version,
                    m,
                    header,
                    &header.governing_ref,
                    &header.key_id,
                    || Ok::<_, ()>(pt.to_vec()),
                ),
                Disposition::Accept | Disposition::Drop
            )
        })?;
        Ok(approved)
    }

    /// Discard a pending trailing edit (OPE-426): the administrator declines to keep it. It stays suppressed.
    /// Returns whether it was present in the pending queue.
    pub fn discard_pending(&mut self, replica: &str, counter: u64) -> bool {
        self.client.forget_dropped(replica, counter)
    }

    /// Install (or refresh) the §B3 governing membership. The worker calls this on unlock and after every
    /// keyring sync, passing a resolver ([`openom_vault::ChainMembershipResolver`] /
    /// [`openom_vault::DagMembershipResolver`])
    /// built from the freshly-verified keyring. Once set, every peer entry [`ingest`](Self::ingest) sees is
    /// verified against the resolved roles before it is stored or folded.
    ///
    /// Re-runs verification on the Held buffer (entries whose governing keyring/epoch is now retained are
    /// stored + folded; the rest stay held or are rejected) AND re-attempts the stalled pins
    /// ([`retry_stalled`](Self::retry_stalled)) — a membership change is a discrete event that can authorize a
    /// peer write the old view rejected. Returns how many entries the new membership released (held drained +
    /// stalls cleared).
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
        // Re-validate every retained Cover against the NEW membership (pin P3): a cover whose author is no
        // longer a Maintainer must stop blessing, so rebuild `covered` from scratch rather than let it grow.
        self.rebuild_covered();
        // Re-fold: the client re-verifies its held dots under the new membership (a now-retained governing
        // keyring/epoch releases them), and folds the newly-released entries.
        let released = self.fold()?;
        // A membership change is exactly the discrete event `retry_stalled` is meant for: re-attempt the
        // stalled pins under the new view, so a peer write the OLD membership rejected but the NEW one
        // authorizes is released (and its subsumed-frontier pin lifts). Terminal by design under auto-retry;
        // safe here because each re-attempt re-runs the full gate.
        let unstalled = self.retry_stalled()?;
        Ok(released + unstalled)
    }

    /// Author a self-heal **cover** over this device's stored entries whose author was legitimately a member
    /// but is no longer current (the OPE-382 writer sweep — dag only in practice). Scans the local store: a
    /// `Delta` by a since-removed EVER-member (pin P6: never a voided thief or a never-member), not already
    /// covered, is covered ONLY if it would itself pass covered-accept — the same [`verify_covered_entry`]
    /// predicate the reader applies (a valid signature by a key the author actually held AND a kind permitted by
    /// the author's strongest role). This is what makes the previously-implicit "the store holds only accepted
    /// entries" coupling explicit: the writer covers exactly what the reader would accept, so a rogue below-role
    /// plant or a forgery in the dumb-mirror store is never blessed. Publishes the sealed `Cover` as a log
    /// object (folded into the local covered set so a re-sweep is idempotent). Returns whether a cover was
    /// authored.
    ///
    /// Re-run on every membership change (a removal, or a covering Maintainer's own later removal — pin P4);
    /// each run covers whatever became uncovered.
    ///
    /// # Errors
    /// Returns [`CoreError`] if the store read or the seal fails.
    pub fn author_cover(&mut self) -> Result<bool, CoreError> {
        let Some(membership) = self.membership.as_deref() else {
            return Ok(false); // solo tree: no removed members to heal
        };
        // Scan every local log object for a Delta by a SINCE-REMOVED ever-member, not already covered.
        let log_prefix = format!("{}/log/", self.doc);
        let mut covered_entries: Vec<CoveredEntry> = Vec::new();
        for (key, _etag) in self.store.list(&log_prefix)? {
            let Some((env, _etag)) = self.store.get(&key)? else {
                continue;
            };
            let Ok(envelope) = Envelope::decode(env.as_slice()) else {
                continue;
            };
            let Some(header) = envelope.header.as_ref() else {
                continue;
            };
            if header.kind != Kind::Delta as i32 || membership.current_member(&header.author_member_id) {
                continue;
            }
            let Some(info) = membership.ever_member_info(&header.author_member_id) else {
                continue; // P6: ever a legitimate member
            };
            let hash = Sha256::digest(&envelope.ciphertext).to_vec();
            if self.covered.contains_key(&hash) {
                continue;
            }
            // Cover ONLY what the reader would covered-accept: open the entry and re-check the exact predicate
            // (real key + strongest role). Skips a forgery / below-role plant sitting in the dumb-mirror store.
            let Ok(plaintext) = self.client.try_open_delta(&env) else {
                continue;
            };
            let accepts = info.keys_ever_held.iter().any(|k| {
                openom_vault::verify_covered_entry(
                    envelope.version,
                    header,
                    &plaintext,
                    &header.author_member_id,
                    k,
                    info.strongest_role,
                )
            });
            if !accepts {
                continue;
            }
            // The writer/reader coupling as a live invariant: never push a candidate the reader would reject.
            debug_assert!(accepts, "author_cover gates every push on verify_covered_entry (the reader's predicate)");
            // The reader resolves the author's key from its own membership, so the cover binds only (hash, id) —
            // there is no key field to forge.
            covered_entries.push(CoveredEntry {
                ciphertext_hash: hash,
                author_member_id: header.author_member_id.clone(),
            });
        }
        if covered_entries.is_empty() {
            return Ok(false);
        }
        // Fold our OWN cover locally (the next sweep skips these hashes; the client advances our frontier past
        // the cover object, so `fold` never re-offers our own cover), then publish it as a Cover log object.
        for e in &covered_entries {
            self.covered.insert(e.ciphertext_hash.clone(), e.author_member_id.clone());
        }
        self.client
            .push_cover(&CoverBody { entries: covered_entries }.encode_to_vec())?;
        Ok(true)
    }

    /// TEST-ONLY: push a raw `Cover` body, bypassing [`author_cover`](Self::author_cover)'s gate — to simulate a
    /// COMPROMISED (but currently-legitimate) Maintainer minting a cover the honest sweep would refuse, so a
    /// test can prove the READER's independent role/key resolution rejects it regardless of the writer.
    ///
    /// # Errors
    /// Returns [`CoreError`] if sealing or the blob write fails.
    #[cfg(test)]
    pub(crate) fn push_raw_cover_for_test(&mut self, body: &CoverBody) -> Result<(), CoreError> {
        self.client.push_cover(&body.encode_to_vec())?;
        Ok(())
    }

    /// Rebuild [`covered`](Self) from the retained Cover envelopes against the current membership — pin P3, so
    /// a cover whose author was since removed stops blessing. Called on every [`set_membership`](Self).
    fn rebuild_covered(&mut self) {
        self.covered.clear();
        let covers = std::mem::take(&mut self.cover_envelopes);
        for env in &covers {
            if let Ok(body) = self.client.try_open_cover(env) {
                // Re-fold iff still valid under the current membership.
                let _ = fold_cover_entry(self.membership.as_deref(), &mut self.covered, env, &body);
            }
        }
        self.cover_envelopes = covers;
    }

    /// How many sealed batches are queued but not yet written (always 0 — the client writes immediately).
    /// A diagnostic for the driver.
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

/// A head/snapshot pointer key (overwritten, unlike immutable log objects) — for [`AppCore::import`]'s
/// precondition choice, and for the wasm veneer to tell JS a PUSH precondition without JS ever parsing a key.
pub(crate) fn is_pointer_key(key: &str) -> bool {
    key.contains("/heads/") || key.ends_with("/snapshot")
}

const fn disposition_to_verdict(d: Disposition) -> Verdict {
    match d {
        Disposition::Accept => Verdict::Accept,
        Disposition::Hold => Verdict::Hold,
        Disposition::Reject => Verdict::Reject,
        // OPE-421 head look-behind failure: a since-demoted/removed author's backdated dot. Terminal +
        // non-resurrecting + non-pinning — docsync routes it to its `dropped` bucket.
        Disposition::Drop => Verdict::Drop,
    }
}

/// The §B3 disposition for one peer `Delta`, as a docsync [`Verdict`] — the `pull_verified` classify gate,
/// re-homed from `AppCore::classify`. Pure over `(membership, covered, envelope, opened plaintext)` (no client
/// borrow: `pull_verified` opens and hands us the plaintext). With no shared membership every entry is
/// accepted (AEAD-only is safe — only the DEK holder can write). Otherwise `verify_ingest` decides, plus the
/// SH-2 covered-accept rescue: a since-removed EVER-member's entry (pin P6) is accepted iff a currently-valid
/// Cover blessed its RECOMPUTED ciphertext hash (pin P1) and it still signature-verifies against a key the
/// author actually held, with its kind permitted by the author's strongest role — key and role resolved from
/// OUR membership, never the cover (pin P2).
fn classify_entry(
    membership: Option<&dyn MembershipResolver>,
    covered: &BTreeMap<Vec<u8>, String>,
    env: &[u8],
    plaintext: &[u8],
) -> Verdict {
    let Some(membership) = membership else {
        return Verdict::Accept;
    };
    let Ok(envelope) = Envelope::decode(env) else {
        return Verdict::Reject;
    };
    let Some(header) = envelope.header.as_ref() else {
        return Verdict::Reject;
    };
    let verdict = openom_vault::verify_ingest(
        envelope.version,
        membership,
        header,
        &header.governing_ref,
        &header.key_id,
        || Ok::<_, ()>(plaintext.to_vec()),
    );
    if verdict == Disposition::Reject {
        let hash = Sha256::digest(&envelope.ciphertext);
        if let Some(member_id) = covered.get(hash.as_slice()) {
            // Resolve the author's keys + STRONGEST role from OUR OWN membership (pin P6), NEVER from the cover
            // — so a forged cover can neither bind an attacker key to a real removed id nor waive the role check.
            // `verify_covered_entry` is the sole covered-accept decision site (see its doc): accept iff the entry
            // signature-verifies against a key the author actually held AND its kind is permitted by that role.
            if let Some(info) = membership.ever_member_info(member_id) {
                if info.keys_ever_held.iter().any(|key| {
                    openom_vault::verify_covered_entry(
                        envelope.version,
                        header,
                        plaintext,
                        member_id,
                        key,
                        info.strongest_role,
                    )
                }) {
                    return Verdict::Accept;
                }
            }
        }
    }
    disposition_to_verdict(verdict)
}

/// Verify a `Snapshot` envelope for adoption (OPE-421 Slice 1): route it through the SAME §B3 gate as a Delta
/// — the head look-behind — so a snapshot's bulk state is trusted only if its author held the required role
/// (Maintainer, for `Kind::Snapshot`) at the CURRENT head. This closes the unauthenticated-adoption hole where
/// a demoted/removed DEK-holder could poison state via a forged snapshot. NO covered-accept rescue: a Cover
/// blesses one removed member's individual delta; it must never bless a bulk state claim standing in for the
/// whole log. `membership == None` (solo/unshared) ⇒ Accept (only the DEK holder can write there).
fn classify_snapshot_entry(
    membership: Option<&dyn MembershipResolver>,
    env: &[u8],
    body: &[u8],
) -> Verdict {
    let Some(membership) = membership else {
        return Verdict::Accept;
    };
    let Ok(envelope) = Envelope::decode(env) else {
        return Verdict::Reject;
    };
    let Some(header) = envelope.header.as_ref() else {
        return Verdict::Reject;
    };
    disposition_to_verdict(openom_vault::verify_ingest(
        envelope.version,
        membership,
        header,
        &header.governing_ref,
        &header.key_id,
        || Ok::<_, ()>(body.to_vec()),
    ))
}

/// Verify one `Cover` envelope as a current Maintainer+ entry (pin P8) and, if valid, fold its `CoverBody`
/// into `covered`. Returns whether it was valid — the `pull_verified` `fold_cover` gate, re-homed from
/// `AppCore::try_fold_cover`. Pure over `(membership, covered, envelope, opened cover body)`. `false` when no
/// membership is installed (a solo tree has no removed members to heal).
fn fold_cover_entry(
    membership: Option<&dyn MembershipResolver>,
    covered: &mut BTreeMap<Vec<u8>, String>,
    env: &[u8],
    body_plaintext: &[u8],
) -> bool {
    let Some(membership) = membership else {
        return false;
    };
    let Ok(envelope) = Envelope::decode(env) else {
        return false;
    };
    let Some(header) = envelope.header.as_ref() else {
        return false;
    };
    let verdict = openom_vault::verify_ingest(
        envelope.version,
        membership,
        header,
        &header.governing_ref,
        &header.key_id,
        || Ok::<_, ()>(body_plaintext.to_vec()),
    );
    if verdict != Disposition::Accept {
        return false;
    }
    let Ok(body) = CoverBody::decode(body_plaintext) else {
        return false;
    };
    for e in body.entries {
        // Store only (hash → author id); the author's KEY + ROLE are resolved from the membership at accept
        // time (`classify_entry`), never from the cover — the reader's defense against a forged binding (the
        // cover carries no key field to trust). Skip a malformed entry rather than fail the cover.
        if !e.ciphertext_hash.is_empty() && !e.author_member_id.is_empty() {
            covered.insert(e.ciphertext_hash, e.author_member_id);
        }
    }
    true
}

#[cfg(test)]
mod tests;
