//! The native (Tauri) host that runs [`openom_app_core::AppCore`] natively — DEK + engine + local device store
//! all native — with the keyring anchor + anti-rollback watermark held in a [`VaultStore`]. The webview never
//! supplies the keyring or the floor: it FETCHES the keyring over the network (ciphertext), and the host
//! accepts and persists it (OPE-427 review fix 1 — ferry in the webview, accept in native). One `AppCore` per
//! doc, `Mutex`-guarded because Tauri dispatches invokes on a thread pool.
//!
//! This is plain, cargo-tested Rust; the Tauri `#[command]`s are thin wrappers over it (a later slice), which
//! run the heavy Argon2id paths under `spawn_blocking`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use openom_app_core::{AppCore, StoredObject};
use openom_crypto::{Passphrase, RecoveryCode};
use openom_keyring_api::EngineKind;
use openom_vault_host::VaultStore;
use store_blob::{BlobStore, FsBlob, Precondition};

/// A live core: an `AppCore` behind its own `Mutex` (Tauri invokes race on a thread pool).
pub type CoreHandle = Arc<Mutex<AppCore<FsBlob>>>;
/// The per-doc registry, keyed by doc id.
type CoreMap = HashMap<String, CoreHandle>;

/// A fresh, ephemeral replica id (16 bytes from the OS CSPRNG) minted per open. NEVER a caller argument: a
/// repeated replica id forks the per-replica counter chain (an anti-fork security property), and a fresh id per
/// open is also what lets a re-opened core pull its own previously-persisted entries as a peer (OPE-431).
fn fresh_replica() -> Result<[u8; 16], HostError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| HostError::Store(format!("csprng: {e}")))?;
    Ok(id)
}

/// Reject a `doc` id that could escape `data_dir` (the webview supplies it, so `../..` etc. must never reach a
/// filesystem join). A doc id is a tree key: non-empty and made only of url-safe id characters.
fn checked_doc(doc: &str) -> Result<&str, HostError> {
    let ok = !doc.is_empty()
        && doc.len() <= 128
        && doc.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(doc)
    } else {
        Err(HostError::Store(format!("invalid doc id: {doc:?}")))
    }
}

/// Wall-clock milliseconds for mint timestamps (the native analog of the wasm veneer's `now_millis`).
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// A host failure: a keyring-engine error, a keyring-store I/O error, or an operation on a tree the host has no
/// keyring for.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The keyring engine rejected the lifecycle op (wrong passphrase, stale keyring, malformed anchor).
    #[error(transparent)]
    Vault(#[from] openom_app_core::VaultError),
    /// The core (fold / commit / bootstrap / sync) failed — a local store I/O or engine fault.
    #[error(transparent)]
    Core(#[from] openom_app_core::CoreError),
    /// The claim engine rejected a mint (un-canonicalizable value, malformed op).
    #[error(transparent)]
    Tree(#[from] openom_data_tree::TreeError),
    /// The native keyring/watermark store failed (I/O, CAS).
    #[error("keyring store: {0}")]
    Store(String),
    /// No keyring is stored for this tree — the host can't unlock a tree it never provisioned/joined.
    #[error("no keyring stored for {0}")]
    NoKeyring(String),
    /// No live core for this tree — provision or unlock it first.
    #[error("no live core for {0}")]
    NoCore(String),
}

/// The result of [`AppCoreHost::provision`] — the durable core is registered in the host; the caller gets only
/// what it shows the user (the recovery code) + the author identity.
#[derive(serde::Serialize)]
pub struct Provisioned {
    pub recovery_code: String,
    pub did_key: String,
}

/// The result of [`AppCoreHost::unlock`] — the core is registered in the host; the caller gets the author
/// identity + the four advisory repair flags.
// Four INDEPENDENT repair signals, mirroring the core's `Unlocked` — not a state enum.
#[derive(serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Unlocked {
    pub did_key: String,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
    pub needs_rrk_backfill: bool,
    pub write_epoch_unreachable: bool,
}

/// A joining member's minted account (from [`AppCoreHost::provision_member`]): the codec-encoded KDF params to
/// persist + replay at member unlock, and the two OOB-shareable public keys the owner needs to admit them.
#[derive(serde::Serialize)]
pub struct MemberAccount {
    pub kdf_params: Vec<u8>,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

/// The OOB-verified joiner an owner admits via [`AppCoreHost::add_member`] — the id + role + the two public
/// keys the joiner shared out of band (from their [`MemberAccount`]). NOT trust-bearing custody: these are the
/// owner's own OOB-verified inputs, distinct from the keyring/floor the host sources natively.
#[derive(serde::Deserialize)]
pub struct MemberToAdd {
    pub member_id: String,
    pub role: String,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

/// The result of [`AppCoreHost::add_member`] — the opaque new keyring revision for the webview to PUBLISH (so
/// peers + the joiner can pull it). The owner's running core has already been re-opened in place on the shared
/// keyring (so its sealer now signs). Publish keyring FIRST, then the advisory summary (OPE-293 add ordering).
#[derive(serde::Serialize)]
pub struct AddedMember {
    pub keyring: Vec<u8>,
}

/// The result of [`AppCoreHost::remove_member`] — the opaque ROTATED keyring revision for the webview to
/// PUBLISH, and whether the departing member's landed history was pinned by a snapshot before the rotation.
/// `history_preserved == false` means the removal ran before the departing member's writes were pulled/covered
/// (offline or a very-last-second edit), so in-transit preservation was reduced — the client look-behind still
/// rejects forgeries, so this is an availability/audit signal, not a security one (design-review Q2). On a
/// removal the webview publishes the ADVISORY summary FIRST, then the keyring (OPE-293 remove ordering), then a
/// data sync to push the self-heal cover.
#[derive(serde::Serialize)]
pub struct RemovedMember {
    pub keyring: Vec<u8>,
    pub history_preserved: bool,
}

/// The result of [`AppCoreHost::recover`] — the new recovery code to show once + the author identity + the two
/// advisory repair flags; the fresh keyring/watermark are persisted natively and the core registered.
#[derive(serde::Serialize)]
pub struct Recovered {
    pub recovery_code: String,
    pub did_key: String,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
}

/// The result of [`AppCoreHost::change_passphrase`] — the rotated recovery code; the re-wrapped keyring +
/// watermark are persisted natively. The DEK is unchanged, so the running core keeps working (no re-open).
#[derive(serde::Serialize)]
pub struct PassphraseChanged {
    pub recovery_code: String,
}

/// The native app-core host. `store` holds the keyring anchor + anti-rollback watermark per tree; `data_dir`
/// roots each doc's local device `FsBlob`; `engine` is the keyring engine for NEW trees (existing trees carry
/// their own in the keyring). Live cores are held per-doc behind a `Mutex`.
pub struct AppCoreHost<St: VaultStore> {
    store: St,
    data_dir: PathBuf,
    engine: EngineKind,
    cores: Mutex<CoreMap>,
}

impl<St: VaultStore> AppCoreHost<St> {
    /// A host over `store` (keyring/watermark custody), rooting each doc's local device store under `data_dir`.
    pub fn new(store: St, data_dir: impl Into<PathBuf>, engine: EngineKind) -> Self {
        Self {
            store,
            data_dir: data_dir.into(),
            engine,
            cores: Mutex::new(HashMap::new()),
        }
    }

    /// The keyring/watermark store (for the Tauri command layer to reach the native custody).
    pub const fn store(&self) -> &St {
        &self.store
    }

    /// This doc's local device store: a `FsBlob` under `data_dir/{doc}`. The `doc` id is validated first so a
    /// webview-supplied value can never traverse out of `data_dir`.
    fn doc_store(&self, doc: &str) -> Result<FsBlob, HostError> {
        let dir = self.data_dir.join(checked_doc(doc)?);
        std::fs::create_dir_all(&dir).map_err(|e| HostError::Store(e.to_string()))?;
        Ok(FsBlob::new(dir))
    }

    /// This doc's chain keyring-revision RETENTION store — a native `FsBlob` at `data_dir/{doc}.kr`, holding one
    /// object per accepted keyring revision keyed by its zero-padded revision number. The §B3 look-behind needs
    /// these prior revisions to judge a write against the membership that governed it at creation (design-review
    /// F5): after a rotation the head alone can't say whether a pre-rotation author was authorized THEN. Kept in
    /// native custody, alongside the head — never fed from the webview. Sibling dir (`.kr` can't collide with
    /// another doc: `checked_doc` forbids `.`). The dag resolver ignores retention (it resolves from the anchor).
    fn retention_store(&self, doc: &str) -> Result<FsBlob, HostError> {
        let dir = self.data_dir.join(format!("{}.kr", checked_doc(doc)?));
        std::fs::create_dir_all(&dir).map_err(|e| HostError::Store(e.to_string()))?;
        Ok(FsBlob::new(dir))
    }

    /// Retain an accepted keyring `revision`'s bytes natively (idempotent).
    fn retain_revision(&self, doc: &str, revision: u32, keyring: &[u8]) -> Result<(), HostError> {
        self.retention_store(doc)?
            .put(&format!("{revision:010}"), keyring, Precondition::Any)
            .map_err(|e| HostError::Store(e.to_string()))?;
        Ok(())
    }

    /// The `(revision, keyring)` pairs retained so far — the prior-revision set the §B3 resolver looks behind to.
    fn retained_revisions(&self, doc: &str) -> Result<Vec<(u32, Vec<u8>)>, HostError> {
        let store = self.retention_store(doc)?;
        let mut out = Vec::new();
        for (key, _etag) in store.list("").map_err(|e| HostError::Store(e.to_string()))? {
            if let Ok(rev) = key.parse::<u32>() {
                if let Some((bytes, _etag)) = store.get(&key).map_err(|e| HostError::Store(e.to_string()))? {
                    out.push((rev, bytes));
                }
            }
        }
        Ok(out)
    }

    /// Provision a fresh tree: open a core over the native store, PERSIST the keyring + watermark natively (one
    /// atomic `commit_keyring`), and register the core. Returns the recovery code + author `did:key`.
    ///
    /// # Errors
    /// [`HostError::Vault`] if provisioning fails; [`HostError::Store`] if the keyring can't be persisted.
    pub fn provision(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, HostError> {
        let p = openom_app_core::provision(
            self.doc_store(doc)?,
            self.engine,
            passphrase,
            tree_id,
            member_id,
            &fresh_replica()?,
            doc.to_string(),
        )?;
        self.store
            .commit_keyring(doc, &p.keyring, &p.watermark)
            .map_err(HostError::Store)?;
        // Retain the genesis revision for the §B3 look-behind (a later rotation must still judge writes made
        // under this revision). Chain-meaningful; a harmless unused blob for the dag.
        self.retain_revision(
            doc,
            openom_vault::sharing::chain_watermark_floor(&p.watermark),
            &p.keyring,
        )?;
        self.register(doc, p.core);
        Ok(Provisioned {
            recovery_code: p.recovery_code,
            did_key: p.did_key,
        })
    }

    /// Unlock an existing tree: load the keyring anchor FROM THE NATIVE STORE (never a webview argument — this
    /// is the boundary that stops an XSS feeding a stale/forged keyring), open the core, and register it.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree was never provisioned/joined; [`HostError::Vault`] on a wrong
    /// passphrase / stale keyring; [`HostError::Store`] on a store read failure.
    pub fn unlock(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        passphrase: &Passphrase,
    ) -> Result<Unlocked, HostError> {
        let anchor = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let u = openom_app_core::unlock(
            self.doc_store(doc)?,
            self.engine,
            passphrase,
            tree_id,
            member_id,
            &fresh_replica()?,
            &anchor,
            doc.to_string(),
        )?;
        self.register(doc, u.core);
        Ok(Unlocked {
            did_key: u.did_key,
            needs_reseal: u.needs_reseal,
            needs_backfill: u.needs_backfill,
            needs_rrk_backfill: u.needs_rrk_backfill,
            write_epoch_unreachable: u.write_epoch_unreachable,
        })
    }

    /// Recover owner access on a device that already has the tree provisioned/joined: load the stored keyring +
    /// watermark FROM THE NATIVE STORE (never a webview argument), recover under a new passphrase, PERSIST the
    /// fresh keyring + watermark natively, and register the new core. Returns the new recovery code + identity.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree isn't stored; [`HostError::Vault`] on a wrong recovery code / stale
    /// keyring; [`HostError::Store`] on a store read/write failure.
    pub fn recover(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
    ) -> Result<Recovered, HostError> {
        let anchor = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let floor = self.store.watermark(doc).map_err(HostError::Store)?;
        let r = openom_app_core::recover(
            self.doc_store(doc)?,
            self.engine,
            recovery_code,
            new_passphrase,
            tree_id,
            member_id,
            &fresh_replica()?,
            &anchor,
            &floor,
            doc.to_string(),
        )?;
        self.store
            .commit_keyring(doc, &r.keyring, &r.watermark)
            .map_err(HostError::Store)?;
        self.register(doc, r.core);
        Ok(Recovered {
            recovery_code: r.recovery_code,
            did_key: r.did_key,
            needs_reseal: r.needs_reseal,
            needs_backfill: r.needs_backfill,
        })
    }

    /// Change the passphrase on a tree in native custody: load the stored keyring + watermark, re-wrap under
    /// the new passphrase, and PERSIST the fresh keyring natively. The DEK is unchanged — the running core
    /// keeps working (no re-open). Returns the rotated recovery code to show once.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree isn't stored; [`HostError::Vault`] on a wrong current passphrase;
    /// [`HostError::Store`] on a store read/write failure.
    pub fn change_passphrase(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> Result<PassphraseChanged, HostError> {
        let anchor = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let floor = self.store.watermark(doc).map_err(HostError::Store)?;
        let re = openom_app_core::change_passphrase(
            self.engine,
            old_passphrase,
            new_passphrase,
            tree_id,
            member_id,
            &fresh_replica()?,
            &anchor,
            &floor,
        )?;
        self.store
            .commit_keyring(doc, &re.keyring, &re.watermark)
            .map_err(HostError::Store)?;
        Ok(PassphraseChanged { recovery_code: re.recovery_code })
    }

    /// Mint a joining member's account from their passphrase (stateless — no tree, no store, no core): the first
    /// step of the member flow, before an owner admits them. Returns the codec-encoded KDF params + the two
    /// OOB-shareable public keys. (Account-level NATIVE custody of the KDF params — so they never round-trip
    /// through the webview — is the F6 follow-up; for now the caller persists them as the wasm worker does.)
    ///
    /// # Errors
    /// [`HostError::Vault`] if the member secret derivation fails.
    #[allow(clippy::unused_self)] // account-level today; becomes stateful when it persists native account custody (F6)
    pub fn provision_member(&self, passphrase: &Passphrase) -> Result<MemberAccount, HostError> {
        let m = openom_vault::sharing::provision_member(passphrase)?;
        Ok(MemberAccount {
            kdf_params: m.kdf_params,
            author_public_key: m.author_public_key,
            hpke_public_key: m.hpke_public_key,
        })
    }

    /// Admit an OOB-verified `member` to a shared tree (owner action): produce a new keyring revision that
    /// HPKE-wraps the tree DEK to the joiner + records them (the shared `sharing::add_member` math), RE-OPEN the
    /// owner's running core on that shared keyring (a solo→shared transition — the solo sealer doesn't sign, so
    /// a signing sealer + a §B3 resolver are installed), and swap it IN PLACE under the per-doc lock held for
    /// the whole op (so no concurrent sync folds/seals against a mid-change core — design-review F1/F3). The
    /// keyring + watermark are committed natively only AFTER the re-open succeeds (candidate-core-before-commit,
    /// F9). Returns the opaque keyring revision the webview PUBLISHES (keyring FIRST, then the advisory summary,
    /// OPE-293 add ordering). Publish-pending durability is the follow-up shared with `remove_member` (F1/Q3).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the owner tree isn't open; [`HostError::NoKeyring`] if none is stored;
    /// [`HostError::Vault`] on a wrong owner passphrase / bad joiner key / unauthorized add; [`HostError::Core`]
    /// on the re-open / resolver / hydrate; [`HostError::Store`] on a store fault.
    pub fn add_member(
        &self,
        doc: &str,
        tree_id: &[u8],
        owner_member_id: &str,
        owner_passphrase: &Passphrase,
        member: &MemberToAdd,
    ) -> Result<AddedMember, HostError> {
        // Hold the owner core's per-doc lock across the WHOLE op — a concurrent sync/session op that grabbed the
        // same Arc must not interleave with the keyring change + in-place re-open (design-review F1/F3).
        let handle = self.core(doc).ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let floor = openom_vault::sharing::chain_watermark_floor(
            &self.store.watermark(doc).map_err(HostError::Store)?,
        );
        let added = openom_vault::sharing::add_member(
            self.engine,
            &keyring,
            owner_passphrase,
            tree_id,
            owner_member_id,
            &fresh_replica()?,
            floor,
            &member.member_id,
            &member.role,
            &member.author_public_key,
            &member.hpke_public_key,
        )?;
        // Retain the new revision natively before building the resolver, so the §B3 look-behind can judge writes
        // under it after any future rotation (F5).
        self.retain_revision(
            doc,
            openom_vault::sharing::chain_watermark_floor(&added.watermark),
            &added.keyring,
        )?;
        // Candidate-core-before-commit (F9): re-open the owner on the shared keyring (fallible), install §B3
        // (over the retained revisions), and hydrate BEFORE persisting the new keyring — a failure leaves store
        // + core consistent.
        let re = openom_app_core::unlock(
            self.doc_store(doc)?,
            self.engine,
            owner_passphrase,
            tree_id,
            owner_member_id,
            &fresh_replica()?,
            &added.keyring,
            doc.to_string(),
        )?;
        let mut new_core = re.core;
        let resolver =
            openom_vault::resolver_from(self.engine, &added.keyring, &self.retained_revisions(doc)?)?;
        new_core.set_membership(resolver)?;
        new_core.bootstrap()?;
        self.store
            .commit_keyring(doc, &added.keyring, &added.watermark)
            .map_err(HostError::Store)?;
        *guard = new_core; // in-place swap under the held lock
        Ok(AddedMember { keyring: added.keyring })
    }

    /// Remove a member (owner action) with FORWARD-SECURE revocation: pin the departing member's landed history
    /// under the PRE-removal epoch (compact-before-remove — else a cold re-judging replica Drops it as a
    /// backdated forge, OPE-421 / F2), mint a fresh epoch the removed member can't reach via the shared
    /// `sharing::remove_member` math, re-open the owner's core under the NEW epoch (the old sealer seals under a
    /// dead epoch), author the self-heal cover over the removed member's stored history (dag; a no-op on a
    /// chain-retained tree), and swap it IN PLACE under the per-doc lock held for the WHOLE op (F1/F3 — no
    /// concurrent sync seals under the dead epoch). Keyring committed only AFTER the re-open succeeds (F9).
    ///
    /// The caller (webview) is responsible for pulling the departing member's writes first (a data sync with a
    /// compaction that UPLOADS the pinning snapshot BEFORE this rotation publishes) and, after this returns,
    /// publishing the ADVISORY summary FIRST, then the keyring, then a data sync to push the cover. Durable
    /// re-publish (a removed member keeps server access until the rotated keyring lands) is derived by the sync
    /// tick from local-head > server-head (F1/Q3), so it needs no marker here.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the tree isn't open; [`HostError::NoKeyring`] if none is stored;
    /// [`HostError::Vault`] on a wrong owner passphrase / removing the owner / unknown member / unauthorized;
    /// [`HostError::Core`] on the compact / re-open / cover; [`HostError::Store`] on a store fault.
    pub fn remove_member(
        &self,
        doc: &str,
        tree_id: &[u8],
        owner_member_id: &str,
        owner_passphrase: &Passphrase,
        remove_member_id: &str,
    ) -> Result<RemovedMember, HostError> {
        // Hold the owner core's per-doc lock across the WHOLE op (F1/F3).
        let handle = self.core(doc).ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let floor = openom_vault::sharing::chain_watermark_floor(
            &self.store.watermark(doc).map_err(HostError::Store)?,
        );

        // compact-before-remove (F2/OPE-421): fold any already-pulled departing writes + pin them into a
        // snapshot under the PRE-removal epoch, so the covered frontier vouches for their landed history. The
        // webview's prior sync pulls + uploads the snapshot; this keeps the local covered frontier current.
        // history_preserved is best-effort: false ⇒ nothing covered yet (removed before pulling).
        guard.fold()?;
        guard.compact()?;
        let history_preserved = !guard.subsumed_frontier().is_empty();

        let removed = openom_vault::sharing::remove_member(
            self.engine,
            &keyring,
            owner_passphrase,
            tree_id,
            owner_member_id,
            &fresh_replica()?,
            floor,
            remove_member_id,
        )?;
        // Retain the rotated revision natively before building the resolver, so the §B3 look-behind can judge the
        // departing member's PRE-rotation writes against the revision that governed them (F5 — without the prior
        // revisions retained, a pre-rotation write is Dropped as an unjudgeable backdated forge).
        self.retain_revision(
            doc,
            openom_vault::sharing::chain_watermark_floor(&removed.watermark),
            &removed.keyring,
        )?;
        // Candidate-core-before-commit (F9): re-open the owner under the NEW epoch (the old sealer is now stale),
        // install §B3 (over the retained revisions), hydrate, then author the self-heal cover.
        let re = openom_app_core::unlock(
            self.doc_store(doc)?,
            self.engine,
            owner_passphrase,
            tree_id,
            owner_member_id,
            &fresh_replica()?,
            &removed.keyring,
            doc.to_string(),
        )?;
        let mut new_core = re.core;
        let resolver =
            openom_vault::resolver_from(self.engine, &removed.keyring, &self.retained_revisions(doc)?)?;
        new_core.set_membership(resolver)?;
        new_core.bootstrap()?;
        new_core.author_cover()?; // dag self-heal over the removed member's stored history (no-op on chain)
        self.store
            .commit_keyring(doc, &removed.keyring, &removed.watermark)
            .map_err(HostError::Store)?;
        *guard = new_core; // in-place swap under the held lock
        Ok(RemovedMember { keyring: removed.keyring, history_preserved })
    }

    /// Rebuild `doc`'s engine from its durable local log — call once after [`unlock`](Self::unlock) on open,
    /// so a mint committed offline in a previous session is folded back in. (A re-open uses a FRESH replica id,
    /// so the previous session's entries are pulled as a peer rather than skipped as "our own".)
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] on a store/merge fault.
    pub fn bootstrap(&self, doc: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| Ok(c.bootstrap()?))
    }

    /// Buffer an identity-anchor mint into `doc`'s intention; [`commit`](Self::commit) seals + persists it.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Tree`] if the mint can't be canonicalized.
    pub fn assert_anchor(&self, doc: &str, id: &str, type_uri: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| Ok(c.tree_mut().assert_anchor(id, type_uri, now_millis())?))
    }

    /// Seal + persist `doc`'s buffered mint batch to its local store (advancing the log + head pointer).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if sealing/persisting fails.
    pub fn commit(&self, doc: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| Ok(c.commit()?))
    }

    /// Fold `doc`'s local store through the §B3 gate — merges own + peer writes into the projection. Returns
    /// how many entries folded.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] on a store read fault.
    pub fn fold(&self, doc: &str) -> Result<usize, HostError> {
        self.with_core(doc, |c| Ok(c.fold()?))
    }

    /// `doc`'s materialized read model as a JSON string (the webview renders it).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if the projection can't be serialized.
    pub fn project(&self, doc: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| Ok(c.project_json()?))
    }

    /// One sync tick against a caller-supplied remote snapshot: mirror the remote's objects into `doc`'s local
    /// store, fold/adopt them through the §B3 gate, maybe compact (when `compact_k > 0`), and return the
    /// objects the remote is missing (for the webview/host to PUT). The webview ferries the ciphertext + drives
    /// the fetch; the DEK, the fold, and the plaintext store stay native (Full-A). Returns `(uploads, folded)`.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] on a store/merge fault.
    pub fn sync(
        &self,
        doc: &str,
        remote: &[StoredObject],
        compact_k: u32,
    ) -> Result<(Vec<StoredObject>, usize), HostError> {
        self.with_core(doc, |c| Ok(c.sync_against(remote, compact_k)?))
    }

    /// The live core for `doc` (for the ops not yet surfaced as host methods), if it has been
    /// provisioned/unlocked this session.
    pub fn core(&self, doc: &str) -> Option<CoreHandle> {
        self.lock_cores().get(doc).cloned()
    }

    /// Run `f` against `doc`'s locked core (poison-tolerant).
    fn with_core<T>(
        &self,
        doc: &str,
        f: impl FnOnce(&mut AppCore<FsBlob>) -> Result<T, HostError>,
    ) -> Result<T, HostError> {
        let handle = self.core(doc).ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    fn register(&self, doc: &str, core: AppCore<FsBlob>) {
        self.lock_cores()
            .insert(doc.to_string(), Arc::new(Mutex::new(core)));
    }

    /// Lock the registry, recovering from a poisoned mutex (a panic in one op must not brick every later op —
    /// the map itself is not left in a torn state).
    fn lock_cores(&self) -> std::sync::MutexGuard<'_, CoreMap> {
        self.cores.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{AppCoreHost, HostError, VaultStore};
    use openom_crypto::{Passphrase, RecoveryCode};
    use openom_keyring_api::EngineKind;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    type Rows = HashMap<String, (Vec<u8>, Vec<u8>)>;

    /// An in-memory [`VaultStore`] fake — the same shape the durable `SQLite` impl backs.
    #[derive(Default)]
    struct MemStore {
        rows: Mutex<Rows>,
    }
    impl VaultStore for MemStore {
        fn load_keyring(&self, tree_key: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.rows.lock().unwrap().get(tree_key).map(|(k, _)| k.clone()))
        }
        fn watermark(&self, tree_key: &str) -> Result<Vec<u8>, String> {
            Ok(self.rows.lock().unwrap().get(tree_key).map(|(_, w)| w.clone()).unwrap_or_default())
        }
        fn commit_keyring(&self, tree_key: &str, anchor: &[u8], watermark: &[u8]) -> Result<(), String> {
            self.rows
                .lock()
                .unwrap()
                .insert(tree_key.to_string(), (anchor.to_vec(), watermark.to_vec()));
            Ok(())
        }
    }

    fn temp_dir() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "openom-host-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn provision_persists_the_keyring_natively_and_unlock_reads_it_not_from_the_webview() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [9u8; 16];

        let p = host.provision("doc-1", &tree_id, "acct-owner", &pass).unwrap();
        assert!(!p.recovery_code.is_empty(), "provision returns a recovery code to show the user");
        assert!(!p.did_key.is_empty(), "and the author did:key");
        // The keyring is persisted NATIVELY — in this model the webview never holds it.
        assert!(host.store().load_keyring("doc-1").unwrap().is_some(), "keyring persisted natively on provision");
        assert!(host.core("doc-1").is_some(), "the provisioned core is registered");

        // Unlock reads the keyring FROM THE NATIVE STORE — no webview-supplied anchor — and re-derives the same
        // identity. (This is the security boundary: an XSS calling unlock can't substitute a stale/forged
        // keyring, because the host ignores any client-supplied anchor and reads its own; the replica id is
        // host-minted, so the webview can't pin a fork either.)
        let u = host.unlock("doc-1", &tree_id, "acct-owner", &pass).unwrap();
        assert_eq!(u.did_key, p.did_key, "unlock re-derives the same identity from the native keyring");

        // A wrong passphrase is refused.
        assert!(matches!(
            host.unlock("doc-1", &tree_id, "acct-owner", &Passphrase::new(b"wrong".to_vec())),
            Err(HostError::Vault(_))
        ));
        // A tree the host has no keyring for can't be unlocked.
        assert!(matches!(
            host.unlock("doc-unknown", &tree_id, "acct-owner", &pass),
            Err(HostError::NoKeyring(_))
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    const PERSON: &str = "openom.org/core/person/v1";

    #[test]
    fn an_offline_mint_survives_a_native_re_open_under_a_fresh_replica() {
        // OPE-431: provision + mint + commit OFFLINE (no sync), then re-open the SAME tree and bootstrap — the
        // mint is recovered from the durable local store. The host MINTS a fresh replica id per open, so the
        // re-opened core pulls its own persisted entries as a peer rather than skipping them as "our own"
        // (reusing the same replica would skip them); push_delta already writes the local head pointer on commit.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [3u8; 16];

        host.provision("t", &tree_id, "acct-owner", &pass).unwrap();
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        assert!(host.project("t").unwrap().contains("pAlice"), "the source session projects its own mint");

        // Re-open (the durable keyring is read natively, a fresh replica is host-minted) + bootstrap.
        host.unlock("t", &tree_id, "acct-owner", &pass).unwrap();
        host.bootstrap("t").unwrap();
        assert!(
            host.project("t").unwrap().contains("pAlice"),
            "the offline mint survives a native re-open under a fresh replica"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_native_hosts_converge_through_a_shared_remote() {
        // The distributed path, all native: two hosts (two devices of the SAME owner, the keyring distributed
        // to each native store), one mints + pushes to a shared remote snapshot, the other pulls + folds it.
        let (dir_a, dir_b) = (temp_dir(), temp_dir());
        let host_a = AppCoreHost::new(MemStore::default(), &dir_a, EngineKind::Chain);
        let host_b = AppCoreHost::new(MemStore::default(), &dir_b, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [4u8; 16];

        host_a.provision("t", &tree_id, "owner", &pass).unwrap();
        // Device B: same owner, the keyring distributed to B's native store (B unlocks it natively). Each host
        // mints its own fresh replica id, so A's and B's cores are distinct peers.
        let keyring = host_a.store().load_keyring("t").unwrap().unwrap();
        host_b.store().commit_keyring("t", &keyring, &[]).unwrap();
        host_b.unlock("t", &tree_id, "owner", &pass).unwrap();

        // A mints, commits, and pushes to the shared remote (empty → all of A's objects are uploads).
        host_a.assert_anchor("t", "pAlice", PERSON).unwrap();
        host_a.commit("t").unwrap();
        let (remote, _folded) = host_a.sync("t", &[], 0).unwrap();
        assert!(!remote.is_empty(), "A has objects to push to the remote");

        // B pulls the remote + folds → converges on A's mint.
        host_b.sync("t", &remote, 0).unwrap();
        assert!(host_b.project("t").unwrap().contains("pAlice"), "B converges on A's mint via native sync");

        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }

    #[test]
    fn recover_re_keys_natively_and_the_new_passphrase_unlocks() {
        // Recovery loads the stored keyring + watermark from NATIVE custody (never a webview arg), re-keys under
        // a new passphrase using the provision recovery code, and persists the fresh keyring — so the new
        // passphrase unlocks and the old one no longer does.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [9u8; 16];
        let old = Passphrase::new(b"the old passphrase here".to_vec());
        let p = host.provision("t", &tree_id, "owner", &old).unwrap();

        let new = Passphrase::new(b"a brand new passphrase".to_vec());
        let r = host
            .recover("t", &tree_id, "owner", &RecoveryCode::new(p.recovery_code), &new)
            .unwrap();
        assert!(!r.recovery_code.is_empty(), "recovery rotates the recovery code");
        assert!(!r.did_key.is_empty(), "and yields the (freshly minted) owner identity");

        assert!(
            host.unlock("t", &tree_id, "owner", &new).is_ok(),
            "the new passphrase unlocks the re-keyed keyring from native custody"
        );
        assert!(
            host.unlock("t", &tree_id, "owner", &old).is_err(),
            "the old passphrase no longer unlocks"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn change_passphrase_re_wraps_natively_and_only_the_new_passphrase_unlocks() {
        // change-passphrase re-wraps the keyring under a new KEK (the DEK unchanged) and persists it natively —
        // so the new passphrase unlocks and the old one no longer does, with no re-open of the running core.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [12u8; 16];
        let a = Passphrase::new(b"the first passphrase here".to_vec());
        host.provision("t", &tree_id, "owner", &a).unwrap();

        let b = Passphrase::new(b"the second passphrase now".to_vec());
        let r = host.change_passphrase("t", &tree_id, "owner", &a, &b).unwrap();
        assert!(!r.recovery_code.is_empty(), "change-passphrase rotates the recovery code");

        assert!(
            host.unlock("t", &tree_id, "owner", &b).is_ok(),
            "the new passphrase unlocks the re-wrapped keyring"
        );
        assert!(
            host.unlock("t", &tree_id, "owner", &a).is_err(),
            "the old passphrase no longer unlocks"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_traversal_or_invalid_doc_id_is_refused_before_touching_the_filesystem() {
        // The webview supplies the doc id, so one that could escape data_dir (or is otherwise malformed) must be
        // rejected rather than joined onto the FsBlob path.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [1u8; 16];
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        for bad in ["../escape", "a/b", "a\\b", "..", ""] {
            assert!(
                matches!(host.provision(bad, &tree_id, "owner", &pass), Err(HostError::Store(_))),
                "the traversal/invalid doc id {bad:?} is refused"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn provision_member_mints_an_account_from_a_passphrase() {
        // The joining member's first step (before an owner admits them): stateless, no tree touched.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let m = host
            .provision_member(&Passphrase::new(b"a joining member passphrase".to_vec()))
            .unwrap();
        assert!(!m.kdf_params.is_empty(), "codec-encoded KDF params to persist + replay at unlock");
        assert!(!m.author_public_key.is_empty(), "the Ed25519 author key to hand the owner");
        assert!(!m.hpke_public_key.is_empty(), "the X25519 HPKE key to hand the owner");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn add_member_admits_a_joiner_and_re_opens_the_owner_core_in_place() {
        use super::MemberToAdd;
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let tree_id = [5u8; 16];
        host.provision("t", &tree_id, "owner", &owner_pass).unwrap();

        // A joiner mints their account OOB; the owner admits them.
        let joiner = host
            .provision_member(&Passphrase::new(b"the joiner passphrase".to_vec()))
            .unwrap();
        let member = MemberToAdd {
            member_id: "bob".into(),
            role: "editor".into(),
            author_public_key: joiner.author_public_key,
            hpke_public_key: joiner.hpke_public_key,
        };
        let added = host.add_member("t", &tree_id, "owner", &owner_pass, &member).unwrap();
        assert!(!added.keyring.is_empty(), "a new keyring revision to publish");
        assert!(
            host.store().load_keyring("t").unwrap().unwrap() == added.keyring,
            "the shared keyring is persisted natively"
        );

        // The owner core was re-opened IN PLACE on the shared keyring — it still mints + projects, proof it
        // came back as a signing, §B3-gated shared core (not the stale solo sealer).
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        assert!(
            host.project("t").unwrap().contains("pAlice"),
            "the re-opened shared owner core still writes + folds its own attributed mint"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_member_rotates_the_epoch_and_re_opens_the_owner_under_it() {
        use super::MemberToAdd;
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let tree_id = [6u8; 16];
        host.provision("t", &tree_id, "owner", &owner_pass).unwrap();

        // Share the tree, THEN mint (so the write is signed under the shared epoch, not the solo sealer).
        let joiner = host
            .provision_member(&Passphrase::new(b"the joiner passphrase".to_vec()))
            .unwrap();
        let bob = MemberToAdd {
            member_id: "bob".into(),
            role: "editor".into(),
            author_public_key: joiner.author_public_key,
            hpke_public_key: joiner.hpke_public_key,
        };
        let added = host.add_member("t", &tree_id, "owner", &owner_pass, &bob).unwrap();
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();

        // Remove bob: forward-secure rotation + owner re-open under the NEW epoch.
        let removed = host.remove_member("t", &tree_id, "owner", &owner_pass, "bob").unwrap();
        assert!(!removed.keyring.is_empty(), "a rotated keyring revision to publish");
        assert!(removed.keyring != added.keyring, "the removal rotated the keyring to a fresh epoch");
        assert!(
            host.store().load_keyring("t").unwrap().unwrap() == removed.keyring,
            "the rotated keyring is persisted natively"
        );

        // The owner core re-opened under the NEW epoch — it still writes, and prior + post-removal history both
        // project (proof the re-opened core signs under the fresh epoch and hydrated the pinned history).
        host.assert_anchor("t", "pCarol", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        let proj = host.project("t").unwrap();
        assert!(proj.contains("pCarol"), "post-removal owner write projects under the rotated epoch");
        assert!(proj.contains("pAlice"), "pre-removal history still projects after the rotation");
        std::fs::remove_dir_all(&dir).ok();
    }
}
