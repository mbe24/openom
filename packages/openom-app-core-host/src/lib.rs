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
use openom_crypto::Passphrase;
use openom_keyring_api::EngineKind;
use openom_vault_host::VaultStore;
use store_blob::FsBlob;

/// A live core: an `AppCore` behind its own `Mutex` (Tauri invokes race on a thread pool).
pub type CoreHandle = Arc<Mutex<AppCore<FsBlob>>>;
/// The per-doc registry, keyed by doc id.
type CoreMap = HashMap<String, CoreHandle>;

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
pub struct Provisioned {
    pub recovery_code: String,
    pub did_key: String,
}

/// The result of [`AppCoreHost::unlock`] — the core is registered in the host; the caller gets the author
/// identity + the four advisory repair flags.
// Four INDEPENDENT repair signals, mirroring the core's `Unlocked` — not a state enum.
#[allow(clippy::struct_excessive_bools)]
pub struct Unlocked {
    pub did_key: String,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
    pub needs_rrk_backfill: bool,
    pub write_epoch_unreachable: bool,
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

    /// This doc's local device store: a `FsBlob` under `data_dir/{doc}`.
    fn doc_store(&self, doc: &str) -> Result<FsBlob, HostError> {
        let dir = self.data_dir.join(doc);
        std::fs::create_dir_all(&dir).map_err(|e| HostError::Store(e.to_string()))?;
        Ok(FsBlob::new(dir))
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
        replica_id: &[u8],
        passphrase: &Passphrase,
    ) -> Result<Provisioned, HostError> {
        let p = openom_app_core::provision(
            self.doc_store(doc)?,
            self.engine,
            passphrase,
            tree_id,
            member_id,
            replica_id,
            doc.to_string(),
        )?;
        self.store
            .commit_keyring(doc, &p.keyring, &p.watermark)
            .map_err(HostError::Store)?;
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
        replica_id: &[u8],
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
            replica_id,
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
    use openom_crypto::Passphrase;
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
        let (tree_id, replica_id) = ([9u8; 16], [2u8; 16]);

        let p = host.provision("doc-1", &tree_id, "acct-owner", &replica_id, &pass).unwrap();
        assert!(!p.recovery_code.is_empty(), "provision returns a recovery code to show the user");
        assert!(!p.did_key.is_empty(), "and the author did:key");
        // The keyring is persisted NATIVELY — in this model the webview never holds it.
        assert!(host.store().load_keyring("doc-1").unwrap().is_some(), "keyring persisted natively on provision");
        assert!(host.core("doc-1").is_some(), "the provisioned core is registered");

        // Unlock reads the keyring FROM THE NATIVE STORE — no webview-supplied anchor — and re-derives the same
        // identity. (This is the security boundary: an XSS calling unlock can't substitute a stale/forged
        // keyring, because the host ignores any client-supplied anchor and reads its own.)
        let u = host.unlock("doc-1", &tree_id, "acct-owner", &replica_id, &pass).unwrap();
        assert_eq!(u.did_key, p.did_key, "unlock re-derives the same identity from the native keyring");

        // A wrong passphrase is refused.
        assert!(matches!(
            host.unlock("doc-1", &tree_id, "acct-owner", &replica_id, &Passphrase::new(b"wrong".to_vec())),
            Err(HostError::Vault(_))
        ));
        // A tree the host has no keyring for can't be unlocked.
        assert!(matches!(
            host.unlock("doc-unknown", &tree_id, "acct-owner", &replica_id, &pass),
            Err(HostError::NoKeyring(_))
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    const PERSON: &str = "openom.org/core/person/v1";

    #[test]
    fn an_offline_mint_survives_a_native_re_open_under_a_fresh_replica() {
        // OPE-431: provision + mint + commit OFFLINE (no sync), then re-open the SAME tree under a FRESH replica
        // id (as a returning device does) and bootstrap — the mint is recovered from the durable local store.
        // Reusing the SAME replica on re-open would skip its own persisted entries; a fresh replica pulls them
        // as a peer. push_delta already writes the local head pointer on commit, so nothing else is needed.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [3u8; 16];

        host.provision("t", &tree_id, "acct-owner", &[10u8; 16], &pass).unwrap();
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        assert!(host.project("t").unwrap().contains("pAlice"), "the source session projects its own mint");

        // Re-open under a FRESH replica (the durable keyring is read natively) + bootstrap.
        host.unlock("t", &tree_id, "acct-owner", &[11u8; 16], &pass).unwrap();
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

        host_a.provision("t", &tree_id, "owner", &[20u8; 16], &pass).unwrap();
        // Device B: same owner, the keyring distributed to B's native store (B unlocks it natively).
        let keyring = host_a.store().load_keyring("t").unwrap().unwrap();
        host_b.store().commit_keyring("t", &keyring, &[]).unwrap();
        host_b.unlock("t", &tree_id, "owner", &[21u8; 16], &pass).unwrap();

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
}
