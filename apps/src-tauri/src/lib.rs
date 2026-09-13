#![doc = include_str!("../README.md")]

use std::sync::Arc;

use openom_app_core_host::{AppCoreHost, PassphraseChanged, Provisioned, Recovered, Unlocked};
use openom_crypto::{Passphrase, RecoveryCode};
use openom_keyring_api::EngineKind;
use openom_vault_host::sqlite::SqliteVaultStore;
use openom_vault_host::VaultStore;
use tauri::{Manager, State};

/// The one native session host (OPE-427 Full-A): it runs `openom-app-core` natively — the DEK, the claim
/// engine, and each doc's local device store all live in this process — with the keyring anchor + anti-rollback
/// watermark held in a durable `SQLite` `VaultStore`. Every `#[command]` below is a thin wrapper over it.
type Host = Arc<AppCoreHost<SqliteVaultStore>>;

/// A stored object — `(key, ciphertext bytes)` — the webview↔host sync ferry unit (the host's `StoredObject`).
type StoredObject = (String, Vec<u8>);

/// Flatten a host error to a string for the webview. (A typed error-code channel — mapping
/// `HostError`/`VaultError` to stable codes the UI can branch on — is a follow-up; today the message is enough
/// for the shell's error surface.)
fn e(err: impl std::fmt::Display) -> String {
    err.to_string()
}

/// The keyring engine for newly provisioned trees (OPE-278), resolved at RUNTIME and owned by the custody host
/// in Rust — never taken from the (less-trusted) webview. Runtime, not `cfg`, on purpose: one binary can reach
/// more than one backend (managed Lambda, BYO Google Drive), so a future dual-engine world maps each backend to
/// its engine here without a rebuild. Existing trees already carry their own engine in the keyring, so this only
/// picks what to stamp on a NEW tree. Today every backend uses the chain engine; the hidden
/// `OPENOM_KEYRING_ENGINE=dag` override selects the dag keyring for bring-up. Same tag mapping (`EngineKind`'s
/// `FromStr`) as the web/wasm host, so the two can't drift.
fn keyring_engine() -> EngineKind {
    std::env::var("OPENOM_KEYRING_ENGINE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(EngineKind::Chain)
}

// --------------------------------------------------------------- lifecycle (Argon2id: async spawn_blocking)

/// Provision a fresh tree: the host opens a core over the native store, PERSISTS the keyring + watermark
/// natively, and registers the core. Returns the recovery code + author `did:key`.
#[tauri::command]
async fn core_provision(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member_id: String,
    passphrase: String,
) -> Result<Provisioned, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.provision(&doc, &tree_id, &member_id, &Passphrase::new(passphrase.into_bytes()))
            .map_err(e)
    })
    .await
    .map_err(e)?
}

/// Unlock an existing tree: the host loads the keyring FROM THE NATIVE STORE (never a webview argument — the
/// boundary that stops an XSS feeding a stale/forged keyring), opens the core, and registers it. The webview
/// then [`core_bootstrap`]s to fold back any mint committed offline in a previous session.
#[tauri::command]
async fn core_unlock(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member_id: String,
    passphrase: String,
) -> Result<Unlocked, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.unlock(&doc, &tree_id, &member_id, &Passphrase::new(passphrase.into_bytes()))
            .map_err(e)
    })
    .await
    .map_err(e)?
}

/// Recover owner access under a new passphrase using the recovery code: the host loads the stored keyring +
/// watermark from native custody, re-keys, PERSISTS the fresh keyring, and registers the new core. Returns the
/// rotated recovery code + the (freshly minted) owner identity.
#[tauri::command]
async fn core_recover(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member_id: String,
    recovery_code: String,
    new_passphrase: String,
) -> Result<Recovered, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.recover(
            &doc,
            &tree_id,
            &member_id,
            &RecoveryCode::new(recovery_code),
            &Passphrase::new(new_passphrase.into_bytes()),
        )
        .map_err(e)
    })
    .await
    .map_err(e)?
}

/// Change the passphrase: the host loads the stored keyring + watermark, re-wraps under the new passphrase, and
/// PERSISTS the fresh keyring natively. The DEK is unchanged, so the running core keeps working. Returns the
/// rotated recovery code.
#[tauri::command]
async fn core_change_passphrase(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member_id: String,
    old_passphrase: String,
    new_passphrase: String,
) -> Result<PassphraseChanged, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.change_passphrase(
            &doc,
            &tree_id,
            &member_id,
            &Passphrase::new(old_passphrase.into_bytes()),
            &Passphrase::new(new_passphrase.into_bytes()),
        )
        .map_err(e)
    })
    .await
    .map_err(e)?
}

// --------------------------------------------------------------- session ops (cheap: sync is fine)

/// Whether a keyring is already stored natively for `doc` (the shell's "provision vs unlock" fork).
#[tauri::command]
fn core_has_keyring(state: State<'_, Host>, doc: String) -> Result<bool, String> {
    state.store().load_keyring(&doc).map(|k| k.is_some()).map_err(e)
}

/// Rebuild `doc`'s engine from its durable local log — call once after [`core_unlock`] on open.
#[tauri::command]
fn core_bootstrap(state: State<'_, Host>, doc: String) -> Result<(), String> {
    state.bootstrap(&doc).map_err(e)
}

/// Buffer an identity-anchor mint into `doc`'s intention; [`core_commit`] seals + persists it.
#[tauri::command]
fn core_assert_anchor(
    state: State<'_, Host>,
    doc: String,
    id: String,
    type_uri: String,
) -> Result<(), String> {
    state.assert_anchor(&doc, &id, &type_uri).map_err(e)
}

/// Seal + persist `doc`'s buffered mint batch to its local store.
#[tauri::command]
fn core_commit(state: State<'_, Host>, doc: String) -> Result<(), String> {
    state.commit(&doc).map_err(e)
}

/// Fold `doc`'s local store through the §B3 gate; returns how many entries folded.
#[tauri::command]
fn core_fold(state: State<'_, Host>, doc: String) -> Result<usize, String> {
    state.fold(&doc).map_err(e)
}

/// `doc`'s materialized read model as a JSON string (the webview renders it).
#[tauri::command]
fn core_project(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.project(&doc).map_err(e)
}

/// One sync tick against a remote snapshot the webview fetched: the host mirrors it into `doc`'s local store,
/// folds/adopts through the §B3 gate, maybe compacts (when `compact_k > 0`), and returns the objects the remote
/// is missing (for the webview to PUT) plus how many folded. The webview ferries ciphertext + drives the fetch;
/// the DEK, the fold, and the plaintext store stay native.
#[tauri::command]
fn core_sync(
    state: State<'_, Host>,
    doc: String,
    remote: Vec<StoredObject>,
    compact_k: u32,
) -> Result<(Vec<StoredObject>, usize), String> {
    state.sync(&doc, &remote, compact_k).map_err(e)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // The app data dir holds the durable keyring/watermark store (vault.sqlite); each doc's local
            // device store is a FsBlob rooted under docs/{doc}. Kept separate so a copied/restored tree can't
            // drag the anti-rollback watermark with it.
            let dir = app.path().app_data_dir().expect("app data dir");
            std::fs::create_dir_all(&dir).ok();
            let vault = SqliteVaultStore::open(dir.join("vault.sqlite")).expect("open vault store");
            let host = AppCoreHost::new(vault, dir.join("docs"), keyring_engine());
            app.manage(Arc::new(host));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            core_has_keyring,
            core_provision,
            core_unlock,
            core_recover,
            core_change_passphrase,
            core_bootstrap,
            core_assert_anchor,
            core_commit,
            core_fold,
            core_project,
            core_sync
        ])
        .run(tauri::generate_context!())
        .expect("error while running openom");
}
