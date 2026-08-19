//! The Tauri command surface. Two managed states:
//!   - `AppStore`: opaque ciphertext persistence (the doc store), unchanged in spirit.
//!   - `Vault` = `Arc<VaultHost<..>>`: the key-custody host. The DEK lives in Rust and never
//!     crosses to the webview; JS gets an opaque `sealerId` handle back.
//!
//! The commands are THIN wrappers — all the substance (and its tests) live in
//! `openom-vault-host` / `journal`, which build without `tauri`. This file therefore can't
//! be `cargo test`-ed in the headless container (the `tauri` crate needs system webview libs);
//! it is verified by `tauri dev` / `cargo check` on a machine with the Tauri toolchain.
//!
//! The passphrase-bearing flows (provision/unlock/recover/change) run Argon2id, so they are
//! `async` + `spawn_blocking`: a Tauri v2 sync command runs on the main thread and would freeze
//! the UI and all IPC for the ~1s KDF. The cheap AEAD seal/open and the map ops stay sync.

use std::sync::Arc;

use journal::{sqlite::SqliteStore, Caps, DocStore, Snapshot, Update};
use openom_vault_host::sqlite::SqliteVaultStore;
use openom_vault_host::{
    AcceptedKeyring, CoOwnerChanged, MemberAdded, MemberProvisioned, MemberRemoved, Provisioned,
    Recovered, Rekeyed, Sealed, Unlocked, VaultError, VaultErrorCode, VaultHost,
};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

pub struct AppStore(pub Box<dyn DocStore>);
type Vault = Arc<VaultHost<SqliteVaultStore>>;

// ----------------------------------------------------------------- doc store (opaque bytes)

#[derive(Serialize)]
pub struct ReadResult {
    pub snapshot: Option<Snapshot>,
    pub updates: Vec<Update>, // Update = Vec<u8>: raw sealed envelopes
    pub cursor: u64,
    pub caps: Caps,
}

#[derive(Deserialize)]
pub struct AppendArgs {
    pub doc: String,
    pub updates: Vec<Update>,
}

#[tauri::command]
fn store_read(
    state: State<'_, AppStore>,
    doc: String,
    since: Option<u64>,
) -> Result<ReadResult, String> {
    let s = &state.0;
    let snapshot = s.read_snapshot(&doc).map_err(|e| e.to_string())?;
    let (updates, cursor) = s.read_updates(&doc, since).map_err(|e| e.to_string())?;
    Ok(ReadResult {
        snapshot,
        updates,
        cursor,
        caps: s.caps(),
    })
}

#[tauri::command]
fn store_append(state: State<'_, AppStore>, args: AppendArgs) -> Result<u64, String> {
    state
        .0
        .append(&args.doc, &args.updates)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn store_put_snapshot(
    state: State<'_, AppStore>,
    doc: String,
    bytes: Vec<u8>,
    expected: Option<String>,
) -> Result<String, String> {
    state
        .0
        .put_snapshot(&doc, &bytes, expected.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn store_list(state: State<'_, AppStore>) -> Result<Vec<String>, String> {
    state.0.list().map_err(|e| e.to_string())
}

#[tauri::command]
fn store_delete(state: State<'_, AppStore>, doc: String) -> Result<(), String> {
    state.0.delete(&doc).map_err(|e| e.to_string())
}

// ----------------------------------------------------------------- vault (passphrase lifecycle)

fn join_err(e: impl std::fmt::Display) -> VaultError {
    VaultError::new(VaultErrorCode::Internal, e.to_string())
}

#[tauri::command]
fn vault_has_keyring(state: State<'_, Vault>, tree_key: String) -> Result<bool, VaultError> {
    state.has_keyring(&tree_key)
}

#[tauri::command]
async fn vault_provision(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    passphrase: String,
    member_id: String,
) -> Result<Provisioned, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.provision(&tree_key, &tree_id, passphrase, &member_id)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_unlock(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    passphrase: String,
    member_id: String,
) -> Result<Unlocked, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.unlock(&tree_key, &tree_id, passphrase, &member_id)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_recover(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    recovery_code: String,
    new_passphrase: String,
    member_id: String,
) -> Result<Recovered, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.recover(
            &tree_key,
            &tree_id,
            recovery_code,
            new_passphrase,
            &member_id,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_change_passphrase(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    old_passphrase: String,
    new_passphrase: String,
    member_id: String,
) -> Result<Rekeyed, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.change_passphrase(
            &tree_key,
            &tree_id,
            old_passphrase,
            new_passphrase,
            &member_id,
        )
    })
    .await
    .map_err(join_err)?
}

// ----------------------------------------------------------------- sharing (Argon2id: async)

#[tauri::command]
async fn vault_provision_member(
    state: State<'_, Vault>,
    passphrase: String,
) -> Result<MemberProvisioned, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || host.provision_member(passphrase))
        .await
        .map_err(join_err)?
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn vault_add_member(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    owner_passphrase: String,
    owner_member_id: String,
    new_member_id: String,
    role: String,
    member_hpke_public: Vec<u8>,
    member_author_public: Vec<u8>,
) -> Result<MemberAdded, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.add_member(
            &tree_key,
            &tree_id,
            owner_passphrase,
            &owner_member_id,
            &new_member_id,
            &role,
            &member_hpke_public,
            &member_author_public,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_unlock_as_member(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    passphrase: String,
    member_kdf_params: Vec<u8>,
    member_id: String,
    trusted_signers: Vec<Vec<u8>>,
) -> Result<Unlocked, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.unlock_as_member(
            &tree_key,
            &tree_id,
            passphrase,
            &member_kdf_params,
            &member_id,
            trusted_signers,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_remove_member(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    owner_passphrase: String,
    owner_member_id: String,
    remove_member_id: String,
) -> Result<MemberRemoved, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.remove_member(
            &tree_key,
            &tree_id,
            owner_passphrase,
            &owner_member_id,
            &remove_member_id,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn vault_add_member_as_co_owner(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    passphrase: String,
    co_owner_kdf_params: Vec<u8>,
    co_owner_member_id: String,
    trusted_signers: Vec<Vec<u8>>,
    new_member_id: String,
    role: String,
    member_hpke_public: Vec<u8>,
    member_author_public: Vec<u8>,
) -> Result<MemberAdded, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.add_member_as_co_owner(
            &tree_key,
            &tree_id,
            passphrase,
            &co_owner_kdf_params,
            &co_owner_member_id,
            trusted_signers,
            &new_member_id,
            &role,
            &member_hpke_public,
            &member_author_public,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_remove_member_as_co_owner(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    passphrase: String,
    co_owner_kdf_params: Vec<u8>,
    co_owner_member_id: String,
    trusted_signers: Vec<Vec<u8>>,
    remove_member_id: String,
) -> Result<MemberRemoved, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.remove_member_as_co_owner(
            &tree_key,
            &tree_id,
            passphrase,
            &co_owner_kdf_params,
            &co_owner_member_id,
            trusted_signers,
            &remove_member_id,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_add_co_owner(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    founder_passphrase: String,
    founder_member_id: String,
    target_member_id: String,
) -> Result<CoOwnerChanged, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.add_co_owner(
            &tree_key,
            &tree_id,
            founder_passphrase,
            &founder_member_id,
            &target_member_id,
        )
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn vault_remove_co_owner(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    founder_passphrase: String,
    founder_member_id: String,
    target_member_id: String,
    new_role: String,
) -> Result<CoOwnerChanged, VaultError> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.remove_co_owner(
            &tree_key,
            &tree_id,
            founder_passphrase,
            &founder_member_id,
            &target_member_id,
            &new_role,
        )
    })
    .await
    .map_err(join_err)?
}

/// Accept a keyring run pulled from the network (the chain-walk read-side). Sync: it's pure
/// verification (signatures + hashes), no Argon2, so it won't stall the UI thread meaningfully.
#[tauri::command]
fn vault_accept_remote_keyring(
    state: State<'_, Vault>,
    tree_key: String,
    tree_id: Vec<u8>,
    hops: Vec<Vec<u8>>,
) -> Result<AcceptedKeyring, VaultError> {
    state.accept_remote_keyring(&tree_key, &tree_id, hops)
}

// ----------------------------------------------------------------- sealer (cheap: sync is fine)

#[tauri::command]
fn sealer_dev(state: State<'_, Vault>, tree_id: Vec<u8>) -> Result<Unlocked, VaultError> {
    state.dev(&tree_id)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn sealer_seal_entry(
    state: State<'_, Vault>,
    sealer_id: String,
    kind: String,
    format: String,
    compression: String,
    replica_counter: u64,
    prev_ciphertext_hash: Vec<u8>,
    covers_through_seq: u64,
    blob_id: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Sealed, VaultError> {
    state.seal_entry(
        &sealer_id,
        &kind,
        &format,
        &compression,
        replica_counter,
        prev_ciphertext_hash,
        covers_through_seq,
        blob_id,
        &plaintext,
    )
}

#[tauri::command]
fn sealer_open_entry(
    state: State<'_, Vault>,
    sealer_id: String,
    kind: String,
    envelope: Vec<u8>,
) -> Result<Vec<u8>, VaultError> {
    state.open_entry(&sealer_id, &kind, &envelope)
}

#[tauri::command]
fn sealer_lock(state: State<'_, Vault>, sealer_id: String) {
    state.lock(&sealer_id);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Two durable files in the app data dir: the tree ciphertext, and — kept separate so a
            // copied/restored tree can't drag the anti-rollback watermark with it — the keyring +
            // watermark.
            let dir = app.path().app_data_dir().expect("app data dir");
            std::fs::create_dir_all(&dir).ok();
            let tree = SqliteStore::open(dir.join("tree.sqlite")).expect("open tree store");
            app.manage(AppStore(Box::new(tree)));
            let vault = SqliteVaultStore::open(dir.join("vault.sqlite")).expect("open vault store");
            app.manage(Arc::new(VaultHost::new(vault)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            store_read,
            store_append,
            store_put_snapshot,
            store_list,
            store_delete,
            vault_has_keyring,
            vault_provision,
            vault_unlock,
            vault_recover,
            vault_change_passphrase,
            vault_provision_member,
            vault_add_member,
            vault_unlock_as_member,
            vault_remove_member,
            vault_add_member_as_co_owner,
            vault_remove_member_as_co_owner,
            vault_add_co_owner,
            vault_remove_co_owner,
            vault_accept_remote_keyring,
            sealer_dev,
            sealer_seal_entry,
            sealer_open_entry,
            sealer_lock
        ])
        .run(tauri::generate_context!())
        .expect("error while running openom");
}
