#![doc = include_str!("../README.md")]

use std::sync::Arc;

use openom_app_core_host::{
    AddedMember, AppCoreHost, MemberAccount, MemberToAdd, MemberUnlocked, PassphraseChanged,
    Provisioned, Recovered, RemovedMember, RoleChanged, Unlocked,
};
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

/// Mint a joining member's account from their passphrase (stateless): returns the KDF params to persist + the
/// two OOB-shareable public keys the owner needs to admit them. Argon2id, so `spawn_blocking`.
#[tauri::command]
async fn core_provision_member(
    state: State<'_, Host>,
    passphrase: String,
) -> Result<MemberAccount, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.provision_member(&Passphrase::new(passphrase.into_bytes())).map_err(e)
    })
    .await
    .map_err(e)?
}

/// Admit an OOB-verified member to a shared tree (owner action): the host produces the new keyring revision,
/// re-opens the owner core in place on the shared keyring, and persists it natively. Returns the opaque keyring
/// revision the webview PUBLISHES (keyring first, then the advisory summary). Argon2id (re-open), so
/// `spawn_blocking`.
#[tauri::command]
async fn core_add_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    owner_member_id: String,
    owner_passphrase: String,
    member: MemberToAdd,
) -> Result<AddedMember, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.add_member(
            &doc,
            &tree_id,
            &owner_member_id,
            &Passphrase::new(owner_passphrase.into_bytes()),
            &member,
        )
        .map_err(e)
    })
    .await
    .map_err(e)?
}

/// Remove a member (owner action) with forward-secure revocation: the host pins the departing member's history,
/// rotates the epoch, re-opens the owner core under it in place, and persists it natively. Returns the opaque
/// rotated keyring for the webview to publish (advisory summary FIRST, then keyring, then a data sync to push
/// the cover) + whether the history was pinned. Argon2id (re-open), so `spawn_blocking`.
#[tauri::command]
async fn core_remove_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    owner_member_id: String,
    owner_passphrase: String,
    remove_member_id: String,
) -> Result<RemovedMember, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.remove_member(
            &doc,
            &tree_id,
            &owner_member_id,
            &Passphrase::new(owner_passphrase.into_bytes()),
            &remove_member_id,
        )
        .map_err(e)
    })
    .await
    .map_err(e)?
}

/// Change a member's role (owner action): promote to co-owner or demote. No epoch rotation — the host refreshes
/// the owner core's §B3 resolver in place and persists the new keyring. Returns the opaque keyring for the
/// webview to publish (promote keyring-first, demote advisory-first) + whether it was a demote. Argon2id, so
/// `spawn_blocking`.
#[tauri::command]
async fn core_change_role(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    owner_member_id: String,
    owner_passphrase: String,
    target_member_id: String,
    new_role: String,
) -> Result<RoleChanged, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.change_role(
            &doc,
            &tree_id,
            &owner_member_id,
            &Passphrase::new(owner_passphrase.into_bytes()),
            &target_member_id,
            &new_role,
        )
        .map_err(e)
    })
    .await
    .map_err(e)?
}

/// A joining member's first open: the host verifies the fetched keyring history against the OOB pin, unlocks at
/// the verified head, and establishes native custody (member context + keyring + retention). `hops` is the
/// framed keyring history the webview fetched; trusted signers are derived from the verified walk, never passed.
/// Argon2id, so `spawn_blocking`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri invoke convention: the flat argument list IS the JS calling shape
async fn core_join_as_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member_id: String,
    passphrase: String,
    member_kdf_params: Vec<u8>,
    hops: Vec<u8>,
    pinned_revision: u32,
    pinned_hash: Vec<u8>,
) -> Result<MemberUnlocked, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.join_as_member(
            &doc,
            &tree_id,
            &member_id,
            &Passphrase::new(passphrase.into_bytes()),
            &member_kdf_params,
            &hops,
            pinned_revision,
            &pinned_hash,
        )
        .map_err(e)
    })
    .await
    .map_err(e)?
}

/// Re-open a shared tree as a member on a device that already joined: the host loads the keyring + member
/// context from native custody (no webview trust inputs) and unlocks. Argon2id, so `spawn_blocking`.
#[tauri::command]
async fn core_unlock_as_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member_id: String,
    passphrase: String,
) -> Result<MemberUnlocked, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.unlock_as_member(&doc, &tree_id, &member_id, &Passphrase::new(passphrase.into_bytes()))
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

// ---- claim edits (buffered into the intention; core_commit seals them) ----

#[tauri::command]
fn core_assert_claim(
    state: State<'_, Host>,
    doc: String,
    target: String,
    predicate: String,
    value_json: String,
) -> Result<(), String> {
    state.assert_claim(&doc, &target, &predicate, &value_json).map_err(e)
}

#[tauri::command]
fn core_supersede_claim(
    state: State<'_, Host>,
    doc: String,
    prior: String,
    target: String,
    predicate: String,
    value_json: String,
) -> Result<(), String> {
    state.supersede_claim(&doc, &prior, &target, &predicate, &value_json).map_err(e)
}

#[tauri::command]
fn core_remove_record(state: State<'_, Host>, doc: String, target: String) -> Result<String, String> {
    state.remove_record(&doc, &target).map_err(e)
}

#[tauri::command]
fn core_revoke(state: State<'_, Host>, doc: String, removal_op_id: String) -> Result<(), String> {
    state.revoke(&doc, &removal_op_id).map_err(e)
}

#[tauri::command]
fn core_reset(state: State<'_, Host>, doc: String) -> Result<(), String> {
    state.reset(&doc).map_err(e)
}

#[tauri::command]
fn core_set_moderators(state: State<'_, Host>, doc: String, moderators: Vec<String>) -> Result<(), String> {
    state.set_moderators(&doc, moderators).map_err(e)
}

#[tauri::command]
fn core_close(state: State<'_, Host>, doc: String) {
    state.close(&doc);
}

// ---- reads (JSON strings the webview parses, as the wasm veneer returns) ----

#[tauri::command]
fn core_oplog(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.oplog(&doc).map_err(e)
}

#[tauri::command]
fn core_live_records(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.live_records(&doc).map_err(e)
}

#[tauri::command]
fn core_live_claims_of(
    state: State<'_, Host>,
    doc: String,
    target: String,
    predicate: String,
) -> Result<String, String> {
    state.live_claims_of(&doc, &target, &predicate).map_err(e)
}

#[tauri::command]
fn core_live_claims_of_any(state: State<'_, Host>, doc: String, target: String) -> Result<String, String> {
    state.live_claims_of_any(&doc, &target).map_err(e)
}

#[tauri::command]
fn core_resolve_id(state: State<'_, Host>, doc: String, anchor: String) -> Result<Option<String>, String> {
    state.resolve_id(&doc, &anchor).map_err(e)
}

#[tauri::command]
fn core_pending_count(state: State<'_, Host>, doc: String) -> Result<usize, String> {
    state.pending_count(&doc).map_err(e)
}

#[tauri::command]
fn core_anomalies(state: State<'_, Host>, doc: String) -> Result<usize, String> {
    state.anomalies(&doc).map_err(e)
}

// ---- soft-removal review queue (OPE-426) ----

#[tauri::command]
fn core_pending_reviews(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.pending_reviews(&doc).map_err(e)
}

#[tauri::command]
fn core_approve_pending(
    state: State<'_, Host>,
    doc: String,
    replica: String,
    counter: u64,
) -> Result<bool, String> {
    state.approve_pending(&doc, &replica, counter).map_err(e)
}

#[tauri::command]
fn core_discard_pending(
    state: State<'_, Host>,
    doc: String,
    replica: String,
    counter: u64,
) -> Result<bool, String> {
    state.discard_pending(&doc, &replica, counter).map_err(e)
}

/// Adopt newer keyring revisions the webview fetched (a member/device keyring sync): the host validates the
/// successor `hops` against the stored anchor, persists + retains them, adopts any rotated epoch on the running
/// core (via the retained member secret), and refreshes its §B3 resolver. No Argon2 (pure verification), so a
/// sync command.
#[tauri::command]
fn core_sync_keyring(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    hops: Vec<u8>,
) -> Result<(), String> {
    state.sync_keyring(&doc, &tree_id, &hops).map_err(e)
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
            core_provision_member,
            core_add_member,
            core_remove_member,
            core_change_role,
            core_join_as_member,
            core_unlock_as_member,
            core_bootstrap,
            core_assert_anchor,
            core_commit,
            core_fold,
            core_project,
            core_assert_claim,
            core_supersede_claim,
            core_remove_record,
            core_revoke,
            core_reset,
            core_set_moderators,
            core_close,
            core_oplog,
            core_live_records,
            core_live_claims_of,
            core_live_claims_of_any,
            core_resolve_id,
            core_pending_count,
            core_anomalies,
            core_pending_reviews,
            core_approve_pending,
            core_discard_pending,
            core_sync_keyring,
            core_sync
        ])
        .run(tauri::generate_context!())
        .expect("error while running openom");
}
