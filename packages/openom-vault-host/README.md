# openom-vault-host

> The native (Tauri) key-custody host — live Sealer sessions and keyring/watermark storage kept
> in Rust, so the DEK never crosses the invoke boundary into the webview.

**Status:** built · native (Tauri-only) key-custody host, load-bearing · no design doc (built
directly from `openom-sealer`'s `vault` lifecycle, one level higher)

**Last updated:** 2026-08-25

## What it is — and is not

On Tauri the DEK must never reach the webview, so the passphrase lifecycle
(provision/unlock/recover/change-passphrase), the sharing flows (add/remove member, promote/demote
co-owner), and the live `Sealer`/`SealerSet` sessions all live here, in a plain crate with no
`tauri` dependency and no webview — `cargo test`-able without a device. `#[tauri::command]`s are
thin wrappers that (de)serialize and call straight into `VaultHost`. The host also owns keyring +
watermark storage behind an injectable `VaultStore` trait, so a keyring-save and its watermark
advance land in one durable transaction, and key custody shares the ciphertext's durability domain
rather than the evictable webview one. The passphrase lifecycle (provision/unlock/recover/change)
routes through the engine-dispatch `AppVault` (chain or dag, an install-fixed preset), so its
anti-rollback and endorsement checks live inside the engine. The host still re-runs the
`openom-keyring-chain` chain-walk itself for the sharing flows: once as a self-check before persisting a
keyring its own membership flow just produced (`commit_transition`), and once against genuinely
untrusted network bytes (`accept_remote_keyring`) — those two paths are deliberately kept distinct
(see the Invariants below).

Every public method that could hand back a live session returns only an opaque `sealer_id` handle
plus public metadata (the opaque watermark, recovery code, public keys) — never key material; the DEK is
reachable only through `seal_entry`/`open_entry` against that handle inside the process. VAULT-2
below is the concrete evidence that this custody boundary is enforced under an adversarial
condition, not just by convention: on a caught rollback, the derived DEK (`Zeroizing`) is dropped
before it is ever registered, so it never becomes reachable through any handle at all.

It is **not** a Tauri crate: no `tauri` dependency, no `#[command]`s, no webview code — those live
in `apps/src-tauri` and just call this crate. It is **not** the crypto or chain-verification
primitives: AEAD/HPKE/KDF sealing is `openom-sealer`'s, and chain-walk verification
(`verify_transition` / `verify_reset` / `verify_walk`) is `openom-keyring-chain`'s — this crate is the
orchestration and storage-transaction layer above both. And it does not implement the snapshot/delta
replay-window (a separate sync-layer concern); the `VaultStore` seam here carries only the keyring
bytes and an engine-opaque watermark (chain = a 4-byte revision, dag = a frontier; the store never
interprets it). Errors cross as a stable `{ code, message }` `VaultError`
(a `VaultErrorCode` enum the JS side switches on), never a matchable string.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **VAULT-1** | `lock` frees one sealer, `clear` frees all, immediately: a freed `sealer_id` fails closed as `UnknownSealer` on the next call. | A locked vault leaves no lingering live handle a later call could still exploit. | `tests::provision_seal_lock_unlock_open_roundtrip`, `tests::clear_frees_every_sealer` |
| **VAULT-2** | `unlock` is a pure local read: it re-derives the DEK from the stored anchor without consulting or advancing the watermark, so it still succeeds when the local cursor has raced ahead of the anchor. | A transient desync between the saved keyring and its cursor can never lock a user out of their own offline vault; anti-rollback is enforced only where an attacker can reach — the sync path (VAULT-6) and `recover` (the stored watermark is its floor, checked inside the engine). | `tests::unlock_reads_the_local_anchor_without_a_floor_check` |
| **VAULT-3** | Any wrong-credential open (bad passphrase) surfaces as the single opaque `CryptoOpen` code. | Wrong-key, tampered, and corrupted ciphertext stay indistinguishable to the caller. | `tests::wrong_passphrase_is_crypto_open` |
| **VAULT-4** | `change_passphrase` and `recover` re-wrap the same DEK under new credentials — they never rotate it: content sealed before either operation still opens after. | A passphrase change or recovery can never silently orphan previously-sealed data. | `tests::change_passphrase_rotates_and_old_no_longer_opens`, `tests::recover_with_the_code_sets_a_new_passphrase` |
| **VAULT-5** | A keyring the host's own membership flow just produced is self-checked against the chain-walk (`verify_transition`) *before* it is persisted; a construction bug that would yield an unendorsed keyring is refused as `Internal` and nothing is written. | The host refuses to persist a keyring its own verifier would later reject — the fix is on us, never surfaced as a caller-facing error. | `tests::the_writer_self_check_refuses_an_unendorsed_keyring_and_persists_nothing` |
| **VAULT-6** | `accept_remote_keyring` validates an untrusted network-served run against the chain-walk before accepting it: a withheld hop or a rogue-signer injection is refused and the store stays untouched; a valid contiguous run commits the keyring and advances the watermark atomically. | A hostile or lagging server can't fork, roll back, or smuggle an unendorsed keyring into local trust state. | `tests::a_device_accepts_a_validated_remote_keyring_run`, `tests::a_withheld_hop_in_the_run_is_refused`, `tests::a_rogue_signer_in_a_remote_hop_is_refused_and_nothing_is_persisted` |
| **VAULT-7** | `remove_member` re-keys under a fresh epoch; the removed member holds no wrap into it and cannot unlock past that point, even with correct credentials. | Removal is forward-secure — it revokes future access, not just a member-list entry. | `tests::host_removes_a_member_and_denies_them_new_content` |
| **VAULT-8** | A co-owner administers members (`add_member_as_co_owner` / `remove_member_as_co_owner`) through the same host surface as the founder; an ordinary member cannot. | Any-of signing authority is enforced at the host boundary, not left to the caller to police. | `tests::a_co_owner_administers_members_through_the_host` |

Run: `node scripts/cargo.mjs test -p openom-vault-host` (from the repo root; on Windows cargo runs
under WSL2/Docker).

## Usage

```rust
use openom_vault_host::{VaultHost, VaultStore};
use std::collections::HashMap;
use std::sync::Mutex;

// A minimal in-memory VaultStore. A real Tauri host backs this with `sqlite::SqliteVaultStore`
// (behind the `sqlite` feature) instead.
#[derive(Default)]
struct MemStore {
    keyrings: Mutex<HashMap<String, Vec<u8>>>,
    watermarks: Mutex<HashMap<String, Vec<u8>>>,
}
impl VaultStore for MemStore {
    fn load_keyring(&self, tree_key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.keyrings.lock().unwrap().get(tree_key).cloned())
    }
    // The watermark is engine-OPAQUE bytes (the order check lives inside the engine); just persist + return.
    fn watermark(&self, tree_key: &str) -> Result<Vec<u8>, String> {
        Ok(self.watermarks.lock().unwrap().get(tree_key).cloned().unwrap_or_default())
    }
    fn commit_keyring(&self, tree_key: &str, anchor: &[u8], watermark: &[u8]) -> Result<(), String> {
        self.keyrings.lock().unwrap().insert(tree_key.to_string(), anchor.to_vec());
        self.watermarks.lock().unwrap().insert(tree_key.to_string(), watermark.to_vec());
        Ok(())
    }
}

let host = VaultHost::new(MemStore::default());
let tree_id = b"tree-uuid-16byte";

// Provision: a fresh DEK wrapped under a passphrase + a fresh recovery code, and its opaque watermark.
let p = host.provision("my-tree", tree_id, "correct horse".into(), "owner").unwrap();
assert!(!p.watermark.is_empty());

let sealed = host
    .seal_entry(
        &p.sealer_id, "snapshot", "openom-json", "none",
        0, Vec::new(), 0, Vec::new(), b"the family tree",
    )
    .unwrap();

// Lock frees the sealer; the handle is dead afterwards.
host.lock(&p.sealer_id);

// A fresh unlock re-derives the same DEK and opens data sealed before the lock.
let u = host.unlock("my-tree", tree_id, "correct horse".into(), "owner").unwrap();
assert_eq!(
    host.open_entry(&u.sealer_id, "snapshot", &sealed.envelope).unwrap(),
    b"the family tree"
);
```

Entry points: `VaultHost` (`provision`, `unlock`, `recover`, `change_passphrase`); sharing
(`provision_member`/`unlock_as_member`, `add_member`/`remove_member` and their `_as_co_owner`
variants, `add_co_owner`/`remove_co_owner`); sync (`accept_remote_keyring`, the read-side of the
keyring chain-walk over untrusted bytes); session ops (`seal_entry`, `open_entry`, `lock`,
`clear`); and `dev` (the well-known-key local-development sealer, no keyring). `VaultStore` is the
injectable storage seam; `sqlite::SqliteVaultStore` (behind the `sqlite` feature) is the durable
Tauri-side implementation.

## Position

Sits in the access-control/identity/custody layer, directly above `openom-sealer` (the live
session + passphrase lifecycle it drives) and `openom-keyring-chain` (the chain-walk it re-runs both as
a self-check and against the network); it is the Tauri-side counterpart to the web app's
`vault.js` + the worker's sealer registry, cut one level higher so the DEK stays out of the
webview entirely. Full dependency graph: see `packages/README.md`.
