# openom-sealer

> The client sealer — a stateful session holding the unlocked DEK, plus the passphrase-driven
> keyring lifecycle that unlocks it.

**Status:** built · client key-custody/session layer, load-bearing · plan/SERVER-DATA-FORMAT.md
§3, §16 + plan/design.sharing.md §4, §B3

**Last updated:** 2026-08-25

## What it is — and is not

The client-side sealer: a stateful session holding the *unlocked* DEK, turning plaintext into
wire-ready `Envelope` bytes and back (`Sealer` / `SealerSet`), plus the full passphrase-driven
keyring lifecycle that produces that unlocked DEK (`vault`: provision, unlock, recover,
change_passphrase, add/remove member, promote/demote co-owner). It wraps `openom-crypto` — the
AEAD/KDF/HPKE primitives — with the scope binding, chain-state threading, and multi-signer keyring
mechanics those primitives don't know about. One pure-Rust core runs natively inside Tauri and,
compiled to wasm32 with the `wasm` feature, inside the browser through the `wasm` veneer
(`WasmSealer`, `provision`, `unlock`, …) — one implementation, two bindings, so a web and a native
client can never disagree on how a blob was sealed.

It is **not** the source of truth for the log chain: the caller (JS `SealedStore` / the Tauri
command) owns `replica_counter`, `prev_ciphertext_hash`, `covers_through_seq` and passes them in
per call — retry means re-uploading the already-sealed bytes verbatim, never re-sealing, because a
fresh seal mints a fresh nonce under the same counter slot. It is not the keyring wire format or
its chain-verification primitives (`openom-keyring` owns `sign_keyring` / `verify_keyring_any` /
`verify_walk`); this crate drives that mechanism through passphrase flows. And on the web tier the
unlocked DEK lives in wasm linear memory for the session's lifetime — a documented
weaker-isolation trade-off against native, where `openom-vault-host` keeps the session in Rust so
the DEK never enters the webview at all.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **SEALER-1** | `open_entry` checks the envelope's `(tree_id, key_id)` against the sealer's own scope *before* the AEAD — a blob for another tree is rejected structurally, not as a generic auth failure. | A misrouted or cross-tree blob fails with a precise error instead of an opaque one. | `tests::rejects_a_blob_from_another_tree`, `prop::another_trees_blob_is_rejected` |
| **SEALER-2** | `open_entry` checks the envelope's `EntryKind` before the AEAD; a proposal never opens as a delta, and vice versa. | Domain-separates the proposals channel from the append log at the type level. | `tests::rejects_the_wrong_kind`, `tests::round_trips_a_treelog_delta_and_a_proposal`, `prop::the_wrong_kind_is_rejected` |
| **SEALER-3** | `seal_entry` returns the `ciphertext_hash` of the envelope it just produced, and a later entry's header records the prior one's hash as `prev_ciphertext_hash`. | This is the chain link the caller threads between calls — get it wrong and the replica's chain forks. | `tests::returns_the_chain_hash_for_the_next_entry` |
| **SEALER-4** | Flipping any byte of a sealed envelope makes it fail to open. | The AEAD tag is actually being checked, not bypassed. | `tests::corrupted_ciphertext_fails_to_open` |
| **SEALER-5** | The default AEAD is XChaCha20-Poly1305; `with_aead` selects AES-256-GCM instead, and the choice is recorded in (and round-trips through) the header. | Snapshots can opt into the disciplined alternate without a second sealer implementation. | `tests::seals_under_aes_gcm_when_selected` |
| **SEALER-6** | Author attribution is opt-in: `with_author` makes `seal_entry` sign the entry and stamp `author_member_id` / `keyring_revision`; a sealer with no author leaves all three empty (V1 communal-DEK). | A single-owner tree stays unattributed; a shared tree gets per-entry provenance, and the two never get mixed up silently. | `tests::with_author_signs_and_attributes_the_entry` |
| **SEALER-7** | `provision` then `unlock` from the keyring bytes + passphrase alone — on a second, independent replica — reaches the identical DEK and opens what the first replica sealed. | This is the whole point of a passphrase-derived KEK: a new device joins from the passphrase, not a copied key file. | `vault::tests::provision_then_unlock_on_another_device_opens_the_same_data` |
| **SEALER-8** | `unlock`, `change_passphrase`, and `recover` all fail on the wrong credential (wrong passphrase, wrong recovery code). | The keyring is otherwise a public-ish blob; the credential is the only thing standing between it and the DEK. | `vault::tests::wrong_passphrase_is_rejected`, `vault::tests::change_passphrase_with_the_wrong_old_passphrase_fails`, `vault::tests::recover_with_the_wrong_code_fails` |
| **SEALER-9** | A keyring's `tree_id` is *checked* against the caller's own expected `tree_id` and refused on mismatch — never trusted as the AAD input itself. | Keeps "the AEAD binds tree_id" from being circular: the trusted value always comes from the caller, not the untrusted document. | `vault::tests::a_keyring_for_another_tree_is_refused` |
| **SEALER-10** | Argon2id `kdf_params` read from an unverified keyring are range-checked and refused outside the runnable window, before Argon2id ever runs. | A hostile keyring can't OOM/CPU-burn the client before any signature is even checked. | `vault::tests::absurd_kdf_params_are_rejected_before_running_argon2id` |
| **SEALER-11** | On `recover` (which has no signature to catch this), a served `revision` below the caller's watermark is refused before unwrapping, and a poisoned revision can't overflow `u32`. | Recovery's AEAD tag is the only authentication it has; the revision itself must still be rollback- and overflow-safe. | `vault::tests::recover_refuses_a_revision_below_the_watermark`, `vault::tests::recover_guards_against_revision_overflow` |
| **SEALER-12** | `remove_member` (owner or co-owner) mints a fresh epoch reachable only by the owner and the remaining members; the removed member holds no wrap into it and cannot unlock past that point. | Forward secrecy: removal actually revokes future access, not just the member-list entry. | `vault::tests::removing_a_member_re_keys_and_denies_them_new_content`, `vault::tests::a_co_owner_removes_a_member_forward_securely` |
| **SEALER-13** | A signer-set change (promoting/demoting a co-owner) only verifies under the founder's own signature — a co-owner's signature on the same bytes is not sufficient. | Any-of signing covers ordinary edits; who may administer at all is a stricter, founder-gated fact. | `vault::tests::a_signer_set_change_not_signed_by_the_founder_is_rejected` |
| **SEALER-14** | An ordinary member can't add or remove members; a co-owner may remove an ordinary member but not another signer (co-owner or founder). | The any-of administration model has a floor (ordinary members) and a ceiling (signers) it must not cross. | `vault::tests::an_ordinary_member_cannot_administer`, `vault::tests::a_co_owner_cannot_remove_a_signer` |
| **SEALER-15** | The owner/founder can never be removed via `remove_member`. | They're the keyring's root of trust; removing them has no successor to sign the result. | `vault::tests::the_owner_cannot_be_removed_and_a_non_member_is_rejected` |
| **SEALER-16** | `recover` and `change_passphrase` splice only the founder's own slot — every existing member, epoch, and co-owner signer survives both operations unchanged. | A credential-recovery path that silently dropped co-owners or members would be a worse bug than the credential loss it's fixing. | `vault::tests::recover_preserves_a_co_owner_signer_and_their_access`, `vault::tests::change_passphrase_preserves_a_co_owner_and_bridges_their_trust` |
| **SEALER-17** | `open_entry`, `vault::unlock`, and `vault::recover` never panic on arbitrary/garbage bytes — only ever `Ok` or `Err`. | These are the exact entry points fed by an untrusted/partly-trusted server; a crash on malformed input is a denial-of-service bug independent of the cryptography. | `prop::opening_arbitrary_bytes_errors_never_panics`, `prop::unlock_on_arbitrary_bytes_never_panics`, `prop::recover_on_arbitrary_bytes_never_panics` |

Run: `node scripts/cargo.mjs test -p openom-sealer` (from the repo root; on Windows cargo runs
under WSL2/Docker).

## Usage

```rust
use openom_crypto::generate_dek;
use openom_sealer::{EntryKind, SealContext, Sealer};

// Normally built by vault::provision / vault::unlock from a passphrase; shown here from an
// already-unwrapped DEK to keep the example self-contained.
let sealer = Sealer::from_unwrapped(
    1,
    generate_dek().unwrap().into_inner(),
    b"tree-uuid-16byte".to_vec(),
    b"epoch-0".to_vec(),
    b"replica-0".to_vec(),
);

let ctx = SealContext::snapshot(1, Vec::new(), 0);
let out = sealer.seal_entry(&ctx, b"the family tree").unwrap();
assert_eq!(
    sealer.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(),
    b"the family tree"
);
```

Entry points: `Sealer` / `SealerSet` (seal/open one scope, or every reachable key epoch) and
`SealContext` (the caller-owned chain state for one call). The `vault` module is the passphrase
lifecycle that builds a `SealerSet`: `provision`, `unlock`, `recover`, `change_passphrase`,
`provision_member` / `unlock_as_member`, `add_member` / `remove_member` (and their
`_as_co_owner` variants), `add_co_owner` / `remove_co_owner`. Behind `--features wasm`, the
`wasm` module re-exports the same operations to JS as `WasmSealer` plus free functions
(`provision`, `unlock`, `acceptRemoteKeyring`, `verifyEntry`, …) — the JS-facing surface consumed
by `apps/app/src/core/sealer/`.

## Position

Sits directly above the two foundation crates it wraps: `openom-crypto` (AEAD/KDF/HPKE
primitives) and `openom-keyring` (chain verification, signing). Consumed by the web app through
the `wasm` feature and by the Tauri native app directly. Full dependency graph: see
`packages/README.md`.
