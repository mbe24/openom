# openom-sealer

> The client DEK session — a stateful sealer holding the unlocked DEK, turning plaintext into
> wire-ready envelopes and back.

**Status:** built · client key-custody/session layer, load-bearing · plan/SERVER-DATA-FORMAT.md
§3, §16 + plan/design.sharing.md §4, §B3

**Last updated:** 2026-09-03

## What it is — and is not

The client-side DEK session: a stateful sealer holding the *unlocked* DEK, turning plaintext into
wire-ready `Envelope` bytes and back (`Sealer` / `SealerSet`). It wraps `openom-crypto` — the
AEAD/KDF/HPKE primitives — with the scope binding and chain-state threading those primitives don't
know about. **This crate is engine-free** (no keyring dependency), so envelope-only consumers like
`openom-sync` don't transitively rebuild the keyring engines.

The passphrase-driven keyring lifecycle that PRODUCES an unlocked DEK — `vault` (provision, unlock,
recover, change_passphrase, add/remove member, promote/demote co-owner), both engines' vaults, the
`AppVault` dispatch, and the browser `wasm` veneer — was extracted to the **`openom-vault`** crate
(OPE-279). That crate compiles to wasm32 with its `wasm` feature for the browser and runs natively
inside Tauri — one implementation, two bindings, so a web and a native
client can never disagree on how a blob was sealed.

It is **not** the source of truth for the log chain: the caller (JS `SealedStore` / the Tauri
command) owns `replica_counter`, `prev_ciphertext_hash`, `covers_through_seq` and passes them in
per call — retry means re-uploading the already-sealed bytes verbatim, never re-sealing, because a
fresh seal mints a fresh nonce under the same counter slot. It is not the keyring wire format or
its chain-verification primitives (`openom-keyring-chain` owns `sign_keyring` / `verify_keyring_any` /
`verify_walk`); this crate drives that mechanism through passphrase flows. And on the web tier the
unlocked DEK lives in wasm linear memory for the session's lifetime — a documented
weaker-isolation trade-off against native, where `openom-vault-host` keeps the session in Rust so
the DEK never enters the webview at all.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **SEALER-1** | `open_entry` checks the envelope's `(tree_id, key_id)` against the sealer's own scope *before* the AEAD — a blob for another tree is rejected structurally, not as a generic auth failure. | A misrouted or cross-tree blob fails with a precise error instead of an opaque one. | `tests::rejects_a_blob_from_another_tree`, `prop::another_trees_blob_is_rejected` |
| **SEALER-2** | `open_entry` checks the envelope's `EntryKind` before the AEAD; a proposal never opens as a delta, and vice versa. | Domain-separates the proposals channel from the append log at the type level. | `tests::rejects_the_wrong_kind`, `tests::round_trips_a_delta_and_a_proposal`, `prop::the_wrong_kind_is_rejected` |
| **SEALER-3** | `seal_entry` returns the `ciphertext_hash` of the envelope it just produced, and a later entry's header records the prior one's hash as `prev_ciphertext_hash`. | This is the chain link the caller threads between calls — get it wrong and the replica's chain forks. | `tests::returns_the_chain_hash_for_the_next_entry` |
| **SEALER-4** | Flipping any byte of a sealed envelope makes it fail to open. | The AEAD tag is actually being checked, not bypassed. | `tests::corrupted_ciphertext_fails_to_open` |
| **SEALER-5** | The default AEAD is XChaCha20-Poly1305; `with_aead` selects AES-256-GCM instead, and the choice is recorded in (and round-trips through) the header. | Snapshots can opt into the disciplined alternate without a second sealer implementation. | `tests::seals_under_aes_gcm_when_selected` |
| **SEALER-6** | Author attribution is opt-in: `with_author` makes `seal_entry` sign the entry and stamp `author_member_id` / `keyring_revision`; a sealer with no author leaves all three empty (V1 communal-DEK). | A single-owner tree stays unattributed; a shared tree gets per-entry provenance, and the two never get mixed up silently. | `tests::with_author_signs_and_attributes_the_entry` |
| **SEALER-17** | `open_entry` never panics on arbitrary/garbage bytes — only ever `Ok` or `Err`. | This is an entry point fed by an untrusted/partly-trusted server; a crash on malformed input is a denial-of-service bug independent of the cryptography. | `prop::opening_arbitrary_bytes_errors_never_panics` |

> **SEALER-7 … SEALER-16** were the passphrase-lifecycle invariants (provision/unlock/recover/
> change-passphrase, forward-secret removal, founder-gated administration). They moved to
> **`openom-vault`** with the lifecycle extraction (OPE-279) and now live there as **VAULT-1 … VAULT-7**.
> IDs are never renumbered, so this crate's table keeps the gap.

Run: `node scripts/cargo.mjs test -p openom-sealer` (from the repo root; on Windows cargo runs
under WSL2/Docker).

## Usage

```rust
use openom_crypto::generate_dek;
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_sealer::{EntryKind, SealContext, Sealer};

// Normally built by vault::provision / vault::unlock from a passphrase; shown here from an
// already-unwrapped DEK to keep the example self-contained.
let sealer = Sealer::from_unwrapped(
    1,
    generate_dek().unwrap().into_inner(),
    TreeId::new(b"tree-uuid-16byte".to_vec()),
    KeyId::new(b"epoch-0".to_vec()),
    ReplicaId::new(b"replica-0".to_vec()),
);

let ctx = SealContext::snapshot(1, Vec::new(), 0);
let out = sealer.seal_entry(&ctx, b"the family tree").unwrap();
assert_eq!(
    sealer.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(),
    b"the family tree"
);
```

Entry points: `Sealer` / `SealerSet` (seal/open one scope, or every reachable key epoch),
`SealContext` (the caller-owned chain state for one call), `EntryKind`, and `Sealer::from_unwrapped`
(build a session directly from an already-unwrapped DEK). The passphrase lifecycle that *produces* a
`SealerSet` — `provision` / `unlock` / `recover` / `change_passphrase` / member authoring — is
**`openom-vault`**, which builds on this crate; it is not here.

## Position

Sits directly above the two foundation crates it wraps: `openom-crypto` (AEAD/KDF/HPKE primitives) and
`openom-protocol` (the envelope + id types). It is **engine-free** — it carries no keyring dependency
(`openom-keyring-chain` is a `test-util` dev-dependency only, to mint author identities in tests), so
envelope-only consumers like `openom-sync` don't transitively rebuild the keyring engines. The keyring
vault + wasm veneer that consume it live in `openom-vault`. Full dependency graph: see
`packages/README.md`.
