# openom-crypto

> Shared symmetric crypto primitives — the exact same algorithms and parameters on client and server.

**Status:** built · foundation, load-bearing (client & server share this crate byte-for-byte) · plan/SERVER-DATA-FORMAT.md §4–§6, §16–§17
**Last updated:** 2026-08-25

## What it is — and is not

V1 is client-side zero-knowledge: the client seals the family tree before upload and the server
never holds a key. This crate is what keeps the two sides from ever disagreeing on how a blob was
sealed — same AEAD, same nonce sizes, same KDF, same wrap binding — because they link the identical
Rust crate (native on the server, wasm in the browser) instead of two hand-ported implementations.

It fixes the algorithm choices: **XChaCha20-Poly1305** is the default AEAD (192-bit random nonces,
so a long delta log under one DEK never hits AES-GCM's nonce-reuse footgun); **AES-256-GCM** is the
disciplined alternate; **Argon2id** turns a passphrase into a KEK; **HKDF-SHA256** splits one Argon2id
master into independent sibling keys (KEK, Ed25519 identity, X25519 HPKE keypair — `derive_root`);
**HPKE** (RFC 9180, DHKEM-X25519 + HKDF-SHA256 + ChaCha20Poly1305) wraps a DEK to a sharee's public
key. `seal`/`open` bind the *whole* protobuf `Header` as AAD internally, so the AAD encoder is never
exposed across the wasm-bindgen boundary and a JS twin can't drift from it.

It is **not** a general-purpose encryption toolkit: there is no plaintext-storage path, no key
lifecycle/session management (that's `openom-sealer` / `openom-vault-host`), and no network or
storage I/O. `CryptoError::Open`/`CryptoError::Hpke` are deliberately opaque — a bad key, a bad tag,
and a tampered header/context all collapse to the same error, so callers can't build an oracle out
of the failure reason, but this crate makes no formal, proven security claim beyond "the well-reviewed
dependencies (`chacha20poly1305`, `aes-gcm`, `argon2`, `hpke`, `ed25519-dalek`) are wired together
correctly and the wiring is tested." `DEV_KEY_ID`/`dev_dek()` exist so local dev can inspect payloads
under a fixed, non-secret key — the bytes are still real ciphertext, never plaintext — but *this crate
does not refuse the dev key in production*; that check lives at the call sites (`openom` server:
`log.rs`, `proposals.rs`, `trees.rs`) and is outside this crate's contract.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **CRYPTO-1** | `seal`/`open` and `seal_envelope`/`open_envelope` round-trip plaintext unchanged under both XChaCha20-Poly1305 and AES-256-GCM, for arbitrary plaintext (0–2048 bytes, proptest-generated). | The one thing an AEAD wrapper must never get wrong. | `seal::tests::xchacha_round_trip`, `seal::tests::aesgcm_round_trip`, `envelope::tests::round_trip_xchacha`, `envelope::tests::round_trip_aesgcm`, `prop::round_trips` |
| **CRYPTO-2** | The whole `Header` (including `version`) is bound as AAD — flipping any header field (checked with an arbitrary `replica_counter` bump), or opening under a different `version`, fails closed. | A tampered header can never be silently accepted alongside valid ciphertext. | `seal::tests::tampered_header_fails`, `seal::tests::version_is_bound_in_aad`, `prop::the_header_is_authenticated` |
| **CRYPTO-3** | A wrong key, a tampered ciphertext (incl. an arbitrary single flipped byte), or (at the envelope layer) a `ciphertext_hash` mismatch all fail as the single opaque `CryptoError::Open` — never a partial-success or distinguishing error. | No error-shape oracle for an attacker to probe. | `seal::tests::wrong_key_fails`, `seal::tests::tampered_ciphertext_fails`, `envelope::tests::wrong_dek_fails`, `envelope::tests::corrupted_ciphertext_fails`, `prop::a_flipped_ciphertext_byte_is_rejected`, `prop::the_wrong_key_is_rejected` |
| **CRYPTO-4** | Nonce length is checked against the selected AEAD (24 bytes XChaCha20 / 12 bytes AES-GCM) and an unsupported/unspecified AEAD is rejected — never silently truncated, padded, or defaulted. | A malformed header fails fast instead of being coerced into "working." | `seal::tests::wrong_nonce_length_errs`, `seal::tests::unspecified_aead_errs` |
| **CRYPTO-5** | `seal_envelope` mints a fresh random nonce every call; sealing identical plaintext twice under the same DEK never repeats a nonce or ciphertext. | Nonce reuse is the AEAD failure mode this crate exists to avoid. | `envelope::tests::nonces_are_fresh_per_seal` |
| **CRYPTO-6** | `derive_kek` (Argon2id) is deterministic in `(passphrase, params)` and sensitive to both — same inputs reproduce the same KEK; a different passphrase or a different salt always diverges. | A second device can join from the passphrase alone, and a KEK never coincides by accident. | `kdf::tests::deterministic_in_passphrase_and_params`, `kdf::tests::different_passphrase_differs`, `kdf::tests::different_salt_differs` |
| **CRYPTO-7** | `generate_dek`/`generate_salt` draw fresh, correctly-sized, non-repeating material from the OS/browser CSPRNG. | A generated DEK is never predictable or reused across trees. | `kdf::tests::generated_deks_are_random_and_sized` |
| **CRYPTO-8** | A DEK wrap (`wrap_dek`/`unwrap_dek`) binds the full `(tree_id, key_id, member_id, wrap_method, epoch)` context; unwrapping under a wrong KEK or any one changed context field fails, and the wrapped bytes are never the plaintext DEK. | A wrap can't be transplanted between members, epochs, or trees. | `wrap::tests::round_trip`, `wrap::tests::wrong_kek_fails`, `wrap::tests::transplant_across_context_fails`, `wrap::tests::wrapped_dek_is_not_plaintext` |
| **CRYPTO-9** | An HPKE wrap (`hpke_wrap_dek`/`hpke_unwrap_dek`, RFC 9180 base mode) opens only with the matching recipient secret key and the exact `info` context; a tampered ciphertext or a malformed public key is rejected, never silently accepted. | Lets a sharee who never knew the owner's passphrase still receive the tree key, without weakening the binding the symmetric wrap gets. | `hpke_wrap::tests::wrap_then_unwrap_round_trips`, `hpke_wrap::tests::the_wrong_member_secret_cannot_open`, `hpke_wrap::tests::a_wrong_context_fails_to_open`, `hpke_wrap::tests::a_tampered_wrap_fails_to_open`, `hpke_wrap::tests::a_malformed_public_key_is_rejected` |
| **CRYPTO-10** | `derive_root` splits one Argon2id master (via HKDF-SHA256) into independent sibling keys — KEK, Ed25519 identity, X25519 HPKE keypair — deterministically from `(passphrase, params)`, and each derived key actually works (identity signs/verifies; HPKE keypair wraps/unwraps). | A KEK compromise alone can never yield the signing or HPKE key, and unlock is reproducible from the passphrase alone. | `root::tests::is_deterministic_for_the_same_passphrase`, `root::tests::kek_and_identity_are_independent`, `root::tests::the_hpke_keypair_is_deterministic_independent_and_usable`, `root::tests::the_derived_identity_signs_and_verifies` |
| **CRYPTO-11** | A recovery code's checksum catches a typo before any KDF runs, and the code alone (independent of the passphrase) opens the same DEK through its own wrap. | A lost passphrase isn't total loss, and a mistyped code fails fast and cheaply. | `recovery::tests::typo_caught_by_checksum`, `recovery::tests::malformed_rejected`, `recovery::tests::recovery_wrap_opens_the_dek` |
| **CRYPTO-12** | Decoding arbitrary bytes as an `Envelope`, or opening a valid envelope with random bytes spliced into its wire encoding, never panics — only ever `Ok` or `Err`. | This is the fuzz surface a keyless server (and every reader) is directly exposed to; a crash on untrusted input is a denial-of-service bug regardless of what the cryptography does. | `prop::decoding_arbitrary_bytes_never_panics`, `prop::corrupting_a_valid_envelope_never_panics` |

Run: `node scripts/cargo.mjs test -p openom-crypto` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use openom_crypto::{generate_dek, open, seal};
use openom_protocol::v1::{Aead, Header, Kind};

// A fresh 256-bit DEK (zeroizes on drop).
let dek = generate_dek().unwrap();

// seal/open bind the *whole* header as AAD; a real caller draws the nonce from a
// CSPRNG per call (seal_envelope does this) rather than fixing it like this example does.
let header = Header {
    kind: Kind::Snapshot as i32,
    aead: Aead::Xchacha20Poly1305 as i32,
    nonce: vec![1u8; 24],
    tree_id: vec![0x11; 16],
    ..Default::default()
};

let plaintext = b"the family tree";
let ciphertext = seal(1, &header, dek.expose(), plaintext).unwrap();
assert_ne!(ciphertext, plaintext);
assert_eq!(open(1, &header, dek.expose(), &ciphertext).unwrap(), plaintext);
```

Entry points: `seal_envelope` / `open_envelope` (the high-level call — mints the nonce, builds the
header, sets `ciphertext_hash`) are what callers should reach for first; `seal` / `open` are the
lower-level AAD-agnostic primitives they're built on. Key material: `generate_dek`, `generate_salt`,
`derive_kek`, `derive_root` (the full KEK/identity/HPKE split). Secret keys are returned as distinct
role newtypes — `Dek`, `Kek`, `RrkSecret`, `HpkePrivate` — each opaque (no `Deref`/`Serialize`, a
`Debug` that prints `Role(..)`, `.expose()` to read the bytes), so the compiler rejects passing one
role's key where another's is expected and a key can't leak via `{:?}`. Sharing: `wrap_dek` /
`unwrap_dek` (passphrase- or recovery-code-derived KEK), `hpke_wrap_dek` / `hpke_unwrap_dek` (member
public-key wrap). Recovery: `generate_recovery_code` / `parse_recovery_code`.

## Position

A foundation crate: pure, no domain knowledge, depends only on `openom-protocol` (for the `Header`
type and its canonical AAD encoder). Everything that seals or shares tree data sits on top of it —
`openom-sealer`, `openom-keyring`, `openom-vault-host`, and the `openom` server. Full dependency graph:
see `packages/README.md`.
