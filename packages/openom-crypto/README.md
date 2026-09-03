# openom-crypto

> The proto-bound sealing layer — binds the protobuf `Header` as AAD, builds envelopes, and wraps DEKs over `keyeo-crypto`'s primitives, byte-identical on client and server.

**Status:** built · foundation, load-bearing (client & server share this crate byte-for-byte) · plan/SERVER-DATA-FORMAT.md §4–§6, §16–§17
**Last updated:** 2026-09-03

## What it is — and is not

V1 is client-side zero-knowledge: the client seals the family tree before upload and the server
never holds a key. This crate is the **proto-bound layer** of that sealing — it binds the protobuf
`Header` as AAD, builds and opens `Envelope`s, and wraps DEKs — standing on `keyeo-crypto` for the
generic primitives (the AEAD cores, Argon2id KDF, HKDF root split, HPKE wrap, recovery-code codec).
Both sides link the identical Rust crate (native on the server, wasm in the browser) instead of two
hand-ported implementations, so they can never disagree on how a blob was sealed.

What it fixes is the **binding**, not the algorithms: `seal`/`open` bind the *whole* protobuf
`Header` as AAD internally (so the AAD encoder is never exposed across the wasm-bindgen boundary and a
JS twin can't drift from it); `seal_envelope`/`open_envelope` mint the nonce and set the
`ciphertext_hash`; `wrap_dek`/`unwrap_dek` bind the full `WrapContext`; and the `default_kdf_params`
/ `derive_kek` / `derive_root` wrappers feed the wire `KdfParams` and the frozen `openom:*` HKDF
labels into keyeo-crypto's primitives. The algorithm choices themselves — **XChaCha20-Poly1305**
(default AEAD, 192-bit random nonces so a long delta log under one DEK never hits AES-GCM's
nonce-reuse footgun) / **AES-256-GCM** (the disciplined alternate), **Argon2id** (passphrase → KEK),
**HKDF-SHA256** (one Argon2id master → independent KEK / Ed25519 identity / X25519 HPKE keypair via
`derive_root`), and **HPKE** (RFC 9180, DHKEM-X25519 + HKDF-SHA256 + ChaCha20Poly1305) — live one
layer down in `keyeo-crypto` and are re-exported here so consumers are unchanged.

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
| **CRYPTO-8** | A DEK wrap (`wrap_dek`/`unwrap_dek`) binds the full `(tree_id, key_id, member_id, wrap_method, epoch)` context; unwrapping under a wrong KEK or any one changed context field fails, and the wrapped bytes are never the plaintext DEK. | A wrap can't be transplanted between members, epochs, or trees. | `wrap::tests::round_trip`, `wrap::tests::wrong_kek_fails`, `wrap::tests::transplant_across_context_fails`, `wrap::tests::wrapped_dek_is_not_plaintext` |
| **CRYPTO-11** | The recovery code — independent of the passphrase — opens the same DEK through its own wrap (a recovery wrap is an ordinary `wrap_dek` under a recovery-KEK). | A lost passphrase isn't total loss. | `recovery::tests::recovery_wrap_opens_the_dek` |
| **CRYPTO-12** | Decoding arbitrary bytes as an `Envelope`, or opening a valid envelope with random bytes spliced into its wire encoding, never panics — only ever `Ok` or `Err`. | This is the fuzz surface a keyless server (and every reader) is directly exposed to; a crash on untrusted input is a denial-of-service bug regardless of what the cryptography does. | `prop::decoding_arbitrary_bytes_never_panics`, `prop::corrupting_a_valid_envelope_never_panics` |

The primitive-level guarantees — KDF determinism, DEK/salt randomness, HPKE wrap binding,
`derive_root` sibling-key independence, and the recovery-code checksum — now live one layer down; see
the Invariants table in `packages/keyeo-crypto/README.md`. The wrapper tests
(`kdf::tests::derive_kek_wrapper_matches_the_core`, `root::tests::frozen_labels_are_unchanged`) pin
this crate's proto wrappers to those cores.

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

A thin proto-binding crate: no domain knowledge, depends on `openom-protocol` (for the `Header` type
and its canonical AAD encoder) and `keyeo-crypto` (for the generic primitives it binds and
re-exports). Everything that seals or shares tree data sits on top of it — `openom-sealer`,
`openom-keyring`, `openom-vault-host`, and the `openom` server. Full dependency graph: see
`packages/README.md`.
