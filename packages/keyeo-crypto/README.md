# keyeo-crypto

Generic, openom-free symmetric and HPKE crypto primitives shared by openom-crypto (the
proto-bound envelope layer) and the keyeo DAG keyring engine.

It owns the pieces that carry no wire/proto knowledge:

- **Typed secrets** (`secret`): `Dek`, `Kek`, `HpkePrivate`, `RrkSecret`, `Passphrase`,
  `RecoveryCode` — one-level role newtypes over zeroizing buffers (OPE-211).
- **KDF** (`kdf`): Argon2id `derive_kek` over a plain `KdfParams`, plus `generate_dek` /
  `generate_salt` and the pinned default costs.
- **Root derivation** (`root`): `derive_root` (Argon2id → HKDF split into KEK + Ed25519
  identity + X25519 HPKE keypair) genericized over a caller-supplied `RootLabels`, and
  `derive_rvk` (the recovery-verification key, frozen `keyeo:rvk:v1` label).
- **HPKE wrapping** (`hpke_wrap`): RFC 9180 DEK wraps to a member's X25519 public key.
- **AEAD cores** (`aead`): the AAD-agnostic XChaCha20-Poly1305 / AES-256-GCM seal/open
  primitives. The header-driven envelope `seal`/`open` that bind the proto `Header` as AAD
  stay in openom-crypto and call these.
- **Recovery codes** (`recovery`): generation, parsing, and checksum of the printable code.

The frozen HKDF labels (`openom:*` are supplied by openom-crypto via `RootLabels`;
`keyeo:rvk:v1` is owned here) and all algorithm choices are byte-identical to the pre-split
openom-crypto — this crate is a code move, not a behavior change.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|-----------------|-------------|
| **KCRYPTO-1** | `derive_kek` (Argon2id) is deterministic in `(passphrase, params)` and sensitive to both — same inputs reproduce the same KEK; a different passphrase or a different salt always diverges. | A second device can join from the passphrase alone, and a KEK never coincides by accident. | `kdf::tests::deterministic_in_passphrase_and_params`, `kdf::tests::different_passphrase_differs`, `kdf::tests::different_salt_differs` |
| **KCRYPTO-2** | `generate_dek`/`generate_salt` draw fresh, correctly-sized, non-repeating material from the OS/browser CSPRNG. | A generated DEK is never predictable or reused across trees. | `kdf::tests::generated_deks_are_random_and_sized`, `kdf::tests::generated_salts_are_random` |
| **KCRYPTO-3** | An HPKE wrap (`hpke_wrap_dek`/`hpke_unwrap_dek`, RFC 9180 base mode) opens only with the matching recipient secret key and the exact `info` context; a tampered ciphertext or a malformed public key is rejected, never silently accepted. | Lets a sharee who never knew the owner's passphrase still receive the tree key, without weakening the binding the symmetric wrap gets. | `hpke_wrap::tests::wrap_then_unwrap_round_trips`, `hpke_wrap::tests::the_wrong_member_secret_cannot_open`, `hpke_wrap::tests::a_wrong_context_fails_to_open`, `hpke_wrap::tests::a_tampered_wrap_fails_to_open`, `hpke_wrap::tests::a_malformed_public_key_is_rejected` |
| **KCRYPTO-4** | `derive_root` splits one Argon2id master (via HKDF-SHA256, over caller-supplied `RootLabels`) into independent sibling keys — KEK, Ed25519 identity, X25519 HPKE keypair — deterministically from `(passphrase, params)`, and each derived key actually works (identity signs/verifies; HPKE keypair wraps/unwraps). | A KEK compromise alone can never yield the signing or HPKE key, and unlock is reproducible from the passphrase alone. | `root::tests::is_deterministic_for_the_same_passphrase`, `root::tests::kek_and_identity_are_independent`, `root::tests::the_hpke_keypair_is_deterministic_independent_and_usable`, `root::tests::the_derived_identity_signs_and_verifies` |
| **KCRYPTO-5** | A recovery code's checksum catches a typo or a malformed code before any KDF runs. | A mistyped recovery code fails fast and cheaply instead of burning an Argon2id derivation. | `recovery::tests::typo_caught_by_checksum`, `recovery::tests::malformed_rejected` |

Run: `node scripts/cargo.mjs test -p keyeo-crypto` (from the repo root; on Windows cargo runs under
WSL2/Docker).
