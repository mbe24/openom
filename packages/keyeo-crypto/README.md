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
