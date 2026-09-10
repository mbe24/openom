# keyeo-wrap

> The fixed-size keyeo crypto-material newtypes — an X25519 public key, an HPKE encapped key, a nonce, a
> wrapped DEK — whose byte lengths the pinned suite fixes in the *type*. The wrap types without the machinery.

**Status:** built · Layer-0 crypto-material types · openom-free · (OPE-279 keyeo family)
**Last updated:** 2026-09-10

## What it is — and is not

Four `#[repr(transparent)]` newtypes over fixed-length byte arrays, one per wrap byte-string the frozen HPKE
suite produces (DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305 for HPKE; XChaCha20-Poly1305 for
the symmetric KEK wrap). So an X25519 point is 32 bytes and a sealed 32-byte secret is 48 (32 + a 16-byte AEAD
tag), and encoding those lengths in the type makes a wrong-length or swapped key **unconstructable** (illegal
states unrepresentable) while removing a heap allocation per field (`[u8; N]` inline vs. a `Vec<u8>` alloc +
pointer chase). Distinct types for the two 32-byte X25519 points — a recipient's *static* public key vs. a
per-wrap *ephemeral* encapped key — keep them non-swappable.

These live in their **own** crate, split out of `keyeo-crypto`, so a consumer can name a typed public key
**without** pulling in the AEAD / Argon2 / HPKE machinery — the same isolation `edsign` gives the Ed25519 key
types. `keyeo-crypto` re-exports them (they are part of its public wrap/HPKE API); lean consumers (e.g.
`openom-keyring-dag`, which names typed member keys in its anchor) depend on this crate **directly**.

It is **not** the crypto: it does no HPKE, no AEAD, no derivation — only types. Length-checked `TryFrom<&[u8]>`
yields the std [`core::array::TryFromSliceError`], so the crate stays error-domain-free. Pure newtypes:
serde-only, no crypto dependency, openom-free.

## Usage

```rust,ignore
use keyeo_wrap::{X25519PublicKey, EncappedKey, WrappedDek};

let pk = X25519PublicKey::from_bytes(raw32);          // known-length: no validation, the length IS the type
let enc: EncappedKey = slice.try_into()?;             // from an untrusted slice: length-checked
let bytes: [u8; 32] = pk.to_bytes();
```

## Position

Layer 0, alongside `edsign` (Ed25519 key types) and below `keyeo-crypto` (which re-exports these and adds the
HPKE/AEAD/KDF machinery). Depended on directly by any crate that needs the typed material without the
machinery. Full dependency graph: see `packages/README.md`.
