# edsign

> The single Ed25519 dependency edge — newtype `SigningKey` / `VerifyingKey` / `Signature` whose only
> verify is `verify_strict`, so the weak `Verifier::verify` path is uncallable outside this crate.

**Status:** built · substrate primitive, load-bearing · compile-time signature-verification policy (OPE-205/215)
**Last updated:** 2026-09-03

## What it is — and is not

`ed25519-dalek` exposes **two** verify methods: `verify_strict` (rejects small-order / torsion public
keys and non-canonical signatures) and the `Verifier` trait's plain `verify` (weaker). A signature over
attacker-influenced key material — a keyring signer's key, a member's author key — must use the strict
path, or a small-order forgery can pass. This crate is the workspace's **only** dependency on
`ed25519-dalek`: everything else goes through these newtypes, so the weak path is not in scope anywhere
else and cannot be written by construction. The policy is "always `verify_strict`", enforced at
`cargo build`, not by a lint. It is also pure, RNG-free, and serde-free (identities are minted by callers
via `from_seed`), so it is deterministic and wasm-trivial.

It is **not** a general signing toolkit and mints no randomness: there is no keygen-from-entropy here —
a caller supplies the 32-byte seed (its own HKDF-derived identity, or a test seed). It carries **no**
domain separation of its own; `sign` signs exactly the bytes it is handed, and the one derivation helper
([`derive_signing_key`]) takes the domain label as a *parameter* so the crate stays domain-free. It knows
nothing about keyrings, envelopes, or openom — it is a foundation, and nothing openom-specific belongs in
it.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **SIGN-1** | The only verify is `verify_strict`; a small-order / torsion forgery is rejected. | The weak `Verifier::verify` cannot be reached from any other crate — the whole point of the seam. | `tests::our_verify_is_strict_a_small_order_forgery_is_rejected` |
| **SIGN-2** | `from_seed` is deterministic: the same 32-byte seed always yields the same key. | A device re-derives its identity from a secret, never a stored key file. | `tests::from_seed_is_deterministic` |
| **SIGN-3** | Sign/verify round-trips, and any tamper of message or key is rejected. | The base authenticity guarantee every op and keyring entry rests on. | `tests::sign_verify_roundtrip`, `tests::a_tampered_message_is_rejected`, `tests::a_wrong_key_is_rejected` |
| **SIGN-4** | `Debug` on a `SigningKey` (or a struct embedding one) redacts the seed; the signing seed zeroizes on drop. | A key can't leak into a log line, and the seed doesn't linger in freed memory. | `tests::signing_key_debug_redacts_the_seed`, `tests::signature_debug_is_redacted` |
| **SIGN-5** | A malformed public key is a construction error, not a deferred verify failure. | Bad key bytes fail closed at the boundary, before any signature is trusted. | `tests::malformed_public_key_is_a_construction_error` |
| **SIGN-6** | `derive_signing_key(ikm, info)` domain-separates: the same `ikm` under different `info` yields unrelated keys. | Both keyring engines derive their recovery key here; a signing capability can never be confused with an encryption/identity key from the same secret. | `openom_keyring_dag::recovery::tests::rvk_is_domain_separated_from_the_raw_seed_key` |

Run: `node scripts/cargo.mjs test -p edsign` (from the repo root; on Windows cargo runs under WSL2/Docker).

## Usage

```rust
use edsign::{SigningKey, VerifyingKey, derive_signing_key};

// Mint an identity from a caller-supplied 32-byte seed, then sign + verify.
let key = SigningKey::from_seed(&[7u8; 32]);
let msg = b"canonical bytes the caller domain-separated";
let sig = key.sign(msg);

let vk = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
assert!(vk.verify(msg, &sig).is_ok()); // strict verify

// A recovery/derived signing capability under a domain label — same ikm, different label = different key.
let rvk = derive_signing_key(&[7u8; 32], b"keyeo:rvk:v1");
assert_ne!(rvk.verifying_key().to_bytes(), key.verifying_key().to_bytes());
```

Entry points: `SigningKey::{from_seed, verifying_key, sign}`, `VerifyingKey::{from_bytes, to_bytes,
verify}`, `Signature::{from_bytes, to_bytes}`, and `derive_signing_key` (HKDF-SHA256 a signing seed under
a caller's domain label).

## Position

A foundation: it depends only on `ed25519-dalek` + `zeroize` + `hkdf`/`sha2`, and no other openom crate,
so nothing sits beneath it. Everything that authenticates — `keyeo-core` (the keyeo verify seam),
`keyeo-crypto`, `keyeo-linear`, `openom-keyring-chain`, `openom-keyring-dag`, `openom-crypto` — signs
and verifies through it. Full dependency graph: see `packages/README.md`.
