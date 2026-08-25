# openom-did

> `did:key` encode/decode for Ed25519, plus a `member_id ⇄ did:key` resolution seam.

**Status:** built · foundation, pure · design.substrate-adaptation §3
**Last updated:** 2026-08-25

## What it is — and is not

A `did:key` is a self-certifying identifier: the key *is* the identifier, no registry needed. For
Ed25519 it is `did:key:z` + base58btc(multicodec(`0xed01`) ++ 32-byte public key), which always
renders with the `z6Mk…` prefix. This is the byte-format the claim envelope's `createdBy` will
carry, so it is pinned here before any content-hash id is persisted cross-client. Built on the raw
Ed25519 public keys the keyring already holds (`Member.author_public_key`), the crate also exposes
a `MemberResolver` seam — `MemberDirectory` resolves `member_id ⇄ did:key` both ways, so callers
never hand-roll the encoding.

It is **not** a DID resolver or a general multicodec/multibase library: it supports exactly one
method (`did:key`) and exactly one key type (Ed25519, multicodec `0xed01`) — any other prefix or
codec is a hard error, never guessed or silently widened. It does not cryptographically vet the
decoded bytes as a valid Ed25519 curve point — `did:key` format-checks, it doesn't validate the
key. It does no signing or verification itself (that's `openom-claim` / `openom-crypto`), no I/O,
and **depends on no other openom crate** — nothing may sit beneath it. base58btc is implemented
in-crate (~40 lines) so the whole codec can be audited in one file and compiles to wasm with no
extra surface.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **DID-1** | `encode_ed25519` / `decode_ed25519` round-trip for any 32-byte key, always `did:key:z6Mk…`-prefixed. | The `createdBy` byte-format must be lossless and stable, or ids fork across clients. | `proptests::did_key_roundtrips_for_any_pubkey`, `tests::ed25519_did_has_z6mk_prefix_and_roundtrips` |
| **DID-2** | base58btc encode/decode is a bijection on arbitrary bytes, including leading zeros. | The in-crate codec must agree with itself on every input, not just the happy path. | `proptests::base58_roundtrips_any_bytes`, `tests::base58_roundtrips_arbitrary_bytes`, `tests::base58_known_vectors` |
| **DID-3** | `decode_ed25519` never panics or hangs on arbitrary input, and rejects a base58 body over `MAX_B58_LEN` (128) before the O(n²) decode runs. | An adversarial `createdBy` must fail fast, not stall or crash the process. | `proptests::decode_never_panics`, `tests::rejects_overlong_base58_without_hanging` |
| **DID-4** | Decode validates every layer in order — scheme prefix, multibase marker, multicodec, key length — and returns the specific `DidError`, never a generic failure. | Callers can distinguish "not a did:key" from "wrong key type" without re-parsing. | `tests::rejects_malformed` |
| **DID-5** | Decoding a canonical externally-produced `did:key` and re-encoding it reproduces the exact string. | Proves interop with other did:key implementations, not just internal consistency. | `tests::known_ed25519_vector` |
| **DID-6** | `MemberDirectory` resolves both directions (`member_id → did:key`, `did:key → member_id`) and returns `None` for unknown ids. | The resolution seam must be a true bijection over the keyring's members, not encode-only. | `tests::member_directory_resolves_both_ways` |

Run: `node scripts/cargo.mjs test -p openom-did` (from the repo root; on Windows cargo runs under
WSL2/Docker). Fuzz: `cargo +nightly fuzz run decode` (from `packages/openom-did/fuzz`).

## Usage

```rust
use openom_did::{decode_ed25519, encode_ed25519, MemberDirectory, MemberResolver};

let mut pk = [0u8; 32];
for (i, b) in pk.iter_mut().enumerate() {
    *b = i as u8;
}

// Encode/decode round-trip: always the z6Mk-prefixed did:key form.
let did = encode_ed25519(&pk);
assert!(did.starts_with("did:key:z6Mk"));
assert_eq!(decode_ed25519(&did).unwrap(), pk);

// member_id ⇄ did:key resolution, built from the keyring's (member_id, public_key) pairs.
let dir = MemberDirectory::from_members([("m-a".to_string(), pk)]);
assert_eq!(dir.did_for("m-a"), Some(did.as_str()));
assert_eq!(dir.member_for(&did), Some("m-a"));
```

Entry points: `encode_ed25519` / `decode_ed25519` (the codec), and the `MemberResolver` trait with
its `MemberDirectory` implementation (the `member_id ⇄ did:key` seam).

## Position

A foundation crate: it depends on no other openom crate, and sits under `openom-claim` (the
`createdBy` byte-format) and the keyring's member resolution. Full dependency graph: see
`packages/README.md`.
