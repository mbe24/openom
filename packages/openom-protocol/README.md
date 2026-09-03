# openom-protocol

> The wire format: prost-generated protobuf types plus the canonical AAD/signing-bytes encoders that bind them.

**Status:** built · substrate primitive, load-bearing · data-format spec §3–§5 (frozen wire skeleton)
**Last updated:** 2026-08-25

## What it is — and is not

The shared client/server contract. `v1` (`Envelope`, `Header`, `Keyring`, `KeyEpoch`, `KeyWrap`,
`KdfParams`, `RecoveryKey`, and the `Kind` / `Format` / `Aead` / `Compression` / `WrapMethod` /
`MemberRole` enums) is generated from `proto/openom/v1/openom.proto` by `buf generate`
(the `neoeinstein-prost` plugin) and checked into `src/generated/` — there is **no build script and
no `protoc`**, so nothing executes during `cargo build`, which is what lets the crate build on a host
whose policy blocks build-script execution. Regenerate with `cd proto && buf generate` after editing
the `.proto`; the generated file is committed, not built on the fly.

`aad` is the one hand-written module, and it is not generated: protobuf serialization is not
canonical, so it builds the AEAD associated-data and Ed25519 signing byte strings
(`header_aad`, `author_signing_bytes`, `wrap_aad`, `rrk_wrap_aad`, `keyring_signing_bytes`) by
length-prefixed, fixed-field-order, branchless concatenation — the one byte-exact encoding a Rust
build and a WASM/JS build must reproduce identically, since it is what the AEAD tag and the Ed25519
signatures actually authenticate.

It is **not** where anything gets decided or enforced: no CRDT causality, no client wall-clock, no
crypto operations (`openom-crypto`), no keyring policy or chain verification (`openom-keyring`), no
role authorization (`openom-roles`). This crate only defines the wire shapes and the canonical byte
strings derived from them — every consumer above it decides what those bytes mean.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **PROTO-1** | `header_aad` is deterministic and `version` is its first field, making AAD byte-disjoint across `Envelope.version` values. | A future wire version can never be silently misparsed as this one. | `aad::tests::deterministic`, `aad::tests::version_is_first_and_disjoint` |
| **PROTO-2** | `header_aad` matches its documented fixed field order and byte layout exactly, with `ciphertext_hash` excluded (it derives from the ciphertext the AAD itself seals — binding it would be circular). | The anchor a JS/WASM twin must reproduce byte-for-byte; a drift here forks every AEAD open silently. | `aad::tests::matches_documented_layout` |
| **PROTO-3** | `header_aad`'s layout is branchless: two headers differing only in `Kind` produce the same length. | The encoding never forks on the object kind. | `aad::tests::branchless_layout_independent_of_kind` |
| **PROTO-4** | Every variable-length field is 4-byte length-prefixed. | Defeats the `"ab"+"c" == "a"+"bc"` concatenation-boundary forgery class. | `aad::tests::length_framing_prevents_concatenation_forgery` |
| **PROTO-5** | `author_signing_bytes` matches its documented layout, excludes the seal-derived/self fields (`nonce`, `ciphertext_hash`, `author_signature`), and binds `SHA-256(plaintext)`, `author_member_id`, `keyring_revision`, and `kind`. | The signature is computable pre-seal, never self-referential, and can't be replayed onto different content, a different claimed author, a different governing revision, or a re-kinded entry (e.g. a proposal resealed as a delta). | `aad::tests::author_signing_bytes_documented_layout`, `::author_signing_bytes_excludes_seal_derived_fields`, `::author_signing_bytes_binds_content_and_attribution` |
| **PROTO-6** | `wrap_aad` binds every one of `(tree_id, key_id, member_id, wrap_method, epoch)`. | A DEK wrap can't be transplanted between members, epochs, or trees. | `aad::tests::wrap_aad_binds_every_context_field` |
| **PROTO-7** | `keyring_signing_bytes` covers `revision`, `prev_keyring_hash`, `members` (which — since the signer set is derived from members — also covers the trust set), and `epochs`/`wraps`, but excludes `signatures`. | Anti-rollback and the history chain are signed; every signer signs identical bytes, so signatures collect independently (threshold-ready). | `aad::tests::keyring_signing_bytes_covers_and_ignores_signatures` |
| **PROTO-8** | Every AAD/signing byte string is domain-separated by a leading tag or version int, so none collides with another (header vs. author vs. wrap vs. keyring). | A founder/co-owner's author key IS their keyring signer key — only the domain tag stops a signature from being cross-replayed into the wrong context. | `aad::tests::author_signing_bytes_domain_disjoint`, `::wrap_aad_is_disjoint_from_header_aad`, `::keyring_signing_bytes_layout_version_disjoint` |

Run: `node scripts/cargo.mjs test -p openom-protocol` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```sh
cd packages/openom-protocol/proto && buf generate
```

## Position

A foundation crate (no domain knowledge, depends on nothing above it): everything that seals, syncs,
or administers a tree sits on top of its wire types and canonical byte strings — directly
`openom-crypto`, `openom-keyring`, `openom-roles`, `openom-sealer`, `openom-sync`, `openom-vault-host`,
and the server crate. Full dependency graph: see `packages/README.md`.
