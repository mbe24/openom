# jcs

> RFC 8785 canonical JSON bytes — the substrate every content hash rests on.

**Status:** built · substrate primitive, load-bearing · frozen contract
**Last updated:** 2026-08-25

## What it is — and is not

One byte-exact serialization for any JSON value. Every content-addressed identifier in the claim
model is a hash of this crate's output: a claim `id` is `sha256(JCS(envelope − id − signature))`, a
dedup `fingerprint` is `sha256(JCS(targetId, predicate, value))`, and a content reference is
`"sha256:" + hex(JCS(intrinsic))`. If two clients canonicalize the same value to *different* bytes,
their ids fork **silently** — dedup and refutation memory corrupt with no error anywhere — so this
crate is kept tiny, pure, and exhaustively tested, and its native and wasm builds must emit identical
bytes.

It is **not** a general RFC 8785 implementation: non-integer numbers are a hard error
(`JcsError::Float`), never the lossy ES6-double formatting the spec permits — the claim model is
float-free by construction, so a float is treated as a bug, not accommodated. It does no I/O, no
crypto beyond `sha256` helpers, and **depends on no other openom crate** — nothing may sit beneath it.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **JCS-1** | Deterministic: equal values → equal bytes, every call. | The whole content-addressing scheme rests on it. | `proptests::deterministic` |
| **JCS-2** | Idempotent: re-parsing canonical bytes and re-canonicalizing is a fixpoint. | Round-tripping a stored record never shifts its id. | `proptests::idempotent`, `tests::canonical_is_reserialization_stable` |
| **JCS-3** | Keys sort by UTF-16 code units (RFC 8785 §3.2.3), not code-point / UTF-8 order. | A future non-ASCII key can never silently fork a hash. | `tests::utf16_order_differs_from_codepoint_order` |
| **JCS-4** | Integers emit exactly (incl. beyond 2⁵³); any float is a hard `JcsError::Float`. | No silent lossy number formatting inside an id. | `proptests::floats_rejected`, `tests::rejects_floats`, `tests::integers_pass_through` |
| **JCS-5** | Nesting past `MAX_DEPTH` (128) fails with `JcsError::TooDeep` — never a stack-overflow abort. | An adversarial synced record fails closed, not crashes. | `tests::rejects_pathologically_deep_nesting` |
| **JCS-6** | String escaping is RFC 8785 §3.2.2.2-minimal; every other character is literal UTF-8. | Escaping variance would fork hashes. | `tests::string_escaping_is_minimal` |
| **JCS-7** | Field selection (`canonical_subset` / `canonical_excluding`) is order-independent and object-only (else `JcsError::NotObject`). | Fingerprint / id inputs are stable regardless of caller field order. | `tests::subset_and_excluding_pick_fields_order_independently`, `tests::non_object_subset_errors` |
| **JCS-8** | Hex output (`hex`, `hex256`) is lowercase. | Every crate on the content-addressing path encodes hashes identically. | `tests::hex256_is_lowercase_64_chars` |

Run: `node scripts/cargo.mjs test -p jcs` (from the repo root; on Windows cargo runs under
WSL2/Docker). Fuzz: `cargo +nightly fuzz run canonicalize` (from `packages/jcs/fuzz`).

## Usage

```rust
use jcs::{to_canonical_value, canonical_subset, canonical_excluding, hex256};
use serde_json::json;

// Canonical bytes: keys sorted (UTF-16), whitespace stripped, integers only.
let bytes = to_canonical_value(&json!({ "b": 1, "a": 2 })).unwrap();
assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"a":2,"b":1}"#);

let claim = json!({
    "id": "hash-1", "signature": "sig", "targetId": "p1",
    "predicate": "openom.org/core/name/v1", "value": { "given": "Ada" },
});
// fingerprint input — chosen fields, order-independent — then its hash (64 lowercase hex):
let fp_bytes = canonical_subset(&claim, &["targetId", "predicate", "value"]).unwrap();
assert_eq!(hex256(&fp_bytes).len(), 64);
// id input — everything except id + signature:
let id_bytes = canonical_excluding(&claim, &["id", "signature"]).unwrap();
assert!(!id_bytes.is_empty());
```

Entry points: `to_canonical` / `to_canonical_value` (a whole value), `canonical_subset` /
`canonical_excluding` (field-selective — the fingerprint and id primitives), `canonical_hash` (the
raw 32-byte hash), and `hex` / `hex256`.

## Position

The bottom of the content-addressing stack: it depends on no other openom crate, and everything that
computes an id, fingerprint, or content reference sits on top of it — directly `openom-claim` and
`openom-projection`. Full dependency graph: see `packages/README.md`.
