# openom-claim

> The claim-envelope hashing + signing seam — content-hash `id`, dedup `fingerprint`, domain-separated
> Ed25519 sign/verify.

**Status:** built · load-bearing primitive · design.data-model-claims.v1.md §4
**Last updated:** 2026-08-26

## What it is — and is not

Every disputable family-tree fact is a **Claim**: a uniform envelope
`{ id, type, targetId, predicate, value, citation?, createdAt, createdBy, signature? }`. This crate
computes and checks the three derived quantities that hang off that envelope: the content-hash `id`
(`"sha256:" + hex(sha256(JCS(envelope − id − signature)))`), the dedup `fingerprint`
(`sha256(JCS(targetId, predicate, value))` — deliberately excluding `createdBy` and `citation`, so the
same fact asserted by different authors or cited to different sources still collides), and a
domain-separated Ed25519 signature over the content hash, keyed by the key behind `createdBy`'s
`did:key`. It also carries the typed mirror (`envelope::Claim` / `envelope::Anchor`) that routes through
these exact primitives — never a second canonicalization path — and, behind the optional `validation`
feature, a compiled JSON Schema check of the frozen record shape.

It is **not** the operations layer: deletion and edit-supersession are a separate channel, never claims
(design.data-model-claims.v1.md §8.2 / principle 6), and this crate knows nothing about them. It is
**not** an authority check either — `verify` is pure cryptography (does the signature match the
`createdBy` key?), not "was this author allowed to assert this" (a keyring/roles concern, a layer up).
And the schema check is optional and off by default (`validation` feature) so `jsonschema` never lands
in the default/wasm build — it constrains *shape*, never a content hash, which only the primitives here
can verify.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **CLAIM-1** | `id` is `sha256(JCS(envelope − id − signature))`: every other field moves it; `id`/`signature` themselves never do. | Ids are content-addressed and stable regardless of whether — or how — a claim is signed. | `tests::id_excludes_id_and_signature_but_covers_value`, `tests::id_covers_every_content_field`, `tests::attaching_the_signature_does_not_change_the_id`, `proptests::id_and_fingerprint_deterministic` |
| **CLAIM-2** | `fingerprint` covers only `targetId`/`predicate`/`value` — excludes `createdBy` and `citation`. | The same fact from a different author or source shares one fingerprint, which is what lets corroboration count distinct authors and a re-import inherit a refuted fact's rejections. | `tests::fingerprint_excludes_author_and_citation_but_not_value`, `tests::fingerprint_covers_target_and_predicate`, `tests::fingerprint_is_key_order_independent` |
| **CLAIM-3** | `sign`/`verify` is domain-separated Ed25519 (`verify_strict`) over the content hash, keyed by the `createdBy` `did:key`; a content tamper or wrong signing key flips `Valid` → `Bad`. | Authorship of a claim is cryptographically checkable, and a signature can't be replayed as some other signature elsewhere in the system. | `tests::sign_and_verify_roundtrip`, `tests::tampered_content_fails_verification`, `tests::signature_from_a_key_other_than_created_by_fails`, `proptests::sign_verify_and_tamper` |
| **CLAIM-4** | `verify` fails closed: a syntactically valid but non-curve public key or a malformed signature is `SigCheck::Bad`, never a panic or false `Valid`; a missing/malformed `createdBy` is a typed `Err`. | A hostile synced record can never be silently accepted, and can't crash the ingest path either. | `tests::a_did_encoding_a_non_curve_point_is_bad_not_error`, `tests::verify_reports_errors_for_a_missing_or_bad_created_by` |
| **CLAIM-5** | `content_ref` is a stable, field-selective content address: any key order over the same intrinsic value yields the same reference; different content never does. | `equivalent_to` / `derived_from` / `preferred.contentRef` point at *what a claim says*, stable across authors — not at a minted id. | `tests::content_ref_is_stable_and_field_selective` |
| **CLAIM-6** | The typed `envelope::Claim` (`compute_id` / `fingerprint` / `sign_with` / `verify` / `id_is_current`) routes through the exact same seam as the `Value` primitives. | Two implementations of the same hash would be exactly the silent-fork risk this crate exists to prevent. | `envelope::tests::claim_roundtrips_and_ids_match_the_seam`, `envelope::tests::compute_id_then_sign_keeps_the_id`, `envelope::tests::typed_verify_and_id_drift_detection` |
| **CLAIM-7** | The frozen record schema (`validation` feature, Draft 2020-12) rejects a malformed id/type/`createdBy`/signature pattern and a bad attest verdict. | The typed shape and the wire shape can't silently drift apart. | `schema::tests::a_real_claim_and_anchor_validate`, `schema::tests::attestation_value_is_constrained`, `schema::tests::junk_and_malformed_ids_are_rejected` |
| **CLAIM-8** | `Record::try_from` (the parse-don't-validate ingest boundary) verifies a Claim's content-hash id, parses a known anchor type as typed, and preserves an unrecognized `type` verbatim as `Record::Unknown` — provided it has a non-empty, non-content-addressed (`sha256:`) id; a missing id or a reserved `sha256:` id is refused. | Forward-compat: a newer version's record type flows through an older client untouched, yet an unknown record can neither be unfoldable (no id) nor squat a claim's content-address. | `envelope::tests::record_try_from_dispatches_and_verifies_the_id`, `envelope::tests::unknown_records_are_preserved_but_guarded`, `envelope::tests::record_serde_roundtrips_and_verifies_embedded_ids` |

Run: `node scripts/cargo.mjs test -p openom-claim` (from the repo root; on Windows cargo runs under
WSL2/Docker). Fuzz: `cargo +nightly fuzz run hash_and_verify` (from `packages/openom-claim/fuzz`) —
hashing/verifying an arbitrary envelope must never panic, OOM, or hang.

## Usage

```rust
use ed25519_dalek::SigningKey;
use openom_claim::{claim_id, fingerprint, sign, verify, SigCheck};
use openom_did::encode_ed25519;
use serde_json::json;

let key = SigningKey::from_bytes(&[7u8; 32]);
let did = encode_ed25519(&key.verifying_key().to_bytes());

let claim = json!({
    "id": "sha256:PLACEHOLDER",
    "type": "openom.org/core/claim/v1",
    "targetId": "per_uuid",
    "predicate": "openom.org/core/name/v1",
    "value": { "parts": { "given": "Ada", "family": "Lovelace" } },
    "createdAt": 1771765800000_i64,
    "createdBy": did,
});

// id excludes id & signature — safe to compute before or after signing.
let id = claim_id(&claim).unwrap();
assert!(id.starts_with("sha256:"));

// fingerprint excludes createdBy — a different author asserting the same fact would collide here.
let fp = fingerprint(&claim).unwrap();
assert_eq!(fp.len(), 32);

// sign + verify: domain-separated Ed25519 over the content hash, keyed by createdBy.
let sig = sign(&claim, &key).unwrap();
assert_eq!(verify(&claim, &sig).unwrap(), SigCheck::Valid);
```

Entry points: `claim_id` / `content_hash` (the id primitive), `fingerprint` (dedup), `content_ref`
(stable content address), `sign` / `verify` (domain-separated Ed25519). The typed mirror
`envelope::Claim` / `envelope::Anchor` wraps the same primitives as methods (`compute_id`, `fingerprint`,
`sign_with`, `verify`, `id_is_current`). Behind the `validation` feature: `schema::RecordSchema`.

## Position

Sits directly on `openom-jcs` (canonical bytes, the hash input) and `openom-did` (`did:key` ⇄ Ed25519 key
resolution) — nothing else sits beneath it. `openom-projection`, the claim-model read model, sits on top,
consuming committed, signed claims by `id` and `fingerprint`. Full dependency graph: see
`packages/README.md`.
