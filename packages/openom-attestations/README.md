# openom-attestations

> A member Ed25519-signs a fact's canonical content hash — an independent sidecar, never a tree op.

**Status:** built · signed-attestation mechanism, authority-agnostic · plan/design.attestations.md

**Last updated:** 2026-08-25

## What it is — and is not

The signed-attestation **sidecar**: a member vouches for a fact by Ed25519-signing that fact's
canonical content hash (`openom-model::content_hash`). The signature attributes the vouch and is
tamper-evident — signed, not zero-knowledge (ZK is deferred to a possible future cross-boundary use;
see `plan/design.attestations.md`). It binds to the **fact's hash, not a whole-tree root**, so an
unrelated tree edit never touches it; editing the attested fact itself changes the hash, and the old
attestation cleanly reads as "attested an earlier value" rather than silently breaking.

The sidecar is its **own document, independent of the tree** — its own snapshot ([`AttestationDoc`])
and op-log ([`AttestOp`]), riding the generic `journal` substrate (byte-level: `to_snapshot` /
`encode_op` hand journal-shaped bytes to a caller) — never tree ops. That keeps attestations out of the
delta-log's metering and compaction, and lets the sidecar format evolve independently.

**Critical distinction — do not confuse the two:** this crate is *not* the `openom.org/core/attest/v1`
predicate. That predicate is an ordinary **in-tree claim** — "just another claim" resolved by
`openom-projection`'s epistemic-resolution pass, carrying a `verdict` + `createdBy` field and no
cryptographic signature. *This* crate is the opposite: a claim-model-independent, Ed25519-**signed**
sidecar that rides `journal` directly and is verified by recomputing a hash and checking a signature,
not by projection logic. The two solve related but distinct problems and must never be merged (see
OPE-200, referenced from `packages/README.md`).

It is also **not** authority or identity: it doesn't decide who may attest or revoke (role authority —
OPE-104) or resolve a `PubKey` to a person (the attester registry — OPE-105); both layer on top. It has
no dependency on `openom-claim`, `openom-model`, or `journal` — it is handed a `FactHash` and produces
bytes; the caller supplies the hash and threads the bytes through storage.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **ATTEST-1** | A signature is domain-separated (`DOMAIN ‖ fact_hash`) and invalidated by tampering the fact hash or swapping the attester. | A vouch can never be replayed against a different fact or misattributed to a different signer. | `tests::signature_attributes_the_fact_and_tamper_is_caught` |
| **ATTEST-2** | `verify_against` distinguishes `Valid` / `AttestedEarlierValue` / `BadSignature` by rebinding to the fact's *current* hash, not a tree root. | Editing the attested fact fails closed and legibly ("attested an earlier value"), not silently. | `tests::verify_against_current_edited_and_bad` |
| **ATTEST-3** | `AttestationDoc::apply` rejects an `Attest` op whose signature doesn't verify; the doc is left unchanged. | A corrupted or forged op can never enter the sidecar's state. | `tests::a_bad_signature_op_is_rejected` |
| **ATTEST-4** | Concurrent attests **union**: distinct `(attester, fact)` pairs coexist, and re-applying the same pair is idempotent. | Two members attesting independently — or a replayed op — never conflicts or double-counts. | `tests::concurrent_attests_union_and_are_idempotent` |
| **ATTEST-5** | `Revoke` removes the vouch and tombstones `(attester, fact)` so a re-delivered attest is suppressed; `compact` hard-purges the tombstone. | The "known-liar" / bad-divorce case: a revoked vouch leaves no trace once every replica has seen the revoke. | `tests::revoke_tombstones_then_compaction_hard_purges` |
| **ATTEST-6** | `AttestationDoc` and `AttestOp` both round-trip through their `journal`-shaped byte encoding (`to_snapshot`/`from_snapshot`, `encode_op`/`decode_op`). | The sidecar's snapshot + op-log bytes are exactly what `journal` expects, with nothing lost. | `tests::snapshot_and_op_round_trip_through_journal_bytes` |

Run: `node scripts/cargo.mjs test -p openom-attestations` (from the repo root; on Windows cargo runs
under WSL2/Docker).

## Usage

```rust
use ed25519_dalek::SigningKey;
use openom_attestations::{AttestOp, Attestation, AttestationDoc, Verdict};

let member_key = SigningKey::from_bytes(&[1; 32]);
let fact_hash = [9; 32]; // openom-model::content_hash of the fact being vouched for

// Sign a vouch, then apply it to the sidecar document (signature is verified on apply).
let mut doc = AttestationDoc::new();
doc.apply(AttestOp::Attest(Attestation::create(&member_key, fact_hash)))
    .unwrap();
assert_eq!(doc.for_fact(&fact_hash).count(), 1);

// Bind against the fact's current hash — Valid until the fact is edited.
let vouch = doc.for_fact(&fact_hash).next().unwrap();
assert_eq!(vouch.verify_against(&fact_hash), Verdict::Valid);

// Rides `journal`: hand these bytes to the snapshot + op-log store.
let snapshot = doc.to_snapshot();
assert_eq!(AttestationDoc::from_snapshot(&snapshot).unwrap(), doc);
```

Entry points: `Attestation::create` / `verify` / `verify_against` (the signed vouch), `AttestationDoc`'s
`apply` / `for_fact` / `is_attested` / `compact` (the document), and `to_snapshot` / `from_snapshot` /
`encode_op` / `decode_op` (the `journal` byte boundary).

## Position

Sits beside the tree, not under it: it depends on no other openom crate (just `ed25519-dalek` and
`serde`/`serde_json`) and is handed a `FactHash` from the caller — in the claim-model direction, from
`openom-model::content_hash`. It rides `journal`'s snapshot + op-log shape at the byte level, and
authority (OPE-104) and the attester registry (OPE-105) layer on top of it. Full dependency graph: see
`packages/README.md`.
