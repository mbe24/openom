# openom packages

The Rust workspace. Every crate carries a `README.md` that **is its module doc** (wired via
`#![doc = include_str!("../README.md")]`), so the same text serves GitHub, `cargo doc`, and any
agent reading the tree. The format and the rules are at the bottom of this file.

## Architecture seams — the boundaries to keep straight

These are the distinctions a newcomer (human or agent) most often gets wrong. Keep them straight:

- **Family-tree data vs. operations.** The canonical family-tree is a set of **claims** — facts
  *and* epistemic assertions (`same_as`, `attest`, `preferred`, …) — materialized as flat JSON. Its
  crates are **`openom-claim`** (envelope + hashing) and **`openom-projection`** (read model).
  **Deletion, edit-supersession, and merge metadata are operations, a *separate* channel — never
  claims** (design.data-model-claims.v1.md §8.2 / principle 6). The projection reads the **live
  claim set** and does epistemic resolution only; it does **not** process deletion or supersession —
  that is the operations/transport layer (`journal`, `openom-sync`).
- **Substrate vs. domain.** The foundations (`openom-jcs`, `openom-did`, `openom-edtf`,
  `openom-crypto`, `openom-protocol`) know nothing about family trees and must never gain a domain
  dependency. Dependencies point **downward** only.
- **In flight (pre-release, zero users).** The app currently runs on **`openom-treelog`** (over
  `commute`); it is being swapped to the **claim model** (`openom-claim` / `openom-projection` + an
  operations channel). During the transition `openom-model` (the older flat model) and
  `commute` / `openom-treelog` are **legacy** — expect them to shrink or retire. A crate's `Status`
  line says where it stands.

## The crates, by layer

**Foundations** (pure; no domain knowledge)
- **openom-jcs** — RFC 8785 canonical JSON bytes; the substrate under every content hash.
- **openom-did** — `did:key` encode/decode (Ed25519) + `member_id` ⇄ `did:key` resolution.
- **openom-edtf** — EDTF (ISO 8601-2) date parser/normalizer → sortable `[min,max]` bounds.
- **openom-crypto** — shared symmetric crypto primitives (client & server, identical algorithms).
- **openom-protocol** — shared protobuf data model (prost, generated via buf).

**Family-tree data model**
- **openom-claim** — claim-envelope hashing + signing: content-hash `id`, dedup `fingerprint`, domain-separated Ed25519 sign/verify. *(claim model — the direction)*
- **openom-projection** — read-time projection: the claim record set → a materialized read model, a pure function of the records. *(claim model)*
- **openom-model** — the older canonical flat id-keyed model + JSON-Schema validator. *(legacy — superseded by the claim model)*

**Operations / CRDT** (how changes converge)
- **commute** — a small op-based CRDT: Lamport-ordered ops → convergent cells (LWW / OR-set / tombstones).
- **commute-format** — bridge: JSON documents ⇄ mergeable commute cells.
- **openom-treelog** — the family-tree domain over `commute` — *the current engine, being replaced by the claim model.*
- **openom-oplog** — the claim model's operations channel: the operation type + the set-union fold that materializes the live record set (add / remove / supersede / revoke, same-author observed-remove). Domain-agnostic, clock-free. *(claim model — the successor to the op-log half of `openom-treelog`)*

**Storage / sync** (transport; opaque bytes)
- **journal** — local-first sync backend: per-doc snapshot + append-only update-log, CAS, capability negotiation. Backend/domain/crypto-agnostic.
- **openom-sync** — the client sync loop: seal local deltas to the store, merge peers' deltas back.
- **openom-sealer** — the client sealer: a stateful session holding the unlocked DEK, sealing/opening envelopes (wasm veneer + Tauri).
- **openom-attestation-zkp** — the **dormant** ZK-deferred signed-attestation *sidecar*: a member signs a fact's content hash, independent of the tree, riding `journal`. Superseded by the claim-based `core/attest/v1` attestation; kept for a possible future ZK need, slated for deletion (release WP, OPE-109).

**Access control / identity / custody**
- **openom-keyring** — the keyring/membership mechanism: chain verification, entry authorship, signing.
- **openom-roles** — the authorization role model + capability→role policy (Viewer / Editor / Maintainer / Owner).
- **openom-vault-host** — the native (Tauri) key-custody host: keeps Sealer sessions + keyring storage in Rust so the DEK never enters the webview.

Dependencies point downward across those layers; the full graph is derivable from the `Cargo.toml`s
(`cargo tree`). *(A generated dependency table belongs here — TODO once the rollout settles.)*

## Writing a package README (the spec)

One `README.md` per crate, wired as the module doc. Sections, in this order, with **exact,
byte-stable headers** (so `grep '## Invariants' packages/*/README.md` works):

```
# <name>
> one-line purpose
**Status:** built | experimental | deprecated · role/trust-tier · design §ref (prose, no link)
**Last updated:** YYYY-MM-DD

## What it is — and is not     ← prose; the "is not" boundary is the highest-value line
## Invariants                  ← table: id | guarantee | why | verified by (a REAL test name)
## Usage                       ← one compile-valid example + the entry points
## Position                    ← one sentence: where it sits; full graph is here in packages/README.md
```

Rules:
- **README = module doc.** `#![doc = include_str!("../README.md")]` at the crate root — one source of
  truth, and ` ```rust ` fences become doctests. **Tag every non-Rust fence** (` ```sh `, ` ```json `,
  ` ```text `) or rustdoc will try to compile it.
- **Invariants are namespaced and real.** IDs like `JCS-1`, stable, never renumbered/reused; each
  `verified by` points at an existing test. **Never invent invariants to fill the table** — a crate
  with no real contract (a test harness, a thin wrapper) simply has no Invariants section. A README
  may omit any section that would be padding; it may never pad.
- **English is the contract language.** No mixed-language doc prose.
- **`apps/*` variant:** lead with **Run / verify** (commands *with* the working directory, plus the
  Windows→WSL2/Docker cargo caveat), add a **Layout** file-map, and keep Invariants only where the
  unit makes a real runtime guarantee (`src-tauri` yes; `e2e` / `test` → a short "Conventions" note).

Exemplar: **`packages/openom-jcs/README.md`.**
