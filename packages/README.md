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
- **The engine (pre-release, zero users).** The app runs on the **claim model**: `openom-claim` /
  `openom-projection` (data) + `openom-crdt` / `openom-tree` (operations + engine) over an operations
  channel. The former treelog engine (`openom-treelog`) and its op-CRDT (`commute` / `commute-format`)
  have been **removed**. `openom-model` (the older flat model) remains as legacy. A crate's `Status`
  line says where it stands.

## The crates, by layer

**Foundations** (pure; no domain knowledge)
- **openom-jcs** — RFC 8785 canonical JSON bytes; the substrate under every content hash.
- **openom-did** — `did:key` encode/decode (Ed25519) + `member_id` ⇄ `did:key` resolution.
- **openom-edtf** — EDTF (ISO 8601-2) date parser/normalizer → sortable `[min,max]` bounds.
- **keyeo-crypto** — generic, openom-free symmetric + HPKE primitives: typed secrets, Argon2id KDF, HKDF root split, HPKE DEK wrap, AEAD cores, recovery-code codec. Shared by `openom-crypto` and `keyeo`. openom-free.
- **openom-crypto** — the proto-bound sealing layer: binds the protobuf `Header` as AAD, builds envelopes, wraps DEKs (client & server, identical algorithms), standing on `keyeo-crypto` (→ `keyeo-crypto`) for the primitives.
- **openom-protocol** — shared protobuf data model (prost, generated via buf).
- **edsign** — the single Ed25519 dependency edge: newtypes whose only verify is `verify_strict`, so the weak path is uncallable elsewhere (compile-time signature-verification policy). openom-free.

**Family-tree data model**
- **openom-claim** — claim-envelope hashing + signing: content-hash `id`, dedup `fingerprint`, domain-separated Ed25519 sign/verify. *(claim model — the direction)*
- **openom-projection** — read-time projection: the claim record set → a materialized read model, a pure function of the records. *(claim model)*
- **openom-model** — the older canonical flat id-keyed model + JSON-Schema validator. *(legacy — superseded by the claim model)*

**Operations / CRDT** (how changes converge)
- **openom-crdt** — the claim model's convergent operation layer (a CRDT): the operation types + their set-union merge (`materialize`) folding a set of ops into the live record set (add / remove / supersede / revoke, same-author observed-remove). Not a log — owns no storage. Domain-agnostic, clock-free. *(claim model)*
- **openom-tree** — the claim-model family-tree **engine**: composes `openom-crdt` (the fold) + `openom-projection` (the read model) into the app's read+write surface; owns the record set + author id, mints op batches for the transport to seal, and projects the read model. Key-less. *(claim model — the app's only family-tree engine; wasm veneer built)*

**Storage / sync** (transport; opaque bytes)
- **blobstore** — the storage swap seam: content-addressable blobs + per-object CAS, *below* `journal::DocStore`. The managed (R2) and BYO-dumb (Drive/Dropbox) backends are both just `BlobStore` impls. openom-free.
- **journal** — local-first sync backend: per-doc snapshot + append-only update-log, CAS, capability negotiation. Backend/domain/crypto-agnostic.
- **docsync** — a generic local-first client sync loop (push/pull/compact/bootstrap) over a `DocStore`, abstracted over a merge `Engine` + envelope `Sealer`; the vendored set-union sync-client skeleton. openom-free.
- **openom-sync** — the client sync loop: seal local deltas to the store, merge peers' deltas back.
- **openom-sealer** — the client DEK session: a stateful sealer holding the unlocked DEK, sealing/opening envelopes. Engine-free (no keyring dep).

**Access control / identity / custody** — the keyring stack, two swappable engines behind one seam
- **keyeo** — Layer 0: the generic, domain-free group-membership/access-control DAG engine (sequencer-free; resolves signed ops → members + shared keys); its crypto primitives come from `keyeo-crypto` (→ `keyeo-crypto`). openom-free.
- **keyeo-api** — Layer 1: the engine-agnostic seam — `MembershipView`, the keyless `KeyringVerifier`, `EngineKind`, the `ROLE_*` convention. openom-free.
- **openom-keyring** — Layer 2, the **chain** engine: the linear signed keyring (protobuf wire), chain verification, entry authorship, signing. openom-coupled.
- **keyeo-dag** — Layer 2, the **dag** engine: openom's roles/signing/recovery wired onto `keyeo`. openom-free (standalone-publishable).
- **openom-vault** — the lifecycle layer over both engines: provision/unlock/recover/change-passphrase + membership authoring behind `KeyringLifecycle`, with `AppVault` dispatching on the tree's `EngineKind`; owns the engine-neutral sealing core + the browser wasm veneer. openom-coupled.
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
