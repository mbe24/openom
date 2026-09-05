# keyeo-linear

> A generic **linear signed-membership-chain engine** over `<Id, Role, Sig>`: an ordered log of membership
> states where each revision N→N+1 is signed by a quorum of derived signers under a per-group governance
> rule, with a recovery authority and an anti-rollback floor. The domain-neutral core of openom's keyring
> chain.

**Status:** built · generic engine · design keyring-dag/design.keyeo-engine-family.md §4 (OPE-310)
**Last updated:** 2026-09-04

## What it is — and is not

`keyeo-linear` is the domain-neutral core extracted from openom's keyring chain, mirroring how `keyeo-dag`
is a generic DAG membership engine. It owns the *structure* of a linear membership chain and nothing about
any particular payload:

- the transition structure (revision N→N+1, chained by hash, an anti-rollback floor);
- signer-quorum checking and governance-threshold evaluation (founder-only / founder-or-unanimity /
  founder-or-threshold / pure-threshold);
- the recovery / re-key authority model (establish is privileged; rotate needs the old authority);
- the walk (`verify_walk` / `verify_transition` / `verify_reset`) and the two bootstraps;
- the canonical, domain-separated **signing bytes** the engine builds from the doc's own accessor values.

It is **not** a wire format and holds no payload: no proto, no key-epochs, no DEK wraps, no HPKE, no
storage, no server contract. Those live in the openom binding. It is openom-free and `ed25519-dalek`-free
(Ed25519 via `keyeo-core` → `edsign`), so it is standalone-publishable.

## The model

- **`LinearDoc`** — a candidate membership doc the binding implements. Its accessors expose the group id,
  revision, prev-hash, layout version, the FULL member set (roles + author keys), the governance rule, the
  recovery authority, the unattributed signature set, an opaque `payload_commitment`, and a `structure_ok`
  gate. The engine derives the *signer* set from the members via `LinearRole::is_signer` — there is no
  separate signer roster, so signer authority and member role can never drift apart.
- **Engine-owned signed bytes.** The engine encodes its signed message from the *same* accessor values it
  reasons on (`signing_bytes`), so "what decides == what is signed". The encoder is an exhaustive
  `#[deny(unused_variables)]` destructure: adding a signed field is a compile error until it is handled.
  The rest of the binding's payload is bound through the opaque `payload_commitment` (which the binding
  computes and the engine only hashes into the message).
- **`structure_ok` is engine-invoked.** It is a required `LinearDoc` method the engine calls at every entry
  point (including per hop in `verify_walk`) — the un-skippable wrap-completeness / epoch-ordinal /
  layout-bound gate a binding cannot forget to wire.
- **`Anchor`** — a doc *whose legitimacy the chain-walk has established*: the trust state a caller
  persists (group id, revision, doc hash, the derived signer set, governance, recovery authority) and
  passes back as `prior`. A `verify_*` call is the only way to mint one over a candidate, so an unverified
  doc cannot be mistaken for a trusted anchor (the guarantee is a type, not a comment).

## Type-safe + zero-cost

Newtypes throughout (`GroupId` / `Revision` / `DocHash` / `PayloadCommitment` / `Signer`) — no primitive
soup, so a caller can't cross a commitment with a doc hash. The engine is monomorphized (no `dyn` on the
core path). `verify_transition` returns a distinct *verified* `Anchor`, and the signed-bytes encoder's
exhaustive destructure makes an unsigned field a compile error.

## Position

A generic engine on `keyeo-core` (`Role`, `SignatureScheme` + `Ed25519`, `CanonicalBytes`, `Requirement`).
Its reference concrete instantiation — `Id = String`-ish member ids, openom's role ladder, `Ed25519` — is
**openom-keyring-chain** (OPE-300), which adds the proto `Keyring` wire, the key-epoch / DEK payload, and
the `ChainVerifier` seam. Full dependency graph: see `packages/README.md`.

Run: `node scripts/cargo.mjs test -p keyeo-linear` (from the repo root; on Windows cargo runs under
WSL2/Docker).
