# keyeo-core

> The keyeo engine-family SEAM: the generic membership/signing trait types every keyeo engine binds
> to — the `Role`, `SignatureScheme` (Ed25519 via edsign), and `CanonicalBytes` seams, plus the M-of-N
> `Requirement`.

**Status:** built · Layer-0 seam types · design keyring-dag/design.keyeo-engine-family.md (OPE-306)
**Last updated:** 2026-09-03

## What it is — and is not

This crate is the fully-generic vocabulary the keyeo engine (`keyeo`) and any future keyeo engine share,
extracted so the seam is defined once, below every engine. It owns four pieces, all domain-free:

- **`Role`** — the pluggable role model (`grants_at_least`); role *values* are the caller's.
- **`SignatureScheme` + `SigError` + `Ed25519`** — the pluggable signature seam and its one concrete
  scheme. `Ed25519::verify` goes through [`edsign`] (`verify_strict`), so small-order / torsion keys and
  non-canonical signatures are rejected — the single Ed25519 verify path every engine shares, with no raw
  `ed25519-dalek` edge.
- **`CanonicalBytes` + `Postcard`** — the canonical-bytes seam (the single definition of "the bytes" a
  signature and a content id bind to) and the postcard default for `Serialize` sub-fields. The concrete
  block-layout encoders and the by-hand impls for an engine's own payload types name engine types and so
  live in the engine crate; they route their `Serialize` fields through `Postcard`.
- **`Requirement`** — the generic M-of-N quorum requirement over member ids, fail-closed. The
  `QuorumPolicy` that *produces* a `Requirement` from resolved membership state is engine-coupled and
  stays engine-side.

It is **not** an engine: it holds no DAG, no resolver, no `GroupState`, no `MembershipAction`, no HPKE,
and no storage. It is openom-free and `ed25519-dalek`-free (Ed25519 via `edsign`), so it is
standalone-publishable.

## Position

Layer 0 — the seam types beneath the keyeo engine. `keyeo` depends on it and re-exports its types
(`Role`, `SignatureScheme`, `SigError`, `Ed25519`, `CanonicalBytes`, `Requirement`) so existing
`keyeo::X` consumers are unaffected. It depends only on `serde`, `postcard`, `edsign`, and `thiserror`.
Full dependency graph: see `packages/README.md`.

Run: `node scripts/cargo.mjs test -p keyeo-core` (from the repo root; on Windows cargo runs under
WSL2/Docker).
