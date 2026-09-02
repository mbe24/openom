# Architecture

openom is one Rust core compiled two ways — native for the desktop and mobile shell, and to WebAssembly
for the browser — behind narrow, swappable seams. The same engine, crypto, and sync run everywhere; only
the outermost shell differs.

## The seams

- **Store** — a content-agnostic backend that persists opaque snapshot + append-only-log blobs with
  compare-and-swap. Local (SQLite, IndexedDB) or remote (the zero-knowledge server) sit behind one contract.
- **CRDT** — a domain-agnostic, operation-based CRDT that merges edits deterministically.
- **Domain layer** — the family-tree model, expressed as operations over the CRDT.
- **Sealer** — the only component that holds keys; it seals and opens envelopes and never lets the data key
  cross into the webview.
- **Keyring** — the membership and role mechanism, verified on the client.

## Crates

The Rust workspace lives in `packages/`, the server in `openom/`, and the shells in `apps/`.

| Crate | Role |
| --- | --- |
| `openom-protocol` | the wire model — protobuf, shared by client and server |
| `openom-crypto` | symmetric primitives — AEAD seal/open, Argon2id KDF, HPKE key-wrap |
| `openom-roles` | the capability→role policy — one source of truth for the server ACL and client verify |
| `keyeo-chain` | the membership mechanism — signed keyring chain + landed-entry authorship |
| `openom-sealer` | the client seal/open session (WebAssembly on web, native in Tauri) |
| `openom-vault-host` | the native key-custody host — the data key stays in Rust |
| `openom-sync` | the client sync loop — seal local deltas, merge peers' deltas back |
| `openom-claim` | the claim envelope — content-hash id, dedup fingerprint, domain-separated sign/verify |
| `openom-crdt` | the claim model's set-union operation CRDT (`materialize` fold; no storage) |
| `openom-tree` | the claim-model family-tree engine — composes `openom-crdt` + `openom-projection` |
| `openom-projection` | the read-time projection — the live claim set → a materialized read model |
| `journal` | a generic sync-backend store — snapshot + append-only log + compare-and-swap |

`journal` carries no `openom-` prefix on purpose — it is domain-agnostic and reusable.

The shells are `apps/app` (the buildless web app, also served inside the Tauri webview) and `apps/src-tauri`
(the desktop and mobile shell — window, native SQLite, key custody). The server crate `openom` is Axum on
AWS Lambda: a zero-knowledge blob store backed by Neon and Cloudflare R2.
