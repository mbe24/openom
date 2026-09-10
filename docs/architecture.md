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
- **Keyring** — the membership and role mechanism, verified on the client, behind two swappable engines
  (a linear signed chain and a sequencer-free DAG) sharing one seam.

## Crates

The Rust workspace lives in `packages/`, the server in `openom/`, and the shells in `apps/`. This is the
principal set; `packages/README.md` is the authoritative, per-crate map — every crate, its invariants, and
the full dependency graph.

| Crate | Role |
| --- | --- |
| `openom-protocol` | the wire model — protobuf, shared by client and server |
| `openom-crypto` / `keyeo-crypto` | the proto-bound sealing layer + the generic symmetric/HPKE primitives beneath it |
| `edsign` | the single Ed25519 edge — newtypes whose only verify is `verify_strict` |
| `openom-data-model` | the claim envelope — content-hash id, dedup fingerprint, domain-separated sign/verify |
| `openom-data-projection` | the read-time projection — the live claim set → a materialized read model |
| `openom-data-crdt` | the claim model's set-union operation CRDT (`materialize` fold; no storage) |
| `openom-data-tree` | the claim-model family-tree engine — composes `openom-data-crdt` + `openom-data-projection` |
| `store-log` / `store-blob` | the snapshot + append-only-log `DocStore`, and the content-addressable blob store beneath it |
| `openom-docsync` | the client sync loop — seal local deltas, merge peers' deltas back |
| `openom-sealer` | the client seal/open DEK session (WebAssembly on web, native in Tauri) |
| `openom-roles` | the capability→role policy — one source of truth for the server ACL and client verify |
| `keyeo-chain` / `keyeo-dag` | the two generic membership engines — a linear signed chain and a sequencer-free DAG |
| `openom-keyring-chain` / `openom-keyring-dag` | openom's roles/signing/recovery wired onto each engine, behind `openom-keyring-api` |
| `openom-vault` | the keyring lifecycle over both engines — provision/unlock/recover + the engine-neutral sealing core |
| `openom-vault-host` | the native key-custody host — the data key stays in Rust |
| `openom-app-core` | the web app's single wasm worker — engine + sealer + sync + local store |

The openom-free foundations (`format-jcs`, `format-edtf`, `did`, `edsign`, `keyeo-*`, `store-log`, `store-blob`,
`docsync`) carry no `openom-` domain dependency on purpose — they are reusable and never gain that coupling.

The shells are `apps/app` (the buildless web app, also served inside the Tauri webview) and `apps/src-tauri`
(the desktop and mobile shell — window, native SQLite, key custody). The server crate `openom` is Axum on
AWS Lambda: a zero-knowledge blob store backed by Neon and Cloudflare R2.
