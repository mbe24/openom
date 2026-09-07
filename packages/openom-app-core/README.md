# openom-app-core

The web app's **one Rust core**, built to run inside a single Web Worker (wasm). It owns the claim
engine ([`openom-data-tree`]), the DEK sealer session ([`openom-sealer`] / [`openom-vault`]), the
[`docsync`] sync loop (via [`openom-docsync`]), and one **local durable** [`store-log`] `DocStore`.

A thin, synchronous [`Replicator`] bridges the local log to the server: it scans the local store for
this replica's own sealed deltas to push, and folds server deltas back into the local store (which the
docsync loop then merges into the engine). The only asynchrony is a ~1-screen JS worker-driver that
does `fetch` around these synchronous Rust steps — so JS shrinks to UI plus one network transport.

Store model: **one local log + cursors** (a `push_scan` local cursor, a `server_cursor` for the
server's `?since`), not a second `origin/` mirror — CRDT set-union needs no diff, so there is nothing
to rebase against. See `plan/sync/design.max-rust-app-core.md`.

[`openom-data-tree`]: ../openom-data-tree
[`openom-sealer`]: ../openom-sealer
[`openom-vault`]: ../openom-vault
[`docsync`]: ../docsync
[`openom-docsync`]: ../openom-docsync
[`store-log`]: ../store-log
