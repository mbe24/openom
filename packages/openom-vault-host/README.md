# openom-vault-host

The native **keyring/watermark custody seam** for the openom Tauri host: the [`VaultStore`] trait and its
durable `SQLite` backing ([`sqlite::SqliteVaultStore`]).

A tree's keyring is a *wrapped* DEK — not secret, but it must survive a relaunch — and its watermark is the
engine-opaque anti-rollback cursor. `VaultStore` persists both, and `commit_keyring` writes them in **one
transaction** so a crash can never leave the stored anchor disagreeing with its cursor. It's kept in its own
file (`vault.sqlite`), separate from the doc/blob store, so copying or restoring the tree database can't drag
the anti-rollback watermark backward with it.

The trait is injected, so the native host is testable with an in-memory fake and, on Tauri, backs onto
`SqliteVaultStore` (behind the `sqlite` feature).

## Scope

This crate is *only* the custody seam. The DEK, the keyring engine (chain/dag), the claim engine, the local
device store, and the whole passphrase + sharing lifecycle now run natively in
[`openom-app-core-host`](../openom-app-core-host), which is parameterized over a `VaultStore`. The older
thin-custody `VaultHost` that once lived here (holding live sealer sessions + the full lifecycle in this crate)
was superseded by that full-native-core host and has been removed.
