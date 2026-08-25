# apps/src-tauri

> the Tauri v2 native shell — builds the desktop (Windows/macOS/Linux) and Android apps around
> `apps/app/`, wiring the shared Rust core to the webview through `#[tauri::command]`.

**Status:** built · thin wrapper crate, load-bearing (the only path to desktop/Android) · no
design doc of its own (wires `openom-vault-host`'s vault lifecycle + `journal`'s doc store to
Tauri)

**Last updated:** 2026-08-25

## Run / verify

Type-check only, from the repo root (Windows blocks native cargo build scripts here, so
`scripts/cargo.mjs` routes through WSL2/Docker automatically):

```sh
node scripts/cargo.mjs check -p openom-tauri
```

This crate has no `#[cfg(test)]` of its own, and `cargo test -p openom-tauri` is **not** the
verification path here — confirmed by running it: building a *test* binary pulls in Tauri's Linux
webview stack (webkit2gtk/gdk/pango), which the headless container `cargo.mjs` uses doesn't have,
and it fails at the `gdk-sys` build script (`Package 'gdk-3.0' ... not found`). `cargo check`
above succeeds because it stops short of that link step. The custody logic this crate wraps is
tested where it lives — `node scripts/cargo.mjs test -p openom-vault-host` — headless, no webview
needed.

Real verification is running the app. From `apps/`:

```sh
pnpm dev             # tauri dev — desktop window. Works directly unless this machine's
                      # build-script policy blocks a freshly-built cargo binary ("Access is
                      # denied (os error 5)") — see VERIFY.md Step 0; if it does, build under WSL2.
pnpm android:init    # one-time: generates src-tauri/gen/android
pnpm android:dev     # build + install + launch on an emulator/device — on Windows this needs
                      # WSL2 (native cargo is blocked); see WSL-SETUP.md for the full path
                      # (mirrored networking, Linux Android SDK/NDK, cloning into ext4).
```

Then work through the runtime checklist in **VERIFY.md** — provision/durability, change-passphrase
invalidation, tamper/rollback messaging, auto-lock, crash consistency, desktop and Android — it
isn't duplicated here. **WSL-SETUP.md** has the full Windows→WSL2 Android bring-up.

## What it is — and is not

The Tauri v2 native shell: it builds the desktop app and the Android app around the same
`apps/app/` web frontend and exposes the Rust core to it through `#[tauri::command]` invoke
handlers. Two pieces of managed state: `AppStore` (opaque ciphertext persistence — the doc store,
unchanged in spirit from the web app's) and `Vault = Arc<VaultHost<SqliteVaultStore>>` — the
key-custody host. The custody boundary is the reason this crate exists as a distinct native shell
at all: the DEK lives in `VaultHost`, inside this process, and **never crosses the `invoke`
boundary into the webview**. Every vault command hands JS back an opaque `sealerId` plus public
metadata — never key material. The two SQLite files it opens in the Tauri app-data dir
(`tree.sqlite`, `vault.sqlite`) are kept deliberately separate, so a copied/restored tree can't
drag the anti-rollback watermark along with it.

It is **not** where the logic or the tests live. Every `#[command]` here is a thin wrapper: it
(de)serializes arguments, runs the Argon2id-bearing flows
(`provision`/`unlock`/`recover`/`change_passphrase`, and sharing) as `async` +
`spawn_blocking` so the ~1s KDF doesn't freeze the Tauri IPC main thread, and calls straight into
`openom-vault-host`'s `VaultHost` or `journal`'s `DocStore`. The substance — and the real,
cargo-testable contract — lives in those crates, which build without `tauri`; see
`packages/openom-vault-host/README.md` for the custody guarantees this crate just wires up. This
crate also does not implement mobile hardening (mandatory background-lock, `FLAG_SECURE`,
hardware-gated biometrics) — that's the not-yet-built `openom-mobile` Tauri plugin (see VERIFY.md,
"Not yet built (Phase 2)").

## Invariants

None namespaced here. `src/lib.rs`'s own doc comment says why directly: this file "can't be
`cargo test`-ed in the headless container (the `tauri` crate needs system webview libs)" —
confirmed above — so it carries no test-backed contract of its own to table. The real, tested
custody guarantees (`VAULT-1`…`VAULT-8`: sessions fail closed after lock/clear, a rollback is
refused *before* a sealer is ever registered, change-passphrase/recover re-wrap the DEK rather
than rotating it, a remote keyring run is validated before being trusted, …) belong to
`openom-vault-host`; see `packages/openom-vault-host/README.md`.

## Layout

```text
apps/src-tauri/
├── Cargo.toml              # package `openom-tauri`, lib name `openom_lib`; deps: journal,
│                           # openom-vault-host (sqlite feature), tauri
├── build.rs                 # tauri-build codegen
├── tauri.conf.json           # window, CSP, bundle icons, identifier org.openom.app
├── capabilities/default.json # Tauri v2 capability/permission grant for the webview
├── src/
│   ├── main.rs               # binary entry point → openom_lib::run(); on Windows, suppresses
│   │                         # the console window in release builds
│   └── lib.rs                # #![doc = include_str!("../README.md")] + every #[tauri::command]:
│                             # store_* (doc store), vault_* (passphrase lifecycle + sharing),
│                             # sealer_* (seal/open/lock) — plus run(): the Tauri Builder, the
│                             # two managed states, and invoke_handler registration
├── icons/                    # generated from assets/icon.svg (repo root is the source of truth)
├── gen/android/              # generated Android project (from `pnpm android:init`)
├── VERIFY.md                 # the runtime checklist — desktop + Android bring-up
└── WSL-SETUP.md              # Windows→WSL2 Android build path (native cargo is blocked here)
```
