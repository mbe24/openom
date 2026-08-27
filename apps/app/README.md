# apps/app

> The buildless web client — plain ES modules the browser loads directly, driving the same Rust
> core (via wasm) that Tauri bundles for desktop/mobile.

**Status:** built · the web shell of the one-core-three-shells architecture · design §ref: none
(the module-level `§`-refs — SERVER-DATA-FORMAT, the launch-gate design — live inline in the
`core/` files they govern, not in one apps/app-level doc)

**Last updated:** 2026-08-25

## Run / verify

All commands run from `apps/` (this unit has no `package.json` of its own — `apps/package.json`
is the one that defines these scripts).

```sh
cd apps
pnpm install
pnpm serve                 # this app on http://localhost:5173 (store = IndexedDB); serve.mjs is a
                            # tiny static server, needed only because file:// blocks ES modules/IndexedDB
pnpm serve:preview          # serves apps/preview/desktop.html instead, same server
pnpm test:core              # unit (*.test) + integration (*.int) tests for src/, via vitest
pnpm test:e2e               # Playwright, browser-driven (excludes @integration-tagged specs)
pnpm test:e2e:full          # Playwright, the full suite including @integration specs
pnpm check:locales          # every locale in app/locales/ carries the same keys as en.ftl
```

`pnpm test:core` runs vitest **inside a Docker container** (`node ../scripts/vitest.mjs`) — not
because of cargo, but because this host's supply-chain policy makes `pnpm install`'s esbuild
build-script check fatal; a container's pnpm has no such policy. Docker Desktop must be running.

Two things this app *depends on* but does not itself build:

- **The wasm engines** (`src/vendor/sealer/`, `src/vendor/tree/`) are generated, gitignored
  output — `node scripts/build-sealer.mjs` / `node scripts/build-tree.mjs` **from the repo
  root**. Both compile Rust→wasm inside Docker (the host can't run cargo build scripts under
  company policy — same reason `scripts/cargo.mjs` uses Docker/WSL2 for native crate tests), then
  run `wasm-bindgen` on the host. Run these once before `pnpm serve` if `src/vendor/{sealer,tree}/`
  is empty.
- **`pnpm test:store`** (from `apps/`) runs `node ../scripts/cargo.mjs test -p journal -p openom`
  — the native-crate store-conformance suite, not this app's JS — and on Windows that cargo run
  goes through WSL2/Docker too.

## What it is — and is not

This is the **web binding** of the shared Rust core: plain `<script type="module">` ES modules
(`src/main.js` as the entry point, loaded from `index.html`), served as static files. There is no
bundler, no transpile step, no `dist/` — the file you edit is the file the browser runs. Tauri
bundles this exact same `apps/app/` tree for the desktop/mobile shell, so the boundary is load-bearing:
**no bundler, framework, or build step may be introduced into `src/`** — anything that needed one
would no longer be the same tree Tauri serves.

It talks to the family-tree engine and the crypto sealer as **wasm modules vendored under
`src/vendor/`** (openom-tree and openom-sealer, compiled from `packages/`) — this app owns no
domain logic in Rust and re-implements none of it in JS; `src/core/` is the JS orchestration
*around* those wasm cores (storage, sync, sessions), not a parallel engine. openom-tree is the
claim-model engine (an openom-crdt set-union fold + an openom-projection read model); it replaced
the former treelog engine at the claim-model cutover.

It is **not** a general-purpose SPA: there is no client-side router beyond the app's own
`data-view` state, no CSS framework, and no dependency-injection container — `src/ui/dom.js`'s `h()`
plus `tree.revision`-driven re-render is the entire rendering model.

## Layout

```
index.html            entry HTML: loads src/main.js as a module, %SITE_URL%/%DEMO% placeholders
                       substituted at serve/deploy time.
src/main.js            wires the store stack, the sealer/vault, the lock policy, and the view
                       router into one running app.

src/core/              orchestration — no UI, no rendering.
  store.js               DocStore contract: opaque-bytes persistence (memory / IndexedDB / Tauri).
  indexedDbStore.js       the browser DocStore implementation.
  storeStack.js           composition root: assembles the store layers by mode, fail-closed
                          (real user data is always sealed; only demo data may be plaintext).
  sealedStore.js          DocStore decorator: seals on write, opens on read — everything below
                          only ever sees ciphertext.
  syncStore.js            layers remote sync over a durable local DocStore; surfaces conflicts,
                          does not resolve them (it only ever handles opaque bytes).
  sync.js                 SyncController: client half of the delta-log sync protocol.
  syncedDeltaSync.js       wires SyncController together with landed-entry verification (§B3).
  replicator.js            drives a SyncStore to convergence: pull/push + the plaintext merge loop.
  remoteStore.js           DocStore over HTTP to the openom server (opaque bytes, no crypto).
  familyTree.js            the opened tree, backed by the openom-tree claim engine (wasm). The engine
                           owns a monotonic HLC and stamps each op's createdAt itself (no JS clock).
  tree/                    the web shim over packages/openom-tree (wasm): index.js wraps the engine.
  tabSync.js               cross-tab convergence via BroadcastChannel (merge-the-tail on append).
  sealer/                  the crypto vault + session, see below.
  model.js                 the v2 document shape (names/events/parent+child links).
  queries.js, sort.js, dates.js   read-side helpers: ancestor/descendant walks, collation, tolerant
                           date parsing.
  library.js, seed.js, seedKhaldun.js, schema.js   the bundled demo datasets + custom-field defs.
  identity.js              device id + logical clock, persisted across restarts.
  session.js               the local-only (no-account) auth stand-in.
  lockPolicy.js            decides WHEN to auto-lock; platform-agnostic (calls back into the app).
  watermarks.js            anti-rollback: refuses a keyring/snapshot older than one already seen.
  blobs.js                 content-addressed file storage, alongside the document not inside it.
  transfer.js               format-independent import/export (e.g. GEDCOM).
  theme.js                 accent-color picker, clamped to a readable/contrast-safe range.
  profile.js                opt-in hot-path timing, no-op unless explicitly enabled.
  i18n.js                  Fluent-backed translation lookup + locale switch.

src/core/sealer/        the crypto vault: the sole holder of key material.
  index.js                 entry point: createAppVault() (passphrase vault) / createLibrarySealer()
                           (demo, dev key). Backend-selects web-worker vs. Tauri invoke.
  vault.js, keyringStore.js, invokeSealer.js   web vault orchestration, keyring persistence, and
                           the Tauri-invoke backend (DEK stays in the Rust host, never the webview).
  workerSealer.js, sealer.worker.js   the main-thread Comlink handle and the actual crypto worker
                           (the only place unlocked keys live on web).
  session.js, entryVerifier.js   the stateful seal/open bridge, and the launch-gate entry verifier.

src/ui/                generic view-layer helpers, no domain knowledge.
  dom.js                   h()/render(): the whole "framework" — no vdom, no framework dependency.
  components.js             shared widgets (portrait/initials tile, person card, etc).
  icons.js, menu.js, popover.js, personPicker.js, viewport.js   icon set, dropdown/menu, anchored
                           popovers, the person-search picker, and the narrow/compact breakpoints.

src/views/             one file per screen, composed from ui/ + core/ read helpers: ancestors.js,
                       detail.js, editor.js, fan.js, gate.js (pre-unlock flow), graph.js,
                       onboarding.js, people.js, settings.js, transfer.js.

src/vendor/            generated + third-party, never hand-edited.
  sealer/, tree/          wasm-bindgen output for openom-sealer / openom-tree — gitignored,
                          rebuilt by scripts/build-sealer.mjs / build-tree.mjs (repo root).
  sqlite/                 vendored sqlite-wasm (OPFS-SAHPool) bundle, checked in — the persistent
                          browser-SQLite spike (apps/e2e/sqlite*.e2e.ts exercises it).
  comlink.js, fluent.js   vendored third-party libraries (worker RPC, Fluent i18n runtime).

locales/               one .ftl file per language (en.ftl is the reference; check:locales enforces
                       key parity across the rest).
fonts/                 vendored woff2 subsets (vendor-fonts.mjs) — never fetched from a CDN at
                       runtime.
styles/                tokens.css (design tokens), app.css (app styles), fonts.css (@font-face).
```

## Conventions

- **Module boundary = file boundary.** Every `src/` file is a plain ES module imported by
  relative path; there is no barrel/index re-export convention to keep in sync.
- **Layer discipline in `core/`:** each store-stack file states, in its header comment, exactly
  what it does *not* do (e.g. `syncStore.js` surfaces conflicts but never resolves them;
  `remoteStore.js` moves bytes but knows nothing about encryption) — preserve that when editing;
  collapsing layers to "simplify" reintroduces the coupling they were split to avoid.
- **Tests:** `.test` = unit (dependencies faked), `.int` = integration (two-plus real units
  wired together) — both under `apps/test/`, run by vitest. `.e2e` = browser, under `apps/e2e/`,
  run by Playwright only.
