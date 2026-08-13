# openom — Tauri prototype

Privacy-first family tree. This prototype implements the design spec and shows the
architecture: **one Rust core library, three shells** (desktop, Android/iOS,
browser). The store is volatile — this is about navigation, layout and the
interfaces, not about persistence.

## Running it

```powershell
pnpm install
pnpm serve         # webapp on http://localhost:5173, store = IndexedDB
pnpm serve:preview # the same app inside the device frames
pnpm dev           # tauri dev — desktop window, store = rusqlite in-memory
```

`serve` is a twenty-line static server (`scripts/serve.mjs`). It exists only
because `file://` blocks ES modules and IndexedDB in some browsers — nothing is
compiled or bundled. Edit, reload, done. The phone frames are at
`http://localhost:5173/apps/preview/phones.html`.

Without Tauri **the same app** runs in the browser — there is no second build,
Tauri serves exactly the `app/` folder. Any static server does; `pnpm serve`
above is simply the one that ships with the project.

There is **no build chain**: `app/` holds ES modules the browser loads directly.
Tauri serves the sibling folder (`frontendDist: "../app"`).

Two previews sit under `preview/`: `desktop.html` shows the app at 1440×900
next to a landscape phone, `phones.html` three phone sizes side by side. Both
load the same app from `app/` — they are frames, nothing else.

### Web app and desktop — same app, four differences

| | Web app | Tauri |
|---|---|---|
| Store | `IndexedDbStore`, memory as fallback | `SqliteStore` in Rust |
| Export | download | writes a file |
| Biometrics | only via WebAuthn | the system keychain |
| Fonts | from a CDN | should ship with the app |

### Three stores, one interface

`createStore()` picks in order of durability: Rust inside Tauri, otherwise
IndexedDB in the browser, otherwise memory. It is async because only an actual
open attempt reveals whether IndexedDB works — in some browsers' private mode
the object exists but every access fails.

The browser store matters more than it looks: mobile browsers discard
background tabs after minutes, so without it someone loses their tree while
switching to another app. Later, with S3 behind Rust, the same store becomes
the offline copy and the queue for changes not yet uploaded — same interface,
different role.

The UI never notices: `createStore()` picks the provider, everything above it is
identical. There is no layout difference either — the breakpoints follow window
size, not the shell.

### Prerequisites (Windows)

- Rust ≥ 1.85 (`rustup`)
- Microsoft C++ Build Tools and WebView2 (present on Windows 11)
- Node ≥ 20 with pnpm
- SQLite is compiled in through the `rusqlite` feature `bundled` — no DLL needed

### Running cargo on a restricted host

Some machines deny executing freshly built binaries — cargo's own build scripts
fail with `Access is denied (os error 5)` before any of our code runs. `scripts/cargo.mjs`
wraps `cargo` and runs it either on the host or inside a Linux container, where
that policy does not apply. The build is unchanged; only the process that runs it
moves. The repo is bind-mounted at `/work`; the cargo registry and target dir are
cached in named volumes, so rebuilds stay incremental.

```powershell
node scripts/cargo.mjs test -p openom-store -p openom   # the conformance suite
node scripts/cargo.mjs build -p openom                  # the server crate
```

`pnpm test:store` (from `apps/`) routes through it. Pick where cargo runs with
`OPENOM_RUNNER` — `auto` (default), `local`, or `docker` — set once in a `.env`
at the repo root (copy `.env.example`). `docker` skips the host attempt entirely,
so no policy popup. The Tauri shell is **not** built this way: headless it needs
the WebKitGTK stack, so it builds through `pnpm tauri dev|build` and the desktop
CI. This wrapper is for the pure crates — `openom-store` and `openom`.

### Mobile

```powershell
pnpm android:init ; pnpm android:dev     # requires the Android SDK/NDK
pnpm ios:init                            # config only; builds need macOS
```

### Icons

Tauri needs bundle icons. Generate them once from a logo:

```powershell
pnpm tauri icon path\to\logo.png
```

## Architecture

```
openom/
├─ apps/                  die Anwendung und ihre Huellen
│  ├─ app/                das ganze Programm — Kern, Ansichten, Stile, Sprachen
│  ├─ src-tauri/          Huelle fuer Desktop, Android, iOS
│  ├─ preview/            Geraeterahmen zum Ansehen
│  ├─ scripts/            statischer Server, Sprachpruefung
│  └─ package.json
├─ packages/
│  └─ openom-store/       DocStore-Trait + memory + sqlite + Konformitaetssuite
├─ openom/                Server: S3 hinter demselben Trait
├─ docs/                  Handoff, Datenmodell, Designregeln, Svelte-Portierung
├─ Cargo.toml             Workspace
└─ README.md
```

`app/` ist nicht "das Web" — auf Android laeuft derselbe Ordner. Tauri fuegt
nichts hinzu ausser Fenster und SQLite-Store.

`openom-store` liegt bewusst weder in der Huelle noch im Server: beide brauchen
dieselbe Fassung des Vertrags, und die Konformitaetssuite laeuft gegen jede
Implementierung — auch spaeter gegen S3.

### The interfaces

The UI knows: `TreeLibrary`, `FamilyTree`, the query functions, `TreeTransfer`,
`SchemaRegistry`, `SessionController`, `syncStatus`.

A data provider implements: `DocStore`, `TreeFormat`, `AuthProvider`, `KeyStore`.
Between them sit `SyncEngine` and `TokenSource` (not implemented yet, but
foreseen).

**The DocStore does not know the data model.** Snapshots and updates are opaque
bytes — which is exactly what makes S3 or a zero-knowledge server possible later.

### Swapping the store

1. Implement `DocStore` (Rust: `packages/openom-store/src/`, JS: `apps/app/src/core/store.js`).
2. Run the conformance suite against the new implementation:

```powershell
pnpm test:store
```

The suite also checks the compare-and-swap semantics (`put_snapshot` with
`expected`) — on S3 that becomes `If-Match`, on a server a revision.

3. Register it in `createStore()` or `lib.rs`. Nothing else changes: `FamilyTree`
   and the views cannot tell the difference.

### Where Yrs comes in

`FamilyTree` currently holds maps and writes JSON ops. Later a Yrs `Doc` replaces
the maps and the op JSON becomes a Yrs update inside a protobuf envelope. Store
and views stay untouched — that is what the repository in between is for.

## What the prototype does

- Ancestor chart with marriage nodes, anchors and curved edges; fan chart
  (portrait 150°/3 rings, landscape 180°/4 rings); full graph with a
  deterministic generation layout, path highlighting (shift-click) and zoom
- Person detail, with marriages acting as a filter on the children list
- Person editor: autosave, tolerant date fields with a reading hint, custom
  fields on equal footing with the built-in ones
- People list with ICU sorting, search (⌘K)
- Settings: accent colour freely chosen within guardrails (L 30–52 %, chroma
  0.03–0.09), light/dark/system, language, schema editor, reset sample data
- Import/export: `openom-json` lossless, GEDCOM registered but `Unsupported`
- Keyboard: ⌘K search, ⌘N new person, ⌘Z/⌘⇧Z undo/redo, ↑ father, ⇧↑ mother,
  ↓ eldest child, ←→ siblings
- Lock: a dummy with a real flow — Face/Touch ID, passphrase as fallback,
  locking at launch and after never/5/30 minutes idle
- Seven languages (en, de, fr, es, ar, am, ti); Arabic mirrors the whole
  interface including chart, fan and graph
- Two sample trees, switchable in the settings
- Right-click on a graph node opens a context menu: edit the person, or add a
  relation (father and mother only appear while they are missing)

## Fonts

Newsreader covers neither Ge'ez nor Arabic. `i18n.js` holds a `FONTS` table **per
writing system**, not per language, and loads only the system the chosen language
needs. Twenty languages are therefore not twenty downloads but a handful of
writing systems, one of which loads.

In the prototype the fonts come from the Google CDN. **For Tauri they belong
beside the app**: put the `.woff2` files into `app/fonts/`, write one `@font-face`
per writing system in `app/styles/fonts.css`, and replace the CDN URL in `FONTS`
with the local path. Without a network you would otherwise get replacement boxes.

## Right to left

`LOCALES` carries `dir` per language; `loadLocale()` sets `document.dir`, `lang`
and `data-script`. The chrome is mirrored by the browser. The charts mirror **in
their coordinates**, not through a CSS transform: `mx(x) = W - x` in
`ancestors.js` and `graph.js`, the edges inside an SVG group. Reason: a flipped
surface also flips text and anchors.

One pitfall that costs time: **`scrollLeft` changes sign in RTL.** The canvases
therefore carry `direction: ltr` (CSS, `[dir="rtl"] .no-bar`) — they are
coordinate systems, not text.

Names are shortened by measured width, not by character count, and the ruler
reads its font family from the resolved `--font-name` token — a hard-coded family
would measure Newsreader while Noto Naskh Arabic renders.

## What is missing (deliberately)

Persistence, sync, encryption, biometrics, a GEDCOM parser, merge heuristics.
The interfaces are in place, the implementations are not.

## License

AGPL-3.0-or-later — see `LICENSE`.

## Brand

`apps/app/brand/` holds the mark: `wordmark.svg` (+ dark), `mark.svg` (the
monogram tile), `tree.svg`, `icon.svg` (tree in a filled disc — app icon),
`favicon.svg`, and the two 1280 × 640 previews `social-github.png` and
`social-web.png`. The source for the two PNGs is `apps/preview/social-source.html`;
re-render it if the wording changes.

Upload `social-github.png` under Settings → Social preview. The web app carries
`social-web.png` itself through `og:image` — it promises something different
from the repository.

## Documents

- `HANDOFF.md` — screen map, design tokens, open points
- `DATA-MODEL-V2.md` — the document format and what is deliberately missing
- `DESIGN-RULES.md` — binding layout rules; breaking them reads as a bug
- `migration.svelte.md` — porting the interface to Svelte 5

## Continuous integration

Four workflows instead of one, because they answer different questions and
cost very different amounts of time:

| File | Runs on | What it answers |
|---|---|---|
| `web.yml` | every push and PR | Does every module parse, are all seven locales complete? Seconds, no toolchain. |
| `pages.yml` | every push to main | Publishes the webapp to GitHub Pages. The app is served at the root, the device frames at `/preview.html`. |
| `desktop.yml` | every push and PR | Tauri build on Windows, macOS and Linux, plus the store conformance suite (`cargo test`). |
| `mobile.yml` | tags and manual runs | Android APK and an unsigned iOS simulator build. Only on demand — the SDKs make every run expensive and nothing about them changes day to day. |

The locale check lives in `scripts/check-locales.mjs` and can be run locally
with `node scripts/check-locales.mjs`.

### Pages

Enable it once under Settings → Pages → Source: **GitHub Actions**. Nothing is
built: `app/` is copied as-is, the same folder Tauri loads. The store falls back
to the in-memory implementation there, so the published version is a place to
click around, not to keep a tree in.
