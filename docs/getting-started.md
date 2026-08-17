# Getting started

## Prerequisites

- Node ≥ 20 with pnpm
- Rust ≥ 1.85 (for the desktop/mobile shell and the Rust tests)
- On Windows: the Microsoft C++ Build Tools and WebView2 (present on Windows 11)

SQLite is compiled in through `rusqlite`'s `bundled` feature — there is no separate database to install.

## Run the web app

pnpm commands run from `apps/`:

```sh
pnpm install
pnpm serve   # web app on http://localhost:5173 (store = IndexedDB)
```

There is no build chain: `pnpm serve` is a small static server that exists only because `file://` blocks ES
modules in some browsers. Edit a file, reload, done.

## Run the desktop shell

```sh
pnpm dev     # tauri dev — a desktop window, backed by native SQLite
```

Tauri serves the same `apps/app/` folder the browser does, so the two shells run one app — there is no
second build.
