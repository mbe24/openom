# apps/e2e
> one-line: the Playwright browser e2e suite
**Status:** built · test harness · (no design ref)
**Last updated:** 2026-08-25

## Run
One-time: `cd apps && pnpm install --ignore-scripts && pnpm exec playwright install chromium`
Then, from `apps/`: `pnpm test:e2e` (default — excludes `@integration`) or `pnpm test:e2e:full`
(everything). Playwright starts `scripts/serve.mjs` itself; see `apps/playwright.config.js`.

```sh
cd apps
pnpm test:e2e
```

## What it covers
- `vault.e2e.ts` + `vault-harness.html` — the compiled WASM sealer/vault alone (no app boot):
  cross-device unlock, wrong-passphrase rejection, ciphertext-at-rest.
- `worker.e2e.ts` + `worker-harness.html` — the same, through the real Web Worker + Comlink
  boundary (provision/seal/open proxied to the worker; keys never leave it).
- `sqlite.e2e.ts` + `sqlite-harness.html` / `sqlite-harness.worker.js` — WASM SQLite over the
  OPFS-SAHPool VFS, run in a module Worker; asserts data survives a page reload, header-free
  (no COOP/COEP).
- `smoke.e2e.ts` (`@integration`, `test:e2e:full` only) — boots the whole app: welcome/demo gate,
  create → recovery code → onboarding → reload/unlock, change-passphrase, lock-now, and
  forgot-passphrase recovery.

## Conventions
`.e2e.ts` = Playwright browser test (vitest only matches `*.test`/`*.spec`, so these are
invisible to it). Specs live in `./e2e`; a matching `*-harness.html` loads just the WASM/worker
under test with no app shell. Tests tagged `@integration` boot the full app and are excluded
from the default `test:e2e` run.
