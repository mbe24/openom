# apps/test
> one-line: the vitest unit + integration suite
**Status:** built · test harness · (no design ref)
**Last updated:** 2026-08-25

## Run
```sh
cd apps && pnpm test:core
```
`test:core` runs `node ../scripts/vitest.mjs`, which shells out to vitest inside a Linux
container (this host's supply-chain policy blocks esbuild's install script on the Windows
host's pnpm) — no local vitest install needed, just Docker.

## What it covers
Core client modules: the sealed/sync store stack, `SealerSession` + `invokeSealer`, keyring
sync and entry verification, watermarks, replica identity, the treelog/FamilyTreeEngine swap,
and the JSON-Schema model. Two files are **seeded-chaos** integration tests, driven by
`fast-check` + a seeded PRNG so a failing run replays deterministically from its seed:
- `crashRetry.chaos.int.ts` — crashes the process at arbitrary seams in the write path and
  rebuilds over the surviving durable stores; asserts no committed edit is ever lost and no
  double-apply appears.
- `syncNetwork.chaos.int.ts` — drops the network (not the process) mid-sync, including
  lost-ack and mid-conflict-fetch cases; asserts every commit survives and all replicas
  converge with no phantom edits.

## Conventions
File suffix is the test-tier signal, picked up by `apps/vitest.config.js`'s
`include: ['test/**/*.{test,int}.{js,ts}']`:
- `*.test.ts` / `*.test.js` — unit (one unit, dependencies faked).
- `*.int.ts` / `*.int.js` — integration (two or more real units wired together).
- `*.chaos.int.ts` — integration + seeded randomness (crash-retry / network-partition).
- `*.e2e.ts` is a different tier entirely — browser tests under `apps/e2e/`, run only via
  Playwright (`pnpm test:e2e`), never picked up here.
