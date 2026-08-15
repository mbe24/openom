import { test, expect } from '@playwright/test';

// Pipeline smoke: proves the Playwright-in-Docker + serve.mjs setup works, and that the app
// boots through the REAL WASM sealer (the dev-key path) — the tree only shows names if the
// sealed snapshot/deltas decrypt in the browser. This is the harness the worker-layer e2e
// tests build on.
// @integration — boots the WHOLE app (~29s). Excluded from the default `test:e2e` run;
// invoke explicitly with `pnpm test:e2e:full`. Kept as a coarse "the app still boots through
// the crypto path" check; the fast, targeted crypto tests live in the other e2e files.
test('the app boots and renders the (encrypted) demo tree @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto('/app/index.html');
  await expect(page.locator('body')).toContainText('Bach', { timeout: 20_000 });
  expect(errors, 'no uncaught page errors during boot').toEqual([]);
});
