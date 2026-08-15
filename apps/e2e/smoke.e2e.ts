import { test, expect } from '@playwright/test';

// Pipeline smoke: proves the Playwright-in-Docker + serve.mjs setup works, and that the app
// boots through the REAL WASM sealer (the dev-key path) — the tree only shows names if the
// sealed snapshot/deltas decrypt in the browser. This is the harness the worker-layer e2e
// tests build on.
test('the app boots and renders the (encrypted) demo tree', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto('/app/index.html');
  await expect(page.locator('body')).toContainText('Bach', { timeout: 20_000 });
  expect(errors, 'no uncaught page errors during boot').toEqual([]);
});
