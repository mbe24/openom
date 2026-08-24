import { test, expect } from '@playwright/test';

// Persistent SQLite in the browser via the OPFS-SAHPool VFS — the phase-0 substrate spike, as a
// regression. A module Worker runs WASM SQLite loaded from app/src/vendor/sqlite. Each run() opens
// the OPFS DB and inserts 5 rows; reloading the page must see the prior rows, proving OPFS
// persistence across a reload, with crossOriginIsolated === false (no COOP/COEP headers needed).
// (Full cross-browser-restart persistence is covered by the spike's own Playwright check; a default
// Playwright context is ephemeral, so here we assert persistence across a reload within one context.)
test('sqlite-wasm OPFS-SAHPool persists across reload, header-free', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sqlite-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 30_000 });

  const first = await page.evaluate(() => (window as any).__sqlite.run());
  expect(first.ok, first.error).toBe(true);
  expect(first.before).toBe(0); // fresh ephemeral context → empty OPFS
  expect(first.after).toBe(5);
  expect(first.coi).toBe(false); // no cross-origin isolation → no COOP/COEP required

  await page.reload();
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 30_000 });

  const second = await page.evaluate(() => (window as any).__sqlite.run());
  expect(second.ok, second.error).toBe(true);
  expect(second.before).toBe(5); // survived the reload — OPFS persistence
  expect(second.after).toBe(10);

  expect(errors, 'no uncaught page errors').toEqual([]);
});
