import { test, expect } from '@playwright/test';

// The crypto worker path in a real browser: real Web Worker running the WASM vault + sealer,
// seal/open proxied over Comlink. Exercises exactly what the Node fakes can't — the worker
// boundary, WASM-in-a-worker, and the cross-device DEK derivation.
test('crypto worker: provision → seal → open, cross-device unlock, ciphertext at rest', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__worker.roundTrip());

  expect(r.roundTrip).toBe(true); // sealed + opened through the worker
  expect(r.crossDevice).toBe(true); // a second unlock derived the same DEK and opened A's data
  expect(r.leaks).toBe(false); // the sealed bytes are ciphertext
  expect(r.wrongRejected).toBe(true); // wrong passphrase refused
  expect(r.recoveryCodeLen).toBeGreaterThan(20);
  expect(errors, 'no uncaught page errors').toEqual([]);
});
