import { test, expect } from '@playwright/test';

// Targeted: loads only the WASM vault harness (no app boot), runs the real crypto in a real
// browser. Fast, and it verifies the exact thing the Node fakes can't — the compiled WASM
// vault behaving correctly in a browser engine.
test('WASM vault round-trips across a fresh unlock and rejects a wrong passphrase', async ({ page }) => {
  await page.goto('/e2e/vault-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 20_000 });

  const r = await page.evaluate(() => (window as any).__vault.roundTrip());

  expect(r.unlockOk).toBe(true); // device B opened device A's sealed data
  expect(r.opened).toBe('the family tree');
  expect(r.wrongRejected).toBe(true); // wrong passphrase refused
  expect(r.plaintextLeaks).toBe(false); // sealed bytes are ciphertext
  expect(r.revision).toBe(1);
  expect(r.recoveryCodeLen).toBeGreaterThan(20);
});
