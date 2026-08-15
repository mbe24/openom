import { test, expect } from '@playwright/test';

// @integration — these boot the WHOLE app (~seconds each). Excluded from the default
// `test:e2e` run; invoke explicitly with `pnpm test:e2e:full`. Each test gets a fresh browser
// context, so IndexedDB (the keyring) starts empty → the app opens on the welcome gate.

test('welcome gate → demo enters the (encrypted) tree @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/app/index.html');
  await expect(page.getByRole('button', { name: /explore a demo/i })).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: /explore a demo/i }).click();
  await expect(page.locator('body')).toContainText('Bach', { timeout: 20_000 }); // seed tree, decrypted

  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('welcome → create passphrase → recovery code → reload → unlock @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/app/index.html');
  await page.getByRole('button', { name: /create your tree/i }).click();

  // Provision: set + confirm a passphrase.
  await page.locator('#gate-pass').fill('correct horse battery');
  await page.locator('#gate-pass2').fill('correct horse battery');
  await page.getByRole('button', { name: /^create$/i }).click();

  // Recovery code shown once, then continue into the (empty) tree.
  await expect(page.getByText(/only way back/i)).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: /i saved it/i }).click();
  await expect(page.locator('.shell')).toBeVisible({ timeout: 20_000 }); // in the app

  // Reload → the keyring exists → the unlock gate. Wrong passphrase is refused; the right one opens.
  await page.reload();
  await expect(page.locator('#gate-pass')).toBeVisible({ timeout: 20_000 });
  await page.locator('#gate-pass').fill('wrong');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.getByText(/wrong passphrase/i)).toBeVisible({ timeout: 20_000 });
  await page.locator('#gate-pass').fill('correct horse battery');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.locator('.shell')).toBeVisible({ timeout: 20_000 });

  expect(errors, 'no uncaught page errors').toEqual([]);
});
