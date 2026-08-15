import { test, expect } from '@playwright/test';

// @integration — these boot the WHOLE app. Excluded from the default `test:e2e` run; invoke
// with `pnpm test:e2e:full`. Each test gets a fresh browser context, so the keyring
// (IndexedDB) starts empty → the app opens on the welcome gate. serve.mjs sets %DEMO%=true
// locally, so the demo affordance is present here (it's absent in production).

test('welcome → demo enters the (encrypted) tree @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/app/index.html');
  await page.getByRole('button', { name: /explore a demo/i }).click();
  await expect(page.locator('body')).toContainText('Bach', { timeout: 20_000 });

  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('start → passphrase → recovery code → onboarding → reload → unlock @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/app/index.html');
  await page.getByRole('button', { name: /start your family tree/i }).click();
  await page.locator('#gate-pass').fill('correct horse battery');
  await page.locator('#gate-pass2').fill('correct horse battery');
  await page.getByRole('button', { name: /^create$/i }).click();

  await expect(page.getByText(/only way back/i)).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: /i saved it/i }).click();
  // Empty tree → the "start with yourself" onboarding.
  await expect(page.locator('#first-name')).toBeVisible({ timeout: 20_000 });

  // Reload → keyring exists → unlock; wrong refused, right opens.
  await page.reload();
  await page.locator('#gate-pass').fill('nope');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.getByText(/wrong passphrase/i)).toBeVisible();
  await page.locator('#gate-pass').fill('correct horse battery');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.locator('#first-name')).toBeVisible({ timeout: 20_000 });

  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('forgot passphrase → recover with the code → new passphrase works @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/app/index.html');
  await page.getByRole('button', { name: /start your family tree/i }).click();
  await page.locator('#gate-pass').fill('old passphrase one');
  await page.locator('#gate-pass2').fill('old passphrase one');
  await page.getByRole('button', { name: /^create$/i }).click();
  await expect(page.locator('#gate-recovery-code')).toBeVisible({ timeout: 20_000 });
  const code = (await page.locator('#gate-recovery-code').textContent())!.trim();
  await page.getByRole('button', { name: /i saved it/i }).click();
  await expect(page.locator('#first-name')).toBeVisible();

  // Reload → forgot → recover with the code + a new passphrase.
  await page.reload();
  await page.getByRole('button', { name: /forgot your passphrase/i }).click();
  await page.locator('#gate-code').fill(code);
  await page.locator('#gate-pass').fill('brand new passphrase');
  await page.locator('#gate-pass2').fill('brand new passphrase');
  await page.getByRole('button', { name: /^recover$/i }).click();
  await expect(page.locator('#gate-recovery-code')).toBeVisible({ timeout: 20_000 }); // rotated code
  await page.getByRole('button', { name: /i saved it/i }).click();
  await expect(page.locator('#first-name')).toBeVisible();

  // Reload → the NEW passphrase unlocks; the OLD one does not.
  await page.reload();
  await page.locator('#gate-pass').fill('old passphrase one');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.getByText(/wrong passphrase/i)).toBeVisible();
  await page.locator('#gate-pass').fill('brand new passphrase');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.locator('#first-name')).toBeVisible({ timeout: 20_000 });

  expect(errors, 'no uncaught page errors').toEqual([]);
});
