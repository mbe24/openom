import { test, expect } from '@playwright/test';

// @integration — boots the WHOLE app on the claim-based engine (localStorage['openom.engine']='claim'),
// the OPE-187 merge gate: the running GUI must display + edit names backed by FamilyTree (OPE-201),
// build/load with no page errors, and survive a reload (hydrate from the claim log). Run with
// `pnpm test:e2e:full`. Excluded from the default `test:e2e` run.

test.beforeEach(async ({ page }) => {
  // Select the claim engine before any app code runs, on every navigation (survives reload).
  await page.addInitScript(() => {
    try { localStorage.setItem('openom.engine', 'claim'); } catch { /* no storage */ }
  });
});

test('claim engine: create, display, edit, and persist a person @integration', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/app/index.html');
  await page.getByRole('button', { name: /start your family tree/i }).click();
  await page.locator('#gate-pass').fill('claim engine passphrase');
  await page.locator('#gate-pass2').fill('claim engine passphrase');
  await page.getByRole('button', { name: /^create$/i }).click();
  await expect(page.locator('#gate-recovery-code')).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: /i saved it/i }).click();

  // Onboarding → add a person: createPerson + the read model render, backed by the claim engine.
  await page.locator('#first-name').fill('Ada Lovelace');
  await page.getByRole('button', { name: /new person/i }).click();
  await expect(page.getByRole('button', { name: /Ada Lovelace/ })).toBeVisible({ timeout: 20_000 });

  // Open the person (detail) → Edit person (editor) → change the surname → save. This exercises
  // updatePerson / supersede on the claim engine.
  await page.getByRole('button', { name: /Ada Lovelace/ }).first().click();
  await page.getByRole('button', { name: /edit person/i }).click();
  const surname = page.getByLabel('Surname');
  await expect(surname).toBeVisible({ timeout: 20_000 });
  await surname.fill('Byron');
  await surname.blur();
  await page.getByRole('button', { name: /^save$/i }).click();
  await expect(page.locator('body')).toContainText('Byron', { timeout: 20_000 });

  // Reload → unlock → hydrate from the claim log: the edited name survives.
  await page.reload();
  await page.locator('#gate-pass').fill('claim engine passphrase');
  await page.getByRole('button', { name: /^unlock$/i }).click();
  await expect(page.locator('body')).toContainText('Byron', { timeout: 20_000 });

  expect(errors, 'no uncaught page errors').toEqual([]);
});
