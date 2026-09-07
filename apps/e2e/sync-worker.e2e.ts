import { test, expect } from '@playwright/test';

// The max-Rust app-core sync path in a real browser: real Web Workers running the wasm engine +
// sealer + docsync loop + local store + replicator, meeting only through an in-page transport (the
// server seam). This is the layer the Node fakes can't reach — wasm-in-a-worker + the async worker
// driver around the core's synchronous steps.
test('app-core: two devices converge through the server', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.converge());

  expect(r.aPush.state).toBe('ok');
  expect(r.bPull.state).toBe('ok');
  expect(r.serverSize).toBe(1); // A's one committed batch reached the server
  expect(r.aPeople.map((p: any) => p.id)).toContain('pA');
  // B, which minted nothing, sees A's person + name after one pull — the loop converged.
  expect(r.bPeople.map((p: any) => p.id)).toContain('pA');
  expect(r.bPeople[0].names?.length ?? 0).toBeGreaterThan(0);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: an offline mint is offered outbound once a transport attaches', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.offlineThenSync());

  expect(r.offlineResult.state).toBe('no-transport'); // committed locally, nothing pushed yet
  expect(r.serverSize).toBe(1); // after the transport attached, the mint reached the server
  expect(r.bPeople.map((p: any) => p.id)).toContain('pOff'); // and a peer received it
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: an offline mint survives a reload via IndexedDB', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.reloadSurvives());

  expect(r.beforePeople.map((p: any) => p.id)).toContain('pReload'); // minted + committed
  // A fresh core (a reload) hydrated from IndexedDB alone still has it — the durable-outbox gap, closed.
  expect(r.afterPeople.map((p: any) => p.id)).toContain('pReload');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: real keyring lifecycle — provision, mint, reload, unlock', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.provisionUnlockLifecycle());

  expect(r.recoveryCodeLen).toBeGreaterThan(20); // provision returned a real one-time recovery code
  expect(r.beforePeople.map((p: any) => p.id)).toContain('pLife'); // minted under the provisioned key
  expect(r.sameDid).toBe(true); // unlock re-derived the same author identity
  expect(r.afterPeople.map((p: any) => p.id)).toContain('pLife'); // unlock loaded the keyring + hydrated
  expect(r.wrongRejected).toBe(true); // a wrong passphrase is refused
  expect(errors, 'no uncaught page errors').toEqual([]);
});
