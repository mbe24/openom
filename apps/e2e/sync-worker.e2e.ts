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

test('app-core: an owner shares a tree and a member joins + verifies through the worker', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareAndVerify());

  // The member genesis-walked the published keyring and unlocked as a member.
  expect(r.joinedDid.length).toBeGreaterThan(0);
  expect(r.serverKeyringHead).toBe(2); // owner published rev 1 (genesis) + rev 2 (after the add)
  expect(r.sync.state).toBe('ok');
  // Verify-on-ingest ACCEPTED the owner's signed write on the shared tree — the member sees it.
  expect(r.memberPeople).toContain('pShared');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: an owner removes a member through the worker — rotate, re-unlock, lock out', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareRemoveLockout());

  expect(r.beforeRemoval).toContain('pShared'); // the member joined and saw the shared write
  expect(r.headBefore).toBe(2); // genesis + the add
  expect(r.headAfter).toBe(3); // the removal rotated the keyring and published rev 3
  expect(r.pushState).toBe('ok'); // the re-unlocked owner sealer signs + syncs under the new epoch
  expect(r.ownerAfter).toContain('pShared'); // pre-removal history intact
  expect(r.ownerAfter).toContain('pAfter'); // the post-removal signed write landed
  expect(r.lockedOut).toBe(true); // the removed member can no longer unlock the rotated tree
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: dag distribution — a member joins by pin, writes, and removeMember authors a cover', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareVerifyDag());

  expect(r.joinedDid.length).toBeGreaterThan(0); // the member verified the anchor against the OOB pin + unlocked
  expect(r.wrongPinRejected).toBe(true); // a tampered pin is refused — the founder/freshness trust gate holds
  expect(r.memberSees).toContain('pShared'); // verify-on-ingest accepted the owner's signed dag write
  expect(r.ownerSees).toContain('pShared');
  expect(r.ownerSees).toContain('pMember'); // the member's own maintainer write verified on the owner's pull
  expect(r.keyringGrew).toBe(true); // removeMember rotated + republished the anchor
  expect(r.coverPushed).toBe(1); // removeMember authored + pushed exactly one self-heal cover to the data channel
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: reset clears the tree for a clean reseed', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.reseedClears());

  expect(r.beforeIds).toContain('pOld'); // seeded
  expect(r.clearedIds).toEqual([]); // reset emptied the tree
  expect(r.afterIds).toContain('pNew'); // reseed works
  expect(r.afterIds).not.toContain('pOld'); // the old data did not pile up
  expect(errors, 'no uncaught page errors').toEqual([]);
});
