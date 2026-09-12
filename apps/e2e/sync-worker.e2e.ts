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
  // Gate-2 liveness (OPE-409): a sync tick reported its PULL frontier to PUT /frontier — a non-empty
  // {replica: counter} map, so the server's log-GC can pin its floor to the slowest member's pull point.
  expect(r.reportedFrontier, 'a tick reported a pull frontier').toBeTruthy();
  expect(
    Object.values(r.reportedFrontier).some((v: any) => v > 0),
    'the reported frontier is a non-empty {replica:counter} map',
  ).toBe(true);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: compaction publishes a snapshot with the covered header', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.compaction());

  expect(r.push.state).toBe('ok');
  expect(r.hasSnapshot, 'a snapshot object was produced + uploaded').toBe(true);
  expect(r.covered, 'the x-openom-covered header rode the snapshot PUT').toBeTruthy();
  const m = JSON.parse(r.covered);
  expect(Object.values(m).some((v: any) => v > 0), 'covered is a non-empty {replica:counter} map').toBe(true);
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
  // OPE-293: addMember asserted the resolved membership to the advisory /access — owner + the new member,
  // each with a role, plus a CAS generation and a non-empty basis frontier.
  expect(r.access, 'membership summary was pushed to /access').not.toBeNull();
  expect(r.access.generation).toBeGreaterThanOrEqual(1);
  expect(r.access.basis.length).toBeGreaterThan(0);
  const ids = r.access.members.map((m: any) => m.memberId).sort();
  expect(ids).toEqual(['acct-member', 'acct-owner']);
  expect(r.access.members.every((m: any) => typeof m.role === 'number')).toBe(true);
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
  // OPE-293: removeMember asserted the rotated membership to /access — the removed member is dropped from the
  // advisory view (the owner remains), and the generation advanced past the add.
  expect(r.accessAfterRemoval, 'rotated membership was pushed to /access').not.toBeNull();
  const idsAfter = r.accessAfterRemoval.members.map((m: any) => m.memberId);
  expect(idsAfter).toContain('acct-owner');
  expect(idsAfter).not.toContain('acct-member');
  expect(r.accessAfterRemoval.generation).toBeGreaterThanOrEqual(2); // add (gen 1) then remove (gen 2+)
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: chain removeMember preserves the removed maintainer\'s history via compact-before-remove', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.chainRemovePreservesHistory());

  // The owner folded the member's delta live at removal time.
  expect(r.ownerLiveSees).toContain('pMemberWrite');
  // OPE-421 Slice 3: after a COLD reload the owner re-judges the whole log under the post-removal head (member
  // absent → the look-behind would Drop the delta), yet still projects it — recovered from the compact-before-
  // remove pin. This is the end-to-end proof that pre-removal history survives a cold re-judgement.
  expect(r.seenAfterReload).toContain('pMemberWrite');
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

test('app-core: dag self-heal — a remaining member adopts the rotated epoch and covered-accepts removed history', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.dagSelfHealCoveredAccept());

  expect(r.carolBeforeRemoval).not.toContain('pBob'); // carol hadn't pulled bob's write before the removal
  expect(r.carolSyncState).toBe('ok');
  // After the removal, carol adopted the rotated epoch (so she could open the new-epoch cover) and
  // covered-accepted bob's now-removed history — the full self-heal loop, live in a browser.
  expect(r.carolAfter).toContain('pBob');
  expect(r.carolAnomalies).toBe(0); // the cover is honored — nothing rejected
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: dag co-owner promote/demote through the worker — role round-trips via /access', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareChangeRoleDag());

  // OPE-364: the member is admitted as editor, promoted to co-owner, then demoted back to editor — each role
  // reflected in the advisory /access view the worker pushes. Roles are numeric, lower = stronger.
  expect(r.present).toBe(true);
  expect(typeof r.afterAdd).toBe('number');
  expect(r.afterPromote).toBeLessThan(r.afterAdd); // promote raised authority (co-owner is stronger)
  expect(r.afterDemote).toBe(r.afterAdd); // demote restored the original editor role
  expect(r.afterPromote).not.toBe(r.afterDemote);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: chain co-owner demote through the worker — hard + preserves pre-demote history', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareChangeRoleChain());

  // OPE-421: chain co-owner demote is no longer refused. The member is promoted to co-owner then demoted back
  // to editor, each reflected in the advisory /access view (roles numeric, lower = stronger).
  expect(r.present).toBe(true);
  expect(r.afterPromote).toBeLessThan(r.afterDemote); // co-owner (stronger) → editor (weaker)
  // Slice 3: compact-before-demote preserved the demoted member's pre-demote commit across a cold owner reload,
  // even though the look-behind would Drop it under the post-demote head (Editor < Maintainer for a Delta).
  expect(r.seenAfterReload).toContain('pMemberWrite');
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
