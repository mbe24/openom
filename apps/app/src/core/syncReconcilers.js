// The per-channel reconcilers + the one dependency-ordered tick.
//
// "Bootstrap" is NOT a separate phase machine here (the reworked model): row-creation and adopt fall
// out of the snapshot channel's ordinary pull-then-push reconcile, and every channel is idempotent +
// self-healing. These functions only (a) translate each channel's rich, channel-specific result into
// the one Outcome vocabulary, and (b) sequence the channels by their real data dependency:
//
//   keyring PULL  (retain the governing revisions)              — safe with no server row yet
//   snapshot      (create the row [origin] / adopt it [invited])— adopt needs the pulled revisions
//   keyring PUBLISH + deltas (both FK the server row)           — need the row the snapshot established
//
// If the row isn't established this tick (offline/deferred), the row-dependent steps are skipped and the
// blocking Outcome is reported, so the driver retries — no ordering cursor, no persisted phase.

import { Ok, Offline, Conflict, Rejected, Deferred, classifyError, isOk, worst } from './syncOutcome.js';

/**
 * Run a channel op that THROWS on failure (the vault keyring methods, RemoteStore calls) and translate a
 * throw into an Outcome. A KeyringForkError is a permanent, security-relevant divergence (Rejected), not
 * a transient error, so it is surfaced rather than backed off.
 */
export async function attempt(fn) {
  try {
    return Ok(await fn());
  } catch (e) {
    if (e?.name === 'KeyringForkError') return Rejected({ fork: true, revision: e.revision, security: true });
    return classifyError(e);
  }
}

/** Map Replicator.sync's status string to an Outcome. */
export function mapReplicatorStatus(status) {
  switch (status) {
    case 'synced':
    case 'clean':
    case 'upToDate':
    case 'fastForward':
    case 'noRemote':
      return Ok(status); // converged (or nothing to do)
    case 'offline':
      return Offline();
    case 'rollback':
      return Rejected({ rollback: true, security: true }); // §10 anti-rollback tripped — surface, don't retry
    case 'unresolved':
      return Conflict(); // persistent conflict churn — retry next tick
    default:
      return Offline();
  }
}

/**
 * Snapshot channel: ensure a local snapshot exists (a freshly-provisioned tree has none — compact cuts
 * one, with the proper envelope, swallowing the local CAS), then the SyncStore pull-then-push reconcile
 * creates the row (origin: noRemote→push→cas_create), adopts it (invited: fastForward), or merges a
 * conflict — all emergent, no create-vs-adopt branch to maintain.
 */
export async function reconcileSnapshot({ tree, uuid, replicator }) {
  await tree.compact();
  return mapReplicatorStatus(await replicator.sync(uuid));
}

/**
 * Delta channel: push local deltas + pull remote (each pulled entry verified at its governing keyring
 * revision). A HELD entry — its governing revision not retained yet — is Deferred (retry after the next
 * keyring pull), not a failure.
 */
export async function reconcileDeltas({ controller }) {
  try {
    const r = await controller.sync();
    if (r?.held != null) return Deferred('a delta awaits its governing keyring revision');
    return Ok(r);
  } catch (e) {
    return classifyError(e);
  }
}

/**
 * One full reconcile in dependency order. Callbacks are thunks the SyncSession binds to its channel
 * objects; the `signal` aborts cooperatively (a torn-down session stops touching anything). Returns the
 * worst channel Outcome, which the driver dispatches.
 * @param {object} o
 * @param {() => Promise<any>} o.pullKeyring    retain governing revisions (vault.syncKeyring) — throws on failure
 * @param {() => Promise<import('./syncOutcome.js')>} o.snapshot   reconcileSnapshot — already an Outcome
 * @param {() => Promise<any>} o.publishKeyring publish the keyring tail (vault.reconcileKeyring) — throws
 * @param {() => Promise<import('./syncOutcome.js')>} o.deltas     reconcileDeltas — already an Outcome
 * @param {AbortSignal} [o.signal]
 */
export async function reconcileTree({ pullKeyring, snapshot, publishKeyring, deltas, signal }) {
  const aborted = () => signal?.aborted;

  const a = await attempt(pullKeyring); // retain the governing keyring revisions
  if (aborted()) return Ok();
  // Without the keyring context nothing row-dependent (adopt/verify/publish) is safe — report + retry.
  if (!isOk(a)) return a;

  const b = await snapshot(); // create the row (origin) or adopt it (invited)
  if (aborted()) return Ok();
  // The row wasn't established this tick → skip the row-dependent steps; the driver retries.
  if (!isOk(b)) return worst(a, b);

  const c = await attempt(publishKeyring); // publish the keyring tail (needs the row)
  if (aborted()) return Ok();

  const d = await deltas(); // push/pull deltas (need the row)
  return worst(a, b, c, d);
}
