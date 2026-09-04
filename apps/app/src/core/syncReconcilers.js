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

import { Ok, Rejected, Deferred, classifyError, isOk, worst } from './syncOutcome.js';

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

/**
 * Snapshot channel (V1): the snapshot's job is to CREATE the server tree row — put_tree/cas_create is the
 * only way a row comes into being, and the keyring PUT + delta append both FK it. It is NOT a live-synced
 * doc here: state convergence is the delta log's job (log GC is blocked, so the full log is always present
 * and a fresh device reconstructs by replaying it; a merged baseline snapshot is a post-GC optimization).
 * So: if the row already exists, nothing to do; otherwise seal a snapshot of the current state and create
 * it (expected=null → cas_create), tolerating a concurrent creator (a 409 just means the row now exists).
 * @param {object} o
 * @param {object} o.tree    a FamilyTree (snapshotBytes)
 * @param {string} o.uuid    the server tree id
 * @param {object} o.remote  a RemoteStore (readSnapshot / putSnapshot)
 * @param {(bytes: Uint8Array) => Promise<Uint8Array>} o.sealSnapshot  seal under kind:'snapshot'
 */
export async function reconcileSnapshot({ tree, uuid, remote, sealSnapshot }) {
  let existing;
  try {
    existing = await remote.readSnapshot(uuid); // null = 404 = no row; a network failure THROWS
  } catch (e) {
    return classifyError(e); // offline → defer; a permanent refusal → surface
  }
  if (existing) return Ok('exists'); // row present — the delta log carries state; nothing to create in V1
  const sealed = await sealSnapshot(tree.snapshotBytes());
  try {
    await remote.putSnapshot(uuid, sealed, null); // If-None-Match: create only
    return Ok('created');
  } catch (e) {
    if (e?.name === 'ConflictError') return Ok('exists'); // a concurrent creator won — the row exists now
    return classifyError(e);
  }
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
