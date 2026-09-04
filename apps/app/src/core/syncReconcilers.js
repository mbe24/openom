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
 * Snapshot channel: reconcile our base with the server's snapshot row.
 *  - ORIGIN (no row yet): seal the current state and create the row (cas_create; the keyring PUT + delta
 *    append both FK it), tolerating a concurrent creator (a 409 just means the row now exists).
 *  - READER (a row exists): ADOPT it — if the server base subsumes more of the log than our cursor, verify
 *    it (§B3), merge its state, and jump the delta cursor past the subsumed prefix so those deltas are never
 *    replayed. A base that isn't ahead is a no-op; a base we can't (yet) verify is Deferred, which — via the
 *    tick's dependency order — makes the delta pull skip this tick (fail-closed on a shared tree: it never
 *    pulls the pre-share deltas without a verified signed base).
 * The read + the adopt are one `adopt()` call, so there's a single readSnapshot per tick.
 * @param {object} o
 * @param {object} o.tree    a FamilyTree (snapshotBytes)
 * @param {string} o.uuid    the server tree id
 * @param {object} o.remote  a RemoteStore (putSnapshot)
 * @param {(bytes: Uint8Array) => Promise<Uint8Array>} o.sealSnapshot  seal under kind:'snapshot'
 * @param {() => Promise<{rowExists:boolean,adopted?:boolean,deferred?:boolean,coversThroughSeq?:number,version?:string}>} o.adopt  controller.adopt
 * @param {((base:{coversThroughSeq:number,version:string}) => Promise<boolean>)|undefined} [o.selfHealBase]  a
 *        writer's base self-heal: if the tree is shared and the base still subsumes nothing, seal + CAS-PUT a
 *        signed base covering the shared history; returns true if it published one. Idempotent; a no-op for
 *        readers / solo trees / a base already covering.
 */
export async function reconcileSnapshot({ tree, uuid, remote, sealSnapshot, adopt, selfHealBase }) {
  let a;
  try {
    a = await adopt(); // reads the row; adopts a newer verified base; a network failure THROWS
  } catch (e) {
    return classifyError(e); // offline → defer; a permanent refusal → surface
  }
  if (a.rowExists) {
    if (a.deferred) return Deferred('the snapshot base awaits a verifiable signed snapshot');
    // A writer ensures a signed base covering the shared history exists (so members can bootstrap). The
    // thunk owns the decision (shared + committer + base stale) and the CAS publish.
    if (selfHealBase) {
      try {
        if (await selfHealBase(a)) return Ok('healed');
      } catch (e) {
        return classifyError(e);
      }
    }
    return Ok(a.adopted ? 'adopted' : 'exists');
  }
  // Origin: no server row yet → seal the current state and create it.
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
