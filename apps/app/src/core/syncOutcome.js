// One outcome vocabulary for the whole sync stack.
//
// Today the layers signal failure three incompatible ways — SyncStore returns status strings,
// readSnapshot returns null / throws, RemoteStore throws typed errors — and a PERMANENT refusal
// (403 over-quota) is flattened into the same bucket as a dropped packet, so nothing above can tell
// "retry later" from "this will never succeed". This module is the single failure language that
// everything ABOVE the HTTP boundary returns and branches on (`switch (o.tag)`), so the driver, the
// channel reconcilers, and the bootstrap logic all speak one vocabulary.
//
// The HTTP edge (RemoteStore) may still THROW typed errors; `classifyError` maps them here ONCE, at
// the boundary. Nothing above RemoteStore branches on a raw status or a caught throw.
//
//   Ok(value?)       success — value carries whatever the call produces (a new version, an adopted remote…)
//   Offline(cause?)  transient (network / 5xx / 429): retry later, SILENTLY — the local commit is durable
//   Conflict(remote) the CAS lost: pull + merge + retry (or the Replicator loop); `remote` is the winner
//   Rejected(reason) the server refused and retrying WON'T help (403 quota/forbidden, 400): SURFACE it
//   Deferred(reason) NOT an error: a precondition isn't ready yet (retryable verify, row absent): retry
//   Unauthorized()   the session is dead (401): re-gate — never a silent backoff

export const OK = 'ok';
export const OFFLINE = 'offline';
export const CONFLICT = 'conflict';
export const REJECTED = 'rejected';
export const DEFERRED = 'deferred';
export const UNAUTHORIZED = 'unauthorized';

export const Ok = (value = null) => ({ tag: OK, value });
export const Offline = (cause = null) => ({ tag: OFFLINE, cause });
export const Conflict = (remote = null) => ({ tag: CONFLICT, remote });
export const Rejected = (reason = null) => ({ tag: REJECTED, reason });
export const Deferred = (reason = null) => ({ tag: DEFERRED, reason });
export const Unauthorized = () => ({ tag: UNAUTHORIZED });

export const isOk = (o) => o?.tag === OK;
/** Keep waiting — the outcome is not settled; a later tick may succeed (offline / precondition pending). */
export const isRetryable = (o) => o?.tag === OFFLINE || o?.tag === DEFERRED;
/** Must be surfaced to the user: a dead session or a refusal that retrying cannot fix. */
export const isTerminal = (o) => o?.tag === REJECTED || o?.tag === UNAUTHORIZED;

// Severity for combining several channel outcomes into one tick result: the most "did not fully
// succeed" wins, so a single Rejected/Unauthorized in any channel dominates an Offline in another.
const RANK = { [UNAUTHORIZED]: 5, [REJECTED]: 4, [CONFLICT]: 3, [OFFLINE]: 2, [DEFERRED]: 1, [OK]: 0 };
/** Combine channel-reconcile outcomes into the worst (most-severe) one. worst() with no args is Ok. */
export const worst = (...outcomes) =>
  outcomes.reduce((acc, o) => ((RANK[o?.tag] ?? 0) > (RANK[acc?.tag] ?? 0) ? o : acc), Ok());

/**
 * The ONE place a caught RemoteStore error (or a bare HTTP status) becomes an Outcome. 404 is NOT
 * handled here — RemoteStore returns it as data (null / empty), because "not found" means different
 * things per call (no tree row vs. no keyring yet) and only the caller has that context.
 * @param {any} err  a caught error (with optional `.status`/`.name`) or a numeric HTTP status
 */
export function classifyError(err) {
  const status = typeof err === 'number' ? err : err?.status;
  if (err?.name === 'AuthError' || status === 401) return Unauthorized();
  if (err?.name === 'ConflictError' || status === 409) return Conflict(err?.remote ?? null);
  // 410 = the server stripped history we asked for (log GC) → the snapshot channel must re-adopt a
  // fresh baseline; a Deferred retry does exactly that once GC ships (unreachable in V1: GC blocked).
  if (err?.name === 'BootstrapRequiredError' || status === 410) return Deferred({ bootstrapRequired: true, error: err });
  if (status === 403 || status === 400) return Rejected({ status, message: err?.message ?? String(err) });
  // network failure, 5xx, 429, timeouts, anything else → transient
  return Offline(err);
}
