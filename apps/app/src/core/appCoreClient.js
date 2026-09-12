// Main-thread handle to the app-core Web Worker (Comlink), plus the two things the worker needs from
// the main thread: a network transport (the fetch seam, staying where auth/serverUrl live) and a thin
// sync driver (debounce/poll/online → worker.syncNow). The worker owns the engine, DEK, sync loop, and
// durable store; this side is UI + these seams.
import * as Comlink from '../vendor/comlink.js';
import { normalizeUnknown, isAppError } from './errorModel.js';

let workerRef = null;
let apiRef = null;

let heartbeatTimer = null;

// Silent-hang detection (C3): a CRASHED worker fires an 'error' event (handled below), but a WEDGED one (a
// stuck wasm call, an infinite loop) simply stops answering — every Comlink call then waits forever. A
// lightweight ping with a timeout catches that; after MAX_MISSES consecutive unanswered beats we raise the
// SAME openom:worker-error signal a crash would, so the existing teardown + re-gate recovery runs. A heartbeat
// (not a per-call timeout) means a legitimately slow syncNow never looks dead — the worker answers ping()
// between its network awaits; only a truly blocked event loop misses beats.
const HEARTBEAT_INTERVAL_MS = 15_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const HEARTBEAT_MAX_MISSES = 2;

function startHeartbeat(api) {
  let misses = 0;
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(async () => {
    let alive = false;
    try {
      await Promise.race([
        api.ping(),
        new Promise((_, reject) => { setTimeout(() => reject(new Error('ping timeout')), HEARTBEAT_TIMEOUT_MS); }),
      ]);
      alive = true;
    } catch {
      alive = false;
    }
    if (api !== apiRef) return; // the worker was reset out from under this beat
    if (alive) { misses = 0; return; }
    misses += 1;
    if (misses >= HEARTBEAT_MAX_MISSES) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
      console.error('[openom] app-core worker unresponsive — no heartbeat');
      globalThis.dispatchEvent?.(new CustomEvent('openom:worker-error', { detail: 'worker unresponsive' }));
    }
  }, HEARTBEAT_INTERVAL_MS);
}

/** Create (or reuse) the app-core worker and its Comlink proxy. Call `await worker.warm()` early. */
export function appCoreWorker() {
  if (apiRef) return apiRef;
  workerRef = new Worker(new URL('./appCore.worker.js', import.meta.url), { type: 'module' });
  apiRef = Comlink.wrap(workerRef);
  workerRef.addEventListener('error', (e) => {
    // eslint-disable-next-line no-console
    console.error('[openom] app-core worker error', e?.message ?? e);
    globalThis.dispatchEvent?.(new CustomEvent('openom:worker-error', { detail: e?.message }));
  });
  startHeartbeat(apiRef); // detect a silent hang, not just a crash
  return apiRef;
}

/** Tear the worker down (fatal error / identity change) so a fresh one is created next time. */
export function resetAppCoreWorker() {
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  try {
    workerRef?.terminate();
  } catch {
    /* already gone */
  }
  workerRef = null;
  apiRef = null;
}

/**
 * The network transport the worker calls (Comlink-proxied in). A thin adapter over `RemoteStore`, which
 * keeps auth + serverUrl on the main thread. The DATA channel is a BlobStore (list/get/put over opaque
 * object keys — the worker never parses a key); the keyring / access channels ride the same RemoteStore.
 */
export function remoteTransport(remoteStore) {
  return {
    // Explicit create-tree (OPE-407): mint the tree row (entitlement-gated) before the first blob write.
    // The worker calls this once per owner core, driven by a durable "needs-create-tree" marker set at
    // provision — idempotent for the owner, never called by a joining member.
    createTree: (treeUuid) => remoteStore.createTree(treeUuid),
    // The data channel as a BlobStore: the worker lists the remote under a `{treeKey}/` prefix, GETs the
    // objects, and PUTs the diff the core computes. `pointer` (heads/snapshot) overwrites; else If-None-Match.
    blobList: (prefix) => remoteStore.blobList(prefix),
    blobGet: (key) => remoteStore.blobGet(key),
    blobPut: (key, bytes, pointer, covered) => remoteStore.blobPut(key, bytes, pointer, covered),
    // Report this device's PULL frontier (`{replica: counter}`) as gate-2 liveness telemetry so the server's
    // log-GC keeps a slow member's un-pulled tail alive (OPE-409 gate 2). `tree` is the data-channel tree key.
    putFrontier: (tree, frontier) => remoteStore.putFrontier(tree, frontier),
    // The keyring revision chain from `from` (inclusive) — for a member JOIN's genesis-walk. Returns
    // { revisions: [{ revision, bytes }], head }; bytes = the opaque signed keyring (a MembershipEnvelope).
    readKeyring: (treeUuid, from) => remoteStore.readKeyring(treeUuid, from),
    // Publish a produced keyring revision (a wrapped KeyringUpdate) so peers can pull + verify it.
    putKeyring: (treeUuid, updateBytes) => remoteStore.putKeyring(treeUuid, updateBytes),
    // The advisory membership channel (OPE-293): GET the server's stored summary (for the CAS generation +
    // coverage check) and PUT this device's resolved {members, basis} view. Server-side this is the coarse
    // ACL for collaboration features — never the security boundary (the keyring is).
    getAccess: (treeUuid) => remoteStore.getAccess(treeUuid),
    putAccess: (treeUuid, body) => remoteStore.putAccess(treeUuid, body),
  };
}

/**
 * Default minimum interval between sync ticks. A sync tick rewrites this replica's `heads/{replica}` and
 * `snapshot` pointer objects, and R2 rejects more than one write per second to the SAME object key (429). So
 * the driver never starts ticks closer than this floor — comfortably above 1s — and under sustained editing
 * a replica's pointer rewrites stay under the ceiling. Overridable via `startSyncDriver`'s `cadenceMs` (the
 * configurable-cadence groundwork, OPE-410); the driver still clamps the effective floor to ≥1s regardless.
 */
export const DEFAULT_SYNC_CADENCE_MS = 1100;

/**
 * Drive `worker.syncNow(docId)` on a schedule: after each local edit (debounced), on a poll interval, and
 * when the network returns — mirroring the old SyncDriver, but the tick itself is the worker's. Every trigger
 * routes through one rate-limited scheduler so ticks are never started closer than the cadence floor (R2's
 * 1-write/sec-per-key limit). The tick result ({state, anomalies}) is routed to the callbacks. Returns a stop
 * function.
 */
export function startSyncDriver(
  worker,
  docId,
  { subscribeEdits, onStatus, onAuthError, onSecurity, cadenceMs = DEFAULT_SYNC_CADENCE_MS } = {},
) {
  let stopped = false;
  let inflight = false;
  let dirty = false;
  let timer = null;
  let lastTickAt = 0; // when the last tick STARTED — the cadence floor is measured from here
  const DEBOUNCE_MS = 300; // let a burst of edits settle before syncing
  const POLL_MS = 30_000;
  // The hard floor never drops below R2's 1s-per-key ceiling, even if a caller passes something smaller.
  const MIN_INTERVAL_MS = Math.max(1000, cadenceMs);

  // Route a tick failure (an AppError from the worker, or a worker/Comlink death) to the right callback:
  // an auth-required error re-gates; a transient error keeps the driver polling silently ('offline'); a
  // permanent one surfaces ('error'). The AppError rides along so the UI localizes on its code (OPE-418).
  function routeError(raw) {
    const err = isAppError(raw) ? raw : normalizeUnknown(raw);
    if (err.code === 'auth_required') { onAuthError?.(err); return; }
    onStatus?.({ state: err.retriable ? 'offline' : 'error', error: err });
    // Honor server backpressure: a rate-limited tick (429 carrying Retry-After) re-arms after exactly that
    // delay rather than waiting out the full poll interval.
    if (err.retriable && err.retryAfter > 0) arm(err.retryAfter * 1000);
  }

  async function tick() {
    if (stopped) return;
    if (inflight) { dirty = true; return; }
    inflight = true;
    try {
      do {
        dirty = false;
        const res = await worker.syncNow(docId);
        if (stopped) return;
        if (res?.state === 'ok') onStatus?.({ state: 'synced', at: Date.now(), anomalies: res.anomalies ?? 0 });
        else if (res?.state === 'error') routeError(res.error);
      } while (dirty && !stopped);
    } catch (e) {
      routeError(e);
    } finally {
      inflight = false;
    }
  }

  // Run a tick, but never start two closer than MIN_INTERVAL (R2's per-key ceiling). If armed too soon —
  // e.g. a poll landing right after an edit tick — defer for the remainder rather than firing early.
  function runTick() {
    timer = null;
    if (stopped) return;
    const early = MIN_INTERVAL_MS - (Date.now() - lastTickAt);
    if (early > 0) { arm(early); return; }
    lastTickAt = Date.now();
    void tick();
  }

  // Arm a single pending tick `delay` ms out. Coalesces: concurrent triggers collapse onto the one pending
  // timer (every trigger does the same work, so the soonest-permissible tick serves them all).
  function arm(delay) {
    if (stopped || timer !== null) return;
    timer = setTimeout(runTick, Math.max(0, delay));
  }

  const unsub = subscribeEdits?.(() => arm(DEBOUNCE_MS)) ?? (() => {});
  const onOnline = () => arm(0);
  globalThis.addEventListener?.('online', onOnline);
  const poll = setInterval(() => arm(0), POLL_MS);
  arm(0); // initial catch-up

  return {
    syncNow: () => arm(0),
    stop() {
      stopped = true;
      clearTimeout(timer);
      clearInterval(poll);
      globalThis.removeEventListener?.('online', onOnline);
      try { unsub(); } catch { /* best-effort */ }
    },
  };
}
