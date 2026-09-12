// Main-thread handle to the app-core Web Worker (Comlink), plus the two things the worker needs from
// the main thread: a network transport (the fetch seam, staying where auth/serverUrl live) and a thin
// sync driver (debounce/poll/online → worker.syncNow). The worker owns the engine, DEK, sync loop, and
// durable store; this side is UI + these seams.
import * as Comlink from '../vendor/comlink.js';
import { normalizeUnknown, isAppError } from './errorModel.js';

let workerRef = null;
let apiRef = null;

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
  return apiRef;
}

/** Tear the worker down (fatal error / identity change) so a fresh one is created next time. */
export function resetAppCoreWorker() {
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
  };
}

/**
 * Drive `worker.syncNow(docId)` on a schedule: after each local edit (debounced), on a poll interval,
 * and when the network returns — mirroring the old SyncDriver, but the tick itself is the worker's. The
 * tick result ({state, anomalies}) is routed to the callbacks. Returns a stop function.
 */
export function startSyncDriver(worker, docId, { subscribeEdits, onStatus, onAuthError, onSecurity } = {}) {
  let stopped = false;
  let timer = null;
  let inflight = false;
  let dirty = false;
  const DEBOUNCE_MS = 800;
  const POLL_MS = 30_000;

  // Route a tick failure (an AppError from the worker, or a worker/Comlink death) to the right callback:
  // an auth-required error re-gates; a transient error keeps the driver polling silently ('offline'); a
  // permanent one surfaces ('error'). The AppError rides along so the UI localizes on its code (OPE-418).
  function routeError(raw) {
    const err = isAppError(raw) ? raw : normalizeUnknown(raw);
    if (err.code === 'auth_required') { onAuthError?.(err); return; }
    onStatus?.({ state: err.retriable ? 'offline' : 'error', error: err });
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

  let debounceTimer = null;
  const kick = () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(tick, DEBOUNCE_MS);
  };

  const unsub = subscribeEdits?.(kick) ?? (() => {});
  const onOnline = () => tick();
  globalThis.addEventListener?.('online', onOnline);
  timer = setInterval(tick, POLL_MS);
  tick(); // initial catch-up

  return {
    syncNow: tick,
    stop() {
      stopped = true;
      clearTimeout(debounceTimer);
      clearInterval(timer);
      globalThis.removeEventListener?.('online', onOnline);
      try { unsub(); } catch { /* best-effort */ }
    },
  };
}
