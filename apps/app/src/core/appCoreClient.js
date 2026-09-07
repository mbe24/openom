// Main-thread handle to the app-core Web Worker (Comlink), plus the two things the worker needs from
// the main thread: a network transport (the fetch seam, staying where auth/serverUrl live) and a thin
// sync driver (debounce/poll/online → worker.syncNow). The worker owns the engine, DEK, sync loop, and
// durable store; this side is UI + these seams.
import * as Comlink from '../vendor/comlink.js';

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
 * keeps auth + serverUrl on the main thread. Only the delta-log push/pull is wired here; snapshot /
 * keyring / access channels ride the same RemoteStore when those are moved onto the core.
 */
export function remoteTransport(remoteStore) {
  return {
    // Push a sealed delta envelope; the worker ignores the returned seq.
    appendLog: (docId, env) => remoteStore.appendLog(docId, env),
    // Pull the tail after `since` (undefined ⇒ from the start) as { entries: Uint8Array[], nextCursor }.
    async readLog(docId, since) {
      const tail = await remoteStore.readLog(docId, since ?? -1);
      return { entries: tail.entries.map((e) => e.payload), nextCursor: tail.nextCursor };
    },
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
        else if (res?.state === 'error') onStatus?.({ state: 'offline', message: res.message });
      } while (dirty && !stopped);
    } catch (e) {
      onStatus?.({ state: 'offline', message: String(e?.message ?? e) });
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
