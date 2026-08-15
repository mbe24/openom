// Main-thread handle to the crypto worker. Comlink turns its flat API into async proxies, so
// the app calls `await worker.provision(...)` / `await worker.sealEntry(id, ...)` as if local.
// The worker owns all keys; this side only moves plaintext and ciphertext across.

import * as Comlink from '../../vendor/comlink.js';

let workerRef = null;
let apiRef = null;

/**
 * Create (or reuse) the crypto worker and its proxy. Cheap to call early — call it on gate
 * mount and `await worker.warm()` so WASM init overlaps the user reading/typing.
 * @returns {object} the Comlink proxy of the worker's flat API
 */
export function cryptoWorker() {
  if (apiRef) return apiRef;
  workerRef = new Worker(new URL('./sealer.worker.js', import.meta.url), { type: 'module' });
  apiRef = Comlink.wrap(workerRef);
  // A dead worker leaves every in-flight Comlink call pending forever (and any SealerSession
  // queue chained off it wedges). Surface it so the app can tear sessions down and re-unlock.
  workerRef.addEventListener('error', (e) => {
    // eslint-disable-next-line no-console
    console.error('[openom] crypto worker error', e?.message ?? e);
    globalThis.dispatchEvent?.(new CustomEvent('openom:worker-error', { detail: e?.message }));
  });
  return apiRef;
}

/** Tear the worker down (e.g. on a fatal error) so a fresh one is created next time. */
export function resetCryptoWorker() {
  try {
    workerRef?.terminate();
  } catch {
    /* already gone */
  }
  workerRef = null;
  apiRef = null;
}

/**
 * A SealerSession `core` bound to one worker-side sealer id: forwards seal/open (and lock)
 * across the boundary. The session keeps the chain state (counter/prev — no secrets) on the
 * main thread; only the DEK-bearing seal/open runs in the worker.
 */
export function workerCore(worker, sealerId) {
  return {
    sealEntry: (kind, format, compression, counter, prev, covers, blobId, plaintext) =>
      worker.sealEntry(sealerId, kind, format, compression, counter, prev, covers, blobId, plaintext),
    openEntry: (kind, bytes) => worker.openEntry(sealerId, kind, bytes),
    lock: () => worker.lock(sealerId),
  };
}
