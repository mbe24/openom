// The sealer entry point. Two real paths, both routing through the crypto WORKER so key
// material never reaches the main thread:
//   - createAppVault(): the passphrase vault (provision/unlock/recover/changePassphrase).
//   - createLibrarySealer({dev:true}): the demo, sealing under the reserved dev key (§16).
// Everything above this (SealedStore, composeStore) just receives a `sealer` with seal/open
// and never learns which path produced it.
//
// A future Tauri build swaps the Web Worker for an `invoke` backend that exposes the SAME
// flat API — so the DEK lives in the Rust core, never the webview. That swap point is the
// vault's injected `worker` (selected here inside createAppVault), NOT a main-thread sealer
// core: an unwrapped DEK must never cross into main-thread JS.

import { SealerSession } from './session.js';
import { replicaId } from '../identity.js';
import { Watermarks } from '../watermarks.js';
import { createVault } from './vault.js';
import { indexedDbKeyringStore } from './keyringStore.js';
import { cryptoWorker, workerCore } from './workerSealer.js';

/**
 * The real passphrase vault for the app: the crypto worker + the durable IndexedDB keyring
 * store + a persisted anti-rollback watermark. The UI drives provision/unlock/recover/
 * changePassphrase on it. (Web only for now; a Tauri invoke backend is a later step and
 * would be selected here in place of the worker.)
 * @returns {Promise<object>} a vault (see createVault)
 */
export async function createAppVault() {
  const worker = cryptoWorker();
  await worker.warm(); // pre-warm the WASM so only the KDF is visible at submit
  return createVault({ worker, keyringStore: indexedDbKeyringStore(), watermarks: new Watermarks() });
}

// A stable 16-byte tree id derived from a doc id. Real trees carry a UUID; for the dev/local
// path the doc id is the tree's identity, so a deterministic hash gives a consistent scope
// (and thus openable-across-reloads snapshots) without inventing a UUID scheme yet.
async function treeIdBytes(docId) {
  const data = new TextEncoder().encode('openom-tree:' + docId);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest).slice(0, 16);
}

/**
 * A routing sealer: implements the SealedStore seal/open(bytes, docId, {kind}) contract by
 * dispatching each call to the per-tree SealerSession for that doc id. One SealedStore over
 * the shared library store can then serve every tree, while each tree keeps its own scoped
 * session (its own tree id, replica, and chain).
 * Routes through the SAME crypto worker as the real vault, so the demo exercises the identical
 * encryption path as production — it differs only in the KEY (the reserved dev key vs. a
 * passphrase-derived one). The demo is therefore real ciphertext at rest, just under a
 * well-known (non-private) key.
 * @param {object} [opts]
 * @param {boolean} [opts.dev]  build dev-key sessions (the demo path; the only mode here)
 */
export function createLibrarySealer({ dev = false } = {}) {
  if (!dev) throw new Error('createLibrarySealer only supports the dev demo path');
  const worker = cryptoWorker();
  const byDoc = new Map(); // docId -> Promise<SealerSession>
  const sessionFor = (docId) => {
    let p = byDoc.get(docId);
    if (!p) {
      p = (async () => {
        await worker.warm();
        const treeId = await treeIdBytes(docId);
        const { sealerId } = await worker.dev(treeId, replicaId(docId));
        return new SealerSession(workerCore(worker, sealerId));
      })();
      byDoc.set(docId, p);
    }
    return p;
  };
  return {
    async seal(bytes, docId, opts) {
      return (await sessionFor(docId)).seal(bytes, docId, opts);
    },
    async open(sealed, docId, opts) {
      return (await sessionFor(docId)).open(sealed, docId, opts);
    },
  };
}
