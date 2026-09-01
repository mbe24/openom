// The sealer entry point. The passphrase vault and the demo sealer, each behind whichever
// backend the runtime provides:
//   - createAppVault(): the passphrase vault (provision/unlock/recover/changePassphrase).
//   - createLibrarySealer({dev:true}): the demo, sealing under the reserved dev key (§16).
// Everything above this (SealedStore, composeStore) just receives a `sealer` with seal/open
// and never learns which backend produced it.
//
// Backend-select: on WEB, crypto runs in a Web Worker + JS keyring/watermark stores (vault.js).
// On TAURI, it runs in the Rust host over `invoke` (invokeSealer.js) — the DEK lives in the
// Rust core and never enters the webview, and the keyring/watermark live in Rust storage, not
// the evictable webview one. Both expose the identical vault surface.

import { SealerSession } from './session.js';
import { replicaId } from '../identity.js';
import { Watermarks } from '../watermarks.js';
import { createVault } from './vault.js';
import { createInvokeVault, invokeCore } from './invokeSealer.js';
import { indexedDbKeyringStore } from './keyringStore.js';
import { cryptoWorker, workerCore } from './workerSealer.js';

// The keyring ENGINE is a deployment/backend PRESET (OPE-278), not a per-tree user choice: the managed
// backend is fixed to one engine, a BYO backend to one. It's a constant here (a hidden setting / build flag
// changes it); the vault records it in the local head record and dispatches on it. Default = the shipping
// chain engine.
const KEYRING_ENGINE = 'chain';

// The Tauri invoke entry point when running inside the Tauri webview, else undefined (web).
function tauriInvoke() {
  return globalThis.__TAURI__?.core?.invoke;
}

/**
 * The real passphrase vault. On Tauri, the Rust host (openom-vault-host) over `invoke`; on web,
 * the crypto worker + the IndexedDB keyring store + a persisted anti-rollback watermark. The UI
 * drives provision/unlock/recover/changePassphrase on it, unaware which backend answered.
 * @returns {Promise<object>} a vault (see createVault / createInvokeVault)
 */
export async function createAppVault() {
  const invoke = tauriInvoke();
  if (invoke) return createInvokeVault(invoke);
  const worker = cryptoWorker();
  await worker.warm(); // pre-warm the WASM so only the KDF is visible at submit
  return createVault({
    worker,
    keyringStore: indexedDbKeyringStore(),
    watermarks: new Watermarks(),
    engine: KEYRING_ENGINE,
  });
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
 * Routes through the SAME backend as the real vault (the crypto worker on web, the Rust host
 * on Tauri), so the demo exercises production's exact encryption path — it differs only in the
 * KEY (the reserved dev key vs. a passphrase-derived one). Real ciphertext at rest, under a
 * well-known (non-private) key. Because it goes through the Tauri `dev` command too, no
 * worker+WASM path survives inside the Tauri webview.
 * @param {object} [opts]
 * @param {boolean} [opts.dev]  build dev-key sessions (the demo path; the only mode here)
 */
export function createLibrarySealer({ dev = false } = {}) {
  if (!dev) throw new Error('createLibrarySealer only supports the dev demo path');
  const invoke = tauriInvoke();
  const build = invoke
    ? async (treeId) => {
        const { sealerId } = await invoke('sealer_dev', { treeId: Array.from(treeId) });
        return new SealerSession(invokeCore(invoke, sealerId));
      }
    : (() => {
        const worker = cryptoWorker();
        return async (treeId, docId) => {
          await worker.warm();
          const { sealerId } = await worker.dev(treeId, replicaId(docId));
          return new SealerSession(workerCore(worker, sealerId));
        };
      })();
  const byDoc = new Map(); // docId -> Promise<SealerSession>
  const sessionFor = (docId) => {
    let p = byDoc.get(docId);
    if (!p) {
      p = (async () => build(await treeIdBytes(docId), docId))();
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
