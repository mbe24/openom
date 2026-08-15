// The sealer entry point: hands the rest of the app ONE `SealerSession` per tree, backed
// by the right binding (WASM on web, Tauri invoke on native). Everything above this — the
// SealedStore, composeStore — just receives a `sealer` with seal/open and never learns
// which binding produced it.
//
// SINGLETON PER TREE (SERVER-DATA-FORMAT §8a). `identity.replicaId(treeKey)` memoizes one
// random replica_id per (tree, JS-context). If two SealerSessions existed for one tree in
// one context, they would share that replica_id yet each count from 0 → two entries with
// the same (replica_id, 0) dot and divergent content: a self-inflicted fork. So sessions
// are cached per tree here and reused — the guard is structural, not documentation.

import { SealerSession } from './session.js';
import { replicaId } from '../identity.js';
import { Watermarks } from '../watermarks.js';
import { createVault } from './vault.js';
import { indexedDbKeyringStore } from './keyringStore.js';
import { cryptoWorker, workerCore } from './workerSealer.js';

const registry = new Map(); // treeKey -> SealerSession

/**
 * Return the one SealerSession for `treeKey`, building it via `makeCore` on first request
 * and reusing it thereafter. `makeCore` is injected so the registry stays binding-agnostic
 * and unit-testable; the resolvers below supply the real web/native cores.
 * @param {string} treeKey  stable string id for the tree (used for the registry + replica_id)
 * @param {() => Promise<object>} makeCore  builds the low-level sealer core
 * @returns {Promise<SealerSession>}
 */
export async function getSealer(treeKey, makeCore) {
  const existing = registry.get(treeKey);
  if (existing) return existing;
  // Build without awaiting-then-checking-again races: store a promise? Keep it simple —
  // callers for one tree are serialized by the app's open-tree flow. If that ever changes,
  // cache the in-flight promise here instead of the resolved session.
  const core = await makeCore();
  const session = new SealerSession(core);
  registry.set(treeKey, session);
  return session;
}

/** Drop a tree's cached session (e.g. on close/lock) so the next open rebuilds it. */
export function forgetSealer(treeKey) {
  registry.delete(treeKey);
}

/** Test-only: clear the whole registry. */
export function _resetSealerRegistry() {
  registry.clear();
}

// Runtime detection: Tauri v2 injects __TAURI_INTERNALS__ on window. Anything else is web.
function isTauri() {
  return typeof globalThis !== 'undefined' && globalThis.window && '__TAURI_INTERNALS__' in globalThis.window;
}

/**
 * Build (or reuse) the SealerSession for a tree, picking the binding by runtime.
 * @param {object} opts
 * @param {string} opts.treeKey   stable string tree id (registry + replica_id key)
 * @param {Uint8Array} opts.treeId  the 16-byte tree id for the envelope header
 * @param {Uint8Array} opts.replicaId  this context's replica id (identity.replicaId)
 * @param {boolean} [opts.dev]     use the reserved dev key (§16) — serverless UI dev, no unlock
 * @param {Uint8Array} [opts.dek]  an unwrapped 32-byte DEK (required when not dev)
 * @param {Uint8Array} [opts.keyId] the key epoch id (required when not dev)
 * @param {string|null} [opts.aead]  'xchacha20-poly1305' (default) | 'aes-256-gcm'
 */
export async function createSealer(opts) {
  const { treeKey } = opts;
  if (!treeKey) throw new Error('createSealer needs a treeKey');
  const makeCore = isTauri()
    ? () => import('./native.js').then((m) => m.createNativeCore(opts))
    : () => import('./wasm.js').then((m) => m.createWasmCore(opts));
  return getSealer(treeKey, makeCore);
}

/**
 * The real passphrase vault for the app: the WASM module + the durable IndexedDB keyring
 * store + a persisted anti-rollback watermark. The UI drives provision/unlock/recover/
 * changePassphrase on it. (Web only for now; the native binding is a later step.)
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
