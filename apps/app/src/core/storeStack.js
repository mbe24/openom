// The store composition root: the ONE place the layer stack is assembled, keyed off an
// explicit mode, fail-closed. This is the structural guard (§16) that a plaintext path
// can only ever exist for throwaway demo data — real user data is unconditionally
// sealed, because the sealed compositions require a sealer and the demo composition
// requires MemoryStore.
//
//   'demo'   — local-only, PLAINTEXT, seed data. MemoryStore ONLY (never a durable
//              store), no SealedStore/SyncStore. The single unencrypted composition,
//              and it can never persist to the same store real data would.
//   'local'  — offline-first, encrypted at rest: SealedStore over the durable local
//              store. No server.
//   'synced' — encrypted + synced: SealedStore over SyncStore(local, remote).
//
// Layer order (top → bottom): FamilyTree → SealedStore → SyncStore → { local, remote }.

import { MemoryStore, createStore } from './store.js';
import { SealedStore } from './sealedStore.js';
import { SyncStore } from './syncStore.js';
import { RemoteStore } from './remoteStore.js';
import { Watermarks } from './watermarks.js';

/**
 * @param {object} opts
 * @param {'demo'|'local'|'synced'} opts.mode
 * @param {object} [opts.sealer]        required for 'local'/'synced' (§16)
 * @param {object} [opts.local]         durable local DocStore; defaults to createStore()
 * @param {object} [opts.remote]        a RemoteStore (or built from remoteBaseUrl)
 * @param {string} [opts.remoteBaseUrl] server base URL (used if `remote` is omitted)
 * @param {object|null} [opts.auth]     the AuthSession seam for the remote's per-request bearer
 * @param {object} [opts.watermarks]    §10 anti-rollback for 'synced'; defaults to a new one
 * @returns {Promise<{ store, mode, encrypted, kind, sync? }>}
 */
export async function composeStore(opts) {
  const { mode } = opts;

  if (mode === 'demo') {
    // Structurally unable to touch real data: MemoryStore is ephemeral (tab-lifetime),
    // never the durable store a real tree uses. Refuse a durable store here.
    if (opts.local && opts.local.caps?.().durable) {
      throw new Error("demo mode must use MemoryStore, not a durable store");
    }
    return { store: new MemoryStore(), mode, encrypted: false, kind: 'memory (demo)' };
  }

  if (mode !== 'local' && mode !== 'synced') {
    throw new Error(`unknown store mode: ${mode}`);
  }
  if (!opts.sealer) {
    throw new Error(`mode '${mode}' requires a sealer — there is no plaintext path for real data (§16)`);
  }

  const localResult = opts.local ? { store: opts.local, kind: 'injected' } : await createStore();
  const local = localResult.store;

  if (mode === 'local') {
    return {
      store: new SealedStore(local, opts.sealer),
      mode,
      encrypted: true,
      kind: `sealed / ${localResult.kind}`,
    };
  }

  if (mode === 'synced') {
    const remote =
      opts.remote ??
      new RemoteStore({ baseUrl: opts.remoteBaseUrl, auth: opts.auth ?? null });
    if (!remote) throw new Error("mode 'synced' requires a remote or remoteBaseUrl");
    // A partly-trusted server is a real adversary once sync exists, so the sync layer gets a
    // Watermarks — it refuses a fast-forward onto a snapshot the client already moved past
    // (§10 anti-rollback). Injectable for tests; persisted per device by default.
    const sync = new SyncStore(local, remote, { watermarks: opts.watermarks ?? new Watermarks() });
    return {
      store: new SealedStore(sync, opts.sealer),
      mode,
      encrypted: true,
      kind: `sealed / synced / ${localResult.kind}`,
      sync, // exposed so the Replicator can drive reconcile()
    };
  }
}
