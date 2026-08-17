// The synced-mode delta-sync assembly (§B3): the ONE place the delta-log SyncController is wired together
// with landed-entry verification. Synced mode calls this to get a SyncController that already refuses
// unauthorized entries — nothing downstream has to remember to inject `verify`.
//
// This is the injection point the launch gate has been building toward: the composer
// (createEntryVerifier) is fed the client's retained keyring chain (keyringStore.at) and the crypto worker,
// and handed to the SyncController as its `verify`. What's still outside here is turning synced mode ON
// (auth token, RemoteStore base URL/config, the user-facing trigger in main.js) — deliberately, so this
// stays UI-free and unit-testable.

import { SyncController } from './sync.js';
import { createEntryVerifier } from './sealer/entryVerifier.js';

/**
 * @param {object} o
 * @param {number} o.version      envelope version (ENVELOPE_VERSION)
 * @param {object} o.tree         a FamilyTree (onDelta / mergeRemote / snapshotBytes)
 * @param {object} o.remote       a RemoteStore (appendLog / readLog / readSnapshot / activity)
 * @param {string} o.docId        the tree/doc id
 * @param {(raw: Uint8Array) => Promise<Uint8Array>|Uint8Array} o.seal   raw delta → sealed KIND_DELTA bytes
 * @param {(sealed: Uint8Array) => Promise<Uint8Array>|Uint8Array} o.open sealed bytes → raw delta
 * @param {object} o.worker       the crypto worker (entryAttribution / epochIsAttributed / verifyEntry)
 * @param {object} o.keyringStore the revision-retaining keyring store (`at(treeKey, revision)`)
 * @param {string|null} [o.replicaKey]  our own base64 replica id, to skip our echoes on pull
 * @param {object} [o.persist]    durable KV for the pull cursor
 * @returns {SyncController}  a controller that verifies every landed entry before merging
 */
export function createSyncedDeltaSync({ version, tree, remote, docId, seal, open, worker, keyringStore, replicaKey = null, persist }) {
  if (version == null || !tree || !remote || !docId || !seal || !open || !worker || !keyringStore) {
    throw new Error('createSyncedDeltaSync needs { version, tree, remote, docId, seal, open, worker, keyringStore }');
  }
  const verify = createEntryVerifier({
    version,
    worker,
    keyringAt: (revision) => keyringStore.at(docId, revision), // the client's verified, retained chain
  });
  return new SyncController({ tree, remote, docId, seal, open, replicaKey, persist, verify });
}
