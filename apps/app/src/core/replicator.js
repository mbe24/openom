// Replicator: drives a SyncStore toward convergence for a document. It owns the sync
// loop and the conflict-resolution cycle — pull/push, and on a conflict:
//   open remote → merge into local → re-seal → resolve → reconcile again
// until the push lands (or the network drops, or churn exceeds a round budget).
//
// The merge itself is plaintext- and FamilyTree-specific, so it is INJECTED: only the
// app has the sealer (open/seal) and the tree's fold logic. This keeps the Replicator a
// pure orchestrator, testable against fakes.
//
//   open(sealed: Uint8Array)  => Promise<Uint8Array>   // sealer.open — ciphertext → plaintext
//   seal(plain: Uint8Array)   => Promise<Uint8Array>   // sealer.seal — plaintext → sealed Envelope
//   merge(localPlain|null, remotePlain) => Promise<Uint8Array>  // fold remote into local (§10)

const DEFAULT_MAX_ROUNDS = 8;

export class Replicator {
  #sync;
  #open;
  #seal;
  #merge;
  #maxRounds;

  constructor(sync, { open, seal, merge, maxRounds = DEFAULT_MAX_ROUNDS }) {
    if (!sync || !open || !seal || !merge) {
      throw new Error('Replicator needs a SyncStore plus open/seal/merge');
    }
    this.#sync = sync;
    this.#open = open;
    this.#seal = seal;
    this.#merge = merge;
    this.#maxRounds = maxRounds;
  }

  /**
   * Bring one document into sync. Terminal statuses:
   *   'synced' | 'fastForward' | 'upToDate' | 'clean' | 'noRemote' — converged
   *   'offline'    — network error; the caller retries later (state stays dirty)
   *   'unresolved' — exceeded the round budget (persistent conflict churn)
   */
  async sync(id) {
    for (let round = 0; round < this.#maxRounds; round++) {
      const r = await this.#sync.reconcile(id);
      if (r.status === 'offline') return 'offline';
      if (r.status !== 'conflict') return r.status;

      // Conflict: both sides changed. Merge the remote into local, re-seal, and record
      // the resolution against the remote version so the next push's If-Match matches.
      const localSnap = await this.#sync.readSnapshot(id);
      const localPlain = localSnap ? await this.#open(localSnap.bytes) : null;
      const remotePlain = await this.#open(r.remote.bytes);
      const merged = await this.#merge(localPlain, remotePlain);
      const sealed = await this.#seal(merged);
      await this.#sync.resolveWith(id, sealed, r.remote.version);
      // loop → reconcile again → push (If-Match = the merged-from remote version)
    }
    return 'unresolved';
  }
}
