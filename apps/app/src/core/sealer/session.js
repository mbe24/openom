// SealerSession — the stateful bridge between SealedStore's byte contract and the sealer
// `core` (the WasmSealer on web / a Tauri-invoke binding on native). It owns the
// per-replica chain state (SERVER-DATA-FORMAT §8a) so SealedStore can stay a thin
// seal(bytes, docId, {kind}) / open(bytes, docId, {kind}) decorator that knows no crypto.
//
// Chain state, per the vetted design:
//   * ONE monotonic `counter` (from 0, +1 per sealed envelope) and ONE `prev` hash chain,
//     SHARED across KIND_SNAPSHOT and KIND_DELTA (interleaved). Media is out-of-band and
//     never flows through here.
//   * IN-MEMORY ONLY, zero persistence — correct because `replica_id` is ephemeral per
//     JS-context (a reload = a brand-new replica, counter back to 0, empty prev). There is
//     no cross-reload chain to resume, so there is nothing to persist.
//   * Seals are SERIALIZED (an async queue): a hash chain is inherently sequential, and
//     SealedStore.append seals a batch — without serialization two seals would race for the
//     same `prev`/`counter`.
//
// `covers_through_seq` is 0 in V1 (§8a: it's the server-`seq` domain, and V1 has no server
// delta log; the local fold cursor stays inside the ciphertext body, never in the header).
//
// Advance-ordering note (§8a / crash-retry): the strict "advance the chain head only AFTER
// the durable local commit" rule bites for the V2 delta log. In V1 every snapshot is FULL
// state that supersedes the prior and readers take the latest, so an optimistic advance
// that wastes a counter on a rare local-commit conflict is benign. The crash-retry chaos
// suite pins the exact ordering when the delta path lands; this class keeps the seam (the
// head is a single mutable field advanced in one place) so tightening it is a local change.

const EMPTY = new Uint8Array(0);

// The core contract (satisfied by the wasm `WasmSealer` directly, or a native veneer):
//   sealEntry(kind, format, compression, replicaCounter, prevCiphertextHash,
//             coversThroughSeq, blobId, plaintext) -> { envelope, ciphertextHash }  (sync or async)
//   openEntry(expectKind, envelopeBytes) -> plaintext                               (sync or async)
//   get treeId -> Uint8Array
export class SealerSession {
  #core;
  #counter = 0;
  #prev = EMPTY;
  #queue = Promise.resolve();
  #locked = false;

  constructor(core) {
    if (!core || typeof core.sealEntry !== 'function' || typeof core.openEntry !== 'function') {
      throw new Error('SealerSession needs a sealer core (sealEntry/openEntry)');
    }
    this.#core = core;
  }

  /**
   * Seal `plaintext` under this session's DEK/scope with the next chain coordinate.
   * `kind` ∈ {'snapshot','delta'}; defaults to 'snapshot'. Serialized against every other
   * seal on this session so the chain stays linear. Returns the wire-ready envelope bytes.
   */
  seal(plaintext, _docId, { kind = 'snapshot' } = {}) {
    if (this.#locked) return Promise.reject(new Error('sealer is locked'));
    const run = this.#queue.then(() => this.#doSeal(plaintext, kind));
    // Keep the queue chained but don't let one rejection poison the next seal.
    this.#queue = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  async #doSeal(plaintext, kind) {
    const out = await this.#core.sealEntry(
      kind,
      'openom-json', // V1 payload format
      'none', // compression handled by the caller when it lands; not in V1
      this.#counter,
      this.#prev,
      0, // covers_through_seq — 0 in V1 (§8a)
      EMPTY, // blob_id — snapshot/delta only, never media here
      plaintext,
    );
    // Advance the chain head. Single point, so the crash-retry work can move it after the
    // durable commit without touching the seal logic.
    this.#counter += 1;
    this.#prev = out.ciphertextHash;
    return out.envelope;
  }

  /**
   * Open a sealed envelope, verifying it is the expected `kind` (and, in the core, that it
   * belongs to this tree/key) before decrypting. `kind` defaults to 'snapshot'.
   */
  async open(sealed, _docId, { kind = 'snapshot' } = {}) {
    if (this.#locked) throw new Error('sealer is locked');
    return this.#core.openEntry(kind, sealed);
  }

  /**
   * Free the key. DRAIN-then-free: chain onto the same queue as seal() so any in-flight or
   * queued seal completes (its ciphertext lands durably) BEFORE the core frees the key —
   * a lock racing a seal would otherwise drop that write while in-memory state moved on.
   * Idempotent; once locked, seal/open reject rather than hit a freed core.
   */
  async lock() {
    if (this.#locked) return;
    this.#locked = true;
    const done = this.#queue.then(() => this.#core.lock?.());
    // Keep the queue resolvable so a late seal()'s rejection path stays clean.
    this.#queue = done.then(() => {}, () => {});
    await done;
  }

  get locked() {
    return this.#locked;
  }

  /** The next counter this session will assign — for tests/introspection, not the wire. */
  get nextCounter() {
    return this.#counter;
  }
}
