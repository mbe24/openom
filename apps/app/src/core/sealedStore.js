// SealedStore: a DocStore decorator that seals on write and opens on read, so every
// layer below it (local cache AND remote) only ever handles OPAQUE ciphertext. The
// crypto itself lives in the injected `sealer` — openom-crypto reached via WASM on the
// web / `invoke` on Tauri — so this layer stays thin and knows no algorithm.
//
// Two consequences of sitting ABOVE the cache/sync split (see the client store stack):
//   * the local cache is encrypted at rest — the lock screen finally means something;
//   * the bytes cached are the exact bytes uploaded (SyncStore moves them verbatim).
//
// A `ConflictError` from below propagates UNCHANGED: a ciphertext layer can't merge —
// only FamilyTree, with plaintext, can pull + reapply + re-seal.
//
// The `sealer` contract (async; the WASM/native binding provides it). The `kind` tells the
// sealer which envelope Kind to stamp on seal and to VERIFY on open — snapshots and the
// delta log share one replica hash-chain but must not be opened as each other:
//   seal(plaintext: Uint8Array, docId: string, opts?: {kind}) => Promise<Uint8Array>  // → Envelope bytes
//   open(sealed: Uint8Array,   docId: string, opts?: {kind}) => Promise<Uint8Array>  // → plaintext, or throws
// `kind` ∈ {'snapshot','delta'}; it is optional so a plaintext test fake can ignore it.

export class SealedStore {
  #inner;
  #sealer;

  constructor(inner, sealer) {
    if (!inner || !sealer) throw new Error('SealedStore needs an inner store and a sealer');
    this.#inner = inner;
    this.#sealer = sealer;
  }

  // Expose that this composition is encrypted, so the UI can assert it rather than
  // infer it from which build it thinks it is.
  caps() {
    return { ...this.#inner.caps(), encrypted: true };
  }

  async list() {
    return this.#inner.list();
  }

  async readSnapshot(id) {
    const snap = await this.#inner.readSnapshot(id);
    if (!snap) return null;
    return { bytes: await this.#sealer.open(snap.bytes, id, { kind: 'snapshot' }), version: snap.version };
  }

  async putSnapshot(id, bytes, expected = null) {
    const sealed = await this.#sealer.seal(bytes, id, { kind: 'snapshot' });
    return this.#inner.putSnapshot(id, sealed, expected); // ConflictError bubbles up
  }

  async readUpdates(id, since) {
    const { updates, cursor } = await this.#inner.readUpdates(id, since);
    const opened = await Promise.all(updates.map((u) => this.#sealer.open(u, id, { kind: 'delta' })));
    return { updates: opened, cursor };
  }

  async append(id, updates) {
    const sealed = await Promise.all(updates.map((u) => this.#sealer.seal(u, id, { kind: 'delta' })));
    return this.#inner.append(id, sealed);
  }

  async delete(id) {
    return this.#inner.delete(id);
  }
}
