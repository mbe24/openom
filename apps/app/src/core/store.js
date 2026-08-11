// DocStore: Persistenz opaker Bytes. Zwei Implementierungen mit identischer
// Semantik — die Speicher-Variante für den Browser, die Tauri-Variante
// spricht rusqlite über genau zwei Kommandos.

export class ConflictError extends Error {
  constructor(expected, found) {
    super(`version conflict: expected ${expected}, found ${found}`);
    this.name = 'ConflictError';
    this.expected = expected;
    this.found = found;
  }
}

export class MemoryStore {
  #docs = new Map();

  caps() {
    return { remote: false, conditionalWrites: true, durable: false };
  }

  #doc(id) {
    if (!this.#docs.has(id)) this.#docs.set(id, { snapshot: null, version: null, log: [], counter: 0 });
    return this.#docs.get(id);
  }

  async list() {
    return [...this.#docs.keys()];
  }

  async readSnapshot(id) {
    const d = this.#doc(id);
    return d.snapshot ? { bytes: d.snapshot, version: d.version } : null;
  }

  async readUpdates(id, since) {
    const d = this.#doc(id);
    const from = since ?? 0;
    return { updates: d.log.slice(from), cursor: d.log.length };
  }

  async append(id, updates) {
    const d = this.#doc(id);
    d.log.push(...updates);
    d.counter = d.log.length;
    return d.counter;
  }

  async putSnapshot(id, bytes, expected = null) {
    const d = this.#doc(id);
    if (d.version !== expected) throw new ConflictError(expected, d.version);
    d.counter += 1;
    d.snapshot = bytes;
    d.version = 'v' + d.counter;
    return d.version;
  }

  async delete(id) {
    this.#docs.delete(id);
  }
}

export class TauriStore {
  #invoke;
  #caps = { remote: false, conditionalWrites: true, durable: false };

  constructor(invoke) {
    this.#invoke = invoke;
  }

  caps() {
    return this.#caps;
  }

  async list() {
    return this.#invoke('store_list');
  }

  async #read(doc, since) {
    const res = await this.#invoke('store_read', { doc, since: since ?? null });
    this.#caps = { remote: res.caps.remote, conditionalWrites: res.caps.conditional_writes, durable: res.caps.durable };
    return res;
  }

  async readSnapshot(doc) {
    const res = await this.#read(doc, null);
    return res.snapshot ? { bytes: new Uint8Array(res.snapshot.bytes), version: res.snapshot.version } : null;
  }

  async readUpdates(doc, since) {
    const res = await this.#read(doc, since);
    return { updates: res.updates, cursor: res.cursor };
  }

  async append(doc, updates) {
    return this.#invoke('store_append', { args: { doc, updates } });
  }

  async putSnapshot(doc, bytes, expected = null) {
    try {
      return await this.#invoke('store_put_snapshot', { doc, bytes: Array.from(bytes), expected });
    } catch (e) {
      if (String(e).includes('version conflict')) throw new ConflictError(expected, null);
      throw e;
    }
  }

  async delete(doc) {
    return this.#invoke('store_delete', { doc });
  }
}

/**
 * Waehlt den Anbieter: Rust in Tauri, sonst IndexedDB im Browser, sonst
 * Speicher. Die Reihenfolge ist die Rangfolge der Haltbarkeit — und weil alle
 * drei dieselbe Schnittstelle haben, merkt die Oberflaeche nichts davon.
 *
 * Asynchron, weil sich nur durch Oeffnen herausfindet, ob IndexedDB wirklich
 * benutzbar ist: im privaten Modus mancher Browser gibt es das Objekt, aber
 * jeder Zugriff scheitert.
 */
export async function createStore() {
  const invoke = globalThis.__TAURI__?.core?.invoke;
  if (invoke) return { store: new TauriStore(invoke), kind: 'sqlite (rust)' };
  const { IndexedDbStore, indexedDbUsable } = await import('./indexedDbStore.js');
  if (await indexedDbUsable()) return { store: new IndexedDbStore(), kind: 'indexeddb (browser)' };
  return { store: new MemoryStore(), kind: 'memory (browser)' };
}
