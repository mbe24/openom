// DocStore mit IndexedDB. Gleiche Semantik wie MemoryStore und TauriStore —
// nur bleibt hier etwas liegen, wenn der Browser den Tab verwirft.
//
// Warum ueberhaupt: mobile Browser raeumen Hintergrund-Tabs schon nach Minuten
// ab. Ohne Speicher verliert jemand seinen Baum, waehrend er kurz in eine
// andere App wechselt — und merkt es erst danach.
//
// Spaeter mit S3 wird daraus die Offline-Kopie und die Warteschlange fuer noch
// nicht hochgeladene Aenderungen: dieselbe Schnittstelle, andere Rolle.

import { ConflictError } from './store.js';

const DB = 'openom';
const VERSION = 2;
const SNAPSHOTS = 'snapshots';
const UPDATES = 'updates';
// The durable mirror of the core's local BlobStore: opaque (doc, key) → bytes objects. The app-core core owns
// the keyspace; this just persists whatever `export()` hands it and replays it into `import()` on reload.
const BLOBS = 'blobs';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(SNAPSHOTS)) db.createObjectStore(SNAPSHOTS, { keyPath: 'doc' });
      if (!db.objectStoreNames.contains(UPDATES)) {
        // Fortlaufender Schluessel: der Log ist eine Reihenfolge, kein Satz.
        const s = db.createObjectStore(UPDATES, { keyPath: 'seq', autoIncrement: true });
        s.createIndex('doc', 'doc');
      }
      if (!db.objectStoreNames.contains(BLOBS)) {
        // Keyed by the composite [doc, key]; indexed by doc so a whole document's objects load in one range.
        const b = db.createObjectStore(BLOBS, { keyPath: ['doc', 'key'] });
        b.createIndex('doc', 'doc');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

const done = (tx) => new Promise((resolve, reject) => {
  tx.oncomplete = () => resolve();
  tx.onerror = () => reject(tx.error);
  tx.onabort = () => reject(tx.error);
});

const ask = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

export class IndexedDbStore {
  #db = null;

  caps() {
    return { remote: false, conditionalWrites: true, durable: true };
  }

  async #handle() {
    if (!this.#db) this.#db = await open();
    return this.#db;
  }

  async #tx(names, mode) {
    const db = await this.#handle();
    return db.transaction(names, mode);
  }

  async list() {
    const tx = await this.#tx([SNAPSHOTS, UPDATES], 'readonly');
    const docs = new Set(await ask(tx.objectStore(SNAPSHOTS).getAllKeys()));
    for (const row of await ask(tx.objectStore(UPDATES).getAll())) docs.add(row.doc);
    return [...docs];
  }

  async readSnapshot(doc) {
    const tx = await this.#tx([SNAPSHOTS], 'readonly');
    const row = await ask(tx.objectStore(SNAPSHOTS).get(doc));
    return row ? { bytes: new Uint8Array(row.bytes), version: row.version } : null;
  }

  async readUpdates(doc, since) {
    const tx = await this.#tx([UPDATES], 'readonly');
    const rows = await ask(tx.objectStore(UPDATES).index('doc').getAll(doc));
    // Nach seq sortiert: der Index gibt die Reihenfolge nicht zu.
    rows.sort((a, b) => a.seq - b.seq);
    const from = since ?? 0;
    return { updates: rows.slice(from).map((r) => r.update), cursor: rows.length };
  }

  async append(doc, updates) {
    const tx = await this.#tx([UPDATES], 'readwrite');
    const store = tx.objectStore(UPDATES);
    for (const update of updates) store.add({ doc, update });
    await done(tx);
    const { cursor } = await this.readUpdates(doc, null);
    return cursor;
  }

  async putSnapshot(doc, bytes, expected = null) {
    const tx = await this.#tx([SNAPSHOTS], 'readwrite');
    const store = tx.objectStore(SNAPSHOTS);
    const prev = await ask(store.get(doc));
    const found = prev?.version ?? null;
    // Bedingtes Schreiben in derselben Transaktion wie das Lesen — sonst
    // koennten zwei Tabs desselben Browsers einander ueberschreiben.
    if (found !== expected) { tx.abort(); throw new ConflictError(expected, found); }
    const counter = (prev?.counter ?? 0) + 1;
    store.put({ doc, bytes: Array.from(bytes), version: 'v' + counter, counter });
    await done(tx);
    return 'v' + counter;
  }

  // Load every persisted object for a doc as [{ key, bytes }] — fed straight into the core's `import`.
  async readBlobs(doc) {
    const tx = await this.#tx([BLOBS], 'readonly');
    const rows = await ask(tx.objectStore(BLOBS).index('doc').getAll(doc));
    return rows.map((r) => ({ key: r.key, bytes: new Uint8Array(r.bytes) }));
  }

  // Persist a batch of the core's objects (from `export()`). Idempotent: immutable log objects re-put
  // identically; pointer objects (heads/snapshot) overwrite. `objects` is [{ key, bytes }] (a `pointer` flag,
  // if present, is ignored here — durability keeps every object regardless).
  async putBlobs(doc, objects) {
    if (!objects.length) return;
    const tx = await this.#tx([BLOBS], 'readwrite');
    const store = tx.objectStore(BLOBS);
    for (const { key, bytes } of objects) store.put({ doc, key, bytes: Array.from(bytes) });
    await done(tx);
  }

  async delete(doc) {
    const tx = await this.#tx([SNAPSHOTS, UPDATES, BLOBS], 'readwrite');
    tx.objectStore(SNAPSHOTS).delete(doc);
    const updIndex = tx.objectStore(UPDATES).index('doc');
    for (const key of await ask(updIndex.getAllKeys(doc))) tx.objectStore(UPDATES).delete(key);
    const blobIndex = tx.objectStore(BLOBS).index('doc');
    for (const key of await ask(blobIndex.getAllKeys(doc))) tx.objectStore(BLOBS).delete(key);
    await done(tx);
  }
}

/** Steht IndexedDB zur Verfuegung? Im privaten Modus mancher Browser nicht. */
export async function indexedDbUsable() {
  if (typeof indexedDB === 'undefined') return false;
  try {
    const db = await open();
    db.close();
    return true;
  } catch {
    return false;
  }
}
