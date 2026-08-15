// Where a tree's keyring lives on the device: one opaque record per tree key. The keyring is
// not secret (only wrapped material + a signature), so plain durable storage is fine; it is
// the source of truth for unlocking. Kept in its own IndexedDB database so it never entangles
// with the snapshot/update store's versioning.
//
// The store is a tiny { load, save } interface so the vault can be tested against an
// in-memory one and run against IndexedDB in the browser.

const DB = 'openom-keyrings';
const STORE = 'keyrings';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, mode) {
  return db.transaction(STORE, mode).objectStore(STORE);
}

/** The durable browser keyring store (IndexedDB). Records store byte arrays keyed by tree key. */
export function indexedDbKeyringStore() {
  let dbPromise = null;
  const db = () => (dbPromise ??= openDb());
  return {
    async load(treeKey) {
      const store = tx(await db(), 'readonly');
      const row = await new Promise((res, rej) => {
        const r = store.get(treeKey);
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      return row ? new Uint8Array(row) : null;
    },
    async save(treeKey, bytes) {
      const store = tx(await db(), 'readwrite');
      await new Promise((res, rej) => {
        const r = store.put(Array.from(bytes), treeKey);
        r.onsuccess = () => res();
        r.onerror = () => rej(r.error);
      });
    },
  };
}

/** In-memory keyring store (tests, or environments without IndexedDB). */
export function memoryKeyringStore() {
  const m = new Map();
  return {
    async load(treeKey) {
      return m.has(treeKey) ? m.get(treeKey) : null;
    },
    async save(treeKey, bytes) {
      m.set(treeKey, bytes);
    },
  };
}
