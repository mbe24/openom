// Where a tree's keyring lives on the device. The keyring is not secret (only wrapped material + a
// signature), so plain durable storage is fine; it is the source of truth for unlocking AND — since the
// launch gate (§B3) — for verifying a landed entry against the keyring revision that governed it. So the
// store RETAINS EVERY revision (not just the head): a peer's delta stamped at an older revision is verified
// against the keyring AT that revision, which the client walked + trusts.
//
// Interface (async): the vault reads/writes the head for unlock; the verify composer reads `at(revision)`.
//   save(treeKey, revision, bytes)      // persist one verified revision
//   at(treeKey, revision) -> bytes|null // a specific retained revision (the governing keyring)
//   head(treeKey) -> {revision, bytes}|null   // the highest retained revision
//   load(treeKey) -> bytes|null         // head bytes (the unlock anchor) — a convenience over head()
//
// Kept in its own IndexedDB database so it never entangles with the snapshot/update store's versioning.

const DB = 'openom-keyrings';
const STORE = 'keyrings';
const HEAD = (treeKey) => `${treeKey}::head`; // pointer record: the max retained revision
const REV = (treeKey, revision) => `${treeKey}::r${revision}`;

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

function get(store, key) {
  return new Promise((res, rej) => {
    const r = store.get(key);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
function put(store, value, key) {
  return new Promise((res, rej) => {
    const r = store.put(value, key);
    r.onsuccess = () => res();
    r.onerror = () => rej(r.error);
  });
}

/** The durable browser keyring store (IndexedDB), retaining every revision. */
export function indexedDbKeyringStore() {
  let dbPromise = null;
  const db = () => (dbPromise ??= openDb());
  return {
    async save(treeKey, revision, bytes) {
      const store = tx(await db(), 'readwrite');
      await put(store, Array.from(bytes), REV(treeKey, revision));
      const curHead = await get(store, HEAD(treeKey));
      if (curHead == null || revision > curHead) await put(store, revision, HEAD(treeKey));
    },
    async at(treeKey, revision) {
      const row = await get(tx(await db(), 'readonly'), REV(treeKey, revision));
      return row ? new Uint8Array(row) : null;
    },
    async head(treeKey) {
      const store = tx(await db(), 'readonly');
      const rev = await get(store, HEAD(treeKey));
      if (rev == null) return null;
      const row = await get(store, REV(treeKey, rev));
      return row ? { revision: rev, bytes: new Uint8Array(row) } : null;
    },
    async load(treeKey) {
      const h = await this.head(treeKey);
      return h ? h.bytes : null;
    },
  };
}

/** In-memory keyring store (tests, or environments without IndexedDB), retaining every revision. */
export function memoryKeyringStore() {
  const trees = new Map(); // treeKey -> Map(revision -> bytes)
  const forTree = (k) => {
    let t = trees.get(k);
    if (!t) trees.set(k, (t = new Map()));
    return t;
  };
  const headOf = (treeKey) => {
    const t = trees.get(treeKey);
    if (!t || t.size === 0) return null;
    let max = -1;
    for (const r of t.keys()) if (r > max) max = r;
    return { revision: max, bytes: t.get(max) };
  };
  return {
    async save(treeKey, revision, bytes) {
      forTree(treeKey).set(revision, bytes);
    },
    async at(treeKey, revision) {
      return trees.get(treeKey)?.get(revision) ?? null;
    },
    async head(treeKey) {
      return headOf(treeKey);
    },
    async load(treeKey) {
      return headOf(treeKey)?.bytes ?? null;
    },
  };
}
