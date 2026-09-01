// Where a tree's keyring lives on the device. The keyring is not secret (only wrapped material + a
// signature), so plain durable storage is fine; it is the source of truth for unlocking AND — since the
// launch gate (§B3) — for verifying a landed entry against the keyring revision that governed it. So the
// store RETAINS EVERY revision (not just the head): a peer's delta stamped at an older revision is verified
// against the keyring AT that revision, which the client walked + trusts.
//
// Interface (async):
//   saveHead(treeKey, engine, bytes)    // the current UNLOCK anchor + its engine tag (both engines; OPE-278)
//   loadHead(treeKey) -> {engine,bytes}|null
//   load(treeKey) -> bytes|null         // the head record's anchor — a convenience over loadHead()
//   save(treeKey, revision, bytes)      // CHAIN retention: persist one verified revision (§B3)
//   at(treeKey, revision) -> bytes|null // a specific retained revision (the governing keyring, chain-only)
//   head(treeKey) -> {revision, bytes}|null   // the highest retained revision (chain-only)
//
// The head record is the engine-neutral unlock anchor (the dag has no revisions — its anchor is one blob).
// The per-revision retention is CHAIN-ONLY: the §B3 verify composer reads `at(revision)` for the keyring
// that governed a landed entry. Kept in its own IndexedDB database so it never entangles with the
// snapshot/update store's versioning.

const DB = 'openom-keyrings';
const STORE = 'keyrings';
const HEAD = (treeKey) => `${treeKey}::head`; // pointer record: the max retained revision (chain retention)
const HEADREC = (treeKey) => `${treeKey}::headrec`; // the current head record: { engine, bytes }
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
    async saveHead(treeKey, engine, bytes) {
      await put(tx(await db(), 'readwrite'), { engine, bytes: Array.from(bytes) }, HEADREC(treeKey));
    },
    async loadHead(treeKey) {
      const rec = await get(tx(await db(), 'readonly'), HEADREC(treeKey));
      return rec ? { engine: rec.engine, bytes: new Uint8Array(rec.bytes) } : null;
    },
    async load(treeKey) {
      return (await this.loadHead(treeKey))?.bytes ?? null;
    },
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
  };
}

/** In-memory keyring store (tests, or environments without IndexedDB), retaining every revision. */
export function memoryKeyringStore() {
  const trees = new Map(); // treeKey -> Map(revision -> bytes)   (chain retention)
  const heads = new Map(); // treeKey -> { engine, bytes }        (the unlock head record)
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
    async saveHead(treeKey, engine, bytes) {
      heads.set(treeKey, { engine, bytes });
    },
    async loadHead(treeKey) {
      return heads.get(treeKey) ?? null;
    },
    async load(treeKey) {
      return heads.get(treeKey)?.bytes ?? null;
    },
    async save(treeKey, revision, bytes) {
      forTree(treeKey).set(revision, bytes);
    },
    async at(treeKey, revision) {
      return trees.get(treeKey)?.get(revision) ?? null;
    },
    async head(treeKey) {
      return headOf(treeKey);
    },
  };
}
