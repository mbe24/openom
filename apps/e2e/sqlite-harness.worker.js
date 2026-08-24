// E2E harness worker: one open → count → insert-5 → count cycle over the OPFS-SAHPool VFS,
// loading the vendored sqlite-wasm exactly as the app will (app/src/vendor/sqlite). SAHPool uses
// synchronous access handles — no SharedArrayBuffer, so no COOP/COEP cross-origin isolation.
import sqlite3InitModule from '../app/src/vendor/sqlite/index.mjs';

const locateFile = () => new URL('../app/src/vendor/sqlite/sqlite3.wasm', import.meta.url).href;

async function cycle() {
  const sqlite3 = await sqlite3InitModule({ locateFile, print() {}, printErr() {} });
  const pool = await sqlite3.installOpfsSAHPoolVfs({ name: 'openom-e2e-pool', initialCapacity: 6 });
  const db = new pool.OpfsSAHPoolDb('/openom-e2e.sqlite');
  db.exec(`CREATE TABLE IF NOT EXISTS claim(
    id TEXT PRIMARY KEY, target TEXT, predicate TEXT, value TEXT, created_at TEXT)`);

  const before = Number(db.selectValue('SELECT count(*) FROM claim'));
  const stmt = db.prepare(
    'INSERT OR IGNORE INTO claim(id,target,predicate,value,created_at) VALUES (?,?,?,?,?)');
  for (let i = 0; i < 5; i++) {
    const n = before + i;
    stmt.bind([
      'claim-' + n, 'person-1', 'openom.org/core/name/v1',
      JSON.stringify({ parts: { given: 'Test' + n } }), '2026-01-01',
    ]).stepReset();
  }
  stmt.finalize();
  const after = Number(db.selectValue('SELECT count(*) FROM claim'));
  db.close();
  return { before, after, coi: globalThis.crossOriginIsolated, lib: sqlite3.version.libVersion };
}

cycle()
  .then((r) => postMessage({ type: 'done', ok: true, ...r }))
  .catch((e) => postMessage({ type: 'done', ok: false, error: String((e && e.stack) || e) }));
