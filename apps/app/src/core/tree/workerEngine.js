// A worker-backed engine with the SAME method surface `tree/index.js`'s main-thread `wrap()` exposes —
// but every call is async (Comlink-proxied to the app-core Web Worker, keyed by `docId`). This is the
// swap that moves the claim engine off the main thread: `FamilyTree` keeps its structure and just awaits
// these instead of a local `WasmTree`. The DEK + engine + sync + durable store all live in the worker;
// this side only marshals JSON/ids.
//
// Differences from `wrap()`, all deliberate:
//  - `commit()` replaces `flush()` — the worker seals the minted batch AND appends it to the durable log
//    in one step (persistence is the worker's job now), so callers no longer hand bytes to a JS store.
//  - `merge` / `snapshot` / `loadSnapshot` are gone — merging peers and (re)hydrating are the worker's
//    job (ingest / bootstrap), not the view-model's.
//  - reads (`project` / `liveClaimsOf` / `liveClaimsOfAny` / `liveRecords` / `oplog`) return parsed JSON.
export function workerEngine(worker, docId) {
  return {
    // --- mint: buffer ops into the current intention (the worker's Tree.pending) ---
    assertAnchor: (id, typeUri) => worker.assertAnchor(docId, id, typeUri),
    assertClaim: (target, predicate, value) =>
      worker.assertClaim(docId, target, predicate, JSON.stringify(value)),
    supersedeClaim: (prior, target, predicate, value) =>
      worker.supersedeClaim(docId, prior, target, predicate, JSON.stringify(value)),
    remove: (recordId) => worker.removeRecord(docId, recordId), // resolves to the Remove op id
    revoke: (opId) => worker.revoke(docId, opId),

    // --- commit: seal everything minted since the last commit as ONE batch + persist it ---
    commit: () => worker.commit(docId),

    // --- roles ---
    setModerators: (dids) => worker.setModerators(docId, dids),

    // --- reads (parsed) ---
    project: async () => JSON.parse(await worker.project(docId)),
    liveClaimsOf: async (target, predicate) =>
      JSON.parse(await worker.liveClaimsOf(docId, target, predicate)),
    liveClaimsOfAny: async (target) => JSON.parse(await worker.liveClaimsOfAny(docId, target)),
    liveRecords: async () => JSON.parse(await worker.liveRecords(docId)),
    resolveId: (anchor) => worker.resolveId(docId, anchor),
    oplog: async () => JSON.parse(await worker.oplog(docId)),
  };
}
