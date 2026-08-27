// The web shim over the claim-based family-tree engine (packages/openom-tree, compiled to wasm). Like
// the treelog shim it runs in the MAIN thread — the engine holds no key material, so no worker
// isolation is needed. Build the wasm with `node scripts/build-tree.mjs` (output under ../../vendor/tree).
//
// A wrapped tree turns each edit into the encoded op-batch bytes to seal + append (a Uint8Array),
// integrates peers' decrypted batches with merge(), and parses the read model + granular claim readers
// (JSON strings from wasm) back into objects. Claim values cross as JS objects here and are JSON-encoded
// at the boundary. Ids (anchor/claim ids) are opaque strings the caller mints; the author `created_by`
// is the vault-derived did:key (OPE-191), stamped on every op this replica emits.
import init, { WasmTree } from '../../vendor/tree/openom_tree.js';

let ready;
// In the browser, init() fetches the .wasm next to the module; in node/tests, pass the bytes as
// `initInput` (wasm-bindgen accepts a module/bytes/URL). Only the first call's input is used.
const ensureInit = (initInput) => (ready ??= init(initInput));

function wrap(inner) {
  return {
    // --- edits: mints accumulate in the engine (see flush below); the return is unused except for
    //     `remove`, which hands back the Remove op's id so an anchor removal can later be revoked ---
    assertAnchor: (id, typeUri, createdAt) => inner.assertAnchor(id, typeUri, createdAt),
    assertClaim: (target, predicate, value, createdAt) =>
      inner.assertClaim(target, predicate, JSON.stringify(value), createdAt),
    supersedeClaim: (prior, target, predicate, value, createdAt) =>
      inner.supersedeClaim(prior, target, predicate, JSON.stringify(value), createdAt),
    remove: (target, createdAt) => inner.remove(target, createdAt),
    revoke: (removalOpId, createdAt) => inner.revoke(removalOpId, createdAt),
    // Encode everything minted since the last flush as ONE op-batch (empty if nothing) — one settled
    // intention = one sealed store entry. The mint methods above now accumulate; flush produces the batch.
    flush: () => inner.flush(),

    // --- role authority: the did:keys currently at Maintainer+ whose remove/supersede/revoke ops the
    //     fold honors (a solo tree defaults to its own author) ---
    setModerators: (dids) => inner.setModerators(dids),

    // --- sync / persistence (op-batch + snapshot bytes are opaque to the store) ---
    merge: (bytes) => inner.merge(bytes),
    snapshot: () => inner.snapshot(),
    loadSnapshot: (bytes) => inner.loadSnapshot(bytes),

    // --- read model (parsed) ---
    project: () => JSON.parse(inner.project()),
    liveClaimsOf: (target, predicate) => JSON.parse(inner.liveClaimsOf(target, predicate)),
    liveClaimsOfAny: (target) => JSON.parse(inner.liveClaimsOfAny(target)),
    liveRecords: () => JSON.parse(inner.liveRecords()),
    resolveId: (anchor) => inner.resolveId(anchor) ?? null,
  };
}

/**
 * Create (or restore) a claim-based family tree.
 * @param {{ createdBy?: string, snapshot?: Uint8Array, initInput?: any }} [opts]
 *   `createdBy` — the vault-derived did:key stamped as the author of every op (a stable local
 *   placeholder is used if omitted, e.g. a read-only shadow run); `snapshot` — restore from a
 *   snapshot batch; `initInput` — wasm init input for non-browser hosts (tests pass the .wasm bytes).
 */
export async function createTree({ createdBy, snapshot, initInput } = {}) {
  await ensureInit(initInput);
  const inner = new WasmTree(createdBy ?? 'did:key:zLocalReplica');
  if (snapshot) inner.loadSnapshot(snapshot);
  return wrap(inner);
}
