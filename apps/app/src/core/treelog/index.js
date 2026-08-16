// The web shim over the family-tree engine (packages/openom-treelog, compiled to wasm). It runs in
// the MAIN thread — unlike the sealer, the tree holds no key material, so no worker isolation is
// needed. Build the wasm with `node scripts/build-treelog.mjs` (output under ../../vendor/treelog).
//
// A wrapped tree returns the encoded commute ops from each edit (a Uint8Array to seal + append via
// the sealer/store), integrates peers' decrypted deltas with mergeBytes, and parses the read model
// (JSON strings from wasm) back into objects. Ids are opaque 16-byte handles the shim mints.
import init, { WasmTree } from '../../vendor/treelog/openom_treelog.js';

let ready;
// In the browser, init() fetches the .wasm next to the module; in node/tests, pass the bytes as
// `initInput` (wasm-bindgen accepts a module/bytes/URL). Only the first call's input is used.
const ensureInit = (initInput) => (ready ??= init(initInput));

/** A fresh opaque id (person/family/claim handle) — 16 random bytes. */
export function newId() {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return b;
}

function wrap(inner) {
  return {
    // --- edits: each returns the encoded ops (Uint8Array) to seal + append ---
    addPerson: (id) => inner.addPerson(id),
    removePerson: (id) => inner.removePerson(id),
    addClaim: (person, field, claim, value, source = null) => inner.addClaim(person, field, claim, value, source ?? undefined),
    setPreferredClaim: (person, field, claim) => inner.setPreferredClaim(person, field, claim),
    retractClaim: (person, field, claim) => inner.retractClaim(person, field, claim),
    addFamily: (id) => inner.addFamily(id),
    removeFamily: (id) => inner.removeFamily(id),
    linkChild: (family, person, pedi = 'birth') => inner.linkChild(family, person, pedi),
    unlinkChild: (family, person) => inner.unlinkChild(family, person),
    moveChild: (person, from, to, pedi = 'birth') => inner.moveChild(person, from, to, pedi),
    linkSpouse: (family, person) => inner.linkSpouse(family, person),
    unlinkSpouse: (family, person) => inner.unlinkSpouse(family, person),

    // --- sync ---
    mergeBytes: (bytes) => inner.mergeBytes(bytes),
    snapshot: () => inner.snapshot(),

    // --- read model (parsed) ---
    persons: () => JSON.parse(inner.persons()),
    hasPerson: (id) => inner.hasPerson(id),
    fact: (person, field) => JSON.parse(inner.fact(person, field)),
    families: () => JSON.parse(inner.families()),
    children: (family) => JSON.parse(inner.children(family)),
    spouses: (family) => JSON.parse(inner.spouses(family)),

    newId,
  };
}

/**
 * Create (or restore) a family tree.
 * @param {{ replica?: Uint8Array, snapshot?: Uint8Array, initInput?: any }} [opts]
 *   `replica` — a 16-byte replica id (minted if omitted); `snapshot` — restore from commute bytes;
 *   `initInput` — wasm init input for non-browser hosts (tests pass the .wasm bytes).
 */
export async function createTree({ replica, snapshot, initInput } = {}) {
  await ensureInit(initInput);
  const rep = replica ?? newId();
  const inner = snapshot ? WasmTree.fromSnapshot(rep, snapshot) : new WasmTree(rep);
  return wrap(inner);
}
