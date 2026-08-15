// Web binding: build a sealer core from the WASM module (packages/openom-sealer/pkg,
// produced by scripts/build-sealer.mjs). The generated `WasmSealer` already exposes exactly
// the core contract SealerSession expects — sealEntry(...) → {envelope, ciphertextHash},
// openEntry(...) → plaintext, and a `treeId` getter — so no adapter is needed.
//
// INTEGRATION NOTE (verify in-app): the pkg is built on demand and gitignored, so it is
// imported dynamically (below) rather than at module load, and the .wasm asset is resolved
// relative to the generated JS via import.meta.url. Under Vite this typically needs the
// asset served as a URL; if init() can't find the .wasm, pass it explicitly:
//   await mod.default({ module_or_path: new URL('<pkg>/openom_sealer_bg.wasm', import.meta.url) })
// This path is exercised by the app's serverless dev flow, not the headless unit tests.

// Resolved lazily + once: initializing the WASM module is idempotent per page. The pkg is
// built into src/vendor/sealer by scripts/build-sealer.mjs and served over HTTP; the dynamic
// import keeps it out of the load path until a sealer is actually needed.
let modPromise = null;
export function loadModule() {
  if (!modPromise) {
    modPromise = import('../../vendor/sealer/openom_sealer.js').then(async (mod) => {
      await mod.default(); // wasm-bindgen --target web init (fetches the _bg.wasm)
      return mod;
    });
  }
  return modPromise;
}

/**
 * Build a WasmSealer core for a tree. Dev mode uses the reserved dev key (§16) so the web
 * app runs the full seal/open path with no server and no unlock; otherwise an unwrapped DEK
 * + key epoch (from the unlock/provision flow) is required.
 * @returns {Promise<object>} a WasmSealer (satisfies the SealerSession core contract)
 */
export async function createWasmCore({ dev = false, treeId, replicaId, dek = null, keyId = null, aead = null }) {
  const mod = await loadModule();
  if (dev) {
    return mod.WasmSealer.dev(treeId, replicaId);
  }
  if (!dek || !keyId) {
    throw new Error('createWasmCore needs an unwrapped dek + keyId when not in dev mode');
  }
  return mod.WasmSealer.fromUnwrapped(dek, treeId, keyId, replicaId, aead ?? undefined);
}
