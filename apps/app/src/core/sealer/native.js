// Native binding: build a sealer core backed by Tauri commands, so the DEK lives in the
// Rust core's memory and NEVER enters the webview (the native tier's stronger-isolation
// guarantee vs. the WASM tier). The same pure-Rust `openom-sealer` core runs here directly.
//
// NOT YET WIRED. The Rust side needs #[tauri::command] wrappers (seal_entry/open_entry over
// a Sealer held in Tauri state) in apps/src-tauri; this file will then `invoke` them and
// adapt the results into the core contract SealerSession expects:
//   sealEntry(...) -> { envelope: Uint8Array, ciphertextHash: Uint8Array }
//   openEntry(kind, bytes) -> Uint8Array
//   get treeId -> Uint8Array
// The invoke calls are async, which SealerSession already handles (it awaits the core).

export async function createNativeCore(_opts) {
  throw new Error(
    'native sealer not yet wired: add the #[tauri::command] seal/open wrappers in ' +
      'apps/src-tauri and implement the invoke adapter here',
  );
}
