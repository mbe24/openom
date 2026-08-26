//! The `#[wasm_bindgen]` veneer over [`Tree`](crate::Tree) — the web app's family-tree engine. Only
//! compiled with the `wasm` feature. Marshalling: ids and op-batch bytes cross as `Uint8Array`
//! (`&[u8]` / `Vec<u8>`); claim values and the read model cross as JSON strings (non-secret display
//! data — never key material); an edit throws a JS `Error` on failure. The engine is key-less — it
//! emits op-batch bytes for the JS sealer-worker to seal + append.

use wasm_bindgen::prelude::*;

use crate::Tree;

/// A family-tree engine instance for one tree, living in wasm memory.
#[wasm_bindgen]
pub struct WasmTree {
    inner: Tree,
}

#[wasm_bindgen]
impl WasmTree {
    /// A fresh engine for author `created_by` (the vault-derived `did:key`).
    #[wasm_bindgen(constructor)]
    pub fn new(created_by: String) -> WasmTree {
        WasmTree {
            inner: Tree::new(created_by),
        }
    }

    /// Assert a claim (`value_json` = the claim value as JSON). Returns op-batch bytes to seal.
    #[wasm_bindgen(js_name = assertClaim)]
    pub fn assert_claim(
        &mut self,
        target: &str,
        predicate: &str,
        value_json: &str,
        created_at: f64,
    ) -> Result<Vec<u8>, JsError> {
        let value = serde_json::from_str(value_json).map_err(to_js)?;
        self.inner
            .assert_claim(target, predicate, value, created_at as i64)
            .map_err(to_js)
    }

    /// Assert an identity anchor (Person/Event/Place/Tree). Returns op-batch bytes to seal.
    #[wasm_bindgen(js_name = assertAnchor)]
    pub fn assert_anchor(
        &mut self,
        id: &str,
        type_uri: &str,
        created_at: f64,
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .assert_anchor(id, type_uri, created_at as i64)
            .map_err(to_js)
    }

    /// Remove one of this author's own records by id.
    pub fn remove(&mut self, target: &str, created_at: f64) -> Result<Vec<u8>, JsError> {
        self.inner.remove(target, created_at as i64).map_err(to_js)
    }

    /// Edit: supersede `prior` with a fresh claim value (`value_json`).
    #[wasm_bindgen(js_name = supersedeClaim)]
    pub fn supersede_claim(
        &mut self,
        prior: &str,
        target: &str,
        predicate: &str,
        value_json: &str,
        created_at: f64,
    ) -> Result<Vec<u8>, JsError> {
        let value = serde_json::from_str(value_json).map_err(to_js)?;
        self.inner
            .supersede_claim(prior, target, predicate, value, created_at as i64)
            .map_err(to_js)
    }

    /// Undo a same-author `Remove` by its operation id.
    pub fn revoke(&mut self, removal_op_id: &str, created_at: f64) -> Result<Vec<u8>, JsError> {
        self.inner
            .revoke(removal_op_id, created_at as i64)
            .map_err(to_js)
    }

    /// Merge a peer's (or replayed) op batch into the set. Returns the number of items ingested.
    pub fn merge(&mut self, bytes: &[u8]) -> Result<usize, JsError> {
        self.inner.merge(bytes).map_err(to_js)
    }

    /// The live record set as a snapshot batch.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsError> {
        self.inner.snapshot().map_err(to_js)
    }

    /// Load a snapshot batch into the set.
    #[wasm_bindgen(js_name = loadSnapshot)]
    pub fn load_snapshot(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.inner.load_snapshot(bytes).map_err(to_js)
    }

    /// The read model as a JSON string.
    pub fn project(&self) -> Result<String, JsError> {
        self.inner.project_json().map_err(to_js)
    }

    /// The canonical person id an anchor resolves to (or `undefined`).
    #[wasm_bindgen(js_name = resolveId)]
    pub fn resolve_id(&self, anchor: &str) -> Option<String> {
        self.inner.resolve_id(anchor)
    }
}

fn to_js<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}
