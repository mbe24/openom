//! The **web binding** for the sealer — a thin `wasm-bindgen` veneer over the pure
//! [`Sealer`](crate::Sealer) core. Only compiled with `--features wasm --target wasm32-*`;
//! native (Tauri) callers use the core directly, so this file is the *only* web-specific
//! code and the crypto path stays identical across web and native.
//!
//! Marshalling is deliberately plain wasm-bindgen — no serde:
//! * enums cross as lowercase strings (`"snapshot"`, `"openom-json"`, `"none"`),
//! * bytes cross as `Uint8Array` (`&[u8]` in, `Vec<u8>` out),
//! * the two chain counters cross as JS `number`s, range-checked to a safe integer.
//!
//! That avoids serde-wasm-bindgen's u64-as-`BigInt` and byte-array-as-`Array` surprises;
//! the JS shim (`apps/app/src/core/sealer/`) wraps these calls with ergonomic defaults.

use wasm_bindgen::prelude::*;

use openom_crypto::{Key32, KEY_LEN};
use openom_protocol::v1::{Aead, Compression, Format};
use openom_protocol::ENVELOPE_VERSION;

use crate::{EntryKind, SealContext, Sealer, SealerError};

/// A sealing session, exported to JS. Wraps the core [`Sealer`]; the unlocked DEK lives
/// inside WASM linear memory for the session's lifetime (the web tier's documented
/// weaker-isolation trade-off vs. native — see the threat model / SERVER-DATA-FORMAT §16).
#[wasm_bindgen]
pub struct WasmSealer {
    inner: Sealer,
}

/// The result of [`WasmSealer::seal_entry`]: the wire-ready envelope bytes and the
/// chain hash to thread into the next call. Both surface to JS as `Uint8Array`.
#[wasm_bindgen]
pub struct SealOutcome {
    envelope: Vec<u8>,
    ciphertext_hash: Vec<u8>,
}

#[wasm_bindgen]
impl SealOutcome {
    /// The prost-encoded `Envelope`, ready to upload.
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    /// `SHA-256(ciphertext)` — persist as the next entry's `prevCiphertextHash`.
    #[wasm_bindgen(getter, js_name = ciphertextHash)]
    pub fn ciphertext_hash(&self) -> Vec<u8> {
        self.ciphertext_hash.clone()
    }
}

#[wasm_bindgen]
impl WasmSealer {
    /// A local-development sealer (§16 reserved dev key): the full seal/open path with no
    /// server and no unlock flow, for fast UI iteration. Production refuses its `key_id`.
    pub fn dev(tree_id: &[u8], replica_id: &[u8]) -> WasmSealer {
        WasmSealer {
            inner: Sealer::dev(tree_id.to_vec(), replica_id.to_vec()),
        }
    }

    /// Build a sealer from an already-unwrapped 32-byte DEK and its scope. The unlock /
    /// provision flow (Argon2id KEK derivation, DEK unwrap, keyring verification) produces
    /// the DEK and calls this. `aead` is optional (`"xchacha20-poly1305"` default, or
    /// `"aes-256-gcm"`).
    #[wasm_bindgen(js_name = fromUnwrapped)]
    pub fn from_unwrapped(
        dek: &[u8],
        tree_id: &[u8],
        key_id: &[u8],
        replica_id: &[u8],
        aead: Option<String>,
    ) -> Result<WasmSealer, JsError> {
        if dek.len() != KEY_LEN {
            return Err(JsError::new("dek must be exactly 32 bytes"));
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(dek);
        let key: Key32 = zeroize::Zeroizing::new(bytes);

        let mut sealer = Sealer::from_unwrapped(
            ENVELOPE_VERSION,
            key,
            tree_id.to_vec(),
            key_id.to_vec(),
            replica_id.to_vec(),
        );
        if let Some(name) = aead {
            sealer = sealer.with_aead(parse_aead(&name)?);
        }
        Ok(WasmSealer { inner: sealer })
    }

    /// Seal `plaintext` under this sealer's DEK/scope with the caller-supplied chain state.
    /// `kind` ∈ {`snapshot`,`delta`,`media`}, `format` ∈ {`openom-json`}, `compression` ∈
    /// {`none`,`zstd`} (the caller compresses; the sealer only records the label).
    #[wasm_bindgen(js_name = sealEntry)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_entry(
        &self,
        kind: &str,
        format: &str,
        compression: &str,
        replica_counter: f64,
        prev_ciphertext_hash: &[u8],
        covers_through_seq: f64,
        blob_id: &[u8],
        plaintext: &[u8],
    ) -> Result<SealOutcome, JsError> {
        let ctx = SealContext {
            kind: parse_kind(kind)?,
            format: parse_format(format)?,
            compression: parse_compression(compression)?,
            replica_counter: as_u64(replica_counter, "replicaCounter")?,
            prev_ciphertext_hash: prev_ciphertext_hash.to_vec(),
            covers_through_seq: as_u64(covers_through_seq, "coversThroughSeq")?,
            blob_id: blob_id.to_vec(),
        };
        let out = self.inner.seal_entry(&ctx, plaintext).map_err(to_js)?;
        Ok(SealOutcome {
            envelope: out.envelope,
            ciphertext_hash: out.ciphertext_hash,
        })
    }

    /// Decode + scope/kind-verify + AEAD-open an envelope, returning the plaintext.
    #[wasm_bindgen(js_name = openEntry)]
    pub fn open_entry(&self, expect_kind: &str, envelope_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let kind = parse_kind(expect_kind)?;
        self.inner.open_entry(kind, envelope_bytes).map_err(to_js)
    }

    /// The tree this sealer is scoped to.
    #[wasm_bindgen(getter, js_name = treeId)]
    pub fn tree_id(&self) -> Vec<u8> {
        self.inner.tree_id().to_vec()
    }
}

fn parse_kind(s: &str) -> Result<EntryKind, JsError> {
    match s {
        "snapshot" => Ok(EntryKind::Snapshot),
        "delta" => Ok(EntryKind::Delta),
        "media" => Ok(EntryKind::Media),
        other => Err(JsError::new(&format!("unknown kind: {other}"))),
    }
}

fn parse_format(s: &str) -> Result<Format, JsError> {
    match s {
        "openom-json" => Ok(Format::OpenomJson),
        other => Err(JsError::new(&format!("unknown format: {other}"))),
    }
}

fn parse_compression(s: &str) -> Result<Compression, JsError> {
    match s {
        "none" => Ok(Compression::None),
        "zstd" => Ok(Compression::Zstd),
        other => Err(JsError::new(&format!("unknown compression: {other}"))),
    }
}

fn parse_aead(s: &str) -> Result<Aead, JsError> {
    match s {
        "xchacha20-poly1305" => Ok(Aead::Xchacha20Poly1305),
        "aes-256-gcm" => Ok(Aead::Aes256Gcm),
        other => Err(JsError::new(&format!("unknown aead: {other}"))),
    }
}

/// A JS `number` is only exact up to 2^53; a u64 counter beyond that would silently
/// round. Reject non-integers and anything past the safe range rather than corrupt the
/// chain — a real openom counter never approaches this.
fn as_u64(n: f64, field: &str) -> Result<u64, JsError> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0; // 2^53 - 1
    if n.is_nan() || n < 0.0 || n.fract() != 0.0 || n > MAX_SAFE {
        return Err(JsError::new(&format!(
            "{field} must be a non-negative integer within 2^53"
        )));
    }
    Ok(n as u64)
}

fn to_js(e: SealerError) -> JsError {
    JsError::new(&e.to_string())
}
