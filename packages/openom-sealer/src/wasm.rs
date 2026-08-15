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
use zeroize::Zeroizing;

use openom_crypto::{Key32, KEY_LEN};
use openom_protocol::v1::{Aead, Compression, Format};
use openom_protocol::ENVELOPE_VERSION;

use crate::{vault, EntryKind, SealContext, Sealer, SealerError};

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

// ---- the keyring vault (passphrase lifecycle) ----

/// The result of a vault flow. Carries only non-secret outputs — the keyring (to store), the
/// recovery code (to show ONCE), the revision (to watermark), and the sealer HANDLE. No raw
/// key material (DEK/KEK/identity) ever crosses to JS; the DEK lives inside the sealer.
#[wasm_bindgen]
pub struct VaultResult {
    keyring: Vec<u8>,
    recovery_code: String,
    revision: u32,
    sealer: Option<WasmSealer>,
}

#[wasm_bindgen]
impl VaultResult {
    /// The encoded keyring to persist (empty for unlock).
    #[wasm_bindgen(getter)]
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }

    /// The recovery code to show once (empty for unlock).
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    pub fn recovery_code(&self) -> String {
        self.recovery_code.clone()
    }

    /// The keyring revision the caller must watermark.
    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// Take the sealer out to JS (once). `undefined` for change-passphrase (no new sealer).
    #[wasm_bindgen(js_name = takeSealer)]
    pub fn take_sealer(&mut self) -> Option<WasmSealer> {
        self.sealer.take()
    }
}

// Passphrases and recovery codes arrive as owned `String`s — wasm-bindgen hands us ownership
// of the copy it wrote into WASM linear memory, so wrapping them in `Zeroizing` immediately
// scrubs that copy on drop. (The JS-side original string is GC-managed and can't be scrubbed;
// callers minimise its lifetime — documented in the JS shim.)

/// Create a new encrypted tree. Returns the keyring, the recovery code (show once), revision
/// 1, and the sealer.
#[wasm_bindgen]
pub fn provision(
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let passphrase = Zeroizing::new(passphrase);
    let p = vault::provision(passphrase.as_bytes(), tree_id, member_id, replica_id).map_err(to_js)?;
    Ok(VaultResult {
        keyring: p.keyring,
        recovery_code: p.recovery_code,
        revision: 1,
        sealer: Some(WasmSealer { inner: p.sealer }),
    })
}

/// Open an existing keyring with a passphrase; returns the sealer + revision.
#[wasm_bindgen]
pub fn unlock(
    keyring: &[u8],
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let passphrase = Zeroizing::new(passphrase);
    let u = vault::unlock(keyring, passphrase.as_bytes(), tree_id, member_id, replica_id).map_err(to_js)?;
    Ok(VaultResult {
        keyring: Vec::new(),
        recovery_code: String::new(),
        revision: u.revision,
        sealer: Some(WasmSealer { inner: u.sealer }),
    })
}

/// Recover with the recovery code, re-provisioning under a new passphrase. `min_revision` is
/// the caller's stored watermark (0 if none) — a served revision below it is refused.
#[wasm_bindgen]
pub fn recover(
    keyring: &[u8],
    recovery_code: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
) -> Result<VaultResult, JsError> {
    let recovery_code = Zeroizing::new(recovery_code);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let r = vault::recover(
        keyring,
        recovery_code.as_str(),
        new_passphrase.as_bytes(),
        tree_id,
        member_id,
        replica_id,
        min_revision,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: r.recovery_code,
        revision: r.revision,
        sealer: Some(WasmSealer { inner: r.sealer }),
    })
}

/// Change the passphrase (rotates the recovery code, bumps the revision). No new sealer — the
/// DEK is unchanged, so the running one keeps working.
#[wasm_bindgen(js_name = changePassphrase)]
pub fn change_passphrase(
    keyring: &[u8],
    old_passphrase: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    min_revision: u32,
) -> Result<VaultResult, JsError> {
    let old_passphrase = Zeroizing::new(old_passphrase);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let re = vault::change_passphrase(
        keyring,
        old_passphrase.as_bytes(),
        new_passphrase.as_bytes(),
        tree_id,
        member_id,
        min_revision,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: re.keyring,
        recovery_code: re.recovery_code,
        revision: re.revision,
        sealer: None,
    })
}
