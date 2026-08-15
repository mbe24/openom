//! Shared crypto — the symmetric primitives, used identically on client and
//! server.
//!
//! V1 is client-side zero-knowledge: the client seals the tree before upload and
//! the server never holds a key. Sharing this crate is what keeps V2 sharing and
//! any cross-side validation on the *exact* same algorithms and parameters, so
//! the two ends can never disagree on how a blob was sealed.
//!
//! The seal/open surface lands next; for now the type aliases below fix the
//! algorithm choices and wire the underlying crates.

/// Default AEAD cipher — **XChaCha20-Poly1305** (frozen §6). Its 192-bit nonce makes
/// random nonces collision-free in practice, so a long delta log under one DEK never
/// hits AES-GCM's nonce-reuse footgun. Matches `Aead::Xchacha20Poly1305`.
pub type Cipher = chacha20poly1305::XChaCha20Poly1305;

/// Disciplined alternate — **AES-256-GCM** (§6): snapshots, or counter-based nonces if
/// ever used for deltas. Matches `Aead::Aes256Gcm`.
pub type CipherAlt = aes_gcm::Aes256Gcm;

/// Key-derivation function (Argon2id).
pub type Kdf<'a> = argon2::Argon2<'a>;

/// Symmetric key length in bytes — XChaCha20 and AES-256 both use 256-bit keys.
pub const KEY_LEN: usize = 32;

/// Argon2id salt length in bytes.
pub const SALT_LEN: usize = 16;

/// 256-bit key material (a DEK or KEK) that **zeroizes on drop**. Derefs to
/// `[u8; KEY_LEN]`, so it passes straight to [`seal`]/[`open`] as `&*key`.
pub type Key32 = zeroize::Zeroizing<[u8; KEY_LEN]>;

/// The reserved `Header.key_id` for local development (§16). Local dev / demo seal with
/// a well-known fixed DEK ([`dev_dek`]) so a developer can inspect payloads — but the
/// bytes on disk / in MinIO are still real ciphertext, sealed and AAD-bound exactly
/// like production. **Production MUST refuse any envelope carrying this `key_id`**, so a
/// dev key can never seal real user data even by misconfiguration.
pub const DEV_KEY_ID: &[u8] = b"openom-dev-key-v1";

/// The well-known fixed dev DEK — SHA-256 of a constant label. Not secret (dev
/// inspection only); never valid for real data, since the server refuses [`DEV_KEY_ID`]
/// under `RUN_MODE=production`.
pub fn dev_dek() -> Key32 {
    use sha2::{Digest, Sha256};
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&Sha256::digest(DEV_KEY_ID));
    zeroize::Zeroizing::new(key)
}

/// Human-readable cipher-suite name, for logs and diagnostics.
pub fn cipher_suite() -> &'static str {
    "XChaCha20-Poly1305 (default) / AES-256-GCM (disciplined); Argon2id KDF"
}

mod envelope;
mod hpke_wrap;
mod kdf;
mod keyring;
mod recovery;
mod root;
mod seal;
mod wrap;
pub use envelope::{open_envelope, seal_envelope, SealParams};
pub use hpke_wrap::{
    derive_hpke_keypair, generate_hpke_keypair, hpke_unwrap_dek, hpke_wrap_dek, HpkeWrap,
    HPKE_PUBLIC_LEN, HPKE_SECRET_LEN,
};
pub use kdf::{
    default_kdf_params, derive_kek, generate_dek, generate_salt, DEFAULT_ARGON2_ITERATIONS,
    DEFAULT_ARGON2_MEMORY_KIB, DEFAULT_ARGON2_PARALLELISM,
};
pub use keyring::{
    generate_identity, keyring_hash, sign_keyring, verify_keyring, verify_keyring_any, Signature,
    SigningKey, VerifyingKey,
};
pub use recovery::{
    generate_recovery_code, parse_recovery_code, recovery_kdf_params, RECOVERY_ENTROPY_LEN,
};
pub use root::{derive_root, RootKeys};
pub use seal::{open, seal};
pub use wrap::{unwrap_dek, unwrap_rrk_secret, wrap_dek, wrap_rrk_secret, WrapContext, WrappedDek};

/// A crypto operation failed. `Open` deliberately does not distinguish a bad key from
/// a bad tag from a tampered header — all are "this ciphertext didn't authenticate".
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// `Header.aead` is `AEAD_UNSPECIFIED` or a value this build doesn't implement.
    #[error("unsupported or unspecified AEAD ({0})")]
    UnsupportedAead(i32),
    /// The DEK is not [`KEY_LEN`] bytes.
    #[error("wrong DEK length")]
    KeyLength,
    /// The header's nonce is the wrong length for the selected AEAD (24 for XChaCha20,
    /// 12 for AES-256-GCM).
    #[error("wrong nonce length for the selected AEAD")]
    NonceLength,
    /// Encryption failed (should not happen with valid inputs).
    #[error("AEAD seal failed")]
    Seal,
    /// Decryption/authentication failed — bad key, nonce, tag, or a tampered
    /// header/AAD. Intentionally opaque.
    #[error("AEAD open failed")]
    Open,
    /// Argon2id key derivation failed (invalid params or salt).
    #[error("KDF failed: {0}")]
    Kdf(String),
    /// The system CSPRNG failed.
    #[error("RNG failed: {0}")]
    Rng(String),
    /// A recovery code isn't valid base32 or the wrong length.
    #[error("malformed recovery code")]
    RecoveryFormat,
    /// A recovery code's checksum doesn't match — almost certainly a typo.
    #[error("recovery code checksum mismatch (likely a typo)")]
    RecoveryChecksum,
    /// Keyring signature verification failed, or the signature isn't the right length
    /// (§4).
    #[error("keyring signature invalid")]
    Signature,
    /// An HPKE seal/open failed — a malformed member public/secret/encapsulated key, or
    /// a wrap that didn't authenticate (wrong recipient, tampered context). Opaque.
    #[error("HPKE wrap/unwrap failed")]
    Hpke,
}
