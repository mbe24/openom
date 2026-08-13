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

/// Primary AEAD cipher.
pub type Cipher = aes_gcm::Aes256Gcm;

/// Alternate AEAD cipher.
pub type CipherAlt = chacha20poly1305::ChaCha20Poly1305;

/// Key-derivation function (Argon2id).
pub type Kdf<'a> = argon2::Argon2<'a>;

/// Symmetric key length in bytes — AES-256 and ChaCha20 both use 256-bit keys.
pub const KEY_LEN: usize = 32;

/// Human-readable cipher-suite name, for logs and diagnostics.
pub fn cipher_suite() -> &'static str {
    "AES-256-GCM / ChaCha20-Poly1305; Argon2id KDF"
}
