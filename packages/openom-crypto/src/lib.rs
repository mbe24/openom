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

/// Human-readable cipher-suite name, for logs and diagnostics.
pub fn cipher_suite() -> &'static str {
    "XChaCha20-Poly1305 (default) / AES-256-GCM (disciplined); Argon2id KDF"
}
