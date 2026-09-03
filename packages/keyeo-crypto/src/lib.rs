#![doc = include_str!("../README.md")]

/// Default AEAD cipher — **XChaCha20-Poly1305** (frozen §6). Its 192-bit nonce makes
/// random nonces collision-free in practice, so a long delta log under one DEK never
/// hits AES-GCM's nonce-reuse footgun. Matches `Aead::Xchacha20Poly1305`.
pub type Cipher = chacha20poly1305::XChaCha20Poly1305;

/// Disciplined alternate — **AES-256-GCM** (§6): snapshots, or counter-based nonces if
/// ever used for deltas. Matches `Aead::Aes256Gcm`.
pub type CipherAlt = aes_gcm::Aes256Gcm;

/// Symmetric key length in bytes — XChaCha20 and AES-256 both use 256-bit keys.
pub const KEY_LEN: usize = 32;

/// Argon2id salt length in bytes.
pub const SALT_LEN: usize = 16;

/// 256-bit key material (a DEK or KEK) that **zeroizes on drop**. Derefs to
/// `[u8; KEY_LEN]`. The role-typed [`Dek`]/[`Kek`] newtypes (no `Deref`, one `.expose()`)
/// are the guarded surface; this bare alias is the escape hatch used at the sealer boundary.
pub type Key32 = zeroize::Zeroizing<[u8; KEY_LEN]>;

pub mod aead;
mod hpke_wrap;
mod kdf;
mod recovery;
mod root;
mod secret;

pub use hpke_wrap::{
    derive_hpke_keypair, generate_hpke_keypair, hpke_unwrap_dek, hpke_wrap_dek,
    hpke_wrap_dek_with_rng, HpkeKeypair, HpkeWrap, HPKE_PUBLIC_LEN, HPKE_SECRET_LEN,
};
pub use kdf::{
    derive_kek, generate_dek, generate_salt, KdfParams, DEFAULT_ARGON2_ITERATIONS,
    DEFAULT_ARGON2_MEMORY_KIB, DEFAULT_ARGON2_PARALLELISM,
};
pub use recovery::{
    generate_recovery_code, parse_recovery_code, RECOVERY_ARGON2_ITERATIONS,
    RECOVERY_ARGON2_MEMORY_KIB, RECOVERY_ARGON2_PARALLELISM, RECOVERY_ENTROPY_LEN,
};
pub use root::{derive_root, derive_rvk, RootKeys, RootLabels};
pub use secret::{Dek, HpkePrivate, Kek, Passphrase, RecoveryCode, RrkSecret};

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
