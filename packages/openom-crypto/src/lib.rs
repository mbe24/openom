#![doc = include_str!("../README.md")]

//! The thin, proto-bound layer over [`keyeo_crypto`]'s generic primitives (OPE-305): the §5
//! header-AAD encoder, the header-driven envelope `seal`/`open`, the openom DEK/RRK wraps, and the
//! wire-`KdfParams` edges — plus a full re-export of the primitives so every consumer keeps calling
//! `openom_crypto::*` unchanged.

/// Argon2id key-derivation function type alias (kept in the public surface).
pub type Kdf<'a> = argon2::Argon2<'a>;

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

pub mod aad;
mod envelope;
mod kdf;
mod recovery;
mod root;
mod seal;
mod wrap;

// The generic primitives, re-exported so `openom_crypto::X` still resolves for every consumer.
pub use keyeo_crypto::{
    derive_hpke_keypair, derive_rvk, generate_dek, generate_hpke_keypair, generate_recovery_code,
    generate_salt, hpke_unwrap_dek, hpke_wrap_dek, parse_recovery_code, Cipher, CipherAlt,
    CryptoError, Dek, HpkeKeypair, HpkePrivate, HpkeWrap, Kek, Key32, Passphrase, RecoveryCode,
    RootKeys, RrkSecret, DEFAULT_ARGON2_ITERATIONS, DEFAULT_ARGON2_MEMORY_KIB,
    DEFAULT_ARGON2_PARALLELISM, HPKE_PUBLIC_LEN, HPKE_SECRET_LEN, KEY_LEN, RECOVERY_ENTROPY_LEN,
    SALT_LEN,
};

// The proto-bound layer.
pub use envelope::{open_envelope, seal_envelope, AuthorIdentity, SealParams};
pub use kdf::{default_kdf_params, derive_kek};
pub use recovery::recovery_kdf_params;
pub use root::derive_root;
pub use seal::{open, seal};
pub use wrap::{unwrap_dek, unwrap_rrk_secret, wrap_dek, wrap_rrk_secret, WrapContext, WrappedDek};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_dek_is_the_fixed_nonzero_hash() {
        // Not Default (all-zero): the dev DEK is a SHA-256, so it's non-zero and deterministic.
        // Kills `dev_dek -> Default::default()`.
        assert_ne!(*dev_dek(), [0u8; KEY_LEN]);
        assert_eq!(*dev_dek(), *dev_dek());
    }

    #[test]
    fn cipher_suite_names_the_primitives() {
        // Kills `cipher_suite -> ""` / `"xyzzy"`.
        assert_eq!(
            cipher_suite(),
            "XChaCha20-Poly1305 (default) / AES-256-GCM (disciplined); Argon2id KDF"
        );
    }
}
