//! Argon2id → KEK derivation.
//! Adapted from openom-crypto::kdf (MIT).

use crate::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

/// Default Argon2id costs.
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 19_456;
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 2;
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 1;

pub type Key32 = Zeroizing<[u8; KEY_LEN]>;

/// KDF parameters (serializable).
#[derive(Debug, Clone)]
pub struct KdfParams {
    pub salt: Vec<u8>,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn new(salt: Vec<u8>) -> Self {
        KdfParams {
            salt,
            memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
            iterations: DEFAULT_ARGON2_ITERATIONS,
            parallelism: DEFAULT_ARGON2_PARALLELISM,
        }
    }
}

/// Derive a 256-bit KEK from `passphrase` under the given Argon2id params.
pub fn derive_kek(passphrase: &[u8], params: &KdfParams) -> Result<Key32, CryptoError> {
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, &params.salt, out.as_mut_slice())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

/// Generate a fresh random salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(salt)
}

/// Generate a fresh random DEK.
pub fn generate_dek() -> Result<Key32, CryptoError> {
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(dek.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(dek)
}
