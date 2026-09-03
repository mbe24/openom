//! Random key material (DEK generation) + the shared key/salt sizes.
//! Adapted from openom-crypto::kdf (MIT).

use crate::CryptoError;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

pub type Key32 = Zeroizing<[u8; KEY_LEN]>;

/// Generate a fresh random DEK.
pub fn generate_dek() -> Result<Key32, CryptoError> {
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(dek.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(dek)
}
