//! Recovery code — base32-checksummed recovery for lost passphrases.
//! Adapted from openom-crypto::recovery (MIT).

use crate::CryptoError;
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const RECOVERY_ENTROPY_LEN: usize = 16;

pub fn generate_recovery_code() -> Result<String, CryptoError> {
    let mut entropy = Zeroizing::new([0u8; RECOVERY_ENTROPY_LEN]);
    getrandom::fill(entropy.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(format_code(&entropy))
}

pub fn parse_recovery_code(
    input: &str,
) -> Result<Zeroizing<[u8; RECOVERY_ENTROPY_LEN]>, CryptoError> {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let decoded = BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| CryptoError::RecoveryFormat)?;
    if decoded.len() != RECOVERY_ENTROPY_LEN + 1 {
        return Err(CryptoError::RecoveryFormat);
    }
    let (entropy, check) = decoded.split_at(RECOVERY_ENTROPY_LEN);
    if checksum(entropy) != check[0] {
        return Err(CryptoError::RecoveryChecksum);
    }
    let mut out = Zeroizing::new([0u8; RECOVERY_ENTROPY_LEN]);
    out.copy_from_slice(entropy);
    Ok(out)
}

fn checksum(entropy: &[u8]) -> u8 {
    Sha256::digest(entropy)[0]
}

fn format_code(entropy: &[u8; RECOVERY_ENTROPY_LEN]) -> String {
    let mut buf = Vec::with_capacity(RECOVERY_ENTROPY_LEN + 1);
    buf.extend_from_slice(entropy);
    buf.push(checksum(entropy));
    let code = BASE32_NOPAD.encode(&buf);
    code.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}
