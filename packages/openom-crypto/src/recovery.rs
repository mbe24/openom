//! Recovery code — a second wrap path so a lost passphrase isn't total loss (§4, §17).
//!
//! The code is 128 bits of entropy plus an appended checksum byte, base32-encoded and
//! hyphen-grouped for legibility. The checksum lets the client reject a typo instantly,
//! *before* running Argon2. Because the code is already high-entropy, its Argon2id cost
//! is minimal — memory-hardness defends low-entropy passphrases and buys nothing here.
//!
//! Mechanically a recovery wrap is an ordinary [`crate::wrap_dek`] under
//! `WRAP_METHOD_RECOVERY_CODE_ARGON2ID`, with the KEK derived from the code's entropy
//! via [`crate::derive_kek`] and [`recovery_kdf_params`]. This module owns only the
//! code's generation, parsing, and checksum.

use data_encoding::BASE32_NOPAD;
use openom_protocol::v1::KdfParams;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{CryptoError, RecoveryCode};

/// Recovery-code entropy in bytes (128 bits).
pub const RECOVERY_ENTROPY_LEN: usize = 16;

/// Argon2id cost for the recovery wrap — minimal, since the code is high-entropy.
pub const RECOVERY_ARGON2_MEMORY_KIB: u32 = 8192; // 8 MiB
pub const RECOVERY_ARGON2_ITERATIONS: u32 = 1;
pub const RECOVERY_ARGON2_PARALLELISM: u32 = 1;

/// Generate a fresh printable recovery code (entropy + checksum, base32, hyphenated).
/// Display it once; it can't be recovered if lost (§17).
pub fn generate_recovery_code() -> Result<RecoveryCode, CryptoError> {
    let mut entropy = Zeroizing::new([0u8; RECOVERY_ENTROPY_LEN]);
    getrandom::fill(entropy.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(RecoveryCode::new(format_code(&entropy)))
}

/// Parse + checksum-verify a recovery code (tolerant of case, spaces, hyphens),
/// returning its raw entropy. Fails fast on a typo (checksum) before any KDF runs.
pub fn parse_recovery_code(
    code: &RecoveryCode,
) -> Result<Zeroizing<[u8; RECOVERY_ENTROPY_LEN]>, CryptoError> {
    let input = code.expose();
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

/// `KdfParams` for a recovery-code wrap (minimal cost) with the given `salt`.
pub fn recovery_kdf_params(salt: Vec<u8>) -> KdfParams {
    KdfParams {
        salt,
        memory_kib: RECOVERY_ARGON2_MEMORY_KIB,
        iterations: RECOVERY_ARGON2_ITERATIONS,
        parallelism: RECOVERY_ARGON2_PARALLELISM,
    }
}

/// The appended typo-detection byte: the first byte of SHA-256(entropy). Non-secret.
fn checksum(entropy: &[u8]) -> u8 {
    Sha256::digest(entropy)[0]
}

fn format_code(entropy: &[u8; RECOVERY_ENTROPY_LEN]) -> String {
    let mut buf = Zeroizing::new(Vec::with_capacity(RECOVERY_ENTROPY_LEN + 1));
    buf.extend_from_slice(entropy);
    buf.push(checksum(entropy));
    // 17 bytes → 28 base32 chars → seven 4-char groups.
    let code = BASE32_NOPAD.encode(&buf);
    code.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_kek, generate_dek, unwrap_dek, wrap_dek, WrapContext};
    use openom_protocol::v1::WrapMethod;

    #[test]
    fn generate_parse_round_trip() {
        let code = generate_recovery_code().unwrap();
        // Grouped + parseable back to 16 bytes of entropy.
        assert!(code.expose().contains('-'));
        assert_eq!(
            parse_recovery_code(&code).unwrap().len(),
            RECOVERY_ENTROPY_LEN
        );
    }

    #[test]
    fn tolerant_of_formatting() {
        let code = generate_recovery_code().unwrap();
        let messy = format!("  {}  ", code.expose().to_lowercase().replace('-', " "));
        assert_eq!(
            *parse_recovery_code(&RecoveryCode::new(messy)).unwrap(),
            *parse_recovery_code(&code).unwrap()
        );
    }

    #[test]
    fn typo_caught_by_checksum() {
        let code = generate_recovery_code().unwrap();
        // Flip the first alphanumeric char to a different valid base32 char.
        let mut chars: Vec<char> = code.expose().chars().collect();
        let i = chars
            .iter()
            .position(|c| c.is_ascii_alphanumeric())
            .unwrap();
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(
            parse_recovery_code(&RecoveryCode::new(typo)),
            Err(CryptoError::RecoveryChecksum) | Err(CryptoError::RecoveryFormat)
        ));
    }

    #[test]
    fn malformed_rejected() {
        assert!(matches!(
            parse_recovery_code(&RecoveryCode::new("not base32 !!!")),
            Err(CryptoError::RecoveryFormat)
        ));
        assert!(matches!(
            parse_recovery_code(&RecoveryCode::new("AAAA")),
            Err(CryptoError::RecoveryFormat)
        ));
    }

    #[test]
    fn recovery_wrap_opens_the_dek() {
        // The recovery code is a genuine second door to the same DEK (§4).
        let dek = generate_dek().unwrap();
        let salt = crate::generate_salt().unwrap().to_vec();
        let code = generate_recovery_code().unwrap();
        let params = recovery_kdf_params(salt);
        let ctx = WrapContext {
            tree_id: b"tree-uuid-16byte",
            key_id: b"epoch-0-key",
            member_id: "acct-1",
            wrap_method: WrapMethod::RecoveryCodeArgon2id as i32,
        };

        // Wrap under the recovery-code-derived KEK.
        let entropy = parse_recovery_code(&code).unwrap();
        let kek = derive_kek(entropy.as_slice(), &params).unwrap();
        let w = wrap_dek(&kek, &dek, &ctx).unwrap();

        // Later, from the code alone, recover the DEK.
        let entropy2 = parse_recovery_code(&code).unwrap();
        let kek2 = derive_kek(entropy2.as_slice(), &params).unwrap();
        let recovered = unwrap_dek(&kek2, &w.nonce, &w.wrapped_dek, &ctx).unwrap();
        assert_eq!(recovered.expose(), dek.expose());
    }
}
