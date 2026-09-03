//! AEAD seal / open — bind the whole header as AAD (§5), select the cipher by
//! `Header.aead`, and use the header's public `nonce`.
//!
//! There is no plaintext path: sealing always happens; only the *key* varies (the
//! reserved dev key locally, a passphrase-derived DEK in prod — §16). `seal`/`open`
//! build the AAD internally from the header, so the §5 encoder is never exposed
//! across the wasm-bindgen boundary and a JS twin can't drift from it. The actual AEAD
//! primitives are the AAD-agnostic cores in `keyeo_crypto::aead`; this layer just builds
//! the header AAD and dispatches on `Header.aead`.

use crate::aad::header_aad;
use keyeo_crypto::aead::{aesgcm_open, aesgcm_seal, xchacha_open, xchacha_seal};
use openom_protocol::v1::{Aead as AeadAlg, Header};

use crate::{CryptoError, KEY_LEN};

/// Seal `plaintext` under the DEK `key` for `header`, binding the whole header as AAD
/// (§5). The AEAD and nonce come from `header` (`aead` + `nonce`). Returns the
/// ciphertext with the AEAD tag appended; the caller then sets `header.ciphertext_hash
/// = sha256(ciphertext)` (excluded from the AAD — see [`crate::aad`]).
pub fn seal(
    version: u32,
    header: &Header,
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad = header_aad(version, header);
    match AeadAlg::try_from(header.aead) {
        Ok(AeadAlg::Xchacha20Poly1305) => xchacha_seal(key, &header.nonce, &aad, plaintext),
        Ok(AeadAlg::Aes256Gcm) => aesgcm_seal(key, &header.nonce, &aad, plaintext),
        _ => Err(CryptoError::UnsupportedAead(header.aead)),
    }
}

/// Open `ciphertext` under the DEK `key` for `header`. Rebuilds the AAD from the
/// header and requires the AEAD tag to verify — so any tampered header field (or
/// ciphertext) fails as [`CryptoError::Open`].
pub fn open(
    version: u32,
    header: &Header,
    key: &[u8; KEY_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad = header_aad(version, header);
    match AeadAlg::try_from(header.aead) {
        Ok(AeadAlg::Xchacha20Poly1305) => xchacha_open(key, &header.nonce, &aad, ciphertext),
        Ok(AeadAlg::Aes256Gcm) => aesgcm_open(key, &header.nonce, &aad, ciphertext),
        _ => Err(CryptoError::UnsupportedAead(header.aead)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_protocol::v1::Kind;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    fn header(aead: AeadAlg, nonce: Vec<u8>) -> Header {
        Header {
            kind: Kind::Snapshot as i32,
            aead: aead as i32,
            nonce,
            tree_id: vec![0x11; 16],
            ..Default::default()
        }
    }

    #[test]
    fn xchacha_round_trip() {
        let h = header(AeadAlg::Xchacha20Poly1305, vec![1u8; 24]);
        let pt = b"secret family tree bytes";
        let ct = seal(1, &h, &KEY, pt).unwrap();
        assert_ne!(ct.as_slice(), pt.as_slice());
        assert_eq!(open(1, &h, &KEY, &ct).unwrap(), pt);
    }

    #[test]
    fn aesgcm_round_trip() {
        let h = header(AeadAlg::Aes256Gcm, vec![2u8; 12]);
        let pt = b"snapshot bytes";
        let ct = seal(1, &h, &KEY, pt).unwrap();
        assert_eq!(open(1, &h, &KEY, &ct).unwrap(), pt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let h = header(AeadAlg::Xchacha20Poly1305, vec![1u8; 24]);
        let mut ct = seal(1, &h, &KEY, b"payload").unwrap();
        ct[0] ^= 0xFF;
        assert!(matches!(open(1, &h, &KEY, &ct), Err(CryptoError::Open)));
    }

    #[test]
    fn tampered_header_fails() {
        // The whole header is the AAD — flipping tree_id on open must fail.
        let h = header(AeadAlg::Xchacha20Poly1305, vec![1u8; 24]);
        let ct = seal(1, &h, &KEY, b"payload").unwrap();
        let mut tampered = h.clone();
        tampered.tree_id = vec![0x22; 16];
        assert!(matches!(
            open(1, &tampered, &KEY, &ct),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let h = header(AeadAlg::Xchacha20Poly1305, vec![1u8; 24]);
        let ct = seal(1, &h, &KEY, b"payload").unwrap();
        assert!(matches!(
            open(1, &h, &[9u8; KEY_LEN], &ct),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn version_is_bound_in_aad() {
        // `version` is the first AAD field — opening under a different version fails.
        let h = header(AeadAlg::Xchacha20Poly1305, vec![1u8; 24]);
        let ct = seal(1, &h, &KEY, b"payload").unwrap();
        assert!(matches!(open(2, &h, &KEY, &ct), Err(CryptoError::Open)));
    }

    #[test]
    fn wrong_nonce_length_errs() {
        let h = header(AeadAlg::Xchacha20Poly1305, vec![1u8; 12]); // 12 != 24
        assert!(matches!(
            seal(1, &h, &KEY, b"x"),
            Err(CryptoError::NonceLength)
        ));
    }

    #[test]
    fn unspecified_aead_errs() {
        let h = header(AeadAlg::Unspecified, vec![1u8; 24]);
        assert!(matches!(
            seal(1, &h, &KEY, b"x"),
            Err(CryptoError::UnsupportedAead(0))
        ));
    }
}
