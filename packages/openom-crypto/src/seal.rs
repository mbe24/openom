//! AEAD seal / open — bind the whole header as AAD (§5), select the cipher by
//! `Header.aead`, and use the header's public `nonce`.
//!
//! There is no plaintext path: sealing always happens; only the *key* varies (the
//! reserved dev key locally, a passphrase-derived DEK in prod — §16). `seal`/`open`
//! build the AAD internally from the header, so the §5 encoder is never exposed
//! across the wasm-bindgen boundary and a JS twin can't drift from it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use openom_protocol::aad::header_aad;
use openom_protocol::v1::{Aead as AeadAlg, Header};

use crate::{CryptoError, KEY_LEN};

const XCHACHA_NONCE_LEN: usize = 24;
const AES_GCM_NONCE_LEN: usize = 12;

/// Seal `plaintext` under the DEK `key` for `header`, binding the whole header as AAD
/// (§5). The AEAD and nonce come from `header` (`aead` + `nonce`). Returns the
/// ciphertext with the AEAD tag appended; the caller then sets `header.ciphertext_hash
/// = sha256(ciphertext)` (excluded from the AAD — see [`openom_protocol::aad`]).
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

// Low-level, AAD-agnostic AEAD (crate-internal). The DEK-wrap path (§4) reuses the
// XChaCha20 pair with the wrap-context AAD instead of a header AAD.

pub(crate) fn xchacha_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, XCHACHA_NONCE_LEN)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Seal)
}

pub(crate) fn xchacha_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, XCHACHA_NONCE_LEN)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Open)
}

fn aesgcm_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, AES_GCM_NONCE_LEN)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Seal)
}

fn aesgcm_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, AES_GCM_NONCE_LEN)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Open)
}

fn check_nonce(nonce: &[u8], want: usize) -> Result<(), CryptoError> {
    if nonce.len() == want {
        Ok(())
    } else {
        Err(CryptoError::NonceLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_protocol::v1::Kind;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    #[test]
    fn check_nonce_requires_the_exact_length() {
        // Kills `check_nonce -> Ok(())` (which would accept any nonce length and defeat the guard
        // at all four seal/open call sites).
        assert!(check_nonce(&[0u8; XCHACHA_NONCE_LEN], XCHACHA_NONCE_LEN).is_ok());
        assert!(matches!(
            check_nonce(&[0u8; XCHACHA_NONCE_LEN - 1], XCHACHA_NONCE_LEN),
            Err(CryptoError::NonceLength)
        ));
        assert!(matches!(
            check_nonce(&[0u8; AES_GCM_NONCE_LEN + 1], AES_GCM_NONCE_LEN),
            Err(CryptoError::NonceLength)
        ));
    }

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
