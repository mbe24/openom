//! AAD-agnostic AEAD cores — XChaCha20-Poly1305 and AES-256-GCM seal/open over raw
//! `(key, nonce, aad, data)`. These carry no header/proto knowledge.
//!
//! The header-driven envelope `seal`/`open` (which build the §5 AAD from a proto `Header`)
//! live in openom-crypto and call these; the DEK-wrap path (§4) reuses the XChaCha20 pair
//! with a wrap-context AAD instead. Keeping the ciphers here (openom-free) lets both the
//! envelope layer and the keyeo engine share one implementation.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{CryptoError, KEY_LEN};

const XCHACHA_NONCE_LEN: usize = 24;
const AES_GCM_NONCE_LEN: usize = 12;

pub fn xchacha_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, XCHACHA_NONCE_LEN)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .encrypt(&nonce, Payload { msg: data, aad })
        .map_err(|_| CryptoError::Seal)
}

pub fn xchacha_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, XCHACHA_NONCE_LEN)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .decrypt(&nonce, Payload { msg: data, aad })
        .map_err(|_| CryptoError::Open)
}

pub fn aesgcm_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, AES_GCM_NONCE_LEN)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .encrypt(&nonce, Payload { msg: data, aad })
        .map_err(|_| CryptoError::Seal)
}

pub fn aesgcm_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce(nonce, AES_GCM_NONCE_LEN)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KeyLength)?;
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| CryptoError::NonceLength)?;
    cipher
        .decrypt(&nonce, Payload { msg: data, aad })
        .map_err(|_| CryptoError::Open)
}

pub fn check_nonce(nonce: &[u8], want: usize) -> Result<(), CryptoError> {
    if nonce.len() == want {
        Ok(())
    } else {
        Err(CryptoError::NonceLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn xchacha_core_round_trips_and_binds_aad() {
        let ct = xchacha_seal(&KEY, &[1u8; 24], b"aad", b"payload").unwrap();
        assert_ne!(ct.as_slice(), b"payload".as_slice());
        assert_eq!(xchacha_open(&KEY, &[1u8; 24], b"aad", &ct).unwrap(), b"payload");
        // A different AAD must not open.
        assert!(matches!(
            xchacha_open(&KEY, &[1u8; 24], b"other", &ct),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn aesgcm_core_round_trips() {
        let ct = aesgcm_seal(&KEY, &[2u8; 12], b"aad", b"snapshot").unwrap();
        assert_eq!(aesgcm_open(&KEY, &[2u8; 12], b"aad", &ct).unwrap(), b"snapshot");
    }
}
