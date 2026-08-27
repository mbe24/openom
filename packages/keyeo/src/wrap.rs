//! Symmetric DEK wrapping under a KEK (XChaCha20-Poly1305).
//! Adapted from openom-crypto::wrap (MIT).

use crate::{CryptoError, Key32, KEY_LEN};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const WRAP_NONCE_LEN: usize = 24;

pub struct WrapContext<'a> {
    pub context_id: &'a [u8],
    pub key_id: &'a [u8],
    pub member_id: &'a str,
    pub wrap_method: i32,
    pub epoch: u32,
}

fn build_aad(ctx: &WrapContext) -> Vec<u8> {
    let mut aad = b"flowcontrol:keyeo:v1".to_vec();
    aad.push(0);
    aad.extend_from_slice(ctx.context_id);
    aad.push(0);
    aad.extend_from_slice(ctx.key_id);
    aad.push(0);
    aad.extend_from_slice(ctx.member_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&ctx.wrap_method.to_le_bytes());
    aad.push(0);
    aad.extend_from_slice(&ctx.epoch.to_le_bytes());
    aad
}

pub struct WrappedDek {
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

#[allow(deprecated)]
pub fn wrap_dek(
    kek: &Key32,
    dek: &[u8; KEY_LEN],
    ctx: &WrapContext,
) -> Result<WrappedDek, CryptoError> {
    use chacha20poly1305::aead::Payload;
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let key_arr: [u8; KEY_LEN] = **kek;
    let key = Key::from(key_arr);
    let cipher = XChaCha20Poly1305::new(&key);
    let aad = build_aad(ctx);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Seal)?;
    Ok(WrappedDek {
        nonce: nonce.to_vec(),
        wrapped_dek: ct,
    })
}

#[allow(deprecated)]
pub fn unwrap_dek(
    kek: &Key32,
    nonce: &[u8],
    wrapped_dek: &[u8],
    ctx: &WrapContext,
) -> Result<Key32, CryptoError> {
    use chacha20poly1305::aead::Payload;
    let key_arr: [u8; KEY_LEN] = **kek;
    let key = Key::from(key_arr);
    let cipher = XChaCha20Poly1305::new(&key);
    let aad = build_aad(ctx);
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: wrapped_dek,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Open)?;
    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&pt);
    Ok(Zeroizing::new(dek))
}
