//! HPKE member wraps — RFC 9180 (`WRAP_METHOD_X25519_HPKE`, §4).
//!
//! When a tree is shared, the DEK is wrapped to a member's **X25519 public key** instead
//! of a passphrase-derived KEK: the owner (or any authorized signer) seals the DEK to the
//! member's public key; the member opens it with their secret key. This is what lets a
//! sharee who never knew the owner's passphrase still receive the tree key.
//!
//! Suite (the one the format pins for this wrap method): **DHKEM(X25519, HKDF-SHA256) +
//! HKDF-SHA256 + ChaCha20Poly1305**, HPKE base mode. The wrap's context tuple
//! (`tree_id, key_id, member_id, wrap_method, epoch`) is passed as the HPKE `info`, so a
//! wrap can't be transplanted across members, epochs, or trees — the same binding the
//! symmetric wrap gets from its AAD.
//!
//! The member's keypair is derived deterministically from their passphrase root (see
//! `derive_root`), so there is no separate secret to store — symmetric with how the
//! owner's Ed25519 identity is derived.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use crate::{CryptoError, Key32, KEY_LEN};

/// The pinned HPKE KEM / KDF / AEAD for `WRAP_METHOD_X25519_HPKE`.
type KemImpl = X25519HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = ChaCha20Poly1305;

/// X25519 public-key length (also the encapsulated-key length).
pub const HPKE_PUBLIC_LEN: usize = 32;
/// X25519 secret-key length.
pub const HPKE_SECRET_LEN: usize = 32;

/// A getrandom-backed CSPRNG for HPKE's ephemeral key. `fill_bytes` panics only if the OS
/// / browser entropy source fails, which is unrecoverable — the same contract `rand`'s
/// `OsRng` provides.
struct OsCsprng;

impl rand_core::RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS/browser CSPRNG failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::fill(dest).map_err(|_| {
            // rand_core 0.6 wants a NonZeroU32 error code; CUSTOM_START is non-zero.
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}
impl rand_core::CryptoRng for OsCsprng {}

/// An HPKE-wrapped DEK: the encapsulated key (stored in `KeyWrap.ephemeral_public_key`)
/// and the sealed DEK (stored in `KeyWrap.wrapped_dek`). HPKE carries its own nonce
/// internally, so `KeyWrap.nonce` is empty for this method.
pub struct HpkeWrap {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Deterministically derive a member's X25519 HPKE keypair from 32 bytes of key material
/// (their passphrase root, `derive_root`). Returns `(secret, public)`.
pub fn derive_hpke_keypair(ikm: &[u8; 32]) -> ([u8; HPKE_SECRET_LEN], [u8; HPKE_PUBLIC_LEN]) {
    let (sk, pk) = KemImpl::derive_keypair(ikm);
    let mut secret = [0u8; HPKE_SECRET_LEN];
    let mut public = [0u8; HPKE_PUBLIC_LEN];
    secret.copy_from_slice(sk.to_bytes().as_slice());
    public.copy_from_slice(pk.to_bytes().as_slice());
    (secret, public)
}

/// Generate a fresh random X25519 HPKE keypair — for a per-tree escrow key (the recovery
/// root key) that is NOT derived from any passphrase. Returns `(secret, public)`.
pub fn generate_hpke_keypair() -> Result<([u8; HPKE_SECRET_LEN], [u8; HPKE_PUBLIC_LEN]), CryptoError>
{
    let mut ikm = [0u8; 32];
    getrandom::fill(&mut ikm).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let out = derive_hpke_keypair(&ikm);
    ikm.iter_mut().for_each(|b| *b = 0); // scrub the IKM
    Ok(out)
}

/// Seal `dek` to a member's X25519 public key, binding `info` (the wrap context tuple) so
/// the wrap can't be replayed for another member/epoch/tree.
pub fn hpke_wrap_dek(
    recipient_public: &[u8],
    dek: &[u8],
    info: &[u8],
) -> Result<HpkeWrap, CryptoError> {
    let pk = <KemImpl as KemTrait>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| CryptoError::Hpke)?;
    let mut rng = OsCsprng;
    let (encapped, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
        &OpModeS::Base,
        &pk,
        info,
        dek,
        &[],
        &mut rng,
    )
    .map_err(|_| CryptoError::Hpke)?;
    Ok(HpkeWrap {
        encapped_key: encapped.to_bytes().as_slice().to_vec(),
        ciphertext,
    })
}

/// Open an HPKE-wrapped DEK with the member's X25519 secret key. `info` must be the exact
/// context tuple used at wrap time, or the AEAD tag fails. Returns the zeroizing DEK.
pub fn hpke_unwrap_dek(
    recipient_secret: &[u8],
    encapped_key: &[u8],
    ciphertext: &[u8],
    info: &[u8],
) -> Result<Key32, CryptoError> {
    let sk = <KemImpl as KemTrait>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|_| CryptoError::Hpke)?;
    let encapped = <KemImpl as KemTrait>::EncappedKey::from_bytes(encapped_key)
        .map_err(|_| CryptoError::Hpke)?;
    let plaintext = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        ciphertext,
        &[],
    )
    .map_err(|_| CryptoError::Hpke)?;
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::KeyLength);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    Ok(zeroize::Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &[u8] = b"openom:wrap:v1\x00tree\x00key\x00member";

    fn dek() -> [u8; KEY_LEN] {
        let mut d = [0u8; KEY_LEN];
        for (i, b) in d.iter_mut().enumerate() {
            *b = i as u8;
        }
        d
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let (secret, public) = derive_hpke_keypair(&[7u8; 32]);
        let w = hpke_wrap_dek(&public, &dek(), INFO).unwrap();
        let out = hpke_unwrap_dek(&secret, &w.encapped_key, &w.ciphertext, INFO).unwrap();
        assert_eq!(&*out, &dek());
    }

    #[test]
    fn derive_is_deterministic_and_distinct() {
        let (s1, p1) = derive_hpke_keypair(&[1u8; 32]);
        let (s2, p2) = derive_hpke_keypair(&[1u8; 32]);
        assert_eq!((s1, p1), (s2, p2), "same IKM => same keypair");
        let (_, p3) = derive_hpke_keypair(&[2u8; 32]);
        assert_ne!(p1, p3, "different IKM => different public key");
    }

    #[test]
    fn the_wrong_member_secret_cannot_open() {
        let (_, public) = derive_hpke_keypair(&[7u8; 32]);
        let (other_secret, _) = derive_hpke_keypair(&[8u8; 32]);
        let w = hpke_wrap_dek(&public, &dek(), INFO).unwrap();
        assert!(matches!(
            hpke_unwrap_dek(&other_secret, &w.encapped_key, &w.ciphertext, INFO),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn a_wrong_context_fails_to_open() {
        let (secret, public) = derive_hpke_keypair(&[7u8; 32]);
        let w = hpke_wrap_dek(&public, &dek(), INFO).unwrap();
        assert!(matches!(
            hpke_unwrap_dek(
                &secret,
                &w.encapped_key,
                &w.ciphertext,
                b"openom:wrap:v1\x00other"
            ),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn a_tampered_wrap_fails_to_open() {
        let (secret, public) = derive_hpke_keypair(&[7u8; 32]);
        let mut w = hpke_wrap_dek(&public, &dek(), INFO).unwrap();
        w.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            hpke_unwrap_dek(&secret, &w.encapped_key, &w.ciphertext, INFO),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn a_malformed_public_key_is_rejected() {
        assert!(matches!(
            hpke_wrap_dek(&[0u8; 10], &dek(), INFO),
            Err(CryptoError::Hpke)
        ));
    }
}
