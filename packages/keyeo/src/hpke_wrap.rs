//! HPKE DEK wrapping — RFC 9180 (DHKEM-X25519 + HKDF-SHA256 + ChaCha20Poly1305).
//! Adapted from openom-crypto::hpke_wrap (MIT).

use crate::{CryptoError, Key32, KEY_LEN};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

type KemImpl = X25519HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = ChaCha20Poly1305;

pub const HPKE_PUBLIC_LEN: usize = 32;
pub const HPKE_SECRET_LEN: usize = 32;

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
        getrandom::fill(dest).unwrap_or_else(|_| panic!("CSPRNG failed"));
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::fill(dest).map_err(|_| {
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}
impl rand_core::CryptoRng for OsCsprng {}

pub struct HpkeWrap {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn derive_hpke_keypair(ikm: &[u8; 32]) -> ([u8; HPKE_SECRET_LEN], [u8; HPKE_PUBLIC_LEN]) {
    let (sk, pk) = KemImpl::derive_keypair(ikm);
    let mut secret = [0u8; HPKE_SECRET_LEN];
    let mut public = [0u8; HPKE_PUBLIC_LEN];
    secret.copy_from_slice(sk.to_bytes().as_slice());
    public.copy_from_slice(pk.to_bytes().as_slice());
    (secret, public)
}

pub fn hpke_wrap_dek(
    recipient_public: &[u8],
    dek: &[u8],
    info: &[u8],
) -> Result<HpkeWrap, CryptoError> {
    let pk =
        <KemImpl as Kem>::PublicKey::from_bytes(recipient_public).map_err(|_| CryptoError::Hpke)?;
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

pub fn hpke_unwrap_dek(
    recipient_secret: &[u8],
    encapped_key: &[u8],
    ciphertext: &[u8],
    info: &[u8],
) -> Result<Key32, CryptoError> {
    let sk = <KemImpl as Kem>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|_| CryptoError::Hpke)?;
    let encapped =
        <KemImpl as Kem>::EncappedKey::from_bytes(encapped_key).map_err(|_| CryptoError::Hpke)?;
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
    Ok(Zeroizing::new(key))
}
