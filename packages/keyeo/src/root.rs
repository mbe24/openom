//! Root key derivation: one Argon2id → HKDF-SHA256 → KEK + Ed25519 + X25519 HPKE.
//! Adapted from openom-crypto::root (MIT).

use crate::hpke_wrap::derive_hpke_keypair;
use crate::kdf::{derive_kek, KdfParams, Key32, KEY_LEN};
use crate::CryptoError;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const HKDF_KEK_INFO: &[u8] = b"flowcontrol:kek:v1";
const HKDF_IDENTITY_INFO: &[u8] = b"flowcontrol:identity:v1";
const HKDF_HPKE_INFO: &[u8] = b"flowcontrol:hpke:v1";

pub struct RootKeys {
    pub kek: Key32,
    pub identity: SigningKey,
    pub hpke_secret: Zeroizing<[u8; 32]>,
    pub hpke_public: [u8; 32],
}

pub fn derive_root(passphrase: &[u8], params: &KdfParams) -> Result<RootKeys, CryptoError> {
    let master = derive_kek(passphrase, params)?;
    let hk = Hkdf::<Sha256>::new(None, master.as_slice());

    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_KEK_INFO, kek.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (kek)".into()))?;

    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_IDENTITY_INFO, seed.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (identity)".into()))?;
    let identity = SigningKey::from_bytes(&seed);

    let mut hpke_ikm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_HPKE_INFO, hpke_ikm.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (hpke)".into()))?;
    let (hpke_secret, hpke_public) = derive_hpke_keypair(&hpke_ikm);

    Ok(RootKeys {
        kek,
        identity,
        hpke_secret: Zeroizing::new(hpke_secret),
        hpke_public,
    })
}
