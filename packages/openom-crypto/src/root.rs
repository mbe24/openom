//! Proto-edge root-key derivation: pin the frozen `openom:*` HKDF labels and convert the wire
//! `KdfParams` into the neutral form, delegating the actual Argon2id→HKDF split to
//! [`keyeo_crypto::derive_root`].
//!
//! The generic construction (one Argon2id master, then HKDF-SHA256 into sibling KEK / Ed25519
//! identity / X25519 HPKE keys) lives in `keyeo_crypto::root`. What stays HERE is openom's
//! **frozen** domain: the three `openom:*` labels a second implementation must reproduce
//! byte-for-byte. (The RVK label `keyeo:rvk:v1` is engine-neutral and owned by keyeo-crypto;
//! [`derive_rvk`](keyeo_crypto::derive_rvk) is re-exported unchanged.)

use keyeo_crypto::{RootKeys, RootLabels};
use openom_protocol::v1::KdfParams;

use crate::kdf::to_core;
use crate::CryptoError;

/// HKDF `info` label for the KEK. **Frozen.**
const HKDF_KEK_INFO: &[u8] = b"openom:kek:v1";
/// HKDF `info` label for the owner identity seed. **Frozen.**
const HKDF_IDENTITY_INFO: &[u8] = b"openom:identity:v1";
/// HKDF `info` label for the HPKE keypair IKM. **Frozen.**
const HKDF_HPKE_INFO: &[u8] = b"openom:hpke:v1";

/// The frozen openom label set fed to [`keyeo_crypto::derive_root`].
const OPENOM_ROOT_LABELS: RootLabels = RootLabels {
    kek: HKDF_KEK_INFO,
    identity: HKDF_IDENTITY_INFO,
    hpke: HKDF_HPKE_INFO,
};

/// Derive [`RootKeys`] from a passphrase under the frozen `openom:*` HKDF labels. Converts the wire
/// `params` to the neutral form (a plain field copy) and delegates to [`keyeo_crypto::derive_root`];
/// see that crate for the frozen construction and the zeroize-on-drop guarantees.
pub fn derive_root(passphrase: &[u8], params: &KdfParams) -> Result<RootKeys, CryptoError> {
    keyeo_crypto::derive_root(passphrase, &to_core(params), &OPENOM_ROOT_LABELS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edsign::SigningKey;
    use keyeo_crypto::generate_salt;

    fn cheap(salt: Vec<u8>) -> KdfParams {
        KdfParams { salt, memory_kib: 8, iterations: 1, parallelism: 1 }
    }
    fn params() -> KdfParams {
        cheap(vec![7u8; 16])
    }

    #[test]
    fn frozen_labels_are_unchanged() {
        // A silent relabel would break every existing account's derivation. Pin the bytes.
        assert_eq!(HKDF_KEK_INFO, b"openom:kek:v1");
        assert_eq!(HKDF_IDENTITY_INFO, b"openom:identity:v1");
        assert_eq!(HKDF_HPKE_INFO, b"openom:hpke:v1");
    }

    #[test]
    fn wrapper_is_deterministic_and_uses_distinct_labels() {
        let a = derive_root(b"correct horse", &params()).unwrap();
        let b = derive_root(b"correct horse", &params()).unwrap();
        assert_eq!(a.kek.expose(), b.kek.expose());
        assert_eq!(
            a.identity.verifying_key().to_bytes(),
            b.identity.verifying_key().to_bytes()
        );
        // KEK / identity / HPKE are siblings (distinct labels), so none coincides with another.
        assert_ne!(
            SigningKey::from_seed(a.kek.expose()).verifying_key().to_bytes(),
            a.identity.verifying_key().to_bytes()
        );
        assert_ne!(a.kek.expose(), a.hpke_secret.expose());
    }

    #[test]
    fn the_hpke_keypair_is_usable() {
        use keyeo_crypto::{hpke_unwrap_dek, hpke_wrap_dek, Dek, KEY_LEN};
        let salt = generate_salt().unwrap().to_vec();
        let r = derive_root(b"member pass", &cheap(salt)).unwrap();
        let w = hpke_wrap_dek(&r.hpke_public, &Dek::new([9u8; KEY_LEN]), b"info").unwrap();
        let out = hpke_unwrap_dek(r.hpke_secret.expose(), &w.encapped_key, &w.ciphertext, b"info").unwrap();
        assert_eq!(out.expose(), &[9u8; KEY_LEN]);
    }
}
