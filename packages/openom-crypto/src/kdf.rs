//! KDF helpers pinning openom's default Argon2id costs over `keyeo_crypto`'s engine-neutral primitives.
//! The derivation itself, DEK/salt generation, and the default-cost constants live in `keyeo_crypto::kdf`;
//! this module traffics in keyeo's `KdfParams` (the proto wire `KdfParams` only appears at the wasm↔JS
//! account-record boundary now).

use keyeo_crypto::{
    Kek, KdfParams, DEFAULT_ARGON2_ITERATIONS, DEFAULT_ARGON2_MEMORY_KIB, DEFAULT_ARGON2_PARALLELISM,
};

use crate::CryptoError;

/// Derive a 256-bit KEK from `passphrase` under the given Argon2id `params` (salt + costs). Deterministic
/// in its inputs — the same passphrase + params yield the same KEK, which is what lets a second device join
/// from the passphrase alone (§4).
pub fn derive_kek(passphrase: &[u8], params: &KdfParams) -> Result<Kek, CryptoError> {
    keyeo_crypto::derive_kek(passphrase, params)
}

/// `KdfParams` with the default Argon2id costs and the given `salt`.
pub fn default_kdf_params(salt: Vec<u8>) -> KdfParams {
    KdfParams {
        salt,
        memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
        iterations: DEFAULT_ARGON2_ITERATIONS,
        parallelism: DEFAULT_ARGON2_PARALLELISM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyeo_crypto::generate_salt;

    // Tiny params so tests stay fast — production uses the DEFAULT_* costs.
    fn fast_params(salt: &[u8]) -> KdfParams {
        KdfParams { salt: salt.to_vec(), memory_kib: 8, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn kek_seals_and_opens() {
        use crate::{open, seal};
        use openom_protocol::v1::{Aead, Header, Kind};

        let salt = generate_salt().unwrap();
        let kek = derive_kek(b"unlock me", &fast_params(&salt)).unwrap();
        let h = Header {
            kind: Kind::Snapshot as i32,
            aead: Aead::Xchacha20Poly1305 as i32,
            nonce: vec![3u8; 24],
            tree_id: vec![0x11; 16],
            ..Default::default()
        };
        let ct = seal(1, &h, kek.expose(), b"wrapped-by-passphrase").unwrap();
        assert_eq!(
            open(1, &h, kek.expose(), &ct).unwrap(),
            b"wrapped-by-passphrase"
        );
    }

    #[test]
    fn default_params_carry_the_salt_and_default_costs() {
        // Kills `default_kdf_params -> Default::default()` (which would drop the salt and zero the costs).
        let p = default_kdf_params(vec![1, 2, 3]);
        assert_eq!(p.salt, vec![1, 2, 3]);
        assert_eq!(p.memory_kib, DEFAULT_ARGON2_MEMORY_KIB);
        assert_eq!(p.iterations, DEFAULT_ARGON2_ITERATIONS);
        assert_eq!(p.parallelism, DEFAULT_ARGON2_PARALLELISM);
    }
}
