//! Proto-edge KDF wrappers: the wire `openom_protocol::v1::KdfParams` face over
//! `keyeo_crypto`'s engine-neutral primitives.
//!
//! The Argon2id derivation, DEK/salt generation, and default costs live in `keyeo_crypto::kdf`
//! (openom-free). This module owns only the mapping between the wire `KdfParams` (whose costs can
//! rise over time, §4) and the neutral `keyeo_crypto::KdfParams`, so every consumer keeps calling
//! `openom_crypto::derive_kek(passphrase, &proto_params)` unchanged.

use keyeo_crypto::{Kek, KdfParams as CoreKdfParams, DEFAULT_ARGON2_ITERATIONS,
    DEFAULT_ARGON2_MEMORY_KIB, DEFAULT_ARGON2_PARALLELISM};
use openom_protocol::v1::KdfParams;

use crate::CryptoError;

/// Convert the wire `KdfParams` into the engine-neutral `keyeo_crypto::KdfParams` (a plain field
/// copy — the two structs carry the identical salt + three Argon2id costs).
pub(crate) fn to_core(params: &KdfParams) -> CoreKdfParams {
    CoreKdfParams {
        salt: params.salt.clone(),
        memory_kib: params.memory_kib,
        iterations: params.iterations,
        parallelism: params.parallelism,
    }
}

/// Derive a 256-bit KEK from `passphrase` under the given wire Argon2id `params` (salt +
/// costs). Deterministic in its inputs — the same passphrase + params yield the same KEK,
/// which is what lets a second device join from the passphrase alone (§4).
pub fn derive_kek(passphrase: &[u8], params: &KdfParams) -> Result<Kek, CryptoError> {
    keyeo_crypto::derive_kek(passphrase, &to_core(params))
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
        KdfParams {
            salt: salt.to_vec(),
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
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
    fn derive_kek_wrapper_matches_the_core() {
        // The proto→core conversion is a plain field copy: the wrapper must produce the same KEK the
        // core derive_kek does from the copied fields (kills a conversion that drops/rewrites a field).
        let p = fast_params(b"salt-0123456789ab");
        let via_wrapper = derive_kek(b"correct horse", &p).unwrap();
        let via_core = keyeo_crypto::derive_kek(b"correct horse", &to_core(&p)).unwrap();
        assert_eq!(via_wrapper.expose(), via_core.expose());
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
