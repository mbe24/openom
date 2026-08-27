//! Passphrase → KEK via Argon2id (§6), plus CSPRNG helpers for DEKs and salts.
//!
//! Key material leaves this crate only as a role newtype ([`Kek`] / [`Dek`]) — opaque and
//! zeroized on drop, its bytes reachable only via `.expose()`. Argon2 params live in the wire
//! `KdfParams` so cost can rise over time (§4) — a wrap carries the exact params it was derived
//! under, so an old wrap stays openable.

use argon2::{Algorithm, Argon2, Params, Version};
use openom_protocol::v1::KdfParams;
use zeroize::Zeroizing;

use crate::{CryptoError, Dek, Kek, KEY_LEN, SALT_LEN};

/// Argon2id memory cost (KiB) — ~19 MiB, the OWASP minimum for Argon2id. Explicit and
/// versioned in `KdfParams`, so it can rise without breaking old wraps.
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 19_456;
/// Argon2id time cost (passes).
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 2;
/// Argon2id parallelism (lanes).
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 1;

/// Derive a 256-bit KEK from `passphrase` under the given Argon2id `params` (salt +
/// costs). Deterministic in its inputs — the same passphrase + params yield the same
/// KEK, which is what lets a second device join from the passphrase alone (§4).
pub fn derive_kek(passphrase: &[u8], params: &KdfParams) -> Result<Kek, CryptoError> {
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, &params.salt, out.as_mut_slice())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out.into())
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

/// A fresh random 256-bit DEK (per tree, per epoch — §6).
pub fn generate_dek() -> Result<Dek, CryptoError> {
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(dek.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(dek.into())
}

/// A fresh random Argon2id salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn production_kdf_params_are_pinned() {
        // The passphrase KDF's cost IS the brute-force defense, so a silent weakening is a security
        // regression. This pins the production values instantly (it asserts constants — it does NOT run
        // Argon2id). Raising the cost is deliberate: bump these together with the constants.
        assert_eq!(DEFAULT_ARGON2_MEMORY_KIB, 19_456); // ~19 MiB, the OWASP Argon2id minimum
        assert_eq!(DEFAULT_ARGON2_ITERATIONS, 2);
        assert_eq!(DEFAULT_ARGON2_PARALLELISM, 1);
    }

    #[test]
    fn deterministic_in_passphrase_and_params() {
        let p = fast_params(b"salt-0123456789ab");
        let a = derive_kek(b"correct horse", &p).unwrap();
        let b = derive_kek(b"correct horse", &p).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn different_passphrase_differs() {
        let p = fast_params(b"salt-0123456789ab");
        let a = derive_kek(b"passphrase one", &p).unwrap();
        let b = derive_kek(b"passphrase two", &p).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn different_salt_differs() {
        let a = derive_kek(b"same pass", &fast_params(b"salt-aaaaaaaaaaaa")).unwrap();
        let b = derive_kek(b"same pass", &fast_params(b"salt-bbbbbbbbbbbb")).unwrap();
        assert_ne!(a.expose(), b.expose());
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
    fn generated_deks_are_random_and_sized() {
        let a = generate_dek().unwrap();
        let b = generate_dek().unwrap();
        assert_eq!(a.expose().len(), KEY_LEN);
        assert_ne!(a.expose(), b.expose()); // astronomically unlikely to collide
    }
}
