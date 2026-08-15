//! Root-key derivation: turn a passphrase into the two keys the unlock flow needs — the
//! **KEK** that wraps the DEK, and the **Ed25519 owner identity** that signs the keyring.
//!
//! One Argon2id run (the single slow, memory-hard step) produces a 256-bit master; HKDF-
//! SHA256 then expands it into two independent 32-byte keys under distinct `info` labels.
//! They are **siblings** — neither is derived from the other — so a KEK compromise can never
//! yield the signing key. Argon2id output is already uniform, so HKDF-Expand is the textbook
//! way to split it; a second Argon2id would only double the ~1s cost for no security gain.
//!
//! ## Frozen construction (a second implementation must reproduce this byte-for-byte)
//! - master = Argon2id(passphrase, params)  — 32 bytes (same as [`derive_kek`]).
//! - HKDF-SHA256 with **Extract salt = empty** (`Hkdf::new(None, master)`).
//! - Expand two 32-byte outputs with the exact ASCII labels below.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{derive_kek, CryptoError, Key32, KEY_LEN};
use openom_protocol::v1::KdfParams;

/// HKDF `info` label for the KEK. **Frozen.**
const HKDF_KEK_INFO: &[u8] = b"openom:kek:v1";
/// HKDF `info` label for the owner identity seed. **Frozen.**
const HKDF_IDENTITY_INFO: &[u8] = b"openom:identity:v1";

/// The two keys a passphrase unlocks: the DEK-wrapping KEK and the keyring-signing identity.
pub struct RootKeys {
    pub kek: Key32,
    pub identity: SigningKey,
}

/// Derive [`RootKeys`] from a passphrase (see the module docs for the frozen construction).
/// The passphrase should already be a [`Zeroizing`] buffer at the call site; this scrubs
/// every intermediate (the master and the identity seed) on the way out.
pub fn derive_root(passphrase: &[u8], params: &KdfParams) -> Result<RootKeys, CryptoError> {
    // The Argon2id output is the HKDF master (derive_kek is exactly that Argon2id step).
    let master = derive_kek(passphrase, params)?;
    let hk = Hkdf::<Sha256>::new(None, master.as_slice());

    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_KEK_INFO, kek.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (kek)".into()))?;

    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_IDENTITY_INFO, seed.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (identity)".into()))?;
    let identity = SigningKey::from_bytes(&seed);

    Ok(RootKeys { kek, identity })
}

// Compile-time confirmation (not an assumption) that the derived owner identity scrubs its
// secret seed on drop — a concrete `where` bound is checked at definition, so this fails to
// compile if ed25519-dalek's `zeroize` feature ever stops providing ZeroizeOnDrop.
#[allow(dead_code)]
fn _identity_zeroizes_on_drop()
where
    SigningKey: zeroize::ZeroizeOnDrop,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_kdf_params, generate_salt};

    fn params() -> KdfParams {
        // A cheap fixed salt/params for tests (real use gets a CSPRNG salt).
        default_kdf_params(vec![7u8; 16])
    }

    #[test]
    fn is_deterministic_for_the_same_passphrase() {
        let a = derive_root(b"correct horse", &params()).unwrap();
        let b = derive_root(b"correct horse", &params()).unwrap();
        assert_eq!(a.kek.as_slice(), b.kek.as_slice());
        assert_eq!(a.identity.to_bytes(), b.identity.to_bytes());
        assert_eq!(
            a.identity.verifying_key().to_bytes(),
            b.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn a_different_passphrase_gives_different_keys() {
        let a = derive_root(b"passphrase-one", &params()).unwrap();
        let b = derive_root(b"passphrase-two", &params()).unwrap();
        assert_ne!(a.kek.as_slice(), b.kek.as_slice());
        assert_ne!(a.identity.to_bytes(), b.identity.to_bytes());
    }

    #[test]
    fn a_different_salt_gives_different_keys() {
        let a = derive_root(b"same pass", &default_kdf_params(vec![1u8; 16])).unwrap();
        let b = derive_root(b"same pass", &default_kdf_params(vec![2u8; 16])).unwrap();
        assert_ne!(a.kek.as_slice(), b.kek.as_slice());
        assert_ne!(a.identity.to_bytes(), b.identity.to_bytes());
    }

    #[test]
    fn kek_and_identity_are_independent() {
        // Siblings: the KEK bytes and the identity seed must not coincide.
        let r = derive_root(b"whatever", &params()).unwrap();
        assert_ne!(r.kek.as_slice(), &r.identity.to_bytes());
    }

    #[test]
    fn the_derived_identity_signs_and_verifies() {
        use ed25519_dalek::{Signer, Verifier};
        let r = derive_root(b"signer", &params()).unwrap();
        let msg = b"keyring bytes";
        let sig = r.identity.sign(msg);
        assert!(r.identity.verifying_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn salt_is_usable_from_the_generator() {
        // Smoke: a real CSPRNG salt flows through without panicking.
        let salt = generate_salt().unwrap().to_vec();
        let _ = derive_root(b"pass", &default_kdf_params(salt)).unwrap();
    }
}
