//! Recovery-key derivation for the DAG keyring (OPE-269).
//!
//! The **Recovery Verification Key (RVK)** is the Ed25519 key that authorizes a `ReFound` (recovery
//! re-founding) op. It is derived from the escrowed **Recovery Root Key (RRK)** secret via HKDF-SHA256
//! under a dedicated info label — DOMAIN-SEPARATED from every other key the same secret might derive, so
//! the signing capability the RVK grants can never be confused with an encryption or identity key (never
//! reuse a scalar across roles). Anyone who can unwrap the RRK secret (via the passphrase or the recovery
//! code) can derive the RVK and sign a `ReFound`; nobody else can.
//!
//! `rvk_public` is pinned in the signed genesis, so every replica can verify a `ReFound` at admission
//! against the recovery authority the group was founded with — strictly stronger than the linear chain's
//! `verify_reset`, which accepts any self-signed reset and rests entirely on an out-of-band ceremony.
//!
//! This is the crypto primitive only; the `ReFound` op, its pinning, and the merge semantics land in the
//! following OPE-269 slices.

use zeroize::Zeroizing;

/// HKDF info label for the RVK — distinct from any identity / HPKE / KEK label the RRK secret feeds, so
/// the RVK is cryptographically separated from those uses.
pub const RVK_HKDF_INFO: &[u8] = b"openom:rvk:v1";

/// Derive the Recovery Verification Key from the RRK secret. Deterministic: the same secret always yields
/// the same RVK, so a recovering client re-derives the identical signing key that the pinned `rvk_public`
/// verifies against.
pub fn derive_rvk(rrk_secret: &[u8; 32]) -> openom_sign::SigningKey {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, rrk_secret);
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(RVK_HKDF_INFO, seed.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    openom_sign::SigningKey::from_seed(&seed)
}

/// The public half of the RVK — the value pinned in genesis and checked against a `ReFound`'s carried
/// author key.
pub fn rvk_public(rrk_secret: &[u8; 32]) -> [u8; 32] {
    derive_rvk(rrk_secret).verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rvk_is_deterministic() {
        let secret = [7u8; 32];
        assert_eq!(rvk_public(&secret), rvk_public(&secret));
    }

    #[test]
    fn rvk_is_domain_separated_from_the_raw_seed_key() {
        // The RVK must NOT equal the signing key you'd get by using the secret directly as a seed — the
        // HKDF + dedicated label is exactly what separates the recovery-authority role from every other
        // use of the same secret.
        let secret = [7u8; 32];
        let direct = openom_sign::SigningKey::from_seed(&secret).verifying_key().to_bytes();
        assert_ne!(rvk_public(&secret), direct, "the RVK must be domain-separated, not the raw seed key");
    }

    #[test]
    fn different_secrets_yield_different_rvks() {
        assert_ne!(rvk_public(&[1u8; 32]), rvk_public(&[2u8; 32]));
    }

    #[test]
    fn rvk_signs_and_the_openom_sign_seam_verifies() {
        // A ReFound will be signed by the RVK and verified by every replica via the same OpenomSign seam
        // (openom-sign verify_strict) the engine authenticates all ops with.
        let secret = [9u8; 32];
        let rvk = derive_rvk(&secret);
        let msg = b"a refound op's canonical bytes";
        let sig = rvk.sign(msg);
        let vk = openom_sign::VerifyingKey::from_bytes(&rvk_public(&secret)).unwrap();
        assert!(vk.verify(msg, &sig).is_ok(), "the pinned rvk_public verifies an RVK signature");
    }
}
