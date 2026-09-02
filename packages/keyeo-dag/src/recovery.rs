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

/// The frozen HKDF domain label for the recovery-verification key. Byte-identical to the chain's
/// (`openom_crypto::derive_rvk`), so a tree provisioned by either engine pins the same RVK from the same
/// secret — an openom-vault cross-check test guards the two copies against drift.
const RVK_HKDF_INFO: &[u8] = b"keyeo:rvk:v1";

/// Derive the Recovery Verification Key from the RRK secret via the shared generic HKDF→Ed25519 derivation
/// ([`edsign::derive_signing_key`]) under the frozen `RVK_HKDF_INFO` label. Deterministic + domain-separated; keeps this
/// crate free of any openom dependency (it derives the RVK itself rather than borrowing openom-crypto's).
pub fn derive_rvk(rrk_secret: &[u8; 32]) -> edsign::SigningKey {
    edsign::derive_signing_key(rrk_secret, RVK_HKDF_INFO)
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
        let direct = edsign::SigningKey::from_seed(&secret).verifying_key().to_bytes();
        assert_ne!(rvk_public(&secret), direct, "the RVK must be domain-separated, not the raw seed key");
    }

    #[test]
    fn different_secrets_yield_different_rvks() {
        assert_ne!(rvk_public(&[1u8; 32]), rvk_public(&[2u8; 32]));
    }

    #[test]
    fn rvk_signs_and_the_edsign_seam_verifies() {
        // A ReFound will be signed by the RVK and verified by every replica via the same OpenomSign seam
        // (edsign verify_strict) the engine authenticates all ops with.
        let secret = [9u8; 32];
        let rvk = derive_rvk(&secret);
        let msg = b"a refound op's canonical bytes";
        let sig = rvk.sign(msg);
        let vk = edsign::VerifyingKey::from_bytes(&rvk_public(&secret)).unwrap();
        assert!(vk.verify(msg, &sig).is_ok(), "the pinned rvk_public verifies an RVK signature");
    }
}
