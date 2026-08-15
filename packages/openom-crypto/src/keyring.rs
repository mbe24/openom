//! Owner identity + keyring signing (§4).
//!
//! The owner's Ed25519 key signs the whole keyring (canonically encoded and
//! domain-separated, see [`openom_protocol::aad::keyring_signing_bytes`]) so the
//! partly-untrusted server can't substitute a member's wrapped key undetectably.
//! Verification is against a key the client **trusts** — its own passphrase-derived
//! identity in V1, or a pinned out-of-band key when sharing — never the
//! `signer_key_id` the keyring names, which is only a hint (§4a).
//!
//! A signature proves *authorship*, never *currency*: `revision` is covered so it
//! can't be tampered, but refusing a stale keyring is a client watermark concern (the
//! caller persists the highest `revision` seen and rejects a regression, §4/§10).

use ed25519_dalek::{Signer, Verifier};
use openom_protocol::aad::keyring_signing_bytes;
use openom_protocol::v1::Keyring;

use crate::CryptoError;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Ed25519 signature length in bytes.
const SIG_LEN: usize = 64;

/// Generate a fresh owner identity (Ed25519). The seed is protected like the DEK
/// (passphrase-wrapped, §6); `SigningKey` zeroizes on drop.
pub fn generate_identity() -> Result<SigningKey, CryptoError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Sign the keyring in place: compute the §4 canonical bytes and set
/// `keyring.signature`. Set `tree_id`, `epochs`, `revision`, and `signer_key_id`
/// first — all are covered.
pub fn sign_keyring(keyring: &mut Keyring, signing_key: &SigningKey) {
    let msg = keyring_signing_bytes(keyring);
    keyring.signature = signing_key.sign(&msg).to_bytes().to_vec();
}

/// Verify the keyring's signature against a **trusted** verifying key (§4a). Any
/// tampered keyring field, or a wrong key, fails as [`CryptoError::Signature`].
pub fn verify_keyring(
    keyring: &Keyring,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let sig_bytes: [u8; SIG_LEN] = keyring
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Signature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let msg = keyring_signing_bytes(keyring);
    verifying_key
        .verify(&msg, &signature)
        .map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_protocol::v1::{KeyEpoch, KeyWrap};

    fn sample_keyring() -> Keyring {
        Keyring {
            tree_id: vec![0x11; 16],
            revision: 1,
            signer_key_id: vec![0xAB; 4],
            signature: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![1, 2, 3],
                epoch: 0,
                wraps: vec![KeyWrap {
                    member_id: "acct-1".into(),
                    wrap_method: 1,
                    nonce: vec![7; 24],
                    wrapped_dek: vec![9; 48],
                    kdf_params: None,
                    ephemeral_public_key: vec![],
                }],
            }],
        }
    }

    #[test]
    fn sign_then_verify() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.signer_key_id = id.verifying_key().to_bytes().to_vec();
        sign_keyring(&mut kr, &id);
        assert_eq!(kr.signature.len(), SIG_LEN);
        verify_keyring(&kr, &id.verifying_key()).unwrap();
    }

    #[test]
    fn wrong_key_rejected() {
        let id = generate_identity().unwrap();
        let other = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &id);
        assert!(matches!(
            verify_keyring(&kr, &other.verifying_key()),
            Err(CryptoError::Signature)
        ));
    }

    #[test]
    fn tampering_after_signing_is_detected() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &id);

        // Bump the revision (a rollback/replay attempt) — signature no longer verifies.
        let mut rolled = kr.clone();
        rolled.revision = 2;
        assert!(matches!(verify_keyring(&rolled, &id.verifying_key()), Err(CryptoError::Signature)));

        // Swap a member's wrapped DEK — detected.
        let mut swapped = kr.clone();
        swapped.epochs[0].wraps[0].wrapped_dek = vec![0; 48];
        assert!(matches!(verify_keyring(&swapped, &id.verifying_key()), Err(CryptoError::Signature)));
    }

    #[test]
    fn malformed_signature_rejected() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.signature = vec![0u8; 10]; // not 64 bytes
        assert!(matches!(verify_keyring(&kr, &id.verifying_key()), Err(CryptoError::Signature)));
    }
}
