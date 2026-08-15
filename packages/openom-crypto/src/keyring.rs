//! Signer identities + keyring signing (§4, multi-signer).
//!
//! An authorized signer's Ed25519 key signs the whole keyring (canonically encoded and
//! domain-separated, see [`openom_protocol::aad::keyring_signing_bytes`]) so the
//! partly-untrusted server can't substitute a member's wrapped key, role, or public key
//! undetectably. A keyring carries **one or more** signatures (any-of / 1-of-N in V1);
//! each signs the *same* bytes (the `signatures` field is excluded from them), so
//! signatures collect independently — the property a future threshold policy reuses.
//!
//! Verification is against keys the client **trusts** — its own passphrase-derived
//! identity for a single owner, or a pinned out-of-band signer set when sharing — never
//! the `signer_public_key` a signature names, which is only a hint (§4a).
//!
//! A signature proves *authorship*, never *currency*: `revision`/`prev_keyring_hash` are
//! covered so they can't be tampered, but refusing a stale or off-chain keyring is a
//! client watermark concern (the caller persists the highest `revision`/last hash + the
//! trusted signer set, and rejects a regression or an unendorsed set change, §4/§10).

use ed25519_dalek::{Signer, Verifier};
use openom_protocol::aad::keyring_signing_bytes;
use openom_protocol::v1::{Keyring, KeyringSignature};
use sha2::{Digest, Sha256};

use crate::CryptoError;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Ed25519 signature length in bytes.
const SIG_LEN: usize = 64;

/// Generate a fresh signer identity (Ed25519). The seed is protected like the DEK
/// (passphrase-wrapped, §6); `SigningKey` zeroizes on drop.
pub fn generate_identity() -> Result<SigningKey, CryptoError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Append a signature from `signing_key` to the keyring (the any-of model): compute the
/// §4 canonical bytes and push a [`KeyringSignature`] carrying this signer's public key
/// (a hint) and the signature. Set `tree_id`, `epochs`, `revision`, `layout_version`,
/// `prev_keyring_hash`, `authorized_signers`, and `members` first — all are covered.
/// Multiple signers can each call this on the same keyring (order-independent).
pub fn sign_keyring(keyring: &mut Keyring, signing_key: &SigningKey) {
    let msg = keyring_signing_bytes(keyring);
    let signature = signing_key.sign(&msg).to_bytes().to_vec();
    keyring.signatures.push(KeyringSignature {
        signer_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature,
    });
}

/// Verify the keyring carries **at least one** valid signature from the `trusted` set
/// (§4a), returning the trusted key that verified. The signatures' `signer_public_key`
/// hints are ignored — every trusted key is tried against every present signature, so a
/// forged or mislabeled hint can neither help nor mislead. Fails as
/// [`CryptoError::Signature`] if no trusted key has a valid signature.
pub fn verify_keyring_any(
    keyring: &Keyring,
    trusted: &[VerifyingKey],
) -> Result<VerifyingKey, CryptoError> {
    let msg = keyring_signing_bytes(keyring);
    for sig in &keyring.signatures {
        let Ok(sig_bytes): Result<[u8; SIG_LEN], _> = sig.signature.as_slice().try_into() else {
            continue;
        };
        let signature = Signature::from_bytes(&sig_bytes);
        for key in trusted {
            if key.verify(&msg, &signature).is_ok() {
                return Ok(*key);
            }
        }
    }
    Err(CryptoError::Signature)
}

/// Convenience for the single-trusted-key case (a single owner verifying with its own
/// derived identity): the keyring must carry a valid signature from `verifying_key`.
pub fn verify_keyring(
    keyring: &Keyring,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    verify_keyring_any(keyring, std::slice::from_ref(verifying_key)).map(|_| ())
}

/// SHA-256 of a keyring's canonical signing bytes — the value the *next* revision
/// records as its `prev_keyring_hash`, chaining the revision history (§4). Hashing the
/// signing bytes (not the non-canonical protobuf) keeps the chain reproducible.
pub fn keyring_hash(keyring: &Keyring) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(keyring_signing_bytes(keyring));
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_protocol::v1::{AuthorizedSigner, KeyEpoch, KeyWrap, Member};

    fn sample_keyring() -> Keyring {
        Keyring {
            tree_id: vec![0x11; 16],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![AuthorizedSigner {
                public_key: vec![],
                member_id: "acct-1".into(),
                role: 1, // FOUNDER
            }],
            members: vec![Member {
                member_id: "acct-1".into(),
                role: 1, // OWNER
                author_public_key: vec![],
                hpke_public_key: vec![],
            }],
            signatures: vec![],
            recovery_keys: vec![],
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
        kr.authorized_signers[0].public_key = id.verifying_key().to_bytes().to_vec();
        sign_keyring(&mut kr, &id);
        assert_eq!(kr.signatures.len(), 1);
        assert_eq!(kr.signatures[0].signature.len(), SIG_LEN);
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
    fn any_of_verifies_when_at_least_one_trusted_key_signed() {
        // Two authorized signers; the keyring carries only the second's signature.
        let a = generate_identity().unwrap();
        let b = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &b);
        let trusted = [a.verifying_key(), b.verifying_key()];
        assert_eq!(verify_keyring_any(&kr, &trusted).unwrap(), b.verifying_key());

        // A keyring signed by neither trusted key fails.
        let rogue = generate_identity().unwrap();
        let mut kr2 = sample_keyring();
        sign_keyring(&mut kr2, &rogue);
        assert!(matches!(verify_keyring_any(&kr2, &trusted), Err(CryptoError::Signature)));
    }

    #[test]
    fn a_lying_signer_public_key_hint_neither_helps_nor_misleads() {
        let real = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &real);
        // Tamper the untrusted hint to claim a different signer — verification is against
        // the trusted key and the actual signature bytes, so it still verifies.
        kr.signatures[0].signer_public_key = vec![0x00; 32];
        verify_keyring(&kr, &real.verifying_key()).unwrap();
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

        // Change a member's role (would-be privilege escalation) — detected.
        let mut escalated = kr.clone();
        escalated.members[0].role = 3; // OWNER -> ADMIN
        assert!(matches!(verify_keyring(&escalated, &id.verifying_key()), Err(CryptoError::Signature)));
    }

    #[test]
    fn malformed_signature_rejected() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.signatures = vec![KeyringSignature { signer_public_key: vec![], signature: vec![0u8; 10] }];
        assert!(matches!(verify_keyring(&kr, &id.verifying_key()), Err(CryptoError::Signature)));
    }

    #[test]
    fn keyring_hash_changes_with_content_and_ignores_signatures() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        let h0 = keyring_hash(&kr);
        sign_keyring(&mut kr, &id);
        assert_eq!(h0, keyring_hash(&kr), "signatures are excluded from the chain hash");
        kr.revision = 2;
        assert_ne!(h0, keyring_hash(&kr), "content changes the chain hash");
    }
}
