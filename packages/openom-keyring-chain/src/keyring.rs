//! Signer identities + keyring signing (§4, multi-signer).
//!
//! An authorized signer's Ed25519 key signs the whole keyring — via the generic engine's canonical,
//! domain-separated signed bytes ([`keyeo_linear::signing_bytes`] over the chain's [`ChainDoc`]) — so the
//! partly-untrusted server can't substitute a member's wrapped key, role, or public key undetectably. A
//! keyring carries one or more signatures (any-of / 1-of-N in V1); each signs the *same* bytes (the
//! `signatures` field is excluded from them), so signatures collect independently.
//!
//! Verification is against keys the client **trusts** — never the `signer_public_key` a signature names,
//! which is only a hint (§4a). (The full chain-walk policy lives in `chain`; these are the low-level
//! signature helpers a producer and the vault use.)

use crate::doc::ChainDoc;
use crate::wire::{Keyring, KeyringSignature};
use keyeo_core::{Ed25519, SigError, SignatureScheme};

// The Ed25519 key types come from the signing seam — the one crate that holds the ed25519-dalek edge —
// whose only verify is verify_strict. Downstream (openom-vault, openom-vault-host) consume these through
// this re-export. Load-bearing: keep these names resolving here.
pub use edsign::{Signature, SigningKey, VerifyingKey};

/// Generate a random signer identity (Ed25519) — a **test helper**, not a production path: real identities
/// are passphrase-derived so they can be recovered. Gated behind `test-util` (and the crate's own tests).
/// `SigningKey` zeroizes on drop.
#[cfg(any(test, feature = "test-util"))]
pub fn generate_identity() -> Result<SigningKey, SigError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| SigError)?;
    Ok(SigningKey::from_seed(&seed))
}

/// The canonical bytes an authorized signer signs over `keyring` — the generic engine's message
/// (`keyeo_linear::signing_bytes`), which the engine also verifies over, so producer and verifier agree by
/// construction. `pub(crate)` so `blob_sync`'s countersign content-comparison uses the same bytes.
pub(crate) fn signing_bytes(keyring: &Keyring) -> Vec<u8> {
    keyeo_linear::signing_bytes(&ChainDoc::new(keyring))
}

/// Append a signature from `signing_key` to the keyring (the any-of model). Set every keyring field first —
/// all are covered (the signer set is derived from `members`). Multiple signers can each call this on the
/// same keyring (order-independent, since signatures are excluded from the signed bytes).
pub fn sign_keyring(keyring: &mut Keyring, signing_key: &SigningKey) {
    let msg = signing_bytes(keyring);
    let signature = signing_key.sign(&msg).to_bytes().to_vec();
    keyring.signatures.push(KeyringSignature {
        signer_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature,
    });
}

/// Verify the keyring carries **at least one** valid signature from the `trusted` set (§4a), returning the
/// trusted key that verified. The signatures' `signer_public_key` hints are ignored — every trusted key is
/// tried against every present signature. Fails as [`SigError`] if none match.
pub fn verify_keyring_any(
    keyring: &Keyring,
    trusted: &[VerifyingKey],
) -> Result<VerifyingKey, SigError> {
    let msg = signing_bytes(keyring);
    for sig in &keyring.signatures {
        let Ok(sig_bytes): Result<[u8; 64], _> = sig.signature.as_slice().try_into() else {
            continue;
        };
        for key in trusted {
            // The scheme's verify is verify_strict — it rejects small-order / torsion keys.
            if <Ed25519 as SignatureScheme>::verify(&key.to_bytes(), &msg, &sig_bytes).is_ok() {
                return Ok(*key);
            }
        }
    }
    Err(SigError)
}

/// Convenience for the single-trusted-key case: the keyring must carry a valid signature from
/// `verifying_key`.
pub fn verify_keyring(keyring: &Keyring, verifying_key: &VerifyingKey) -> Result<(), SigError> {
    verify_keyring_any(keyring, std::slice::from_ref(verifying_key)).map(|_| ())
}

/// SHA-256 of a keyring's canonical signed bytes — the value the *next* revision records as its
/// `prev_keyring_hash`, chaining the revision history (§4). Delegates to the engine's `doc_hash` so the
/// chain hash is exactly what the engine chains on.
pub fn keyring_hash(keyring: &Keyring) -> [u8; 32] {
    keyeo_linear::doc_hash(&ChainDoc::new(keyring)).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{KeyEpoch, KeyWrap, Member};

    fn sample_keyring() -> Keyring {
        Keyring {
            tree_id: vec![0x11; 16],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            members: vec![Member {
                member_id: "acct-1".into(),
                role: 1, // OWNER (the sole signer, derived from this member)
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
                    recipient_public_key: vec![],
                }],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn sign_then_verify() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.members[0].author_public_key = id.verifying_key().to_bytes().to_vec();
        sign_keyring(&mut kr, &id);
        assert_eq!(kr.signatures.len(), 1);
        assert_eq!(kr.signatures[0].signature.len(), 64);
        verify_keyring(&kr, &id.verifying_key()).unwrap();
    }

    #[test]
    fn wrong_key_rejected() {
        let id = generate_identity().unwrap();
        let other = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &id);
        assert!(matches!(verify_keyring(&kr, &other.verifying_key()), Err(SigError)));
    }

    #[test]
    fn any_of_verifies_when_at_least_one_trusted_key_signed() {
        let a = generate_identity().unwrap();
        let b = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &b);
        let trusted = [a.verifying_key(), b.verifying_key()];
        assert_eq!(verify_keyring_any(&kr, &trusted).unwrap(), b.verifying_key());

        let rogue = generate_identity().unwrap();
        let mut kr2 = sample_keyring();
        sign_keyring(&mut kr2, &rogue);
        assert!(matches!(verify_keyring_any(&kr2, &trusted), Err(SigError)));
    }

    #[test]
    fn a_lying_signer_public_key_hint_neither_helps_nor_misleads() {
        let real = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &real);
        kr.signatures[0].signer_public_key = vec![0x00; 32];
        verify_keyring(&kr, &real.verifying_key()).unwrap();
    }

    #[test]
    fn tampering_after_signing_is_detected() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        sign_keyring(&mut kr, &id);

        let mut rolled = kr.clone();
        rolled.revision = 2;
        assert!(matches!(verify_keyring(&rolled, &id.verifying_key()), Err(SigError)));

        let mut swapped = kr.clone();
        swapped.epochs[0].wraps[0].wrapped_dek = vec![0; 48];
        assert!(matches!(verify_keyring(&swapped, &id.verifying_key()), Err(SigError)));

        let mut escalated = kr.clone();
        escalated.members[0].role = 3; // OWNER -> ADMIN
        assert!(matches!(verify_keyring(&escalated, &id.verifying_key()), Err(SigError)));
    }

    #[test]
    fn malformed_signature_rejected() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.signatures = vec![KeyringSignature {
            signer_public_key: vec![],
            signature: vec![0u8; 10],
        }];
        assert!(matches!(verify_keyring(&kr, &id.verifying_key()), Err(SigError)));
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

    #[test]
    fn payload_commitment_signs_and_verifies_round_trip() {
        // A change confined to the PAYLOAD (a member's hpke key — not in the engine's SignedFields) must
        // still invalidate a signature: it is bound through payload_commitment. This is the sign==verify
        // round-trip that proves the commitment is part of the signed bytes.
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.members[0].author_public_key = id.verifying_key().to_bytes().to_vec();
        sign_keyring(&mut kr, &id);
        verify_keyring(&kr, &id.verifying_key()).unwrap();

        // Tamper a payload-only field (hpke_public_key) — the signature must no longer verify.
        let mut tampered = kr.clone();
        tampered.members[0].hpke_public_key = vec![0xAB; 32];
        assert!(
            matches!(verify_keyring(&tampered, &id.verifying_key()), Err(SigError)),
            "a payload-only change is bound via payload_commitment"
        );

        // Re-signing the tampered keyring verifies again (sign==verify agree on the same commitment).
        sign_keyring(&mut tampered, &id);
        verify_keyring(&tampered, &id.verifying_key()).unwrap();
    }
}
