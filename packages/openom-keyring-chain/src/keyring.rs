//! Signer identities + keyring signing (§4, multi-signer).
//!
//! An authorized signer's Ed25519 key signs the whole keyring — via the generic engine's canonical,
//! domain-separated signed bytes ([`keyeo_chain::signing_bytes`] over the chain's [`KeyringDoc`]) — so the
//! partly-untrusted server can't substitute a member's wrapped key, role, or public key undetectably. A
//! keyring carries one or more signatures (any-of / 1-of-N in V1); each signs the *same* bytes (the
//! `signatures` field is excluded from them), so signatures collect independently.
//!
//! Verification is against keys the client **trusts** — never the `signer_public_key` a signature names,
//! which is only a hint (§4a). (The full chain-walk policy lives in `chain`; these are the low-level
//! signature helpers a producer and the vault use.)

use crate::doc::KeyringDoc;
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
/// (`keyeo_chain::signing_bytes`), which the engine also verifies over, so producer and verifier agree by
/// construction. `pub(crate)` so `blob_sync`'s countersign content-comparison uses the same bytes.
pub(crate) fn signing_bytes(keyring: &Keyring) -> Vec<u8> {
    keyeo_chain::signing_bytes(&KeyringDoc::new(keyring))
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
///
/// # Errors
/// Returns [`SigError`] if no `trusted` key verifies any of the keyring's signatures.
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
///
/// # Errors
/// Returns [`SigError`] if the keyring carries no valid signature from `verifying_key`.
pub fn verify_keyring(keyring: &Keyring, verifying_key: &VerifyingKey) -> Result<(), SigError> {
    verify_keyring_any(keyring, std::slice::from_ref(verifying_key)).map(|_| ())
}

/// SHA-256 of a keyring's canonical signed bytes — the value the *next* revision records as its
/// `prev_keyring_hash`, chaining the revision history (§4). Delegates to the engine's `doc_hash` so the
/// chain hash is exactly what the engine chains on.
#[must_use]
pub fn keyring_hash(keyring: &Keyring) -> [u8; 32] {
    keyeo_chain::doc_hash(&KeyringDoc::new(keyring)).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Member;
    use keyeo_crypto::{
        codec, Epoch as KeyeoEpoch, EncappedKey, KeyId, Wrap as KeyeoWrap, WrapMethod, WrappedDek,
        X25519PublicKey,
    };

    fn sample_epochs() -> Vec<KeyeoEpoch<String>> {
        vec![KeyeoEpoch {
            key_id: KeyId::new(vec![1, 2, 3]),
            ordinal: 0,
            wraps: vec![KeyeoWrap {
                recipient: "acct-1".into(),
                method: WrapMethod::MemberHpke {
                    encapped: EncappedKey::from_bytes([1u8; 32]),
                    recipient_key: X25519PublicKey::from_bytes([2u8; 32]),
                },
                ciphertext: WrappedDek::from_bytes([9u8; 48]),
            }],
        }]
    }

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
            epochs: codec::encode_epochs(&sample_epochs()),
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
        let mut eps = swapped.key_material().unwrap();
        eps[0].wraps[0].ciphertext = WrappedDek::from_bytes([0u8; 48]);
        swapped.epochs = codec::encode_epochs(&eps);
        assert!(matches!(verify_keyring(&swapped, &id.verifying_key()), Err(SigError)));

        let mut escalated = kr.clone();
        escalated.members[0].role = 3; // OWNER -> ADMIN
        assert!(matches!(verify_keyring(&escalated, &id.verifying_key()), Err(SigError)));
    }

    /// Every field of the keyeo key material is bound in the signature via the payload commitment (it is
    /// hashed as opaque `codec` bytes, so this is the end-to-end proof of what the codec's per-field
    /// mutation test asserts at the byte level). Mutate one decoded field, re-encode WITHOUT re-signing, and
    /// verification must reject. Extend this when a field/variant is added (the sentinel in `doc.rs` forces
    /// the reminder).
    #[test]
    fn every_key_material_field_is_bound_in_the_signature() {
        let id = generate_identity().unwrap();
        let mut kr = sample_keyring();
        kr.members[0].author_public_key = id.verifying_key().to_bytes().to_vec();
        sign_keyring(&mut kr, &id);
        verify_keyring(&kr, &id.verifying_key()).unwrap();

        let fails = |f: &dyn Fn(&mut KeyeoEpoch<String>)| {
            let mut k = kr.clone();
            let mut eps = k.key_material().unwrap();
            f(&mut eps[0]);
            k.epochs = codec::encode_epochs(&eps);
            matches!(verify_keyring(&k, &id.verifying_key()), Err(SigError))
        };
        assert!(fails(&|e| e.ordinal = 5), "ordinal");
        assert!(fails(&|e| e.key_id = KeyId::new(vec![9, 9, 9])), "key_id");
        assert!(fails(&|e| e.wraps[0].recipient = "someone-else".into()), "recipient");
        assert!(
            fails(&|e| e.wraps[0].ciphertext = WrappedDek::from_bytes([0u8; 48])),
            "ciphertext"
        );
        assert!(
            fails(&|e| {
                if let WrapMethod::MemberHpke { encapped, .. } = &mut e.wraps[0].method {
                    *encapped = EncappedKey::from_bytes([0u8; 32]);
                }
            }),
            "encapped"
        );
        assert!(
            fails(&|e| {
                if let WrapMethod::MemberHpke { recipient_key, .. } = &mut e.wraps[0].method {
                    *recipient_key = X25519PublicKey::from_bytes([0u8; 32]);
                }
            }),
            "recipient_key"
        );
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
