//! Entry author verification.
//! Adapted from keyeo-chain::entry (MIT).

use crate::keyring_mod::Keyring;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    Unattributed,
    UnknownAuthor,
    BadSignature,
    InsufficientRole,
    EpochMismatch,
}

pub fn verify_entry(
    author_member_id: &str,
    author_signature: &[u8],
    _key_id: &[u8],
    plaintext: &[u8],
    governing: &Keyring,
) -> Result<(), EntryError> {
    if author_signature.is_empty() {
        return Err(EntryError::Unattributed);
    }
    let member = governing
        .members
        .iter()
        .find(|m| m.member_id == author_member_id)
        .ok_or(EntryError::UnknownAuthor)?;
    let key_bytes: [u8; 32] = member
        .author_public_key
        .as_slice()
        .try_into()
        .map_err(|_| EntryError::BadSignature)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| EntryError::BadSignature)?;
    let sig_bytes: [u8; 64] = author_signature
        .try_into()
        .map_err(|_| EntryError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let plaintext_hash = Sha256::digest(plaintext);
    let msg = [b"flowcontrol:entry:v1", plaintext_hash.as_slice()].concat();
    key.verify(&msg, &signature)
        .map_err(|_| EntryError::BadSignature)?;
    if member.role > 2 {
        return Err(EntryError::InsufficientRole);
    }
    Ok(())
}
