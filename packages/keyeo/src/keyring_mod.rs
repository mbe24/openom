//! Keyring signing and verification.
//! Adapted from keyeo-chain::keyring (MIT).

use crate::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Keyring {
    pub project_id: Vec<u8>,
    pub revision: u32,
    pub prev_keyring_hash: Vec<u8>,
    pub signers: Vec<SignerEntry>,
    pub members: Vec<MemberEntry>,
    pub signatures: Vec<KeyringSig>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignerEntry {
    pub public_key: Vec<u8>,
    pub member_id: String,
    pub role: i32,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MemberEntry {
    pub member_id: String,
    pub role: i32,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
    /// Wrap method: 1 = passphrase (KEK), 2 = HPKE (X25519)
    pub wrap_method: i32,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KeyringSig {
    pub signer_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn signing_bytes(keyring: &Keyring) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();
    write!(&mut buf, "flowcontrol:keyeo:v1").unwrap();
    buf.push(0);
    buf.extend_from_slice(&keyring.project_id);
    buf.extend_from_slice(&keyring.revision.to_le_bytes());
    buf.extend_from_slice(&keyring.prev_keyring_hash);
    for s in &keyring.signers {
        buf.extend_from_slice(&s.public_key);
        buf.extend_from_slice(s.member_id.as_bytes());
        buf.extend_from_slice(&s.role.to_le_bytes());
        buf.push(0);
    }
    for m in &keyring.members {
        buf.extend_from_slice(m.member_id.as_bytes());
        buf.extend_from_slice(&m.role.to_le_bytes());
        buf.extend_from_slice(&m.author_public_key);
        buf.extend_from_slice(&m.hpke_public_key);
        buf.extend_from_slice(&m.wrap_method.to_le_bytes());
        buf.push(0);
    }
    buf
}

pub fn generate_identity() -> Result<SigningKey, CryptoError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn sign_keyring(keyring: &mut Keyring, signing_key: &SigningKey) {
    let msg = signing_bytes(keyring);
    let sig = signing_key.sign(&msg).to_bytes().to_vec();
    keyring.signatures.push(KeyringSig {
        signer_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature: sig,
    });
}

pub fn verify_keyring_any(
    keyring: &Keyring,
    trusted: &[VerifyingKey],
) -> Result<VerifyingKey, CryptoError> {
    let msg = signing_bytes(keyring);
    for sig in &keyring.signatures {
        let Ok(sig_bytes): Result<[u8; 64], _> = sig.signature.as_slice().try_into() else {
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

pub fn verify_keyring(keyring: &Keyring, verifying_key: &VerifyingKey) -> Result<(), CryptoError> {
    verify_keyring_any(keyring, std::slice::from_ref(verifying_key)).map(|_| ())
}

pub fn keyring_hash(keyring: &Keyring) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(signing_bytes(keyring));
    h.finalize().into()
}
