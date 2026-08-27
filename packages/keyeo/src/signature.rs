//! Signature schemes — pluggable, with Ed25519 as default.
use ed25519_dalek::VerifyingKey;
use std::fmt::Debug;
use std::hash::Hash;
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("signature verification failed")]
pub struct SigError;

pub trait SignatureScheme: Debug + Clone + PartialEq + Eq + Send + Sync {
    // `AsRef<[u8]>` (not `Serialize`): keys/signatures are encoded into canonical bytes as their raw
    // bytes, which also sidesteps serde's lack of a `Serialize` impl for `[u8; 64]` (Ed25519 sigs).
    type PublicKey: Debug + Clone + Eq + std::hash::Hash + Ord + Send + Sync + AsRef<[u8]>;
    type Signature: Debug + Clone + Eq + Hash + Ord + Send + Sync + AsRef<[u8]>;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<(), SigError>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519;

impl SignatureScheme for Ed25519 {
    type PublicKey = [u8; 32];
    type Signature = [u8; 64];
    fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), SigError> {
        let pk = VerifyingKey::from_bytes(pk).map_err(|_| SigError)?;
        let sig = ed25519_dalek::Signature::from_bytes(sig);
        pk.verify_strict(msg, &sig).map_err(|_| SigError)
    }
}
