//! Signature schemes — pluggable, with Ed25519 as default.
//!
//! The one concrete scheme, [`Ed25519`], verifies through [`edsign`] — i.e. `verify_strict`, which
//! rejects small-order / torsion public keys and non-canonical signatures. This is the single Ed25519
//! verify path every keyeo engine shares (there is no raw `ed25519-dalek` edge here; §0 / OPE-205/215).
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

/// Ed25519 through the [`edsign`] seam: `verify` is `verify_strict`, so small-order / torsion keys and
/// non-canonical signatures are rejected. The single Ed25519 scheme shared by every keyeo engine.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519;

impl SignatureScheme for Ed25519 {
    type PublicKey = [u8; 32];
    type Signature = [u8; 64];
    fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), SigError> {
        let vk = edsign::VerifyingKey::from_bytes(pk).map_err(|_| SigError)?;
        vk.verify(msg, &edsign::Signature::from_bytes(sig))
            .map_err(|_| SigError)
    }
}
