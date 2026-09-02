#![doc = include_str!("../README.md")]

pub mod access;
pub mod blocklace;
pub mod canonical;
pub mod content;
pub mod dag;
pub mod engine;
pub mod entry;
pub mod epoch;
pub mod gc;
pub mod hpke_wrap;
pub mod kdf;
pub mod keyring_mod;
pub mod op;
pub mod quorum;
pub mod recovery;
pub mod roles;
pub mod root;
pub mod signature;
pub mod wrap;

pub use access::{AccessControl, DefaultAccessControl, DynAccessControl};
pub use canonical::{canonical_encode, CanonicalBytes};
pub use content::{content_id, verify_content_id, ContentId};
pub use blocklace::Graph;
pub use dag::lamport::LamportTiebreak;
pub use dag::resolver::{
    ApplyOutcome, DekWrap, Error, GroupState, MemberId, MemberInit, MemberState, MembershipAction,
    MembershipEvent, OpId, SignedOp,
};
pub use dag::strong_remove::StrongRemove;
pub use engine::{keyeo, Keyeo, StandardKeyeo};
pub use epoch::{
    epoch_context, generate_epoch, membership_commitment, reconcile_epochs, recover_epoch_dek,
    wraps_complete, Epoch,
};
pub use gc::{compact, Frontier, RetentionPolicy, Snapshot};
pub use kdf::{Key32, KEY_LEN, SALT_LEN};
pub use op::Op;
pub use quorum::{Individual, QuorumPolicy, Requirement};
pub use roles::Role;
pub use signature::{Ed25519, SigError, SignatureScheme};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported or unspecified AEAD")]
    UnsupportedAead(i32),
    #[error("wrong DEK length")]
    KeyLength,
    #[error("wrong nonce length")]
    NonceLength,
    #[error("AEAD seal failed")]
    Seal,
    #[error("AEAD open failed")]
    Open,
    #[error("KDF failed: {0}")]
    Kdf(String),
    #[error("RNG failed: {0}")]
    Rng(String),
    #[error("malformed recovery code")]
    RecoveryFormat,
    #[error("recovery code checksum mismatch")]
    RecoveryChecksum,
    #[error("keyeo signature invalid")]
    Signature,
    #[error("HPKE wrap/unwrap failed")]
    Hpke,
}
