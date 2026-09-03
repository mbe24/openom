#![doc = include_str!("../README.md")]

pub mod access;
pub mod blocklace;
pub mod canonical;
pub mod content;
pub mod dag;
pub mod engine;
pub mod epoch;
pub mod gc;
pub mod op;
pub mod quorum;
pub mod roles;
pub mod signature;

pub use access::{AccessControl, DefaultAccessControl, DynAccessControl};
pub use canonical::{canonical_encode, CanonicalBytes};
pub use content::{content_id, verify_content_id, ContentId};
pub use blocklace::Graph;
pub use dag::lamport::LamportTiebreak;
pub use dag::resolver::{
    ApplyOutcome, DekWrap, Error, GroupId, GroupState, MemberId, MemberInit, MemberState, MembershipAction,
    MembershipEvent, OpId, SignedOp,
};
pub use dag::strong_remove::StrongRemove;
pub use engine::{keyeo, Keyeo, StandardKeyeo};
pub use epoch::{
    epoch_context, generate_epoch, membership_commitment, reconcile_epochs, recover_epoch_dek,
    wraps_complete, Epoch,
};
pub use gc::{compact, Frontier, RetentionPolicy, Snapshot};
pub use op::Op;
pub use quorum::{Individual, QuorumPolicy, Requirement};
pub use roles::Role;
pub use signature::{Ed25519, SigError, SignatureScheme};

// The generic crypto primitives now live in keyeo-crypto (OPE-305). Re-exported here so `keyeo::X`
// keeps resolving for the group-membership engine's own consumers.
pub use keyeo_crypto::{CryptoError, Key32, KEY_LEN, SALT_LEN};
