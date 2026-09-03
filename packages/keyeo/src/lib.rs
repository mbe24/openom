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

pub use access::{AccessControl, DefaultAccessControl, DynAccessControl};
pub use canonical::canonical_encode;
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
pub use quorum::{Individual, QuorumPolicy};

// The generic engine-family SEAM types now live in keyeo-core (OPE-306). Re-exported here so `keyeo::X`
// keeps resolving for keyeo-dag and the engine's other consumers (Role / SignatureScheme / SigError /
// Ed25519 / CanonicalBytes / Requirement).
pub use keyeo_core::{CanonicalBytes, Ed25519, Requirement, Role, SigError, SignatureScheme};

// The generic crypto primitives now live in keyeo-crypto (OPE-305). Re-exported here so `keyeo::X`
// keeps resolving for the group-membership engine's own consumers.
pub use keyeo_crypto::{CryptoError, Key32, KEY_LEN, SALT_LEN};
