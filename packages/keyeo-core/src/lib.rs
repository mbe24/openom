#![doc = include_str!("../README.md")]

pub mod canonical;
pub mod group;
pub mod quorum;
pub mod retention;
pub mod roles;
pub mod signature;
pub mod signed;

pub use canonical::{CanonicalBytes, Postcard};
pub use group::GroupId;
pub use quorum::Requirement;
pub use retention::{
    Compaction, CompactionError, Retention, RetentionMetrics, RetentionPlan, RetentionPolicy,
};
pub use roles::Role;
pub use signature::{Ed25519, SigError, SignatureScheme};
pub use signed::Signed;
