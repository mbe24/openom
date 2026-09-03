#![doc = include_str!("../README.md")]

pub mod canonical;
pub mod quorum;
pub mod roles;
pub mod signature;

pub use canonical::{CanonicalBytes, Postcard};
pub use quorum::Requirement;
pub use roles::Role;
pub use signature::{Ed25519, SigError, SignatureScheme};
