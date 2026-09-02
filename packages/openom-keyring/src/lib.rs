#![doc = include_str!("../README.md")]

pub mod blob_sync;
pub mod verifier;
mod chain;
mod entry;
mod keyring;
mod roles;
mod signing_bytes;

pub use signing_bytes::keyring_signing_bytes;

pub use chain::{
    bootstrap_from_genesis, bootstrap_from_oob, decode_governing_ref, encode_governing_ref,
    verify_reset, verify_transition, verify_walk, ChainError, GoverningKeyring, KeyringAnchor,
};
pub use entry::{epoch_is_attributed, verify_entry, EntryError};
pub use roles::moderators;
pub use keyring::{
    keyring_hash, sign_keyring, verify_keyring, verify_keyring_all, verify_keyring_any,
    verify_keyring_threshold, Signature, SigningKey, VerifyingKey,
};
// A random-identity test helper (see keyring::generate_identity); off in production.
#[cfg(any(test, feature = "test-util"))]
pub use keyring::generate_identity;
