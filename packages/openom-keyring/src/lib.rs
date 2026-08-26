#![doc = include_str!("../README.md")]

mod chain;
mod entry;
mod keyring;

pub use chain::{
    bootstrap_from_genesis, bootstrap_from_oob, verify_reset, verify_transition, verify_walk,
    ChainError, KeyringAnchor,
};
pub use entry::{epoch_is_attributed, verify_entry, EntryError};
pub use keyring::{
    keyring_hash, sign_keyring, verify_keyring, verify_keyring_all, verify_keyring_any, Signature,
    SigningKey, VerifyingKey,
};
// A random-identity test helper (see keyring::generate_identity); off in production.
#[cfg(any(test, feature = "test-util"))]
pub use keyring::generate_identity;
