//! openom-keyring — the keyring/membership mechanism.
//!
//! The signed `Keyring` is the authoritative membership + role manifest for a tree. This crate is where
//! that mechanism lives, extracted from the raw-primitives crate (`openom-crypto`) so the conceptual
//! weight is contained in one place:
//!
//! - **`chain`** — the anti-rollback / anti-fork revision chain: verify a keyring transition (or a
//!   genesis / recovery reset) as a legitimate successor of a trusted anchor (`verify_transition`,
//!   `verify_reset`, `verify_walk`, `KeyringAnchor`, `bootstrap_*`).
//! - **`entry`** — landed-entry authorship: is a delta/snapshot/proposal signed by a member who held the
//!   required capability at the governing revision (`verify_entry`, `epoch_is_attributed`)?
//! - **`keyring`** — signing + verifying the keyring itself, member identities, and the chain hash.
//!
//! It depends only on the wire types (`openom-protocol`), the shared error type + primitives layering
//! (`openom-crypto`), the role policy (`openom-roles`), and Ed25519 — never on the tree/op layer, so the
//! zero-knowledge server and both clients reach it through a narrow, content-agnostic surface.

mod chain;
mod entry;
mod keyring;

pub use chain::{
    bootstrap_from_genesis, bootstrap_from_oob, verify_reset, verify_transition, verify_walk,
    ChainError, KeyringAnchor,
};
pub use entry::{epoch_is_attributed, verify_entry, EntryError};
pub use keyring::{
    generate_identity, keyring_hash, sign_keyring, verify_keyring, verify_keyring_all,
    verify_keyring_any, Signature, SigningKey, VerifyingKey,
};
