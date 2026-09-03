#![doc = include_str!("../README.md")]

pub mod blob_sync;
pub mod verifier;
pub mod wire;
mod chain;
mod doc;
mod keyring;

pub use chain::{
    bootstrap_from_genesis, bootstrap_from_oob, decode_governing_ref, encode_governing_ref,
    verify_reset, verify_transition, verify_walk, AuthorizedSigner, ChainError, GoverningKeyring,
    KeyringAnchor,
};
pub use doc::ChainRole;
pub use verifier::membership_view;
pub use keyring::{
    keyring_hash, sign_keyring, verify_keyring, verify_keyring_any, Signature, SigningKey,
    VerifyingKey,
};
// The chain's own keyring wire (moved out of openom-protocol in OPE-300). Consumers (the vault,
// vault-host, the dag differential tests) import the keyring message types from here.
pub use wire::{
    KdfParams, KeyEpoch, KeyWrap, Keyring, KeyringSignature, Member, RecoveryKey,
    KEYRING_LAYOUT_VERSION, MEMBER_CO_OWNER, MEMBER_OWNER,
};
// A random-identity test helper (see keyring::generate_identity); off in production.
#[cfg(any(test, feature = "test-util"))]
pub use keyring::generate_identity;
