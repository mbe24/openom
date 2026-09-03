#![doc = include_str!("../README.md")]

mod error;
pub use error::VaultError;

pub mod vault;
mod vault_core;

pub mod lifecycle;
pub use lifecycle::{ChainVault, KeyringLifecycle, VaultContext};

pub mod dag_vault;
pub use dag_vault::{Backfilled, DagVault, Resealed};

// Re-exported: the dag membership methods take a KeyringRole, so callers name it through openom-vault
// without a direct openom-keyring-dag dependency.
pub use openom_keyring_dag::KeyringRole;

pub mod app_vault;
pub use app_vault::AppVault;

// Landed-entry author verification (§B3) — moved out of the chain keyring engine (OPE-300): it consumes a
// keyring, it isn't the membership engine.
pub mod attribution;
pub use attribution::{epoch_is_attributed, verify_entry, EntryError};

#[cfg(feature = "wasm")]
pub mod wasm;
