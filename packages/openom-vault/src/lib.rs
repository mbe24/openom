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
// without a direct keyeo-dag dependency.
pub use keyeo_dag::KeyringRole;

pub mod app_vault;
pub use app_vault::AppVault;

#[cfg(feature = "wasm")]
pub mod wasm;
