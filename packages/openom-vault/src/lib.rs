//! The keyring **vault** layer (extracted from openom-sealer in OPE-279).
//!
//! This crate owns the passphrase-driven lifecycle over a keyring — provision / unlock / recover /
//! change-passphrase + membership authoring — for BOTH engines (the linear chain and the dag), behind the
//! [`KeyringLifecycle`] trait, with [`AppVault`] dispatching on the deployment's [`KeyringRole`]-carrying
//! engine. It sits ABOVE the two keyring engines (`openom-keyring`, `keyeo-dag`) and above
//! [`openom_sealer`] — which it uses purely for the DEK session ([`Sealer`](openom_sealer::Sealer) /
//! [`SealerSet`](openom_sealer::SealerSet) / seal-open / [`SealerError`](openom_sealer::SealerError)).
//!
//! Keeping this out of openom-sealer lets envelope-only consumers (e.g. openom-sync) depend on the lean
//! sealer without transitively rebuilding both keyring engines.

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
