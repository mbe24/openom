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
pub use openom_keyring_dag::{KeyringMemberInit, KeyringRole};

pub mod app_vault;
pub use app_vault::AppVault;

// Landed-entry author verification (§B3) — moved out of the chain keyring engine (OPE-300): it consumes a
// keyring, it isn't the membership engine.
pub mod attribution;
pub use attribution::{epoch_is_attributed, has_been_shared, verify_entry, EntryError};

// Engine-neutral keyring/membership orchestration glue (walk / wrap / summary / reset), lifted out of the
// wasm veneer so both it and openom-app-core call one implementation (OPE-382 Half B).
pub mod sharing;

pub mod verify;
pub use verify::chain::ChainMembershipResolver;
pub use verify::dag::DagMembershipResolver;
pub use verify::{
    resolver_from, verify_covered_entry, verify_ingest, Disposition, Governing, MembershipResolver,
};

// The moderator (Maintainer-or-above did:key) feed for the claim engine's authority — re-typed over the
// engine-neutral MembershipView so it serves either keyring engine (OPE-308). Moved out of the chain
// keyring engine: it consumes a resolved membership, it isn't the membership engine.
pub mod membership;
pub use membership::moderators;

// (The legacy `#[wasm_bindgen]` veneer was retired — the app-core worker is the single wasm surface now;
// this crate is consumed only as an rlib by openom-app-core + openom-vault-host.)
