//! The engine selector (OPE-278): ONE enum both host consumers (the web-worker RPC in [`crate::wasm`] and
//! the Tauri invoke host in `openom-vault-host`) dispatch through, so the chain-vs-dag choice is made once
//! here rather than hand-wired at 2 hosts × 2 engines — OPE-276's "write once". It implements the shared
//! client lifecycle [`KeyringLifecycle`] by delegating to the selected engine.
//!
//! The engine is a **deployment/backend preset** (owner decision 2026-09-03): the managed Lambda backend is
//! fixed to one engine, a BYO backend (Google Drive) to one — never a per-tree user choice. The choice is
//! resolved at RUNTIME, not a compile-time feature (revised 2026-09-02), so one binary can map different
//! backends to different engines: the host builds the right `AppVault` from config via [`AppVault::from_kind`]
//! and records the tag in its local head record; there is no per-tree engine discovery.
//!
//! Engine-SPECIFIC membership authoring (add/remove member, member-unlock, reseal) is deliberately NOT on
//! this trait — the chain and dag signatures differ (the chain needs a trusted-signer set + a scalar floor;
//! the dag does not), so each host dispatches those with its own `match` on the enum arm (OPE-277 gate).

use openom_crypto::{Passphrase, RecoveryCode};
use keyeo_api::EngineKind;

use crate::lifecycle::{
    KeyringLifecycle, Provisioned, Recovered, Rekeyed, Unlocked, VaultContext,
};
use crate::lifecycle::ChainVault;
use crate::{DagVault, VaultError};

/// The two keyring engines behind one dispatch point. Zero-sized selectors, so an `AppVault` is just its
/// discriminant — the engine choice carried by the type, not held state.
pub enum AppVault {
    Chain(ChainVault),
    Dag(DagVault),
}

impl AppVault {
    /// Build the vault for the deployment's configured engine.
    pub fn from_kind(kind: EngineKind) -> Self {
        match kind {
            EngineKind::Chain => AppVault::Chain(ChainVault),
            EngineKind::Dag => AppVault::Dag(DagVault),
        }
    }

    /// Which engine this is — for recording the tag in the host's local head record.
    pub fn kind(&self) -> EngineKind {
        match self {
            AppVault::Chain(_) => EngineKind::Chain,
            AppVault::Dag(_) => EngineKind::Dag,
        }
    }

    /// The DAG engine, if this is one — the seam a host uses to reach the dag-specific membership authoring
    /// (add/remove member, member-unlock, reseal, merge), which is deliberately NOT on the shared lifecycle
    /// trait (the chain and dag signatures differ). `None` on a chain deployment. `DagVault` is a zero-sized
    /// selector, so this hands back a value, not a borrow.
    pub fn as_dag(&self) -> Option<DagVault> {
        match self {
            AppVault::Dag(_) => Some(DagVault),
            AppVault::Chain(_) => None,
        }
    }
}

impl KeyringLifecycle for AppVault {
    fn provision(
        &self,
        ctx: &VaultContext,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, VaultError> {
        match self {
            AppVault::Chain(v) => v.provision(ctx, passphrase),
            AppVault::Dag(v) => v.provision(ctx, passphrase),
        }
    }

    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
    ) -> Result<Unlocked, VaultError> {
        match self {
            AppVault::Chain(v) => v.unlock(ctx, anchor, passphrase),
            AppVault::Dag(v) => v.unlock(ctx, anchor, passphrase),
        }
    }

    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, VaultError> {
        match self {
            AppVault::Chain(v) => v.recover(ctx, anchor, recovery_code, new_passphrase, floor),
            AppVault::Dag(v) => v.recover(ctx, anchor, recovery_code, new_passphrase, floor),
        }
    }

    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, VaultError> {
        match self {
            AppVault::Chain(v) => {
                v.change_passphrase(ctx, anchor, old_passphrase, new_passphrase, floor)
            }
            AppVault::Dag(v) => {
                v.change_passphrase(ctx, anchor, old_passphrase, new_passphrase, floor)
            }
        }
    }
}
