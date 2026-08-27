#![doc = include_str!("../README.md")]

use journal::StoreError;
use openom_sealer::SealerError;

/// A sync failure — one of the layers said no.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sealer(#[from] SealerError),
    /// A pulled claim entry's decrypted bytes didn't decode as a `ChannelItem` batch.
    #[error("claim decode failed: {0}")]
    ClaimDecode(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, SyncError>;

mod claim;
pub use claim::ClaimSyncClient;
