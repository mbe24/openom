#![doc = include_str!("../README.md")]

// openom-docsync is the claim-model binding of the generic `docsync` loop, so a sync failure IS a
// `docsync::SyncError` — its Store / Engine(claim-decode) / Sealer(DEK) variants already cover every
// layer this client can fail in. No second error type.
pub use docsync::SyncError;

type Result<T> = std::result::Result<T, SyncError>;

mod sync;
pub use sync::SyncClient;
