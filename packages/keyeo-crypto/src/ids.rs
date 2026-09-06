//! `KeyId` — an epoch DEK's opaque identity. (The shared `GroupId` moved to `keyeo-core`, the seam both
//! engines and this crate depend on, so it is defined once for the whole family.)

use serde::{Deserialize, Serialize};

/// An epoch DEK's identity — a fresh random salt minted per epoch, so it uniquely identifies the epoch and
/// doubles as the per-epoch binding in the wrap AAD (no separate epoch scalar is needed). An opaque byte
/// string the caller assigns.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct KeyId(pub Vec<u8>);

impl KeyId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
