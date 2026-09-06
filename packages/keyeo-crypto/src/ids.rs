//! Opaque identifiers shared across the keyeo family.

use serde::{Deserialize, Serialize};

/// An opaque group identifier (openom: the tree id) — a byte string the caller assigns. The engine binds
/// every op to it, so an op minted for one group can never resolve into another; the wrap AAD binds it too,
/// so a wrap can't be transplanted across groups. Lives at the crypto foundation so every keyeo layer names
/// the same type.
///
/// [`GroupId::unscoped`] (empty bytes) is the explicit "no group scope" marker for single-group / test
/// callers, so an empty id is always a conscious choice, never a forgotten binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct GroupId(pub Vec<u8>);

impl GroupId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    /// The explicit "no group scope" marker — a single-group or test context. Distinct in intent from a
    /// forgotten binding: a caller writes `GroupId::unscoped()` on purpose.
    #[must_use]
    pub fn unscoped() -> Self {
        Self(Vec::new())
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn is_unscoped(&self) -> bool {
        self.0.is_empty()
    }
}

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
