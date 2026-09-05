//! Fixed-size crypto-material newtypes — the wrap byte-strings whose lengths the pinned suite fixes.
//!
//! The suite (frozen): DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305 for HPKE, and
//! XChaCha20-Poly1305 for the symmetric KEK wrap. So an X25519 point is 32 bytes and a sealed 32-byte
//! secret is 48 (32 + a 16-byte AEAD tag). Encoding those lengths in the *type* makes a wrong-length key
//! or ciphertext unconstructable (illegal states unrepresentable) and removes a heap allocation per field
//! (a `[u8; N]` is inline; a `Vec<u8>` for a 32-byte key is an alloc + a pointer chase). This is the same
//! discipline [`HpkeKeypair`](crate::HpkeKeypair) already uses for its key halves, extended to the wrap
//! outputs — which had regressed to raw `Vec<u8>`.
//!
//! serde is deliberately NOT derived here yet: the current consumer ([`HpkeWrap`](crate::HpkeWrap)) is a
//! transient value converted immediately into the consumer's own record, so nothing serializes these in
//! isolation. The `serde(transparent)` impls (and the hand impl the 48-byte array needs, since serde's
//! blanket array impls stop at 32) land when the shared wrap/epoch types that ARE serialized arrive.

use crate::CryptoError;

/// The HPKE encapsulated key (`enc`) — the ephemeral X25519 public produced by a seal, replayed to the
/// opener. A DISTINCT type from a recipient's static public key: both are 32-byte X25519 points, but one
/// is per-wrap ephemeral output and the other a stable identity, and keeping them non-swappable is the
/// point.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncappedKey([u8; 32]);

impl EncappedKey {
    /// The fixed length of an X25519 encapsulated key.
    pub const LEN: usize = 32;
    /// Wrap a known-length array (no validation needed — the length is in the type).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// The raw bytes, by value.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for EncappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for EncappedKey {
    type Error = CryptoError;
    /// Length-checked at the wire boundary: a slice that isn't exactly 32 bytes is rejected.
    fn try_from(bytes: &[u8]) -> Result<Self, CryptoError> {
        bytes.try_into().map(Self).map_err(|_| CryptoError::Hpke)
    }
}

/// A wrapped 32-byte secret (a DEK or the RRK secret) + its 16-byte AEAD tag = 48 bytes, whether sealed
/// via HPKE (ChaCha20Poly1305) or the symmetric KEK wrap (XChaCha20-Poly1305) — both land on 48.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrappedDek([u8; 48]);

impl WrappedDek {
    /// The fixed length: a 32-byte secret plus a 16-byte Poly1305 tag.
    pub const LEN: usize = 48;
    /// Wrap a known-length array (no validation needed — the length is in the type).
    pub fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }
    /// The raw bytes, by value.
    pub fn to_bytes(self) -> [u8; 48] {
        self.0
    }
}

impl AsRef<[u8]> for WrappedDek {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for WrappedDek {
    type Error = CryptoError;
    /// Length-checked at the wire boundary: a slice that isn't exactly 48 bytes is rejected.
    fn try_from(bytes: &[u8]) -> Result<Self, CryptoError> {
        bytes.try_into().map(Self).map_err(|_| CryptoError::Hpke)
    }
}
