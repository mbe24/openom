//! Identity newtypes for the byte-strings the vault and wire pass around, so that at a boundary a
//! [`TreeId`], a [`ReplicaId`], and a [`MemberId`] can't be swapped for one another (or for a
//! passphrase / keyring blob) — a wrong-argument slip becomes a compile error, not a runtime one.
//!
//! They wrap the exact bytes/string the proto already carries (`Header.tree_id`, `Header.replica_id`,
//! `Member.member_id`); there is no wire change. A boundary holding raw material (a JS `Uint8Array`,
//! an IPC field) constructs one with [`new`](TreeId::new); a lower layer that wants raw bytes reads
//! [`as_bytes`](TreeId::as_bytes) / [`as_str`](MemberId::as_str). The vault surface takes the
//! newtypes; the mechanism layers below it (wraps, sealer) stay raw.

/// A tree id — the 16-byte identifier of an encrypted tree (`Header.tree_id`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TreeId(Vec<u8>);

/// A replica id — per unlock/context, the key half of the `(replica_id, counter)` idempotency dot
/// (`Header.replica_id`). Distinct from a [`TreeId`] though both are opaque byte-strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplicaId(Vec<u8>);

/// An epoch key id — the 16-byte identifier of a DEK generation (`Header.key_id`, `KeyEpoch.key_id`).
/// Distinct from a [`TreeId`]/[`ReplicaId`] though all are opaque byte-strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(Vec<u8>);

/// An application member id (`Member.member_id` / `KeyWrap.member_id`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemberId(String);

impl TreeId {
    /// Wrap raw tree-id bytes (from a `Uint8Array`, an IPC field, a generated id).
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    /// The raw bytes — for a mechanism layer that speaks `&[u8]`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Consume into the owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl ReplicaId {
    /// Wrap raw replica-id bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Consume into the owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl KeyId {
    /// Wrap raw key-id bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Consume into the owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl MemberId {
    /// Wrap a member-id string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// The member id as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Consume into the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_wrap_and_expose_without_changing_the_bytes() {
        let t = TreeId::new(vec![1u8; 16]);
        assert_eq!(t.as_bytes(), &[1u8; 16]);
        assert_eq!(t.clone().into_bytes(), vec![1u8; 16]);

        let r = ReplicaId::new(&b"replica-0"[..]);
        assert_eq!(r.as_bytes(), b"replica-0");
        assert_eq!(r.into_bytes(), b"replica-0".to_vec());

        let k = KeyId::new(vec![7u8; 8]);
        assert_eq!(k.as_bytes(), &[7u8; 8]);
        assert_eq!(k.into_bytes(), vec![7u8; 8]);

        let m = MemberId::new("acct-123");
        assert_eq!(m.as_str(), "acct-123");
        assert_eq!(m.clone().into_string(), "acct-123");

        // Distinct types: a TreeId and a ReplicaId over identical bytes are not interchangeable at a
        // call site (this compiles only because we compare their bytes, not the values themselves).
        assert_eq!(
            TreeId::new(vec![9u8; 4]).as_bytes(),
            ReplicaId::new(vec![9u8; 4]).as_bytes()
        );
    }
}
