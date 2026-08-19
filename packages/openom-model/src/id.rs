//! Opaque, random, high-entropy identifiers for canonical-model entities.
//!
//! Per `plan/design.data-model.md` (Addressing): ids are **128-bit, UUIDv4-class, CSPRNG-generated,
//! opaque, and stable** — never content- or path-derived, so correcting a fact never changes an id
//! or breaks an edge pointing at it. Generation lives behind the [`IdSource`] seam: [`OsIdSource`]
//! (a CSPRNG) is used in **dev AND prod**; only tests inject [`SeededIdSource`] for determinism.
//! Entropy is a security property, not a dev/prod toggle.

use core::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Source of fresh entity ids. One impl for real data ([`OsIdSource`]); one for tests
/// ([`SeededIdSource`]).
pub trait IdSource {
    /// Mint a fresh, well-formed UUIDv4.
    fn next_uuid(&mut self) -> Uuid;
}

/// The only id source for real data (dev and prod): the OS/browser CSPRNG via `Uuid::new_v4`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsIdSource;

impl IdSource for OsIdSource {
    fn next_uuid(&mut self) -> Uuid {
        Uuid::new_v4()
    }
}

/// A **deterministic** id source for TESTS ONLY — never for real data (its entropy is not
/// cryptographic). A xorshift64\* stream stamped into well-formed UUIDv4 layout.
#[derive(Debug, Clone)]
pub struct SeededIdSource {
    state: u64,
}

impl SeededIdSource {
    /// Seed the stream. A zero seed is remapped so the generator never gets stuck at 0.
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

impl IdSource for SeededIdSource {
    fn next_uuid(&mut self) -> Uuid {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.next_u64().to_le_bytes());
        b[8..].copy_from_slice(&self.next_u64().to_le_bytes());
        // `from_random_bytes` stamps the version-4 + RFC-4122 variant bits, so the result is a
        // well-formed v4 regardless of the input entropy quality.
        uuid::Builder::from_random_bytes(b).into_uuid()
    }
}

/// Define a distinct, opaque id newtype over [`Uuid`]. Distinct types keep a `NodeId` from ever
/// being passed where an `EdgeId` is expected. `serde(transparent)` serializes as the bare UUID.
macro_rules! id_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Mint a fresh id from the given source.
            pub fn generate(src: &mut impl IdSource) -> Self {
                Self(src.next_uuid())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

id_type!(
    TreeId,
    "Identity of a whole tree — namespaces node ids for cross-tree references."
);
id_type!(
    NodeId,
    "Identity of a person or family node — the stable graph key."
);
id_type!(EdgeId, "Identity of a relationship edge.");
id_type!(EventId, "Identity of an event record.");
id_type!(SourceId, "Identity of a shared source record.");
id_type!(MediaId, "Identity of a shared media record.");
id_type!(FieldDefId, "Identity of a custom-field definition.");
id_type!(FieldValueId, "Identity of a custom-field value.");
id_type!(
    NameId,
    "Identity of a name entry (see the name model — embedded by a later task)."
);
id_type!(
    LinkId,
    "Identity of a cross-tree link record (federation seam)."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_ids_are_distinct() {
        let mut src = OsIdSource;
        let a = NodeId::generate(&mut src);
        let b = NodeId::generate(&mut src);
        assert_ne!(a, b);
    }

    #[test]
    fn seeded_is_deterministic_and_wellformed() {
        let mut s1 = SeededIdSource::new(7);
        let mut s2 = SeededIdSource::new(7);
        let a = NodeId::generate(&mut s1);
        let b = NodeId::generate(&mut s2);
        assert_eq!(a, b, "same seed → same id stream");
        assert_eq!(a.0.get_version_num(), 4, "well-formed UUIDv4");

        // A different seed diverges.
        let mut s3 = SeededIdSource::new(8);
        assert_ne!(a, NodeId::generate(&mut s3));
    }

    #[test]
    fn ids_serialize_as_bare_uuid_string() {
        let id = NodeId(Uuid::nil());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
