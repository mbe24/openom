//! The keyring key-material records — a rewrap generation (`Epoch`) of per-recipient DEK wraps.
//!
//! An epoch is what a keyring produces whenever it rewraps its data key on a membership change: a fresh
//! DEK wrapped once per recipient. keyeo owns this shape so any keyring consumer builds on it; the DEK
//! material rides the consumer's own carrier (an op, a revision), which is what signs and positions it —
//! so an `Epoch` here is a payload, not a self-signed artifact.

use std::hash::Hash;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::ids::{GroupId, KeyId};
use crate::material::{EncappedKey, Nonce, WrappedDek, X25519PublicKey};
use crate::KdfParams;

/// The group-at-an-epoch binding context (the MLS `GroupContext` role): the two coordinates a DEK wrap is
/// bound to, so a wrap can't be transplanted across groups or epochs. The other two AAD fields come from
/// elsewhere — the recipient supplies the member id, the wrap its method. Borrows, so a rewrap over many
/// recipients builds each wrap against the same context with no clones.
#[derive(Clone, Copy, Debug)]
pub struct GroupContext<'a> {
    pub group_id: &'a GroupId,
    pub key_id: &'a KeyId,
}

/// A recipient's identity — what a wrap is addressed to (a member, the recovery root). Generic, so a
/// consumer chooses its own id type (a string did:key, a number, a custom key), because a keyring library
/// shouldn't dictate that. The bound is exactly what the records need: clone/order/hash for the set
/// operations over recipients, serde for replication, and a deterministic byte view for the AAD binding.
pub trait RecipientId: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned {
    /// The canonical identity bytes bound into the wrap AAD, so a wrap can't be transplanted to another
    /// recipient. Must be deterministic and injective across distinct ids. Kept explicit (rather than
    /// leaking a serialization format into the AAD) so the crypto binding is a deliberate choice.
    fn aad_bytes(&self) -> Vec<u8>;
}

impl RecipientId for String {
    fn aad_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// The KEK-derivation kind — a distinct discriminant per KEK source. It is BOTH an AAD input (so a
/// passphrase wrap can't be reinterpreted as a recovery-code wrap) AND a runtime lookup key (a consumer
/// finds "the passphrase wrap" vs "the recovery-code wrap" by it), so the two never collapse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KekKind {
    /// A KEK derived from the owner's passphrase.
    Passphrase,
    /// A KEK derived from the printed recovery code.
    RecoveryCode,
}

/// How a DEK wrap was sealed, carrying that method's public parameters (the sealed bytes are
/// [`Wrap::ciphertext`]). `MemberHpke` and `RrkHpke` are the same HPKE primitive to different recipient
/// classes but stay DISTINCT — the method is an AAD input, so collapsing them would erase an
/// AEAD-enforced separator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapMethod {
    /// HPKE to an active member's X25519 key.
    MemberHpke { encapped: EncappedKey, recipient_key: X25519PublicKey },
    /// HPKE to the recovery root key — the founder's cross-epoch access.
    RrkHpke { encapped: EncappedKey, recipient_key: X25519PublicKey },
    /// A symmetric wrap under an Argon2id-derived KEK (passphrase or recovery-code).
    Kek { kind: KekKind, kdf: KdfParams, nonce: Nonce },
}

impl WrapMethod {
    /// The pinned discriminants fed into the wrap AAD (and used as lookup keys). The four values mirror the
    /// format's wrap methods; keyeo owns them, so nothing here depends on an application enum. The wrap ops
    /// reference these when building the AAD (before a method value exists), keeping [`Self::tag`] the sole
    /// source of truth.
    pub const TAG_PASSPHRASE_KEK: i32 = 1;
    pub const TAG_MEMBER_HPKE: i32 = 2;
    pub const TAG_RECOVERY_KEK: i32 = 3;
    pub const TAG_RRK_HPKE: i32 = 4;

    /// The discriminant fed into the wrap AAD (and used as a lookup key).
    #[must_use]
    pub fn tag(&self) -> i32 {
        match self {
            WrapMethod::Kek { kind: KekKind::Passphrase, .. } => Self::TAG_PASSPHRASE_KEK,
            WrapMethod::MemberHpke { .. } => Self::TAG_MEMBER_HPKE,
            WrapMethod::Kek { kind: KekKind::RecoveryCode, .. } => Self::TAG_RECOVERY_KEK,
            WrapMethod::RrkHpke { .. } => Self::TAG_RRK_HPKE,
        }
    }
}

/// One DEK wrap: the recipient it is addressed to, how it was sealed, and the sealed 48-byte ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "Id: RecipientId")]
pub struct Wrap<Id: RecipientId> {
    pub recipient: Id,
    pub method: WrapMethod,
    pub ciphertext: WrappedDek,
}

/// A rewrap generation: a keyed DEK (`key_id` — also the per-epoch AAD salt, so it identifies the epoch),
/// a monotone `ordinal`, and the per-recipient wraps of that DEK. A payload — the consumer's carrier signs
/// and positions it, so it carries no parents/author/signature of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "Id: RecipientId")]
pub struct Epoch<Id: RecipientId> {
    /// The epoch DEK's identity — a fresh random salt, so it doubles as the per-epoch AAD binding.
    pub key_id: KeyId,
    /// A monotone generation counter (bumped on each rewrap).
    pub ordinal: u64,
    /// The DEK wrapped once per recipient.
    pub wraps: Vec<Wrap<Id>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_epoch() -> Epoch<String> {
        Epoch {
            key_id: KeyId::new(vec![1, 2, 3, 4]),
            ordinal: 7,
            wraps: vec![
                Wrap {
                    recipient: "alice".to_string(),
                    method: WrapMethod::MemberHpke {
                        encapped: EncappedKey::from_bytes([9u8; 32]),
                        recipient_key: X25519PublicKey::from_bytes([2u8; 32]),
                    },
                    ciphertext: WrappedDek::from_bytes([3u8; 48]),
                },
                Wrap {
                    recipient: "owner".to_string(),
                    method: WrapMethod::Kek {
                        kind: KekKind::Passphrase,
                        kdf: KdfParams { salt: vec![5, 6], memory_kib: 19_456, iterations: 2, parallelism: 1 },
                        nonce: Nonce::from_bytes([4u8; 24]),
                    },
                    ciphertext: WrappedDek::from_bytes([7u8; 48]),
                },
            ],
        }
    }

    #[test]
    fn epoch_round_trips_through_the_wire_format() {
        // postcard is the wire the records replicate under; this also exercises the hand-rolled 48-byte
        // `WrappedDek` serde via serialize_bytes/visit_bytes.
        let epoch = sample_epoch();
        let bytes = postcard::to_allocvec(&epoch).unwrap();
        let back: Epoch<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(epoch, back);
    }

    #[test]
    fn wrap_method_tags_are_the_four_distinct_pinned_values() {
        let hpke = WrapMethod::MemberHpke {
            encapped: EncappedKey::from_bytes([0u8; 32]),
            recipient_key: X25519PublicKey::from_bytes([0u8; 32]),
        };
        let rrk = WrapMethod::RrkHpke {
            encapped: EncappedKey::from_bytes([0u8; 32]),
            recipient_key: X25519PublicKey::from_bytes([0u8; 32]),
        };
        let kdf = KdfParams { salt: vec![], memory_kib: 1, iterations: 1, parallelism: 1 };
        let pass = WrapMethod::Kek { kind: KekKind::Passphrase, kdf: kdf.clone(), nonce: Nonce::from_bytes([0u8; 24]) };
        let rec = WrapMethod::Kek { kind: KekKind::RecoveryCode, kdf, nonce: Nonce::from_bytes([0u8; 24]) };
        // The four discriminants are exactly {1,2,3,4} — passphrase and recovery-code never collapse.
        assert_eq!(pass.tag(), 1);
        assert_eq!(hpke.tag(), 2);
        assert_eq!(rec.tag(), 3);
        assert_eq!(rrk.tag(), 4);
        let mut tags = [pass.tag(), hpke.tag(), rec.tag(), rrk.tag()];
        tags.sort_unstable();
        assert_eq!(tags, [1, 2, 3, 4]);
    }
}
