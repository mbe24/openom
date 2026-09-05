//! The chain keyring's **own** wire — hand-written `prost` messages the chain engine binds onto
//! `keyeo-chain`. Moved out of `openom-protocol` in OPE-300 so the chain crate owns its keyring shape
//! and depends on no openom proto crate (the same pattern `openom-keyring-api`'s `MembershipEnvelope`
//! uses). The field numbers/shapes are byte-identical to the former `openom.v1.Keyring` and sub-messages,
//! so semantics are unchanged.
//!
//! The DEK epochs and the recovery escrow's KEK wraps are NOT prost sub-messages: they carry keyeo's shared
//! key-material types (`keyeo_crypto::{Epoch, Wrap}`) as their canonical `codec` encoding inside `bytes`
//! fields, so both keyring engines share one key-material shape. The chain still owns the structural
//! envelope (`Keyring`/`Member`/`KeyringSignature`/`RecoveryKey` identity fields) as prost.

use keyeo_crypto::{codec, Epoch, Wrap};

/// The `Keyring.layout_version` this build reads and writes (data-format spec §4) — the keyring's own
/// version axis, independent of the envelope version. A keyring carrying a higher layout is opened
/// read-only rather than misread. Chain-owned (was `openom_protocol::KEYRING_LAYOUT_VERSION`).
pub const KEYRING_LAYOUT_VERSION: u32 = 1;

// Role values (the openom ladder; lower is stronger) the chain reasons on. Duplicated as tiny consts so
// the chain needs no `openom-roles` dep — they MUST match the proto `MemberRole` values.
/// The founder / owner role (the single strongest role).
pub const MEMBER_OWNER: i32 = 1;
/// The co-owner role (a signer, but not the founder).
pub const MEMBER_CO_OWNER: i32 = 2;

// Wrap-method discriminants (match the proto `WrapMethod`) the chain's wrap-completeness gate reads.
/// `WRAP_METHOD_X25519_HPKE`: an epoch DEK wrapped to a member's HPKE public key.
pub const WRAP_X25519_HPKE: i32 = 2;
/// `WRAP_METHOD_RRK_HPKE`: an epoch DEK wrapped to the founder's recovery-root public key.
pub const WRAP_RRK_HPKE: i32 = 4;

/// Per-tree key material AND governance: the DEK wrapped for each member across epochs and the signed
/// membership/role list — one signed, anti-rollback, hash-chained document. The authorized-signer set is
/// DERIVED from members (a member at CO_OWNER or stronger is a signer). Field numbers match the former
/// `openom.v1.Keyring` (reserved 4, 5, 8).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Keyring {
    /// Opaque tree id.
    #[prost(bytes = "vec", tag = "1")]
    pub tree_id: Vec<u8>,
    /// Key generations (rotation produces a new epoch), as the canonical encoding of
    /// `Vec<keyeo_crypto::Epoch<String>>` (`keyeo_crypto::codec`). The chain owns the wire envelope but the
    /// key material itself is keyeo's shared type — hashed as opaque bytes in the payload commitment (§doc)
    /// and decoded via [`Keyring::key_material`] for the structure gate + DEK access. Empty only pre-genesis.
    #[prost(bytes = "vec", tag = "2")]
    pub epochs: Vec<u8>,
    /// Monotonic anti-rollback counter, bumped on every revision.
    #[prost(uint32, tag = "3")]
    pub revision: u32,
    /// Keyring layout selector (analogous to `Envelope.version`).
    #[prost(uint32, tag = "6")]
    pub layout_version: u32,
    /// SHA-256 of the previous revision's canonical signing bytes; empty at genesis.
    #[prost(bytes = "vec", tag = "7")]
    pub prev_keyring_hash: Vec<u8>,
    /// The signed membership/role manifest.
    #[prost(message, repeated, tag = "9")]
    pub members: Vec<Member>,
    /// One or more Ed25519 signatures over the keyring's canonical signing bytes (any-of / 1-of-N in V1).
    #[prost(message, repeated, tag = "10")]
    pub signatures: Vec<KeyringSignature>,
    /// The founder-only recovery root key(s). V1: exactly one, the founder's.
    #[prost(message, repeated, tag = "11")]
    pub recovery_keys: Vec<RecoveryKey>,
    /// Governance rule kind (0 = founder-or-unanimity, 1 = founder-only, 2 = founder-or-threshold,
    /// 3 = threshold).
    #[prost(uint32, tag = "12")]
    pub governance_kind: u32,
    /// The `m` for the threshold kinds.
    #[prost(uint32, tag = "13")]
    pub governance_threshold: u32,
    /// The revision at which this tree was FIRST shared — a non-founder member first admitted; 0 = never
    /// shared. MONOTONIC: set once by `do_add_member`, carried forward onto every successor, NEVER cleared
    /// by removal. Once non-zero the tree is a multi-author tree, so every authoritative entry must be
    /// attributed (§B3 slice 2 — the reader requires signatures, the writer attaches them). Covered by the
    /// canonical signing bytes (see `doc.rs`'s payload commitment), so a keyless server can neither forge
    /// nor strip it.
    #[prost(uint32, tag = "14")]
    pub first_shared_revision: u32,
}

/// The signed role + key manifest for one member.
#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct Member {
    /// Account id (matches `KeyWrap.member_id`).
    #[prost(string, tag = "1")]
    pub member_id: String,
    /// Access/approval role (proto `MemberRole` value; carried as `i32` — the chain owns the role
    /// constants, [`MEMBER_OWNER`] / [`MEMBER_CO_OWNER`]).
    #[prost(int32, tag = "2")]
    pub role: i32,
    /// Ed25519 key that produces this member's `Header.author_signature`.
    #[prost(bytes = "vec", tag = "3")]
    pub author_public_key: Vec<u8>,
    /// The member's X25519 HPKE public key.
    #[prost(bytes = "vec", tag = "4")]
    pub hpke_public_key: Vec<u8>,
}

/// One signature over the keyring's canonical signing bytes.
#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct KeyringSignature {
    /// Which signer produced this — a hint only; verification is always against the trusted set.
    #[prost(bytes = "vec", tag = "1")]
    pub signer_public_key: Vec<u8>,
    /// Ed25519 signature over the keyring's canonical signing bytes.
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

/// The founder's cross-epoch recovery root key (an X25519 keypair) + the RVK.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoveryKey {
    /// X25519 public key. Every `KeyEpoch` carries one `WRAP_METHOD_RRK_HPKE` wrap of its DEK to this key.
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: Vec<u8>,
    /// The founder this recovery key belongs to.
    #[prost(string, tag = "2")]
    pub member_id: String,
    /// The recovery root private key wrapped under the founder's two credentials, as the canonical encoding
    /// of `Vec<keyeo_crypto::Wrap<String>>` (`keyeo_crypto::codec`). Decoded via [`RecoveryKey::escrow_wraps`].
    #[prost(bytes = "vec", tag = "3")]
    pub wraps: Vec<u8>,
    /// The Ed25519 Recovery Verification Key (RVK), HKDF-derived from the recovery-root secret. Empty on
    /// pre-RVK keyrings. Stays a first-class prost field (NOT inside the `wraps` blob): `reset_rvk` feeds it
    /// to the engine's recovery-authority via the trusted-path `KeyringAnchor::from_keyring`, which runs
    /// WITHOUT the structure gate — so a corrupt `wraps` blob must never be able to degrade the RVK to absent.
    #[prost(bytes = "vec", tag = "4")]
    pub recovery_verifying_key: Vec<u8>,
}

/// The maximum size of a stored key-material blob, checked BEFORE decode (a raw byte cap, the decode-side
/// analog of `MAX_MEMBERS`/`MAX_EPOCHS`): bounds the work a hostile keyring can impose before the count-based
/// caps in `structure` apply. Generous — a large real keyring is well under this.
pub const MAX_KEY_MATERIAL_BYTES: usize = 4 * 1024 * 1024;

impl Keyring {
    /// Decode the epoch list from its canonical bytes — the ONE fallible accessor for the chain's key
    /// material. Callers MUST propagate the error (never `unwrap_or_default`): an empty/defaulted fallback
    /// on a corrupt blob would silently drop epochs past the acceptance gate. The size cap runs before the
    /// postcard decode.
    pub fn key_material(&self) -> Result<Vec<Epoch<String>>, KeyMaterialError> {
        if self.epochs.len() > MAX_KEY_MATERIAL_BYTES {
            return Err(KeyMaterialError);
        }
        codec::decode_epochs(&self.epochs).map_err(|_| KeyMaterialError)
    }
}

impl RecoveryKey {
    /// Decode this recovery key's escrow KEK wraps from their canonical bytes. Same propagate-don't-default
    /// discipline as [`Keyring::key_material`]. Note the RVK ([`Self::recovery_verifying_key`]) is a separate
    /// prost field and is NEVER gated on this decode succeeding.
    pub fn escrow_wraps(&self) -> Result<Vec<Wrap<String>>, KeyMaterialError> {
        if self.wraps.len() > MAX_KEY_MATERIAL_BYTES {
            return Err(KeyMaterialError);
        }
        codec::decode_wraps(&self.wraps).map_err(|_| KeyMaterialError)
    }
}

/// A stored key-material blob (epochs or escrow wraps) was malformed, had trailing bytes, or exceeded
/// [`MAX_KEY_MATERIAL_BYTES`]. Opaque on purpose — every case is "this keyring's key material is unusable",
/// which the structure gate turns into a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMaterialError;
