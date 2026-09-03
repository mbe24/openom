//! The chain keyring's **own** wire — hand-written `prost` messages the chain engine binds onto
//! `keyeo-linear`. Moved out of `openom-protocol` in OPE-300 so the chain crate owns its keyring shape
//! and depends on no openom proto crate (the same pattern `openom-keyring-api`'s `MembershipEnvelope`
//! uses). The field numbers/shapes are byte-identical to the former `openom.v1.Keyring` and sub-messages,
//! so semantics are unchanged.
//!
//! `KdfParams` is duplicated here (a tiny four-field message) so the chain doesn't pull in
//! `openom-protocol`; `openom-crypto` keeps ITS own proto `KdfParams` for the sealer/vault path. The two
//! are wire-identical and the vault marshals between them at its boundary.

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
    /// Key generations (rotation produces a new epoch).
    #[prost(message, repeated, tag = "2")]
    pub epochs: Vec<KeyEpoch>,
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
    /// The recovery root private key wrapped under the founder's two credentials.
    #[prost(message, repeated, tag = "3")]
    pub wraps: Vec<KeyWrap>,
    /// The Ed25519 Recovery Verification Key (RVK), HKDF-derived from the recovery-root secret. Empty on
    /// pre-RVK keyrings.
    #[prost(bytes = "vec", tag = "4")]
    pub recovery_verifying_key: Vec<u8>,
}

/// One key generation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyEpoch {
    /// Matches `Header.key_id`.
    #[prost(bytes = "vec", tag = "1")]
    pub key_id: Vec<u8>,
    /// Generation number, from 0.
    #[prost(uint32, tag = "2")]
    pub epoch: u32,
    /// The DEK wrapped once per member.
    #[prost(message, repeated, tag = "3")]
    pub wraps: Vec<KeyWrap>,
}

/// The DEK sealed for one member.
#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct KeyWrap {
    /// Member account id.
    #[prost(string, tag = "1")]
    pub member_id: String,
    /// How the DEK was wrapped (proto `WrapMethod` value; carried as `i32`).
    #[prost(int32, tag = "2")]
    pub wrap_method: i32,
    /// AEAD nonce for the wrap.
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: Vec<u8>,
    /// AEAD(DEK).
    #[prost(bytes = "vec", tag = "4")]
    pub wrapped_dek: Vec<u8>,
    /// Set for the Argon2id wrap methods.
    #[prost(message, optional, tag = "5")]
    pub kdf_params: Option<KdfParams>,
    /// Set for `WRAP_METHOD_X25519_HPKE`: the sender's one-time public key.
    #[prost(bytes = "vec", tag = "6")]
    pub ephemeral_public_key: Vec<u8>,
    /// Set for the HPKE wrap methods: the RECIPIENT's public key (an UNAUTHENTICATED coverage hint).
    #[prost(bytes = "vec", tag = "7")]
    pub recipient_public_key: Vec<u8>,
}

/// Argon2id parameters — the chain's own copy (wire-identical to `openom_crypto`'s proto `KdfParams`), so
/// the chain crate needs no `openom-protocol` dep.
#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct KdfParams {
    /// Random per-member salt.
    #[prost(bytes = "vec", tag = "1")]
    pub salt: Vec<u8>,
    /// Memory cost, KiB.
    #[prost(uint32, tag = "2")]
    pub memory_kib: u32,
    /// Time cost (passes).
    #[prost(uint32, tag = "3")]
    pub iterations: u32,
    /// Parallelism (lanes).
    #[prost(uint32, tag = "4")]
    pub parallelism: u32,
}
