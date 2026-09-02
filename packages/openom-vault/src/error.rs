//! The vault layer's error type. These are the keyring / membership / anti-rollback failures the vault
//! flows RAISE — colocated here with the code that produces them, rather than in the lean sealer whose only
//! errors are the envelope/session ones ([`openom_sealer::SealerError`], wrapped via `#[from]` below).

use openom_crypto::CryptoError;
use openom_sealer::SealerError;

/// A keyring-vault failure: verifying/opening an untrusted keyring, membership administration, or the
/// anti-rollback floor. A crypto failure (`Crypto`) or a lean DEK-session failure (`Sealer`) that surfaces
/// through a vault flow is wrapped transparently.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// A DEK-session (envelope) error surfacing through a vault flow.
    #[error("sealer: {0}")]
    Sealer(#[from] SealerError),
    /// The keyring bytes wouldn't decode, are too large, or are structurally invalid.
    #[error("malformed keyring: {0}")]
    BadKeyring(String),
    /// A keyring's Argon2id `kdf_params` are outside the range this build will run — a hostile keyring
    /// could otherwise OOM/CPU-burn the client before any verification.
    #[error("keyring KDF params out of range")]
    BadKdfParams,
    /// No wrap in the keyring matches the expected `(member_id, wrap_method)`.
    #[error("keyring has no matching wrap")]
    MissingWrap,
    /// A member with this id is already in the keyring (add is not idempotent — update or remove first).
    #[error("member already present in the keyring")]
    MemberExists,
    /// No member with the given id is in the keyring (e.g. asked to remove a non-member).
    #[error("member not found in the keyring")]
    MemberNotFound,
    /// The owner/founder cannot be removed — they are the keyring's root of trust. Transfer ownership
    /// instead (a future flow).
    #[error("the owner cannot be removed")]
    CannotRemoveOwner,
    /// The caller isn't authorized for this administrative action — e.g. a member who isn't a co-owner
    /// trying to add/remove members, or a co-owner trying to change the signer set (founder-only).
    #[error("not authorized for this action")]
    NotAuthorized,
    /// The keyring is for a different tree than the caller expected (the caller supplies the trusted
    /// `tree_id`; it is never read from the untrusted keyring for the AEAD context).
    #[error("keyring is for a different tree")]
    TreeMismatch,
    /// The served keyring revision is below the client's watermark — a rollback/replay.
    #[error("keyring revision rolled back: floor {have}, served {got}")]
    RevisionRollback { have: u32, got: u32 },
    /// The served dag anchor is behind the client's watermark — a frontier op it names is absent, so
    /// history was rolled back (the dag analogue of [`Self::RevisionRollback`]; frontiers aren't scalars).
    #[error("dag anchor rolled back below watermark: {detail}")]
    WatermarkRollback { detail: String },
    /// The next revision would overflow `u32` (a poisoned/absurd served revision).
    #[error("keyring revision overflow")]
    RevisionOverflow,
    /// The opaque anti-rollback watermark floor handed to a lifecycle call wasn't a valid encoding for this
    /// engine. The floor is a client-local cursor, so this is local corruption, not an attack — but it's
    /// refused rather than silently dropped, since dropping the floor would drop rollback protection.
    #[error("malformed anti-rollback watermark")]
    MalformedWatermark,
}
