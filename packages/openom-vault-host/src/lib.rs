#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openom_crypto::{Passphrase, RecoveryCode, SALT_LEN};
use openom_keyring::{verify_reset, verify_transition, ChainError, KeyringAnchor, VerifyingKey};
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_protocol::v1::{Compression, Format, KdfParams, Keyring, MemberRole};
use openom_protocol::Message;
use openom_sealer::vault;
use openom_sealer::{EntryKind, SealContext, Sealer, SealerError, SealerSet};
use serde::Serialize;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// ---------------------------------------------------------------- errors

/// A stable error code the JS side switches on (never the message text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultErrorCode {
    /// AEAD open failed — wrong passphrase / wrong recovery code / tampered, deliberately
    /// indistinguishable (the crypto layer keeps these opaque).
    CryptoOpen,
    /// Served keyring revision is below the client's watermark: a rollback/replay.
    RevisionRollback,
    /// Served dag anchor is behind the client's watermark — a frontier op it named is absent, so history
    /// was rolled back (the dag analogue of `RevisionRollback`; frontiers aren't scalar revisions).
    WatermarkRollback,
    /// The next revision would overflow u32 (a poisoned served revision).
    RevisionOverflow,
    /// The opaque anti-rollback watermark handed to a lifecycle call wasn't a valid encoding for this
    /// engine — client-local corruption, refused rather than silently dropped.
    MalformedWatermark,
    /// The keyring is for a different tree than the caller operates on.
    TreeMismatch,
    /// The keyring bytes don't decode / are structurally invalid.
    BadKeyring,
    /// A network-served keyring run rewrites accepted history — its `prev_keyring_hash` doesn't
    /// chain onto the anchor (a fork). An attack, not availability.
    KeyringFork,
    /// A network-served keyring run isn't a contiguous advance from the anchor — a withheld hop
    /// (gap) or an old revision (rollback). Availability or replay.
    KeyringNonSequential,
    /// A network-served keyring carries an unendorsed change — an ordinary revision by a
    /// non-signer, or a signer-set change without the founder / prior-set unanimity. Tampering.
    KeyringUnendorsed,
    /// A network-served keyring is malformed as a successor — bad structure, an incomplete wrap
    /// set (silent lock-out), a too-new layout, or a failed bootstrap.
    KeyringMalformed,
    /// The keyring's Argon2id params are outside the runnable window.
    BadKdfParams,
    /// No wrap in the keyring matches the expected (member, method).
    MissingWrap,
    /// Sharing: a member with this id is already in the keyring.
    MemberExists,
    /// Sharing: no member with this id is in the keyring.
    MemberNotFound,
    /// Sharing: the owner/founder can't be removed (transfer ownership instead).
    CannotRemoveOwner,
    /// Sharing: the caller isn't authorized for this administrative action.
    NotAuthorized,
    /// No keyring is stored for this tree yet (provision first).
    NoKeyring,
    /// An envelope wouldn't decode / had no header.
    BadEnvelope,
    /// An envelope is out of this sealer's (tree_id, key_id) scope.
    WrongScope,
    /// The envelope's epoch isn't one the caller holds a key for (e.g. content from before
    /// a member joined) — an access boundary, not a tampered/misrouted blob.
    EpochUnreachable,
    /// An envelope isn't the expected kind.
    WrongKind,
    /// A malformed request field (unknown kind/format/compression string).
    BadRequest,
    /// No live sealer for this id — never provisioned, or locked/cleared.
    UnknownSealer,
    /// The keyring/watermark store failed.
    Storage,
    /// An unexpected internal failure (e.g. the CSPRNG).
    Internal,
    /// Reserved for the future biometric path: the enrolled wrap is stale (epoch rotated).
    BiometricInvalidated,
    /// Reserved: biometric unlock isn't available on this platform/build.
    BiometricUnavailable,
}

/// The error the host returns across the invoke boundary.
#[derive(Debug, Clone, Serialize)]
pub struct VaultError {
    pub code: VaultErrorCode,
    pub message: String,
}

impl VaultError {
    pub fn new(code: VaultErrorCode, message: impl Into<String>) -> Self {
        VaultError {
            code,
            message: message.into(),
        }
    }
    fn storage(e: impl std::fmt::Display) -> Self {
        VaultError::new(VaultErrorCode::Storage, e.to_string())
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for VaultError {}

impl From<SealerError> for VaultError {
    fn from(e: SealerError) -> Self {
        use SealerError as E;
        use VaultErrorCode as C;
        let code = match &e {
            E::Crypto(_) => C::CryptoOpen,
            E::Decode(_) | E::NoHeader => C::BadEnvelope,
            E::WrongScope => C::WrongScope,
            E::EpochUnreachable => C::EpochUnreachable,
            E::WrongKind => C::WrongKind,
            E::BadKeyring(_) => C::BadKeyring,
            E::BadKdfParams => C::BadKdfParams,
            E::MissingWrap => C::MissingWrap,
            E::MemberExists => C::MemberExists,
            E::MemberNotFound => C::MemberNotFound,
            E::CannotRemoveOwner => C::CannotRemoveOwner,
            E::NotAuthorized => C::NotAuthorized,
            E::TreeMismatch => C::TreeMismatch,
            E::RevisionRollback { .. } => C::RevisionRollback,
            E::WatermarkRollback { .. } => C::WatermarkRollback,
            E::RevisionOverflow => C::RevisionOverflow,
            E::MalformedWatermark => C::MalformedWatermark,
        };
        VaultError::new(code, e.to_string())
    }
}

type Result<T> = std::result::Result<T, VaultError>;

// ---------------------------------------------------------------- storage seam

/// Persistence for the keyring (a wrapped DEK — not secret, needs durability) and the
/// keyring-revision watermark (anti-rollback state). Injected so the host is testable with an
/// in-memory fake and, on Tauri, backs onto durable SQLite. The snapshot-hash replay window
/// (a separate, sync-layer concern) is intentionally NOT here — the vault flows only need the
/// keyring-revision floor.
pub trait VaultStore: Send + Sync {
    fn load_keyring(&self, tree_key: &str) -> std::result::Result<Option<Vec<u8>>, String>;
    /// The highest keyring revision verified for this tree (0 if none).
    fn keyring_watermark(&self, tree_key: &str) -> std::result::Result<u32, String>;
    /// Record a freshly-verified revision without changing the keyring (the unlock path, which
    /// only re-asserts the floor). Monotonic: never lowers the stored floor.
    fn observe_keyring_revision(
        &self,
        tree_key: &str,
        revision: u32,
    ) -> std::result::Result<(), String>;
    /// **Atomically** persist a newly-accepted keyring and raise the revision floor to
    /// `revision`, in ONE durable transaction — so a crash can never leave the stored keyring
    /// and its floor disagreeing. `revision` is the new keyring's revision; the floor is raised
    /// monotonically (a lower value never lowers it).
    fn commit_keyring(
        &self,
        tree_key: &str,
        bytes: &[u8],
        revision: u32,
    ) -> std::result::Result<(), String>;
}

// ---------------------------------------------------------------- outputs (wire shapes)

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provisioned {
    pub sealer_id: String,
    pub revision: u32,
    pub recovery_code: String,
    /// The owner's stable author id — a `did:key` over their public identity key (the claim
    /// `createdBy`). Distinct from the per-context sync replica id.
    pub did_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unlocked {
    pub sealer_id: String,
    pub revision: u32,
    /// The member's stable author id — a `did:key` over their public identity key (the claim
    /// `createdBy`), stable across tabs/reloads.
    pub did_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recovered {
    pub sealer_id: String,
    pub revision: u32,
    pub recovery_code: String,
    /// The NEW owner's stable author id — recovery mints a fresh identity, so this differs from the
    /// pre-recovery did:key.
    pub did_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rekeyed {
    pub revision: u32,
    pub recovery_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sealed {
    pub envelope: Vec<u8>,
    pub ciphertext_hash: Vec<u8>,
}

/// What [`VaultHost::provision_member`] returns: the public keys a joining member shares
/// out-of-band with a tree owner, and the opaque KDF params they persist and pass back at
/// unlock (an encoded `KdfParams` — the client treats it as a blob).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberProvisioned {
    pub kdf_params: Vec<u8>,
    pub author_public: Vec<u8>,
    pub hpke_public: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberAdded {
    pub revision: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRemoved {
    pub sealer_id: String,
    pub revision: u32,
}

/// Result of a co-owner promotion / demotion — a signing-authority change, no new sealer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoOwnerChanged {
    pub revision: u32,
}

/// Result of accepting a keyring run pulled from the network: the revision now anchored locally.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedKeyring {
    pub revision: u32,
}

// ---------------------------------------------------------------- registry

/// The live sealer sessions, keyed by an opaque handle. `Arc` so `lock`/`clear` can drop the
/// map's reference while an in-flight `seal_entry` keeps its own — the running seal completes,
/// then the DEK dies when the last `Arc` drops (drain-then-free). The crypto NEVER runs while
/// the map lock is held (we clone the `Arc` out first), so the lock is never poisoned by a seal.
#[derive(Default)]
struct Registry {
    map: Mutex<HashMap<String, Arc<SealerSet>>>,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<SealerSet>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn insert(&self, id: String, sealer: SealerSet) {
        self.lock().insert(id, Arc::new(sealer));
    }
    fn get(&self, id: &str) -> Option<Arc<SealerSet>> {
        self.lock().get(id).cloned()
    }
    fn remove(&self, id: &str) {
        self.lock().remove(id);
    }
    fn clear(&self) {
        self.lock().clear();
    }
}

// ---------------------------------------------------------------- entropy seam

/// Source of the host's 128-bit random ids — the per-unlock replica id and the sealer-registry
/// handle. [`OsEntropy`] (the OS/browser CSPRNG) is the source for real data in dev AND prod; tests
/// inject a seeded `SeededEntropy` (test-only) for determinism. Entropy is a security property, not a
/// dev/prod toggle — mirrors `openom_model::id::IdSource`. Behind `&self` (a CSPRNG is stateless; a seeded impl uses
/// interior mutability), so the host's methods stay `&self`.
pub trait HostEntropy: Send + Sync {
    /// 128 fresh random bits. Errs only if the OS/browser entropy source fails.
    fn random_id(&self) -> Result<[u8; SALT_LEN]>;
}

/// The only entropy source for real data (dev + prod): the OS/browser CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl HostEntropy for OsEntropy {
    fn random_id(&self) -> Result<[u8; SALT_LEN]> {
        Ok(openom_crypto::generate_salt().map_err(SealerError::from)?)
    }
}

/// A **deterministic** entropy source for TESTS ONLY — never for real data (its output is not
/// cryptographic). A xorshift64\* stream, so the whole [`VaultHost`] state machine (revision
/// monotonicity, replica-id freshness, chain self-check, rollback refusal) can be exercised
/// reproducibly. Interior-mutable so it satisfies `&self` + `Send + Sync`.
///
/// Gated behind `#[cfg(test)]` — not merely documented as test-only — so a production dependency graph
/// physically cannot name it (replica-id freshness is the anti-fork property, so a seeded source
/// reaching real data would be a security bug, not just a mistake). Promote to a non-default
/// `test-entropy` feature only if a cross-crate test ever needs it.
#[cfg(test)]
#[derive(Debug)]
pub struct SeededEntropy {
    state: Mutex<u64>,
}

#[cfg(test)]
impl SeededEntropy {
    /// Seed the stream (a zero seed is remapped so the generator never sticks at 0).
    pub fn new(seed: u64) -> Self {
        SeededEntropy {
            state: Mutex::new(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed }),
        }
    }
}

#[cfg(test)]
impl HostEntropy for SeededEntropy {
    fn random_id(&self) -> Result<[u8; SALT_LEN]> {
        let mut s = self.state.lock().expect("seeded-entropy lock");
        let mut out = [0u8; SALT_LEN];
        for chunk in out.chunks_mut(8) {
            let mut x = *s;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *s = x;
            let bytes = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- the host

pub struct VaultHost<S: VaultStore, E: HostEntropy = OsEntropy> {
    store: S,
    registry: Registry,
    entropy: E,
}

impl<S: VaultStore> VaultHost<S, OsEntropy> {
    /// A host for real data: replica ids + sealer handles come from the OS/browser CSPRNG.
    pub fn new(store: S) -> Self {
        Self::with_entropy(store, OsEntropy)
    }
}

impl<S: VaultStore, E: HostEntropy> VaultHost<S, E> {
    /// A host with an injected entropy source — tests pass a seeded `SeededEntropy` (test-only) for a
    /// deterministic, replayable state machine; real callers use [`new`](VaultHost::new).
    pub fn with_entropy(store: S, entropy: E) -> Self {
        VaultHost {
            store,
            registry: Registry::default(),
            entropy,
        }
    }

    /// Is a keyring stored for this tree? (The gate uses this to choose unlock vs welcome.)
    pub fn has_keyring(&self, tree_key: &str) -> Result<bool> {
        Ok(self
            .store
            .load_keyring(tree_key)
            .map_err(VaultError::storage)?
            .is_some())
    }

    /// Create a brand-new encrypted tree: fresh DEK, wrapped under the passphrase + a fresh
    /// recovery code. Persists the keyring, watermarks revision 1, and returns a live sealer.
    pub fn provision(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        passphrase: String,
        member_id: &str,
    ) -> Result<Provisioned> {
        let replica = self.fresh_replica()?;
        let p = vault::provision(
            &Passphrase::new(passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(member_id),
            &ReplicaId::new(replica),
        )?;
        let revision = self.commit_reset(tree_key, &p.keyring)?;
        let id = self.register(p.sealer)?;
        Ok(Provisioned {
            sealer_id: id,
            revision,
            recovery_code: p.recovery_code.into_string(),
            did_key: p.did_key.into_string(),
        })
    }

    /// Open the stored keyring with a passphrase. Mirrors the worker's refuse-before-expose:
    /// the built sealer is DROPPED (its DEK zeroized) before it is ever registered if the
    /// served revision is below the watermark — a rollback caught before the key is usable.
    pub fn unlock(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        passphrase: String,
        member_id: &str,
    ) -> Result<Unlocked> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let replica = self.fresh_replica()?;
        let u = vault::unlock(
            &keyring,
            &Passphrase::new(passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(member_id),
            &ReplicaId::new(replica),
        )?;
        if u.revision < floor {
            // `u.sealer` drops here — Key32 is Zeroizing, so the DEK is scrubbed — before it is
            // ever registered or used.
            return Err(VaultError::new(
                VaultErrorCode::RevisionRollback,
                format!(
                    "keyring revision rolled back: floor {floor}, served {}",
                    u.revision
                ),
            ));
        }
        self.store
            .observe_keyring_revision(tree_key, u.revision)
            .map_err(VaultError::storage)?;
        let id = self.register(u.sealer)?;
        Ok(Unlocked {
            sealer_id: id,
            revision: u.revision,
            did_key: u.did_key.into_string(),
        })
    }

    /// Recover with the recovery code, re-provisioning under a new passphrase. The stored
    /// watermark is the rollback floor; a fresh recovery code is issued.
    pub fn recover(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        recovery_code: String,
        new_passphrase: String,
        member_id: &str,
    ) -> Result<Recovered> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let replica = self.fresh_replica()?;
        let r = vault::recover(
            &keyring,
            &RecoveryCode::new(recovery_code),
            &Passphrase::new(new_passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(member_id),
            &ReplicaId::new(replica),
            floor,
        )?;
        // Recovery installs a fresh founder identity with no endorsement from the old chain —
        // a deliberate anchor reset (the §6 owner-succession boundary), not a transition.
        let revision = self.commit_reset(tree_key, &r.keyring)?;
        let id = self.register(r.sealer)?;
        Ok(Recovered {
            sealer_id: id,
            revision,
            recovery_code: r.recovery_code.into_string(),
            did_key: r.did_key.into_string(),
        })
    }

    /// Change the passphrase: re-wrap the same DEK under a new passphrase, rotate the recovery
    /// code, bump the revision. No new sealer — the running session keeps working.
    pub fn change_passphrase(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        old_passphrase: String,
        new_passphrase: String,
        member_id: &str,
    ) -> Result<Rekeyed> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let re = vault::change_passphrase(
            &keyring,
            &Passphrase::new(old_passphrase.into_bytes()),
            &Passphrase::new(new_passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(member_id),
            floor,
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &re.keyring)?;
        Ok(Rekeyed {
            revision,
            recovery_code: re.recovery_code.into_string(),
        })
    }

    /// Provision a member identity from a passphrase (stateless — no tree touched): returns
    /// the public keys to share OOB with a tree owner and the opaque KDF params the member
    /// persists and passes back at unlock.
    pub fn provision_member(&self, passphrase: String) -> Result<MemberProvisioned> {
        let m = vault::provision_member(&Passphrase::new(passphrase.into_bytes()))?;
        Ok(MemberProvisioned {
            kdf_params: m.kdf_params.encode_to_vec(),
            author_public: m.author_public,
            hpke_public: m.hpke_public,
        })
    }

    /// Add a member to a shared tree (owner action): HPKE-wrap the DEK to their public key,
    /// record them in the signed member list, persist + watermark the new keyring. The
    /// owner's live sealer is unaffected (no re-key). The member's public keys MUST have
    /// been verified out-of-band before calling.
    #[allow(clippy::too_many_arguments)]
    pub fn add_member(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        owner_passphrase: String,
        owner_member_id: &str,
        new_member_id: &str,
        role: &str,
        member_hpke_public: &[u8],
        member_author_public: &[u8],
    ) -> Result<MemberAdded> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let added = vault::add_member(
            &keyring,
            &Passphrase::new(owner_passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(owner_member_id),
            floor,
            &MemberId::new(new_member_id),
            parse_member_role(role)?,
            member_hpke_public,
            member_author_public,
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &added.keyring)?;
        Ok(MemberAdded { revision })
    }

    /// Unlock a shared tree AS A MEMBER: verify against the caller's pinned signer keys
    /// (from out-of-band verification, not the document's hints), HPKE-unwrap with the
    /// member's passphrase, and register a sealer. `member_kdf_params` is the opaque blob
    /// [`provision_member`] returned.
    pub fn unlock_as_member(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        passphrase: String,
        member_kdf_params: &[u8],
        member_id: &str,
        trusted_signers: Vec<Vec<u8>>,
    ) -> Result<Unlocked> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let kdf = KdfParams::decode(member_kdf_params).map_err(|e| {
            VaultError::new(VaultErrorCode::BadRequest, format!("bad kdf params: {e}"))
        })?;
        let trusted = parse_trusted_signers(&trusted_signers)?;
        let replica = self.fresh_replica()?;
        let u = vault::unlock_as_member(
            &keyring,
            &Passphrase::new(passphrase.into_bytes()),
            &kdf,
            &TreeId::new(tree_id),
            &MemberId::new(member_id),
            &trusted,
            &ReplicaId::new(replica),
            floor,
        )?;
        self.store
            .observe_keyring_revision(tree_key, u.revision)
            .map_err(VaultError::storage)?;
        let id = self.register(u.sealer)?;
        Ok(Unlocked {
            sealer_id: id,
            revision: u.revision,
            did_key: u.did_key.into_string(),
        })
    }

    /// Remove a member (owner action) with forward-secure re-key: a fresh DEK under a new
    /// epoch wrapped only for those remaining, a rotated recovery code, the removed member
    /// dropped from the member list and signer set. Registers a NEW sealer scoped to the new
    /// epoch — the caller re-seals the tree with it and drops its old sealer handle.
    pub fn remove_member(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        owner_passphrase: String,
        owner_member_id: &str,
        remove_member_id: &str,
    ) -> Result<MemberRemoved> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let replica = self.fresh_replica()?;
        let r = vault::remove_member(
            &keyring,
            &Passphrase::new(owner_passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(owner_member_id),
            floor,
            &MemberId::new(remove_member_id),
            &ReplicaId::new(replica),
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &r.keyring)?;
        let id = self.register(r.sealer)?;
        Ok(MemberRemoved {
            sealer_id: id,
            revision,
        })
    }

    /// Add a member **as a co-owner** (any-of): reaches keys via the co-owner's own wraps,
    /// verifies against their pinned signer set, signs with their identity.
    #[allow(clippy::too_many_arguments)]
    pub fn add_member_as_co_owner(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        passphrase: String,
        co_owner_kdf_params: &[u8],
        co_owner_member_id: &str,
        trusted_signers: Vec<Vec<u8>>,
        new_member_id: &str,
        role: &str,
        member_hpke_public: &[u8],
        member_author_public: &[u8],
    ) -> Result<MemberAdded> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let kdf = KdfParams::decode(co_owner_kdf_params).map_err(|e| {
            VaultError::new(VaultErrorCode::BadRequest, format!("bad kdf params: {e}"))
        })?;
        let trusted = parse_trusted_signers(&trusted_signers)?;
        let added = vault::add_member_as_co_owner(
            &keyring,
            &Passphrase::new(passphrase.into_bytes()),
            &kdf,
            &TreeId::new(tree_id),
            &MemberId::new(co_owner_member_id),
            &trusted,
            floor,
            &MemberId::new(new_member_id),
            parse_member_role(role)?,
            member_hpke_public,
            member_author_public,
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &added.keyring)?;
        Ok(MemberAdded { revision })
    }

    /// Remove an ordinary member **as a co-owner** (any-of): re-keys under the new epoch,
    /// signs with the co-owner's identity, and registers a new-epoch sealer.
    #[allow(clippy::too_many_arguments)]
    pub fn remove_member_as_co_owner(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        passphrase: String,
        co_owner_kdf_params: &[u8],
        co_owner_member_id: &str,
        trusted_signers: Vec<Vec<u8>>,
        remove_member_id: &str,
    ) -> Result<MemberRemoved> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let kdf = KdfParams::decode(co_owner_kdf_params).map_err(|e| {
            VaultError::new(VaultErrorCode::BadRequest, format!("bad kdf params: {e}"))
        })?;
        let trusted = parse_trusted_signers(&trusted_signers)?;
        let replica = self.fresh_replica()?;
        let r = vault::remove_member_as_co_owner(
            &keyring,
            &Passphrase::new(passphrase.into_bytes()),
            &kdf,
            &TreeId::new(tree_id),
            &MemberId::new(co_owner_member_id),
            &trusted,
            floor,
            &MemberId::new(remove_member_id),
            &ReplicaId::new(replica),
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &r.keyring)?;
        let id = self.register(r.sealer)?;
        Ok(MemberRemoved {
            sealer_id: id,
            revision,
        })
    }

    /// Promote an existing member to co-owner (founder action). Persists + watermarks the
    /// new keyring; no sealer changes (signing authority, not keys).
    pub fn add_co_owner(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        founder_passphrase: String,
        founder_member_id: &str,
        target_member_id: &str,
    ) -> Result<CoOwnerChanged> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let r = vault::add_co_owner(
            &keyring,
            &Passphrase::new(founder_passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(founder_member_id),
            floor,
            &MemberId::new(target_member_id),
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &r.keyring)?;
        Ok(CoOwnerChanged { revision })
    }

    /// Demote a co-owner to an ordinary role (founder action). Revokes signing authority,
    /// not read access — use remove_member to fully revoke. `new_role` = admin/editor/viewer.
    pub fn remove_co_owner(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        founder_passphrase: String,
        founder_member_id: &str,
        target_member_id: &str,
        new_role: &str,
    ) -> Result<CoOwnerChanged> {
        let keyring = self.require_keyring(tree_key)?;
        let floor = self
            .store
            .keyring_watermark(tree_key)
            .map_err(VaultError::storage)?;
        let r = vault::remove_co_owner(
            &keyring,
            &Passphrase::new(founder_passphrase.into_bytes()),
            &TreeId::new(tree_id),
            &MemberId::new(founder_member_id),
            floor,
            &MemberId::new(target_member_id),
            parse_member_role(new_role)?,
        )?;
        let revision = self.commit_transition(tree_key, &keyring, &r.keyring)?;
        Ok(CoOwnerChanged { revision })
    }

    /// Accept a keyring run pulled from the **untrusted network** — the read-side of the
    /// chain-walk, and its primary purpose. `hops` are the encoded keyring revisions after the
    /// locally-anchored one, in ascending order with no gaps (revision N+1, N+2, …). Each is
    /// validated as a legitimate successor of the last (`verify_walk`) against the locally
    /// stored keyring as the anchor — a fork, rollback, withheld hop, rogue-signer injection, or
    /// unendorsed set change is refused and NOTHING is persisted. On success the head keyring is
    /// stored and the revision floor advances, atomically.
    ///
    /// This updates keyring state only; it does not touch live sealers. A caller that needs to
    /// read content under a newly-rotated epoch re-unlocks. A first-sight member (no local
    /// anchor) bootstraps out-of-band first (a separate path); here an anchor must already exist.
    pub fn accept_remote_keyring(
        &self,
        tree_key: &str,
        tree_id: &[u8],
        hops: Vec<Vec<u8>>,
    ) -> Result<AcceptedKeyring> {
        let anchor_bytes = self.require_keyring(tree_key)?;
        let anchor_keyring = decode_keyring(&anchor_bytes)?;
        if anchor_keyring.tree_id != tree_id {
            return Err(VaultError::new(
                VaultErrorCode::TreeMismatch,
                "anchor keyring is for a different tree",
            ));
        }
        // An empty run is "already up to date" — a no-op at the current revision.
        if hops.is_empty() {
            return Ok(AcceptedKeyring {
                revision: anchor_keyring.revision,
            });
        }
        let decoded: Vec<Keyring> = hops
            .iter()
            .map(|b| {
                Keyring::decode(b.as_slice()).map_err(|e| {
                    VaultError::new(
                        VaultErrorCode::BadKeyring,
                        format!("served keyring failed to decode: {e}"),
                    )
                })
            })
            .collect::<Result<_>>()?;
        let new_anchor =
            openom_keyring::verify_walk(&KeyringAnchor::from_keyring(&anchor_keyring), &decoded)
                .map_err(remote_chain_err)?;
        // Persist the validated head (the last hop) + advance the floor, atomically.
        let head = hops.last().expect("non-empty run");
        self.store
            .commit_keyring(tree_key, head, new_anchor.revision)
            .map_err(VaultError::storage)?;
        Ok(AcceptedKeyring {
            revision: new_anchor.revision,
        })
    }

    /// A local-development sealer under the reserved dev key (the demo path). Real ciphertext,
    /// well-known key — no keyring, no unlock.
    pub fn dev(&self, tree_id: &[u8]) -> Result<Unlocked> {
        let replica = self.fresh_replica()?;
        let id = self.register(SealerSet::single(Sealer::dev(
            TreeId::new(tree_id),
            ReplicaId::new(replica),
        )))?;
        Ok(Unlocked {
            sealer_id: id,
            revision: 0,
            did_key: String::new(), // dev sealer: no vault identity
        })
    }

    /// Seal one entry with the caller-supplied chain state, on the sealer behind `sealer_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_entry(
        &self,
        sealer_id: &str,
        kind: &str,
        format: &str,
        compression: &str,
        replica_counter: u64,
        prev_ciphertext_hash: Vec<u8>,
        covers_through_seq: u64,
        blob_id: Vec<u8>,
        plaintext: &[u8],
    ) -> Result<Sealed> {
        let sealer = self.sealer(sealer_id)?;
        let ctx = SealContext {
            kind: parse_kind(kind)?,
            format: parse_format(format)?,
            compression: parse_compression(compression)?,
            replica_counter,
            prev_ciphertext_hash,
            covers_through_seq,
            blob_id,
        };
        let out = sealer.seal_entry(&ctx, plaintext)?;
        Ok(Sealed {
            envelope: out.envelope,
            ciphertext_hash: out.ciphertext_hash,
        })
    }

    /// Open one envelope on the sealer behind `sealer_id`, verifying scope + kind.
    pub fn open_entry(&self, sealer_id: &str, kind: &str, envelope: &[u8]) -> Result<Vec<u8>> {
        let sealer = self.sealer(sealer_id)?;
        Ok(sealer.open_entry(parse_kind(kind)?, envelope)?)
    }

    /// Free a sealer (idempotent). The DEK dies when the last `Arc` drops.
    pub fn lock(&self, sealer_id: &str) {
        self.registry.remove(sealer_id);
    }

    /// Free ALL sealers — the mobile background-lock / window-teardown hook.
    pub fn clear(&self) {
        self.registry.clear();
    }

    // --- internals ---

    fn require_keyring(&self, tree_key: &str) -> Result<Vec<u8>> {
        self.store
            .load_keyring(tree_key)
            .map_err(VaultError::storage)?
            .ok_or_else(|| {
                VaultError::new(
                    VaultErrorCode::NoKeyring,
                    format!("no keyring for tree {tree_key}"),
                )
            })
    }

    /// Writer self-check + atomic persist for a flow that advanced the chain: the keyring the
    /// flow produced MUST validate as a legitimate successor of `prior_bytes` under the same
    /// chain-walk a remote client would apply (`verify_transition`). A failure is OUR bug, not
    /// the user's — we refuse to persist a keyring our own verifier would later reject, and
    /// surface it as Internal. On success the keyring + floor advance in one store transaction.
    fn commit_transition(
        &self,
        tree_key: &str,
        prior_bytes: &[u8],
        produced_bytes: &[u8],
    ) -> Result<u32> {
        let prior = decode_keyring(prior_bytes)?;
        let produced = decode_keyring(produced_bytes)?;
        let new_anchor = verify_transition(&KeyringAnchor::from_keyring(&prior), &produced)
            .map_err(self_check_failed)?;
        self.store
            .commit_keyring(tree_key, produced_bytes, new_anchor.revision)
            .map_err(VaultError::storage)?;
        Ok(new_anchor.revision)
    }

    /// Writer self-check + atomic persist for a flow that establishes a **new anchor** — a
    /// genesis (provision) or a recovery reset, whose new founder identity deliberately carries
    /// no endorsement from the old chain (`verify_reset`, not `verify_transition`). Same
    /// refuse-our-own-bug discipline as [`commit_transition`].
    fn commit_reset(&self, tree_key: &str, produced_bytes: &[u8]) -> Result<u32> {
        let produced = decode_keyring(produced_bytes)?;
        // Writer self-check: structural soundness + self-signature of our OWN output (refuse-our-own-bug).
        // The RVK continuity gate (candidate rvk == prior rvk) is a READER-side defense against a hostile
        // server swapping the reset — not something the writer enforces against itself — so `None` here.
        let new_anchor = verify_reset(None, &produced).map_err(self_check_failed)?;
        self.store
            .commit_keyring(tree_key, produced_bytes, new_anchor.revision)
            .map_err(VaultError::storage)?;
        Ok(new_anchor.revision)
    }

    fn sealer(&self, id: &str) -> Result<Arc<SealerSet>> {
        self.registry.get(id).ok_or_else(|| {
            VaultError::new(VaultErrorCode::UnknownSealer, "unknown or locked sealer")
        })
    }

    fn register(&self, sealer: SealerSet) -> Result<String> {
        // 128 random bits, hex. Same trust domain as the web worker's sequential ids (any caller
        // able to invoke can call provision itself), just without a shared counter.
        let id = hex(&self.entropy.random_id()?);
        self.registry.insert(id.clone(), sealer);
        Ok(id)
    }

    /// A fresh replica id per unlock, from the injected entropy source. Persisting it would let
    /// lock→re-unlock reuse `(replica_id, counter=0)` and fork the chain — so it is minted here,
    /// never stored.
    fn fresh_replica(&self) -> Result<Vec<u8>> {
        Ok(self.entropy.random_id()?.to_vec())
    }
}

// ---------------------------------------------------------------- helpers

/// Decode a keyring we ourselves produced or previously stored. A failure is an internal
/// invariant break (our bytes should always decode), never a user-facing error.
fn decode_keyring(bytes: &[u8]) -> Result<Keyring> {
    Keyring::decode(bytes).map_err(|e| {
        VaultError::new(
            VaultErrorCode::Internal,
            format!("keyring failed to decode: {e}"),
        )
    })
}

/// A flow produced a keyring its own chain-walk rejects — a construction bug in this crate,
/// caught before persistence. Deliberately Internal (with the ChainError for the log), never a
/// matchable user-facing code: the fix is our code, not the caller's input.
fn self_check_failed(e: ChainError) -> VaultError {
    VaultError::new(
        VaultErrorCode::Internal,
        format!("produced keyring failed the chain-walk self-check: {e}"),
    )
}

/// A keyring served by the untrusted network was refused by the chain-walk. Unlike
/// [`self_check_failed`], this is the *counterparty's* fault, not ours — mapped to a granular,
/// user-facing code so the JS side can react (fork = attack, gap = availability, unendorsed =
/// tampering) rather than a blanket internal error.
fn remote_chain_err(e: ChainError) -> VaultError {
    use ChainError as E;
    use VaultErrorCode as C;
    let code = match e {
        E::TreeMismatch => C::TreeMismatch,
        E::RevisionOverflow => C::RevisionOverflow,
        E::NonSequential => C::KeyringNonSequential,
        E::Fork => C::KeyringFork,
        E::UnendorsedOrdinaryChange | E::UnendorsedSetChange => C::KeyringUnendorsed,
        E::LayoutAhead | E::BadStructure(_) | E::WrapIncomplete | E::BadBootstrap => {
            C::KeyringMalformed
        }
    };
    VaultError::new(code, e.to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn parse_kind(s: &str) -> Result<EntryKind> {
    match s {
        "snapshot" => Ok(EntryKind::Snapshot),
        "delta" => Ok(EntryKind::Delta),
        "media" => Ok(EntryKind::Media),
        "proposal" => Ok(EntryKind::Proposal),
        other => Err(VaultError::new(
            VaultErrorCode::BadRequest,
            format!("unknown kind: {other}"),
        )),
    }
}

fn parse_format(s: &str) -> Result<Format> {
    match s {
        "openom-json" => Ok(Format::OpenomJson),
        "openom-ops" => Ok(Format::OpenomOps),
        "raw-bytes" => Ok(Format::RawBytes),
        other => Err(VaultError::new(
            VaultErrorCode::BadRequest,
            format!("unknown format: {other}"),
        )),
    }
}

fn parse_compression(s: &str) -> Result<Compression> {
    match s {
        "none" => Ok(Compression::None),
        "zstd" => Ok(Compression::Zstd),
        other => Err(VaultError::new(
            VaultErrorCode::BadRequest,
            format!("unknown compression: {other}"),
        )),
    }
}

fn parse_member_role(s: &str) -> Result<MemberRole> {
    match s {
        "owner" => Ok(MemberRole::Owner),
        "co-owner" => Ok(MemberRole::CoOwner),
        "admin" => Ok(MemberRole::Admin),
        "editor" => Ok(MemberRole::Editor),
        "viewer" => Ok(MemberRole::Viewer),
        other => Err(VaultError::new(
            VaultErrorCode::BadRequest,
            format!("unknown role: {other}"),
        )),
    }
}

/// Decode the caller's pinned signer verify-keys (32-byte Ed25519 each). At least one is
/// required — a member unlock with no trust anchor would be verifying against nothing.
fn parse_trusted_signers(raw: &[Vec<u8>]) -> Result<Vec<VerifyingKey>> {
    if raw.is_empty() {
        return Err(VaultError::new(
            VaultErrorCode::BadRequest,
            "no trusted signer keys supplied",
        ));
    }
    raw.iter()
        .map(|b| {
            let arr: [u8; 32] = b.as_slice().try_into().map_err(|_| {
                VaultError::new(
                    VaultErrorCode::BadRequest,
                    "trusted signer key must be 32 bytes",
                )
            })?;
            VerifyingKey::from_bytes(&arr).map_err(|_| {
                VaultError::new(VaultErrorCode::BadRequest, "invalid trusted signer key")
            })
        })
        .collect()
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// An in-memory VaultStore: keyring bytes + a monotonic revision floor per tree.
    #[derive(Default)]
    struct MemStore {
        keyrings: StdMutex<HashMap<String, Vec<u8>>>,
        floors: StdMutex<HashMap<String, u32>>,
    }
    impl VaultStore for MemStore {
        fn load_keyring(&self, tree_key: &str) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(self.keyrings.lock().unwrap().get(tree_key).cloned())
        }
        fn keyring_watermark(&self, tree_key: &str) -> std::result::Result<u32, String> {
            Ok(self
                .floors
                .lock()
                .unwrap()
                .get(tree_key)
                .copied()
                .unwrap_or(0))
        }
        fn observe_keyring_revision(
            &self,
            tree_key: &str,
            revision: u32,
        ) -> std::result::Result<(), String> {
            let mut f = self.floors.lock().unwrap();
            let e = f.entry(tree_key.to_string()).or_insert(0);
            *e = (*e).max(revision);
            Ok(())
        }
        fn commit_keyring(
            &self,
            tree_key: &str,
            bytes: &[u8],
            revision: u32,
        ) -> std::result::Result<(), String> {
            self.keyrings
                .lock()
                .unwrap()
                .insert(tree_key.to_string(), bytes.to_vec());
            let mut f = self.floors.lock().unwrap();
            let e = f.entry(tree_key.to_string()).or_insert(0);
            *e = (*e).max(revision);
            Ok(())
        }
    }

    const TREE: &[u8] = b"tree-uuid-16byte";
    const KEY: &str = "my-tree";
    const MEMBER: &str = "local-owner";

    fn host() -> VaultHost<MemStore> {
        VaultHost::new(MemStore::default())
    }

    fn seal(h: &VaultHost<MemStore>, id: &str, plaintext: &[u8]) -> Vec<u8> {
        h.seal_entry(
            id,
            "snapshot",
            "openom-json",
            "none",
            0,
            Vec::new(),
            0,
            Vec::new(),
            plaintext,
        )
        .unwrap()
        .envelope
    }

    #[test]
    fn the_entropy_seam_makes_host_minted_ids_deterministic() {
        // With a seeded entropy source the host's own minted ids (the sealer-registry handle here) are
        // reproducible — the property that lets the vault-host state machine be tested deterministically.
        // (The sealer's key-minting CSPRNG stays random; injecting that is the deferred OPE-248.)
        let provision = |seed: u64| {
            VaultHost::with_entropy(MemStore::default(), SeededEntropy::new(seed))
                .provision(KEY, TREE, "correct horse".into(), MEMBER)
                .unwrap()
                .sealer_id
        };
        assert_eq!(provision(42), provision(42), "same seed → same host-minted id");
        assert_ne!(provision(42), provision(7), "different seed → different id");
    }

    #[test]
    fn provision_seal_lock_unlock_open_roundtrip() {
        let h = host();
        assert!(!h.has_keyring(KEY).unwrap());
        let p = h
            .provision(KEY, TREE, "correct horse".into(), MEMBER)
            .unwrap();
        assert_eq!(p.revision, 1);
        assert!(h.has_keyring(KEY).unwrap());
        let envelope = seal(&h, &p.sealer_id, b"the family tree");

        // Lock frees the sealer; the handle is dead afterwards.
        h.lock(&p.sealer_id);
        assert_eq!(
            h.seal_entry(
                &p.sealer_id,
                "snapshot",
                "openom-json",
                "none",
                1,
                Vec::new(),
                0,
                Vec::new(),
                b"x"
            )
            .unwrap_err()
            .code,
            VaultErrorCode::UnknownSealer
        );

        // A fresh unlock re-derives the same DEK and opens data sealed before the lock.
        let u = h.unlock(KEY, TREE, "correct horse".into(), MEMBER).unwrap();
        assert_eq!(u.revision, 1);
        assert_eq!(
            h.open_entry(&u.sealer_id, "snapshot", &envelope).unwrap(),
            b"the family tree"
        );
    }

    #[test]
    fn wrong_passphrase_is_crypto_open() {
        let h = host();
        h.provision(KEY, TREE, "right".into(), MEMBER).unwrap();
        let err = h.unlock(KEY, TREE, "wrong".into(), MEMBER).unwrap_err();
        assert_eq!(err.code, VaultErrorCode::CryptoOpen);
    }

    #[test]
    fn unlock_below_the_watermark_is_a_rollback_and_never_registers_a_sealer() {
        let h = host();
        let p = h.provision(KEY, TREE, "pass".into(), MEMBER).unwrap(); // revision 1, floor 1
                                                                        // A hostile store serves the old keyring but the watermark remembers a later revision.
        h.store.observe_keyring_revision(KEY, 7).unwrap();
        let err = h.unlock(KEY, TREE, "pass".into(), MEMBER).unwrap_err();
        assert_eq!(err.code, VaultErrorCode::RevisionRollback);
        // The provisioned sealer is the only live one; unlock registered nothing new.
        assert_eq!(h.registry.lock().len(), 1);
        h.lock(&p.sealer_id);
    }

    #[test]
    fn change_passphrase_rotates_and_old_no_longer_opens() {
        let h = host();
        let p = h.provision(KEY, TREE, "old".into(), MEMBER).unwrap();
        let re = h
            .change_passphrase(KEY, TREE, "old".into(), "new".into(), MEMBER)
            .unwrap();
        assert_eq!(re.revision, 2);
        assert_ne!(re.recovery_code, p.recovery_code);
        assert_eq!(
            h.unlock(KEY, TREE, "old".into(), MEMBER).unwrap_err().code,
            VaultErrorCode::CryptoOpen
        );
        assert!(h.unlock(KEY, TREE, "new".into(), MEMBER).is_ok());
    }

    #[test]
    fn recover_with_the_code_sets_a_new_passphrase() {
        let h = host();
        let p = h.provision(KEY, TREE, "old".into(), MEMBER).unwrap();
        let envelope = seal(&h, &p.sealer_id, b"data");
        let r = h
            .recover(KEY, TREE, p.recovery_code.clone(), "new".into(), MEMBER)
            .unwrap();
        assert_eq!(r.revision, 2);
        // Same DEK: the recovered sealer opens data sealed before recovery.
        assert_eq!(
            h.open_entry(&r.sealer_id, "snapshot", &envelope).unwrap(),
            b"data"
        );
        assert!(h.unlock(KEY, TREE, "new".into(), MEMBER).is_ok());
        assert_eq!(
            h.unlock(KEY, TREE, "old".into(), MEMBER).unwrap_err().code,
            VaultErrorCode::CryptoOpen
        );
    }

    #[test]
    fn unlock_without_a_keyring_is_no_keyring() {
        let h = host();
        assert_eq!(
            h.unlock(KEY, TREE, "x".into(), MEMBER).unwrap_err().code,
            VaultErrorCode::NoKeyring
        );
    }

    #[test]
    fn dev_sealer_round_trips_without_a_keyring() {
        let h = host();
        let d = h.dev(TREE).unwrap();
        let envelope = seal(&h, &d.sealer_id, b"demo");
        assert_eq!(
            h.open_entry(&d.sealer_id, "snapshot", &envelope).unwrap(),
            b"demo"
        );
    }

    #[test]
    fn clear_frees_every_sealer() {
        let h = host();
        let a = h.provision("t1", TREE, "p".into(), MEMBER).unwrap();
        let b = h.dev(TREE).unwrap();
        h.clear();
        for id in [a.sealer_id, b.sealer_id] {
            assert_eq!(
                h.open_entry(&id, "snapshot", b"x").unwrap_err().code,
                VaultErrorCode::UnknownSealer
            );
        }
    }

    #[test]
    fn bad_kind_string_is_bad_request() {
        let h = host();
        let p = h.provision(KEY, TREE, "p".into(), MEMBER).unwrap();
        let err = h
            .seal_entry(
                &p.sealer_id,
                "nope",
                "openom-json",
                "none",
                0,
                Vec::new(),
                0,
                Vec::new(),
                b"x",
            )
            .unwrap_err();
        assert_eq!(err.code, VaultErrorCode::BadRequest);
    }

    /// The founder verify-key from the stored keyring, as a member would pin it OOB.
    fn founder_key(h: &VaultHost<MemStore>, tree_key: &str) -> Vec<u8> {
        use openom_protocol::v1::Keyring;
        let bytes = h.store.load_keyring(tree_key).unwrap().unwrap();
        Keyring::decode(bytes.as_slice())
            .unwrap()
            .authorized_signers[0]
            .public_key
            .clone()
    }

    const MEMBER2: &str = "acct-2";
    const MEMBER3: &str = "acct-3";

    #[test]
    fn owner_adds_a_member_who_unlocks_through_the_host() {
        let h = host();
        let owner = h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let sealed = seal(&h, &owner.sealer_id, b"shared ancestry");

        let m = h.provision_member("member pass".into()).unwrap();
        let added = h
            .add_member(
                KEY,
                TREE,
                "owner pass".into(),
                MEMBER,
                MEMBER2,
                "editor",
                &m.hpke_public,
                &m.author_public,
            )
            .unwrap();
        assert_eq!(added.revision, 2);

        let pinned = vec![founder_key(&h, KEY)];
        let u = h
            .unlock_as_member(
                KEY,
                TREE,
                "member pass".into(),
                &m.kdf_params,
                MEMBER2,
                pinned,
            )
            .unwrap();
        assert_eq!(u.revision, 2);
        assert_eq!(
            h.open_entry(&u.sealer_id, "snapshot", &sealed).unwrap(),
            b"shared ancestry"
        );
    }

    #[test]
    fn member_unlock_rejects_a_missing_trust_anchor() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let m = h.provision_member("member pass".into()).unwrap();
        h.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER2,
            "viewer",
            &m.hpke_public,
            &m.author_public,
        )
        .unwrap();
        // No pinned keys at all → bad request (a member must supply a trust anchor).
        assert_eq!(
            h.unlock_as_member(
                KEY,
                TREE,
                "member pass".into(),
                &m.kdf_params,
                MEMBER2,
                vec![]
            )
            .unwrap_err()
            .code,
            VaultErrorCode::BadRequest
        );
    }

    #[test]
    fn host_removes_a_member_and_denies_them_new_content() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let m = h.provision_member("member pass".into()).unwrap();
        h.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER2,
            "editor",
            &m.hpke_public,
            &m.author_public,
        )
        .unwrap();
        let pinned = vec![founder_key(&h, KEY)];

        let removed = h
            .remove_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2)
            .unwrap();
        assert_eq!(removed.revision, 3);
        // The new-epoch sealer works for new content.
        let _ = seal(&h, &removed.sealer_id, b"post-removal");
        // The removed member can no longer unlock (no wrap in the new epoch).
        assert_eq!(
            h.unlock_as_member(
                KEY,
                TREE,
                "member pass".into(),
                &m.kdf_params,
                MEMBER2,
                pinned
            )
            .unwrap_err()
            .code,
            VaultErrorCode::MissingWrap
        );
    }

    #[test]
    fn change_passphrase_on_a_shared_tree_keeps_the_member() {
        let h = host();
        let owner = h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let sealed = seal(&h, &owner.sealer_id, b"shared");
        let m = h.provision_member("member pass".into()).unwrap();
        h.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER2,
            "editor",
            &m.hpke_public,
            &m.author_public,
        )
        .unwrap();
        let old_founder = founder_key(&h, KEY);

        // Changing the owner passphrase on a shared tree now succeeds (guard retired).
        let re = h
            .change_passphrase(KEY, TREE, "owner pass".into(), "new pass".into(), MEMBER)
            .unwrap();
        assert_eq!(re.revision, 3);

        // The member still unlocks against the key pinned before the change and reads content.
        let u = h
            .unlock_as_member(
                KEY,
                TREE,
                "member pass".into(),
                &m.kdf_params,
                MEMBER2,
                vec![old_founder],
            )
            .unwrap();
        assert_eq!(
            h.open_entry(&u.sealer_id, "snapshot", &sealed).unwrap(),
            b"shared"
        );
    }

    #[test]
    fn the_writer_self_check_refuses_an_unendorsed_keyring_and_persists_nothing() {
        use openom_keyring::{generate_identity, keyring_hash, sign_keyring};
        use openom_protocol::v1::{AuthorizedSigner, KeyWrap, Member};

        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let prior_bytes = h.store.load_keyring(KEY).unwrap().unwrap();
        let prior = Keyring::decode(prior_bytes.as_slice()).unwrap();

        // A structurally-valid successor that injects a rogue co-owner into the signer set and
        // is signed only by that rogue — the exact substitution the chain-walk exists to catch.
        let rogue = generate_identity().unwrap();
        let rogue_pub = rogue.verifying_key().to_bytes().to_vec();
        let mut bad = prior.clone();
        bad.revision += 1;
        bad.prev_keyring_hash = keyring_hash(&prior).to_vec();
        bad.members.push(Member {
            member_id: "rogue".into(),
            role: MemberRole::CoOwner as i32,
            author_public_key: rogue_pub.clone(),
            hpke_public_key: vec![9; 32],
        });
        bad.epochs[0].wraps.push(KeyWrap {
            member_id: "rogue".into(),
            wrap_method: openom_protocol::v1::WrapMethod::X25519Hpke as i32,
            nonce: vec![],
            wrapped_dek: vec![1],
            kdf_params: None,
            ephemeral_public_key: vec![],
        });
        bad.authorized_signers.push(AuthorizedSigner {
            public_key: rogue_pub,
            member_id: "rogue".into(),
            role: openom_protocol::v1::SignerRole::CoOwner as i32,
        });
        bad.signatures.clear();
        sign_keyring(&mut bad, &rogue);
        let bad_bytes = bad.encode_to_vec();

        // The self-check rejects it as an internal fault (a keyring our own verifier refuses)...
        let err = h
            .commit_transition(KEY, &prior_bytes, &bad_bytes)
            .unwrap_err();
        assert_eq!(err.code, VaultErrorCode::Internal);
        // ...and nothing was persisted: the stored keyring is untouched.
        assert_eq!(h.store.load_keyring(KEY).unwrap().unwrap(), prior_bytes);
    }

    /// Device A produces a run of keyring revisions; each successive head is captured as the
    /// bytes a syncing device would pull. Returns (rev1, rev2, rev3).
    fn produce_three_revisions(a: &VaultHost<MemStore>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        a.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap(); // rev1
        let rev1 = a.store.load_keyring(KEY).unwrap().unwrap();
        let m2 = a.provision_member("m2 pass".into()).unwrap();
        a.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER2,
            "editor",
            &m2.hpke_public,
            &m2.author_public,
        )
        .unwrap();
        let rev2 = a.store.load_keyring(KEY).unwrap().unwrap();
        let m3 = a.provision_member("m3 pass".into()).unwrap();
        a.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER3,
            "viewer",
            &m3.hpke_public,
            &m3.author_public,
        )
        .unwrap();
        let rev3 = a.store.load_keyring(KEY).unwrap().unwrap();
        (rev1, rev2, rev3)
    }

    #[test]
    fn a_device_accepts_a_validated_remote_keyring_run() {
        let a = host();
        let (rev1, rev2, rev3) = produce_three_revisions(&a);

        // Device B is anchored at rev1 (as if it had synced/bootstrapped the genesis), then pulls
        // and accepts the rev2..rev3 run.
        let b = host();
        b.store.commit_keyring(KEY, &rev1, 1).unwrap();
        let accepted = b
            .accept_remote_keyring(KEY, TREE, vec![rev2.clone(), rev3.clone()])
            .unwrap();
        assert_eq!(accepted.revision, 3);
        assert_eq!(b.store.load_keyring(KEY).unwrap().unwrap(), rev3);
        assert_eq!(b.store.keyring_watermark(KEY).unwrap(), 3);

        // An empty run is a no-op at the current revision.
        assert_eq!(
            b.accept_remote_keyring(KEY, TREE, vec![]).unwrap().revision,
            3
        );
        // Replaying the old run now rolls backward → refused, store untouched.
        assert_eq!(
            b.accept_remote_keyring(KEY, TREE, vec![rev2])
                .unwrap_err()
                .code,
            VaultErrorCode::KeyringNonSequential
        );
        assert_eq!(b.store.load_keyring(KEY).unwrap().unwrap(), rev3);
    }

    #[test]
    fn a_withheld_hop_in_the_run_is_refused() {
        let a = host();
        let (rev1, _rev2, rev3) = produce_three_revisions(&a);
        let b = host();
        b.store.commit_keyring(KEY, &rev1, 1).unwrap();
        // Skipping rev2 (a server withholding a hop) breaks the contiguous walk.
        assert_eq!(
            b.accept_remote_keyring(KEY, TREE, vec![rev3])
                .unwrap_err()
                .code,
            VaultErrorCode::KeyringNonSequential
        );
        assert_eq!(b.store.keyring_watermark(KEY).unwrap(), 1);
    }

    #[test]
    fn a_rogue_signer_in_a_remote_hop_is_refused_and_nothing_is_persisted() {
        use openom_keyring::{generate_identity, keyring_hash, sign_keyring};
        use openom_protocol::v1::{AuthorizedSigner, KeyWrap, Member};

        let a = host();
        let (rev1, _rev2, _rev3) = produce_three_revisions(&a);
        let anchor = Keyring::decode(rev1.as_slice()).unwrap();

        // A forged rev2: injects a rogue co-owner and is signed only by that rogue.
        let rogue = generate_identity().unwrap();
        let rogue_pub = rogue.verifying_key().to_bytes().to_vec();
        let mut bad = anchor.clone();
        bad.revision = 2;
        bad.prev_keyring_hash = keyring_hash(&anchor).to_vec();
        bad.members.push(Member {
            member_id: "rogue".into(),
            role: MemberRole::CoOwner as i32,
            author_public_key: rogue_pub.clone(),
            hpke_public_key: vec![9; 32],
        });
        bad.epochs[0].wraps.push(KeyWrap {
            member_id: "rogue".into(),
            wrap_method: openom_protocol::v1::WrapMethod::X25519Hpke as i32,
            nonce: vec![],
            wrapped_dek: vec![1],
            kdf_params: None,
            ephemeral_public_key: vec![],
        });
        bad.authorized_signers.push(AuthorizedSigner {
            public_key: rogue_pub,
            member_id: "rogue".into(),
            role: openom_protocol::v1::SignerRole::CoOwner as i32,
        });
        bad.signatures.clear();
        sign_keyring(&mut bad, &rogue);

        let b = host();
        b.store.commit_keyring(KEY, &rev1, 1).unwrap();
        assert_eq!(
            b.accept_remote_keyring(KEY, TREE, vec![bad.encode_to_vec()])
                .unwrap_err()
                .code,
            VaultErrorCode::KeyringUnendorsed
        );
        // Store untouched — still anchored at rev1.
        assert_eq!(b.store.load_keyring(KEY).unwrap().unwrap(), rev1);
        assert_eq!(b.store.keyring_watermark(KEY).unwrap(), 1);
    }

    #[test]
    fn accept_without_a_local_anchor_is_no_keyring() {
        let h = host();
        assert_eq!(
            h.accept_remote_keyring(KEY, TREE, vec![vec![1, 2, 3]])
                .unwrap_err()
                .code,
            VaultErrorCode::NoKeyring
        );
    }

    #[test]
    fn founder_promotes_and_demotes_a_co_owner_through_the_host() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let co = h.provision_member("co pass".into()).unwrap();
        h.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER2,
            "editor",
            &co.hpke_public,
            &co.author_public,
        )
        .unwrap();
        let promoted = h
            .add_co_owner(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2)
            .unwrap();
        assert_eq!(promoted.revision, 3);
        let demoted = h
            .remove_co_owner(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "viewer")
            .unwrap();
        assert_eq!(demoted.revision, 4);
    }

    #[test]
    fn a_co_owner_administers_members_through_the_host() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let co = h.provision_member("co pass".into()).unwrap();
        h.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            MEMBER2,
            "editor",
            &co.hpke_public,
            &co.author_public,
        )
        .unwrap();
        h.add_co_owner(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2)
            .unwrap(); // rev 3
        let founder = founder_key(&h, KEY);

        // The CO-OWNER adds and then removes an ordinary member through the host.
        let m3 = h.provision_member("m3 pass".into()).unwrap();
        let added = h
            .add_member_as_co_owner(
                KEY,
                TREE,
                "co pass".into(),
                &co.kdf_params,
                MEMBER2,
                vec![founder.clone()],
                MEMBER3,
                "viewer",
                &m3.hpke_public,
                &m3.author_public,
            )
            .unwrap();
        assert_eq!(added.revision, 4);
        let removed = h
            .remove_member_as_co_owner(
                KEY,
                TREE,
                "co pass".into(),
                &co.kdf_params,
                MEMBER2,
                vec![founder],
                MEMBER3,
            )
            .unwrap();
        assert_eq!(removed.revision, 5);

        // A non-signer (an ordinary member) can't administer.
        let ed = h.provision_member("ed pass".into()).unwrap();
        h.add_member(
            KEY,
            TREE,
            "owner pass".into(),
            MEMBER,
            "acct-ed",
            "editor",
            &ed.hpke_public,
            &ed.author_public,
        )
        .unwrap();
        let founder2 = founder_key(&h, KEY);
        let err = h
            .remove_member_as_co_owner(
                KEY,
                TREE,
                "ed pass".into(),
                &ed.kdf_params,
                "acct-ed",
                vec![founder2],
                MEMBER,
            )
            .unwrap_err();
        assert_eq!(err.code, VaultErrorCode::NotAuthorized);
    }
}
