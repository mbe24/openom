//! The native key-custody host. On Tauri the DEK must never enter the webview, so the
//! passphrase lifecycle (provision/unlock/recover/change) and the live [`Sealer`] sessions
//! live here in Rust; the `#[tauri::command]`s are thin wrappers that (de)serialize and
//! delegate. Keeping the substance in a plain crate — no `tauri`, no webview — is what makes
//! it `cargo test`-able without a device.
//!
//! This is the Rust twin of the web app's `vault.js` + the worker's sealer registry, cut ONE
//! level higher than the worker: keyring bytes, the anti-rollback watermark, and the replica
//! id never cross the boundary. The host owns keyring + watermark storage (injected as a
//! [`VaultStore`]) so a keyring-save and its watermark advance can be one durable transaction,
//! and so key custody shares the ciphertext's durability domain rather than the evictable
//! webview one.
//!
//! Errors cross as a `{ code, message }` [`VaultError`] with a stable [`VaultErrorCode`] enum,
//! never a matchable string — the web app already has one string-matched error path that broke
//! when a Rust message read "rolled back" instead of "rollback".

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openom_crypto::VerifyingKey;
use openom_sealer::vault;
use openom_sealer::{EntryKind, SealContext, Sealer, SealerError, SealerSet};
use openom_protocol::v1::{Compression, Format, KdfParams, MemberRole};
use openom_protocol::Message;
use serde::Serialize;
use zeroize::Zeroizing;

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
    /// The next revision would overflow u32 (a poisoned served revision).
    RevisionOverflow,
    /// The keyring is for a different tree than the caller operates on.
    TreeMismatch,
    /// The keyring bytes don't decode / are structurally invalid.
    BadKeyring,
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
        VaultError { code, message: message.into() }
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
            E::TreeMismatch => C::TreeMismatch,
            E::RevisionRollback { .. } => C::RevisionRollback,
            E::RevisionOverflow => C::RevisionOverflow,
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
    fn save_keyring(&self, tree_key: &str, bytes: &[u8]) -> std::result::Result<(), String>;
    /// The highest keyring revision verified for this tree (0 if none).
    fn keyring_watermark(&self, tree_key: &str) -> std::result::Result<u32, String>;
    /// Record a freshly-verified revision. Monotonic: never lowers the stored floor.
    fn observe_keyring_revision(&self, tree_key: &str, revision: u32) -> std::result::Result<(), String>;
}

// ---------------------------------------------------------------- outputs (wire shapes)

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provisioned {
    pub sealer_id: String,
    pub revision: u32,
    pub recovery_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unlocked {
    pub sealer_id: String,
    pub revision: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recovered {
    pub sealer_id: String,
    pub revision: u32,
    pub recovery_code: String,
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

// ---------------------------------------------------------------- the host

pub struct VaultHost<S: VaultStore> {
    store: S,
    registry: Registry,
}

impl<S: VaultStore> VaultHost<S> {
    pub fn new(store: S) -> Self {
        VaultHost { store, registry: Registry::default() }
    }

    /// Is a keyring stored for this tree? (The gate uses this to choose unlock vs welcome.)
    pub fn has_keyring(&self, tree_key: &str) -> Result<bool> {
        Ok(self.store.load_keyring(tree_key).map_err(VaultError::storage)?.is_some())
    }

    /// Create a brand-new encrypted tree: fresh DEK, wrapped under the passphrase + a fresh
    /// recovery code. Persists the keyring, watermarks revision 1, and returns a live sealer.
    pub fn provision(&self, tree_key: &str, tree_id: &[u8], passphrase: String, member_id: &str) -> Result<Provisioned> {
        let passphrase = Zeroizing::new(passphrase);
        let replica = fresh_replica()?;
        let p = vault::provision(passphrase.as_bytes(), tree_id, member_id, &replica)?;
        self.store.save_keyring(tree_key, &p.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, 1).map_err(VaultError::storage)?;
        let id = self.register(p.sealer)?;
        Ok(Provisioned { sealer_id: id, revision: 1, recovery_code: p.recovery_code })
    }

    /// Open the stored keyring with a passphrase. Mirrors the worker's refuse-before-expose:
    /// the built sealer is DROPPED (its DEK zeroized) before it is ever registered if the
    /// served revision is below the watermark — a rollback caught before the key is usable.
    pub fn unlock(&self, tree_key: &str, tree_id: &[u8], passphrase: String, member_id: &str) -> Result<Unlocked> {
        let passphrase = Zeroizing::new(passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let replica = fresh_replica()?;
        let u = vault::unlock(&keyring, passphrase.as_bytes(), tree_id, member_id, &replica)?;
        if u.revision < floor {
            // `u.sealer` drops here — Key32 is Zeroizing, so the DEK is scrubbed — before it is
            // ever registered or used.
            return Err(VaultError::new(
                VaultErrorCode::RevisionRollback,
                format!("keyring revision rolled back: floor {floor}, served {}", u.revision),
            ));
        }
        self.store.observe_keyring_revision(tree_key, u.revision).map_err(VaultError::storage)?;
        let id = self.register(u.sealer)?;
        Ok(Unlocked { sealer_id: id, revision: u.revision })
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
        let recovery_code = Zeroizing::new(recovery_code);
        let new_passphrase = Zeroizing::new(new_passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let replica = fresh_replica()?;
        let r = vault::recover(
            &keyring,
            recovery_code.as_str(),
            new_passphrase.as_bytes(),
            tree_id,
            member_id,
            &replica,
            floor,
        )?;
        self.store.save_keyring(tree_key, &r.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, r.revision).map_err(VaultError::storage)?;
        let id = self.register(r.sealer)?;
        Ok(Recovered { sealer_id: id, revision: r.revision, recovery_code: r.recovery_code })
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
        let old_passphrase = Zeroizing::new(old_passphrase);
        let new_passphrase = Zeroizing::new(new_passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let re = vault::change_passphrase(
            &keyring,
            old_passphrase.as_bytes(),
            new_passphrase.as_bytes(),
            tree_id,
            member_id,
            floor,
        )?;
        self.store.save_keyring(tree_key, &re.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, re.revision).map_err(VaultError::storage)?;
        Ok(Rekeyed { revision: re.revision, recovery_code: re.recovery_code })
    }

    /// Provision a member identity from a passphrase (stateless — no tree touched): returns
    /// the public keys to share OOB with a tree owner and the opaque KDF params the member
    /// persists and passes back at unlock.
    pub fn provision_member(&self, passphrase: String) -> Result<MemberProvisioned> {
        let passphrase = Zeroizing::new(passphrase);
        let m = vault::provision_member(passphrase.as_bytes())?;
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
        let owner_passphrase = Zeroizing::new(owner_passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let added = vault::add_member(
            &keyring,
            owner_passphrase.as_bytes(),
            tree_id,
            owner_member_id,
            floor,
            new_member_id,
            parse_member_role(role)?,
            member_hpke_public,
            member_author_public,
        )?;
        self.store.save_keyring(tree_key, &added.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, added.revision).map_err(VaultError::storage)?;
        Ok(MemberAdded { revision: added.revision })
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
        let passphrase = Zeroizing::new(passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let kdf = KdfParams::decode(member_kdf_params)
            .map_err(|e| VaultError::new(VaultErrorCode::BadRequest, format!("bad kdf params: {e}")))?;
        let trusted = parse_trusted_signers(&trusted_signers)?;
        let replica = fresh_replica()?;
        let u = vault::unlock_as_member(
            &keyring,
            passphrase.as_bytes(),
            &kdf,
            tree_id,
            member_id,
            &trusted,
            &replica,
            floor,
        )?;
        self.store.observe_keyring_revision(tree_key, u.revision).map_err(VaultError::storage)?;
        let id = self.register(u.sealer)?;
        Ok(Unlocked { sealer_id: id, revision: u.revision })
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
        let owner_passphrase = Zeroizing::new(owner_passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let replica = fresh_replica()?;
        let r = vault::remove_member(
            &keyring,
            owner_passphrase.as_bytes(),
            tree_id,
            owner_member_id,
            floor,
            remove_member_id,
            &replica,
        )?;
        self.store.save_keyring(tree_key, &r.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, r.revision).map_err(VaultError::storage)?;
        let id = self.register(r.sealer)?;
        Ok(MemberRemoved { sealer_id: id, revision: r.revision })
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
        let founder_passphrase = Zeroizing::new(founder_passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let r = vault::add_co_owner(&keyring, founder_passphrase.as_bytes(), tree_id, founder_member_id, floor, target_member_id)?;
        self.store.save_keyring(tree_key, &r.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, r.revision).map_err(VaultError::storage)?;
        Ok(CoOwnerChanged { revision: r.revision })
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
        let founder_passphrase = Zeroizing::new(founder_passphrase);
        let keyring = self.require_keyring(tree_key)?;
        let floor = self.store.keyring_watermark(tree_key).map_err(VaultError::storage)?;
        let r = vault::remove_co_owner(
            &keyring,
            founder_passphrase.as_bytes(),
            tree_id,
            founder_member_id,
            floor,
            target_member_id,
            parse_member_role(new_role)?,
        )?;
        self.store.save_keyring(tree_key, &r.keyring).map_err(VaultError::storage)?;
        self.store.observe_keyring_revision(tree_key, r.revision).map_err(VaultError::storage)?;
        Ok(CoOwnerChanged { revision: r.revision })
    }

    /// A local-development sealer under the reserved dev key (the demo path). Real ciphertext,
    /// well-known key — no keyring, no unlock.
    pub fn dev(&self, tree_id: &[u8]) -> Result<Unlocked> {
        let replica = fresh_replica()?;
        let id = self.register(SealerSet::single(Sealer::dev(tree_id.to_vec(), replica)))?;
        Ok(Unlocked { sealer_id: id, revision: 0 })
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
        Ok(Sealed { envelope: out.envelope, ciphertext_hash: out.ciphertext_hash })
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
            .ok_or_else(|| VaultError::new(VaultErrorCode::NoKeyring, format!("no keyring for tree {tree_key}")))
    }

    fn sealer(&self, id: &str) -> Result<Arc<SealerSet>> {
        self.registry
            .get(id)
            .ok_or_else(|| VaultError::new(VaultErrorCode::UnknownSealer, "unknown or locked sealer"))
    }

    fn register(&self, sealer: SealerSet) -> Result<String> {
        // 128 random bits, hex. Same trust domain as the web worker's sequential ids (any caller
        // able to invoke can call provision itself), just without a shared counter.
        let id = hex(&openom_crypto::generate_salt().map_err(SealerError::from)?);
        self.registry.insert(id.clone(), sealer);
        Ok(id)
    }
}

// ---------------------------------------------------------------- helpers

fn fresh_replica() -> Result<Vec<u8>> {
    // A fresh replica id per unlock (CSPRNG). Persisting it would let lock→re-unlock reuse
    // (replica_id, counter=0) and fork the chain — so it is minted here, never stored.
    Ok(openom_crypto::generate_salt().map_err(SealerError::from)?.to_vec())
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
        other => Err(VaultError::new(VaultErrorCode::BadRequest, format!("unknown kind: {other}"))),
    }
}

fn parse_format(s: &str) -> Result<Format> {
    match s {
        "openom-json" => Ok(Format::OpenomJson),
        other => Err(VaultError::new(VaultErrorCode::BadRequest, format!("unknown format: {other}"))),
    }
}

fn parse_compression(s: &str) -> Result<Compression> {
    match s {
        "none" => Ok(Compression::None),
        "zstd" => Ok(Compression::Zstd),
        other => Err(VaultError::new(VaultErrorCode::BadRequest, format!("unknown compression: {other}"))),
    }
}

fn parse_member_role(s: &str) -> Result<MemberRole> {
    match s {
        "owner" => Ok(MemberRole::Owner),
        "co-owner" => Ok(MemberRole::CoOwner),
        "admin" => Ok(MemberRole::Admin),
        "editor" => Ok(MemberRole::Editor),
        "viewer" => Ok(MemberRole::Viewer),
        other => Err(VaultError::new(VaultErrorCode::BadRequest, format!("unknown role: {other}"))),
    }
}

/// Decode the caller's pinned signer verify-keys (32-byte Ed25519 each). At least one is
/// required — a member unlock with no trust anchor would be verifying against nothing.
fn parse_trusted_signers(raw: &[Vec<u8>]) -> Result<Vec<VerifyingKey>> {
    if raw.is_empty() {
        return Err(VaultError::new(VaultErrorCode::BadRequest, "no trusted signer keys supplied"));
    }
    raw.iter()
        .map(|b| {
            let arr: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::new(VaultErrorCode::BadRequest, "trusted signer key must be 32 bytes"))?;
            VerifyingKey::from_bytes(&arr)
                .map_err(|_| VaultError::new(VaultErrorCode::BadRequest, "invalid trusted signer key"))
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
        fn save_keyring(&self, tree_key: &str, bytes: &[u8]) -> std::result::Result<(), String> {
            self.keyrings.lock().unwrap().insert(tree_key.to_string(), bytes.to_vec());
            Ok(())
        }
        fn keyring_watermark(&self, tree_key: &str) -> std::result::Result<u32, String> {
            Ok(self.floors.lock().unwrap().get(tree_key).copied().unwrap_or(0))
        }
        fn observe_keyring_revision(&self, tree_key: &str, revision: u32) -> std::result::Result<(), String> {
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
        h.seal_entry(id, "snapshot", "openom-json", "none", 0, Vec::new(), 0, Vec::new(), plaintext)
            .unwrap()
            .envelope
    }

    #[test]
    fn provision_seal_lock_unlock_open_roundtrip() {
        let h = host();
        assert!(!h.has_keyring(KEY).unwrap());
        let p = h.provision(KEY, TREE, "correct horse".into(), MEMBER).unwrap();
        assert_eq!(p.revision, 1);
        assert!(h.has_keyring(KEY).unwrap());
        let envelope = seal(&h, &p.sealer_id, b"the family tree");

        // Lock frees the sealer; the handle is dead afterwards.
        h.lock(&p.sealer_id);
        assert_eq!(
            h.seal_entry(&p.sealer_id, "snapshot", "openom-json", "none", 1, Vec::new(), 0, Vec::new(), b"x")
                .unwrap_err()
                .code,
            VaultErrorCode::UnknownSealer
        );

        // A fresh unlock re-derives the same DEK and opens data sealed before the lock.
        let u = h.unlock(KEY, TREE, "correct horse".into(), MEMBER).unwrap();
        assert_eq!(u.revision, 1);
        assert_eq!(h.open_entry(&u.sealer_id, "snapshot", &envelope).unwrap(), b"the family tree");
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
        let re = h.change_passphrase(KEY, TREE, "old".into(), "new".into(), MEMBER).unwrap();
        assert_eq!(re.revision, 2);
        assert_ne!(re.recovery_code, p.recovery_code);
        assert_eq!(h.unlock(KEY, TREE, "old".into(), MEMBER).unwrap_err().code, VaultErrorCode::CryptoOpen);
        assert!(h.unlock(KEY, TREE, "new".into(), MEMBER).is_ok());
    }

    #[test]
    fn recover_with_the_code_sets_a_new_passphrase() {
        let h = host();
        let p = h.provision(KEY, TREE, "old".into(), MEMBER).unwrap();
        let envelope = seal(&h, &p.sealer_id, b"data");
        let r = h.recover(KEY, TREE, p.recovery_code.clone(), "new".into(), MEMBER).unwrap();
        assert_eq!(r.revision, 2);
        // Same DEK: the recovered sealer opens data sealed before recovery.
        assert_eq!(h.open_entry(&r.sealer_id, "snapshot", &envelope).unwrap(), b"data");
        assert!(h.unlock(KEY, TREE, "new".into(), MEMBER).is_ok());
        assert_eq!(h.unlock(KEY, TREE, "old".into(), MEMBER).unwrap_err().code, VaultErrorCode::CryptoOpen);
    }

    #[test]
    fn unlock_without_a_keyring_is_no_keyring() {
        let h = host();
        assert_eq!(h.unlock(KEY, TREE, "x".into(), MEMBER).unwrap_err().code, VaultErrorCode::NoKeyring);
    }

    #[test]
    fn dev_sealer_round_trips_without_a_keyring() {
        let h = host();
        let d = h.dev(TREE).unwrap();
        let envelope = seal(&h, &d.sealer_id, b"demo");
        assert_eq!(h.open_entry(&d.sealer_id, "snapshot", &envelope).unwrap(), b"demo");
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
            .seal_entry(&p.sealer_id, "nope", "openom-json", "none", 0, Vec::new(), 0, Vec::new(), b"x")
            .unwrap_err();
        assert_eq!(err.code, VaultErrorCode::BadRequest);
    }

    /// The founder verify-key from the stored keyring, as a member would pin it OOB.
    fn founder_key(h: &VaultHost<MemStore>, tree_key: &str) -> Vec<u8> {
        use openom_protocol::v1::Keyring;
        let bytes = h.store.load_keyring(tree_key).unwrap().unwrap();
        Keyring::decode(bytes.as_slice()).unwrap().authorized_signers[0].public_key.clone()
    }

    const MEMBER2: &str = "acct-2";

    #[test]
    fn owner_adds_a_member_who_unlocks_through_the_host() {
        let h = host();
        let owner = h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let sealed = seal(&h, &owner.sealer_id, b"shared ancestry");

        let m = h.provision_member("member pass".into()).unwrap();
        let added = h
            .add_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "editor", &m.hpke_public, &m.author_public)
            .unwrap();
        assert_eq!(added.revision, 2);

        let pinned = vec![founder_key(&h, KEY)];
        let u = h
            .unlock_as_member(KEY, TREE, "member pass".into(), &m.kdf_params, MEMBER2, pinned)
            .unwrap();
        assert_eq!(u.revision, 2);
        assert_eq!(h.open_entry(&u.sealer_id, "snapshot", &sealed).unwrap(), b"shared ancestry");
    }

    #[test]
    fn member_unlock_rejects_a_missing_trust_anchor() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let m = h.provision_member("member pass".into()).unwrap();
        h.add_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "viewer", &m.hpke_public, &m.author_public).unwrap();
        // No pinned keys at all → bad request (a member must supply a trust anchor).
        assert_eq!(
            h.unlock_as_member(KEY, TREE, "member pass".into(), &m.kdf_params, MEMBER2, vec![]).unwrap_err().code,
            VaultErrorCode::BadRequest
        );
    }

    #[test]
    fn host_removes_a_member_and_denies_them_new_content() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let m = h.provision_member("member pass".into()).unwrap();
        h.add_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "editor", &m.hpke_public, &m.author_public).unwrap();
        let pinned = vec![founder_key(&h, KEY)];

        let removed = h.remove_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2).unwrap();
        assert_eq!(removed.revision, 3);
        // The new-epoch sealer works for new content.
        let _ = seal(&h, &removed.sealer_id, b"post-removal");
        // The removed member can no longer unlock (no wrap in the new epoch).
        assert_eq!(
            h.unlock_as_member(KEY, TREE, "member pass".into(), &m.kdf_params, MEMBER2, pinned).unwrap_err().code,
            VaultErrorCode::MissingWrap
        );
    }

    #[test]
    fn change_passphrase_on_a_shared_tree_keeps_the_member() {
        let h = host();
        let owner = h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let sealed = seal(&h, &owner.sealer_id, b"shared");
        let m = h.provision_member("member pass".into()).unwrap();
        h.add_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "editor", &m.hpke_public, &m.author_public).unwrap();
        let old_founder = founder_key(&h, KEY);

        // Changing the owner passphrase on a shared tree now succeeds (guard retired).
        let re = h.change_passphrase(KEY, TREE, "owner pass".into(), "new pass".into(), MEMBER).unwrap();
        assert_eq!(re.revision, 3);

        // The member still unlocks against the key pinned before the change and reads content.
        let u = h
            .unlock_as_member(KEY, TREE, "member pass".into(), &m.kdf_params, MEMBER2, vec![old_founder])
            .unwrap();
        assert_eq!(h.open_entry(&u.sealer_id, "snapshot", &sealed).unwrap(), b"shared");
    }

    #[test]
    fn founder_promotes_and_demotes_a_co_owner_through_the_host() {
        let h = host();
        h.provision(KEY, TREE, "owner pass".into(), MEMBER).unwrap();
        let co = h.provision_member("co pass".into()).unwrap();
        h.add_member(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "editor", &co.hpke_public, &co.author_public).unwrap();
        let promoted = h.add_co_owner(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2).unwrap();
        assert_eq!(promoted.revision, 3);
        let demoted = h.remove_co_owner(KEY, TREE, "owner pass".into(), MEMBER, MEMBER2, "viewer").unwrap();
        assert_eq!(demoted.revision, 4);
    }
}
