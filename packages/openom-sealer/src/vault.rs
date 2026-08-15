//! The keyring vault — the passphrase lifecycle that turns a passphrase into a [`Sealer`].
//! Four flows: **provision** (first time), **unlock** (returning / new device), **recover**
//! (forgot passphrase, via the recovery code), **change_passphrase**. All fit the frozen
//! `Keyring` proto; none add a field.
//!
//! ## Two invariants that carry the security (from the design review)
//! - **Trusted context.** `tree_id` and `member_id` in every [`WrapContext`] come from the
//!   caller's own expectation (the tree the app is operating on), NEVER from the parsed,
//!   untrusted keyring. Otherwise the "the AEAD binds tree_id" argument is circular. The
//!   keyring's `tree_id` is only *checked* against the expected one, never used as the AAD.
//! - **Untrusted revision on recovery.** Recovery skips the signature (it can't re-derive
//!   the old passphrase-derived identity), and the wrap AAD does not cover `revision`. So the
//!   served revision is untrusted: refuse a value below the caller's watermark *before*
//!   unwrapping, and mint the new revision as `checked(max(watermark, served) + 1)`.

use openom_crypto::{
    default_kdf_params, derive_kek, derive_root, generate_dek, generate_recovery_code,
    generate_salt, hpke_unwrap_dek, hpke_wrap_dek, keyring_hash, parse_recovery_code,
    recovery_kdf_params, sign_keyring, unwrap_dek, verify_keyring, verify_keyring_any, wrap_dek,
    Key32, VerifyingKey, WrapContext, KEY_LEN,
};
use openom_protocol::aad::wrap_aad;
use openom_protocol::v1::{
    AuthorizedSigner, KdfParams, KeyEpoch, KeyWrap, Keyring, Member, MemberRole, SignerRole,
    WrapMethod,
};
use openom_protocol::{Message, ENVELOPE_VERSION, KEYRING_LAYOUT_VERSION};

use crate::{Sealer, SealerError};

const PASSPHRASE: i32 = WrapMethod::PassphraseArgon2id as i32;
const RECOVERY: i32 = WrapMethod::RecoveryCodeArgon2id as i32;
const HPKE: i32 = WrapMethod::X25519Hpke as i32;
/// The founder is the sole authorized signer of a freshly-built single-owner keyring,
/// and the owner is its sole member (§4 multi-signer; V1 builds the degenerate case).
const FOUNDER: i32 = SignerRole::Founder as i32;
const OWNER: i32 = MemberRole::Owner as i32;

/// The epoch key id length (matches `Header.key_id`); 16 CSPRNG bytes.
const KEY_ID_LEN: usize = 16;
/// Bound on untrusted keyring input — a real V1 keyring is well under 1 KiB.
const MAX_KEYRING_BYTES: usize = 64 * 1024;

// The Argon2id window this build will actually run (checked before the KDF, on params read
// from an unverified keyring). Rejects absurd values rather than clamping — clamping could
// silently weaken; a legitimate future cost increase stays inside this ceiling.
const MIN_MEMORY_KIB: u32 = 8 * 1024; // 8 MiB — the recovery-wrap floor
const MAX_MEMORY_KIB: u32 = 256 * 1024; // 256 MiB — heavy but won't OOM a browser tab
const MAX_ITERATIONS: u32 = 16;
const MAX_PARALLELISM: u32 = 8;

/// Result of [`provision`]: the encoded keyring to store, the recovery code to show ONCE,
/// and the ready sealer (built from the fresh DEK — one Argon2id, no second unlock).
pub struct Provisioned {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub sealer: Sealer,
}

/// Result of [`unlock`]: the sealer plus the keyring `revision` the caller must watermark.
pub struct Unlocked {
    pub sealer: Sealer,
    pub revision: u32,
}

/// Result of [`recover`]: a freshly re-provisioned keyring + a NEW recovery code (both to
/// store/show), the sealer, and the new `revision`.
pub struct Recovered {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub sealer: Sealer,
    pub revision: u32,
}

/// Result of [`change_passphrase`]: the new keyring + a rotated recovery code + new revision.
/// The DEK is unchanged, so the running sealer keeps working — no re-seal of the tree.
pub struct Rekeyed {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub revision: u32,
}

/// Create a brand-new encrypted tree: fresh DEK + epoch key, wrapped under `passphrase` and
/// a fresh recovery code, in a keyring signed by the passphrase-derived identity (revision 1).
pub fn provision(
    passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<Provisioned, SealerError> {
    let dek = generate_dek()?;
    let key_id = generate_salt()?.to_vec(); // 16 CSPRNG bytes as the epoch key id
    // Genesis revision (1): no prior keyring to chain onto, so prev_keyring_hash is empty.
    let rw = build_keyring(&dek, tree_id, &key_id, 0, member_id, passphrase, 1, Vec::new())?;
    let sealer = Sealer::from_unwrapped(
        ENVELOPE_VERSION,
        dek,
        tree_id.to_vec(),
        key_id,
        replica_id.to_vec(),
    );
    Ok(Provisioned { keyring: rw.keyring, recovery_code: rw.recovery_code, sealer })
}

/// Open an existing keyring with a passphrase and build a sealer. Verifies the keyring with
/// the caller's own derived identity (§4a V1), then unwraps the DEK.
pub fn unlock(
    keyring_bytes: &[u8],
    passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<Unlocked, SealerError> {
    let opened = open_with_passphrase(keyring_bytes, passphrase, tree_id, member_id)?;
    let sealer = Sealer::from_unwrapped(
        ENVELOPE_VERSION,
        opened.dek,
        tree_id.to_vec(),
        opened.key_id,
        replica_id.to_vec(),
    );
    Ok(Unlocked { sealer, revision: opened.revision })
}

/// Recover with the recovery code, then re-provision under `new_passphrase`. Skips signature
/// verification (the old identity is unrecoverable); the recovery wrap's AEAD tag, bound to
/// the trusted `tree_id`, is the authentication. `min_revision` is the caller's watermark
/// floor (0 if none) — a served revision below it is refused as a rollback.
pub fn recover(
    keyring_bytes: &[u8],
    recovery_code: &str,
    new_passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
) -> Result<Recovered, SealerError> {
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(SealerError::TreeMismatch);
    }
    // Refuse a rollback BEFORE unwrapping (recovery has no signature to catch it).
    if keyring.revision < min_revision {
        return Err(SealerError::RevisionRollback { have: min_revision, got: keyring.revision });
    }
    let (epoch_key_id, epoch, wrap) = find_wrap(&keyring, member_id, RECOVERY)?;
    let kdf = wrap
        .kdf_params
        .as_ref()
        .ok_or_else(|| SealerError::BadKeyring("recovery wrap missing kdf_params".into()))?;
    validate_kdf_params(kdf)?;
    let entropy = parse_recovery_code(recovery_code)?; // checksum first — fail fast on a typo
    let recovery_kek = derive_kek(entropy.as_slice(), kdf)?;
    let ctx = WrapContext {
        tree_id, // trusted
        key_id: &epoch_key_id,
        member_id, // trusted
        wrap_method: RECOVERY,
        epoch,
    };
    let dek = unwrap_dek(&recovery_kek, &wrap.nonce, &wrap.wrapped_dek, &ctx)?;

    let new_revision = min_revision
        .max(keyring.revision)
        .checked_add(1)
        .ok_or(SealerError::RevisionOverflow)?;
    // Chain the new revision onto the one we recovered from.
    let prev_hash = keyring_hash(&keyring).to_vec();
    let rw = build_keyring(
        &dek,
        tree_id,
        &epoch_key_id,
        epoch,
        member_id,
        new_passphrase,
        new_revision,
        prev_hash,
    )?;
    let sealer = Sealer::from_unwrapped(
        ENVELOPE_VERSION,
        dek,
        tree_id.to_vec(),
        epoch_key_id,
        replica_id.to_vec(),
    );
    Ok(Recovered { keyring: rw.keyring, recovery_code: rw.recovery_code, sealer, revision: new_revision })
}

/// Change the passphrase: unwrap with the old one, re-wrap under the new (new identity,
/// `revision + 1`), and **rotate the recovery code** so an old code no longer opens the tree.
/// The DEK is unchanged — this is document control, not a data re-key (see the plan's R2).
pub fn change_passphrase(
    keyring_bytes: &[u8],
    old_passphrase: &[u8],
    new_passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    min_revision: u32,
) -> Result<Rekeyed, SealerError> {
    let opened = open_with_passphrase(keyring_bytes, old_passphrase, tree_id, member_id)?;
    let new_revision = min_revision
        .max(opened.revision)
        .checked_add(1)
        .ok_or(SealerError::RevisionOverflow)?;
    let rw = build_keyring(
        &opened.dek,
        tree_id,
        &opened.key_id,
        opened.epoch,
        member_id,
        new_passphrase,
        new_revision,
        opened.prev_hash,
    )?;
    Ok(Rekeyed { keyring: rw.keyring, recovery_code: rw.recovery_code, revision: new_revision })
}

/// What a joining member provisions from their own passphrase: the KDF params they store
/// in their account record (to re-derive on any device) and the two **public** keys they
/// hand a tree owner out-of-band (§4a) — the Ed25519 author key and the X25519 HPKE key.
pub struct MemberProvision {
    pub kdf_params: KdfParams,
    pub author_public: Vec<u8>,
    pub hpke_public: Vec<u8>,
}

/// Provision a member identity from a passphrase: derive the account's signing + HPKE
/// keypairs and return the public keys (to share OOB) plus the KDF params (to persist).
/// The secrets are never returned — they re-derive from the passphrase on unlock.
pub fn provision_member(passphrase: &[u8]) -> Result<MemberProvision, SealerError> {
    let kdf = default_kdf_params(generate_salt()?.to_vec());
    let root = derive_root(passphrase, &kdf)?;
    Ok(MemberProvision {
        kdf_params: kdf,
        author_public: root.identity.verifying_key().to_bytes().to_vec(),
        hpke_public: root.hpke_public.to_vec(),
    })
}

/// Result of [`add_member`]: the new keyring to publish and its revision.
pub struct MemberAdded {
    pub keyring: Vec<u8>,
    pub revision: u32,
}

/// Add a member to a shared tree. An authorized signer (V1: the owner) re-opens the
/// keyring with their passphrase to reach the DEK and their signing identity, HPKE-wraps
/// the DEK to the member's public key, records them in the signed member list, and
/// re-signs at the next revision (chained onto the prior one). The member's public keys
/// MUST have been verified out-of-band (§4a) before calling — this function trusts them.
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    keyring_bytes: &[u8],
    owner_passphrase: &[u8],
    tree_id: &[u8],
    owner_member_id: &str,
    min_revision: u32,
    new_member_id: &str,
    role: MemberRole,
    member_hpke_public: &[u8],
    member_author_public: &[u8],
) -> Result<MemberAdded, SealerError> {
    let Opened { dek, key_id, epoch, revision, prev_hash, identity, mut keyring, .. } =
        open_with_passphrase(keyring_bytes, owner_passphrase, tree_id, owner_member_id)?;

    if new_member_id == owner_member_id
        || keyring.members.iter().any(|m| m.member_id == new_member_id)
    {
        return Err(SealerError::MemberExists);
    }
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(SealerError::RevisionOverflow)?;

    // HPKE-wrap the DEK to the member, bound to the current epoch's context so the wrap
    // can't be transplanted to another member/epoch/tree.
    let info = wrap_aad(tree_id, &key_id, new_member_id, HPKE, epoch);
    let w = hpke_wrap_dek(member_hpke_public, dek.as_slice(), &info)?;
    let ep = keyring
        .epochs
        .iter_mut()
        .find(|e| e.epoch == epoch)
        .ok_or_else(|| SealerError::BadKeyring("current epoch missing".into()))?;
    ep.wraps.push(KeyWrap {
        member_id: new_member_id.to_string(),
        wrap_method: HPKE,
        nonce: Vec::new(), // HPKE carries its own nonce internally
        wrapped_dek: w.ciphertext,
        kdf_params: None,
        ephemeral_public_key: w.encapped_key,
    });
    keyring.members.push(Member {
        member_id: new_member_id.to_string(),
        role: role as i32,
        author_public_key: member_author_public.to_vec(),
        hpke_public_key: member_hpke_public.to_vec(),
    });
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, &identity);
    Ok(MemberAdded { keyring: keyring.encode_to_vec(), revision: new_revision })
}

/// Unlock a shared tree **as a member** (not the owner): verify the keyring against the
/// caller's **pinned** signer set (learned out-of-band, §4a — never the member's own key
/// and never the document's signer hints), then HPKE-unwrap the DEK with the member's
/// passphrase-derived secret. `member_kdf` is the member's own account KDF params.
#[allow(clippy::too_many_arguments)]
pub fn unlock_as_member(
    keyring_bytes: &[u8],
    member_passphrase: &[u8],
    member_kdf: &KdfParams,
    tree_id: &[u8],
    member_id: &str,
    trusted_signers: &[VerifyingKey],
    replica_id: &[u8],
    min_revision: u32,
) -> Result<Unlocked, SealerError> {
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(SealerError::TreeMismatch);
    }
    if keyring.revision < min_revision {
        return Err(SealerError::RevisionRollback { have: min_revision, got: keyring.revision });
    }
    // The trust anchor: a signature from a key the member pinned OOB. This is the member
    // path's whole security — the member cannot derive the owner's key, so it must be
    // supplied, never taken from the (untrusted) document.
    verify_keyring_any(&keyring, trusted_signers)?;

    let (epoch_key_id, epoch, wrap) = find_wrap(&keyring, member_id, HPKE)?;
    validate_kdf_params(member_kdf)?;
    let root = derive_root(member_passphrase, member_kdf)?;
    let info = wrap_aad(tree_id, &epoch_key_id, member_id, HPKE, epoch);
    let dek = hpke_unwrap_dek(
        root.hpke_secret.as_slice(),
        &wrap.ephemeral_public_key,
        &wrap.wrapped_dek,
        &info,
    )?;
    let sealer = Sealer::from_unwrapped(
        ENVELOPE_VERSION,
        dek,
        tree_id.to_vec(),
        epoch_key_id,
        replica_id.to_vec(),
    );
    Ok(Unlocked { sealer, revision: keyring.revision })
}

/// Result of [`remove_member`]: the re-keyed keyring to publish, a NEW recovery code (a
/// re-key rotates it), the new revision, and a sealer scoped to the **new** epoch so the
/// caller can re-seal the tree snapshot under the new key.
pub struct MemberRemoved {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub revision: u32,
    pub sealer: Sealer,
}

/// Remove a member with **forward-secure revocation**: mint a fresh DEK under a new epoch,
/// wrap it only for those who remain (the owner via passphrase + a fresh recovery code,
/// each other member via HPKE to their pinned key), drop the removed member from the
/// member list and signer set, and re-sign at the next chained revision. Old epochs stay
/// so remaining members can still read pre-removal content; the removed member — who never
/// receives a new-epoch wrap — cannot read anything sealed after removal. The owner's
/// identity/KEK are preserved (only the DEK rotates), so pinned members stay valid.
#[allow(clippy::too_many_arguments)]
pub fn remove_member(
    keyring_bytes: &[u8],
    owner_passphrase: &[u8],
    tree_id: &[u8],
    owner_member_id: &str,
    min_revision: u32,
    remove_member_id: &str,
    replica_id: &[u8],
) -> Result<MemberRemoved, SealerError> {
    let Opened { key_id: _old_key_id, epoch: old_epoch, revision, prev_hash, identity, kek, owner_kdf, mut keyring, .. } =
        open_with_passphrase(keyring_bytes, owner_passphrase, tree_id, owner_member_id)?;

    if remove_member_id == owner_member_id {
        return Err(SealerError::CannotRemoveOwner);
    }
    if !keyring.members.iter().any(|m| m.member_id == remove_member_id) {
        return Err(SealerError::MemberNotFound);
    }
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(SealerError::RevisionOverflow)?;

    // Forward-secure re-key: a fresh DEK under a new epoch, wrapped only for those remaining.
    let new_dek = generate_dek()?;
    let new_key_id = generate_salt()?.to_vec();
    let new_epoch = old_epoch.checked_add(1).ok_or(SealerError::RevisionOverflow)?;

    let mut wraps: Vec<KeyWrap> = Vec::new();

    // Owner: passphrase wrap under the SAME KEK/kdf (identity stays stable) + a fresh
    // recovery wrap. Re-keying necessarily rotates the recovery code — the old code only
    // ever unwrapped the old DEK, and we don't hold its entropy here to reuse it.
    let pass_ctx = WrapContext { tree_id, key_id: &new_key_id, member_id: owner_member_id, wrap_method: PASSPHRASE, epoch: new_epoch };
    let pass = wrap_dek(&kek, &new_dek, &pass_ctx)?;
    wraps.push(KeyWrap {
        member_id: owner_member_id.to_string(),
        wrap_method: PASSPHRASE,
        nonce: pass.nonce,
        wrapped_dek: pass.wrapped_dek,
        kdf_params: Some(owner_kdf),
        ephemeral_public_key: Vec::new(),
    });

    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    let rec_ctx = WrapContext { tree_id, key_id: &new_key_id, member_id: owner_member_id, wrap_method: RECOVERY, epoch: new_epoch };
    let rec = wrap_dek(&recovery_kek, &new_dek, &rec_ctx)?;
    wraps.push(KeyWrap {
        member_id: owner_member_id.to_string(),
        wrap_method: RECOVERY,
        nonce: rec.nonce,
        wrapped_dek: rec.wrapped_dek,
        kdf_params: Some(recovery_kdf),
        ephemeral_public_key: Vec::new(),
    });

    // Each remaining non-owner member: HPKE-wrap the new DEK to their pinned public key.
    for m in &keyring.members {
        if m.member_id == owner_member_id || m.member_id == remove_member_id {
            continue;
        }
        let info = wrap_aad(tree_id, &new_key_id, &m.member_id, HPKE, new_epoch);
        let w = hpke_wrap_dek(&m.hpke_public_key, new_dek.as_slice(), &info)?;
        wraps.push(KeyWrap {
            member_id: m.member_id.clone(),
            wrap_method: HPKE,
            nonce: Vec::new(),
            wrapped_dek: w.ciphertext,
            kdf_params: None,
            ephemeral_public_key: w.encapped_key,
        });
    }

    // Append the new epoch (old epochs stay so remaining members can still read old
    // content), then drop the removed member from the member list and the signer set.
    keyring.epochs.push(KeyEpoch { key_id: new_key_id.clone(), epoch: new_epoch, wraps });
    keyring.members.retain(|m| m.member_id != remove_member_id);
    keyring.authorized_signers.retain(|s| s.member_id != remove_member_id);

    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, &identity);

    let sealer =
        Sealer::from_unwrapped(ENVELOPE_VERSION, new_dek, tree_id.to_vec(), new_key_id, replica_id.to_vec());
    Ok(MemberRemoved { keyring: keyring.encode_to_vec(), recovery_code, revision: new_revision, sealer })
}

// ---- internals ----

struct Opened {
    dek: Key32,
    key_id: Vec<u8>,
    epoch: u32,
    revision: u32,
    /// SHA-256 of this (opened) keyring's signing bytes — what a re-signed successor
    /// records as its `prev_keyring_hash` to chain the revision history.
    prev_hash: Vec<u8>,
    /// The opener's derived signing identity — to re-sign a mutated keyring (e.g. adding a
    /// member). For a single owner this is the founder key already in the signer set.
    identity: openom_crypto::SigningKey,
    /// The opener's passphrase KEK — to wrap a *new* epoch's DEK under the same passphrase
    /// (a re-key must keep the owner's identity/KEK stable, not mint a fresh salt).
    kek: Key32,
    /// The KDF params of the opener's existing passphrase wrap (same salt → same KEK and
    /// identity), stored in a re-keyed passphrase wrap so unlock re-derives them.
    owner_kdf: KdfParams,
    /// The decoded prior keyring, so a mutating flow preserves its signers/members/epochs.
    keyring: Keyring,
}

/// Decode + verify + unwrap the passphrase wrap, returning the DEK and epoch coordinates
/// without building a sealer (so change_passphrase can reuse it).
fn open_with_passphrase(
    keyring_bytes: &[u8],
    passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
) -> Result<Opened, SealerError> {
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(SealerError::TreeMismatch);
    }
    let (epoch_key_id, epoch, wrap) = find_wrap(&keyring, member_id, PASSPHRASE)?;
    let kdf = wrap
        .kdf_params
        .as_ref()
        .ok_or_else(|| SealerError::BadKeyring("passphrase wrap missing kdf_params".into()))?;
    validate_kdf_params(kdf)?;
    let owner_kdf = kdf.clone();
    let root = derive_root(passphrase, kdf)?;
    // §4a V1 (single owner): the trusted signer set is our OWN derived identity — verify
    // the keyring carries a valid signature from it, ignoring the untrusted signer hints.
    // A wrong passphrase yields a wrong identity → verification fails here (before unwrap),
    // indistinguishably from a tampered keyring. (Sharing verifies against a pinned set.)
    verify_keyring(&keyring, &root.identity.verifying_key())?;
    let ctx = WrapContext {
        tree_id, // trusted, not from the keyring
        key_id: &epoch_key_id,
        member_id, // trusted
        wrap_method: PASSPHRASE,
        epoch,
    };
    let dek = unwrap_dek(&root.kek, &wrap.nonce, &wrap.wrapped_dek, &ctx)?;
    let prev_hash = keyring_hash(&keyring).to_vec();
    let revision = keyring.revision;
    Ok(Opened {
        dek,
        key_id: epoch_key_id,
        epoch,
        revision,
        prev_hash,
        identity: root.identity,
        kek: root.kek,
        owner_kdf,
        keyring,
    })
}

struct Built {
    keyring: Vec<u8>,
    recovery_code: String,
}

/// Wrap `dek` under a fresh passphrase KEK and a fresh recovery code, into a signed
/// keyring at `revision`, chained onto `prev_keyring_hash` (empty at genesis). Shared by
/// provision, recover, and change_passphrase.
///
/// This builds the **degenerate single-owner keyring**: one authorized signer (the
/// founder = the passphrase-derived identity), one member (the owner), one signature.
/// Sharing extends this — additional `authorized_signers`, `members`, HPKE wraps, and
/// signatures — but the *shape* is frozen here. Two things a multi-member successor MUST
/// change (tracked as Mode-A work, harmless in the single-owner case this builds):
/// carry forward the epochs/signers/members it isn't replacing (this rebuilds from
/// scratch, correct only for one member), and sign a self-key-change with the *old*
/// still-authorized identity, not the freshly-derived one (continuity, §4a).
#[allow(clippy::too_many_arguments)]
fn build_keyring(
    dek: &[u8; KEY_LEN],
    tree_id: &[u8],
    key_id: &[u8],
    epoch: u32,
    member_id: &str,
    passphrase: &[u8],
    revision: u32,
    prev_keyring_hash: Vec<u8>,
) -> Result<Built, SealerError> {
    let salt = generate_salt()?.to_vec();
    let kdf = default_kdf_params(salt);
    let root = derive_root(passphrase, &kdf)?;
    let pass_ctx = WrapContext { tree_id, key_id, member_id, wrap_method: PASSPHRASE, epoch };
    let pass = wrap_dek(&root.kek, dek, &pass_ctx)?;

    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    let rec_ctx = WrapContext { tree_id, key_id, member_id, wrap_method: RECOVERY, epoch };
    let rec = wrap_dek(&recovery_kek, dek, &rec_ctx)?;

    let identity_pub = root.identity.verifying_key().to_bytes().to_vec();
    let mut keyring = Keyring {
        tree_id: tree_id.to_vec(),
        revision,
        layout_version: KEYRING_LAYOUT_VERSION,
        prev_keyring_hash,
        authorized_signers: vec![AuthorizedSigner {
            public_key: identity_pub.clone(),
            member_id: member_id.to_string(),
            role: FOUNDER,
        }],
        // The owner's own author/HPKE keys are pinned in the member list too, so
        // author_signature verifies against the keyring and a future co-owner rotation can
        // HPKE-wrap the new DEK back to the owner.
        members: vec![Member {
            member_id: member_id.to_string(),
            role: OWNER,
            author_public_key: identity_pub,
            hpke_public_key: root.hpke_public.to_vec(),
        }],
        signatures: Vec::new(),
        epochs: vec![KeyEpoch {
            key_id: key_id.to_vec(),
            epoch,
            wraps: vec![
                KeyWrap {
                    member_id: member_id.to_string(),
                    wrap_method: PASSPHRASE,
                    nonce: pass.nonce,
                    wrapped_dek: pass.wrapped_dek,
                    kdf_params: Some(kdf),
                    ephemeral_public_key: Vec::new(),
                },
                KeyWrap {
                    member_id: member_id.to_string(),
                    wrap_method: RECOVERY,
                    nonce: rec.nonce,
                    wrapped_dek: rec.wrapped_dek,
                    kdf_params: Some(recovery_kdf),
                    ephemeral_public_key: Vec::new(),
                },
            ],
        }],
    };
    sign_keyring(&mut keyring, &root.identity);
    Ok(Built { keyring: keyring.encode_to_vec(), recovery_code })
}

fn decode_keyring(bytes: &[u8]) -> Result<Keyring, SealerError> {
    if bytes.len() > MAX_KEYRING_BYTES {
        return Err(SealerError::BadKeyring("too large".into()));
    }
    Keyring::decode(bytes).map_err(|e| SealerError::BadKeyring(e.to_string()))
}

/// Find the wrap for `(member_id, method)` in the latest epoch. Returns `(key_id, epoch, wrap)`.
fn find_wrap<'a>(
    keyring: &'a Keyring,
    member_id: &str,
    method: i32,
) -> Result<(Vec<u8>, u32, &'a KeyWrap), SealerError> {
    let epoch = keyring
        .epochs
        .iter()
        .max_by_key(|e| e.epoch)
        .ok_or_else(|| SealerError::BadKeyring("no epochs".into()))?;
    let wrap = epoch
        .wraps
        .iter()
        .find(|w| w.member_id == member_id && w.wrap_method == method)
        .ok_or(SealerError::MissingWrap)?;
    Ok((epoch.key_id.clone(), epoch.epoch, wrap))
}

/// Reject Argon2id params outside the runnable window (they come from an unverified keyring).
fn validate_kdf_params(p: &openom_protocol::v1::KdfParams) -> Result<(), SealerError> {
    let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&p.memory_kib)
        && (1..=MAX_ITERATIONS).contains(&p.iterations)
        && (1..=MAX_PARALLELISM).contains(&p.parallelism)
        && (8..=64).contains(&p.salt.len());
    if ok {
        Ok(())
    } else {
        Err(SealerError::BadKdfParams)
    }
}

const _: () = assert!(KEY_ID_LEN == 16);

#[cfg(test)]
mod tests {
    use super::{
        add_member, change_passphrase, provision, provision_member, recover, remove_member,
        unlock, unlock_as_member,
    };
    use crate::{EntryKind, SealContext, Sealer, SealerError};
    use openom_crypto::{generate_recovery_code, keyring_hash, VerifyingKey};
    use openom_protocol::v1::{Keyring, MemberRole, SignerRole};
    use openom_protocol::Message;

    /// The founder's verify key, as a member would pin it out-of-band from an invite.
    fn founder_key(keyring_bytes: &[u8]) -> VerifyingKey {
        let k = Keyring::decode(keyring_bytes).unwrap();
        let bytes: [u8; 32] = k.authorized_signers[0].public_key.as_slice().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    const TREE: &[u8] = b"tree-uuid-16byte";
    const MEMBER: &str = "acct-1";

    fn seal_open(sealer: &Sealer, plaintext: &[u8]) -> Vec<u8> {
        let out = sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), plaintext)
            .unwrap();
        out.envelope
    }

    #[test]
    fn provision_then_unlock_on_another_device_opens_the_same_data() {
        let p = provision(b"correct horse", TREE, MEMBER, b"replica-A").unwrap();
        let sealed = seal_open(&p.sealer, b"the family tree"); // device A seals

        // Device B: unlock from the keyring bytes alone, a fresh replica.
        let u = unlock(&p.keyring, b"correct horse", TREE, MEMBER, b"replica-B").unwrap();
        assert_eq!(u.revision, 1);
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"the family tree"
        );
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let p = provision(b"right", TREE, MEMBER, b"r").unwrap();
        assert!(unlock(&p.keyring, b"wrong", TREE, MEMBER, b"r").is_err());
    }

    #[test]
    fn a_keyring_for_another_tree_is_refused() {
        let p = provision(b"pass", TREE, MEMBER, b"r").unwrap();
        assert!(matches!(
            unlock(&p.keyring, b"pass", b"other-tree-16byt", MEMBER, b"r"),
            Err(SealerError::TreeMismatch)
        ));
    }

    #[test]
    fn a_tampered_keyring_fails_verification() {
        let p = provision(b"pass", TREE, MEMBER, b"r").unwrap();
        let mut k = Keyring::decode(p.keyring.as_slice()).unwrap();
        k.epochs[0].wraps[0].wrapped_dek[0] ^= 0xFF;
        let bytes = k.encode_to_vec();
        assert!(unlock(&bytes, b"pass", TREE, MEMBER, b"r").is_err());
    }

    #[test]
    fn recover_then_unlock_with_the_new_passphrase() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap();
        let sealed = seal_open(&p.sealer, b"data");

        let r = recover(&p.keyring, &p.recovery_code, b"new", TREE, MEMBER, b"r2", 0).unwrap();
        assert_eq!(r.revision, 2);
        // Same DEK — the recovered sealer opens data sealed before recovery.
        assert_eq!(r.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"data");
        assert!(unlock(&r.keyring, b"new", TREE, MEMBER, b"r").is_ok());
        assert!(unlock(&r.keyring, b"old", TREE, MEMBER, b"r").is_err());
    }

    #[test]
    fn recover_with_the_wrong_code_fails() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap();
        let wrong = generate_recovery_code().unwrap(); // valid format, wrong entropy
        assert!(recover(&p.keyring, &wrong, b"new", TREE, MEMBER, b"r", 0).is_err());
    }

    #[test]
    fn recover_refuses_a_revision_below_the_watermark() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap(); // revision 1
        assert!(matches!(
            recover(&p.keyring, &p.recovery_code, b"new", TREE, MEMBER, b"r", 5),
            Err(SealerError::RevisionRollback { .. })
        ));
    }

    #[test]
    fn recover_guards_against_revision_overflow() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap();
        let mut k = Keyring::decode(p.keyring.as_slice()).unwrap();
        k.revision = u32::MAX; // a poisoned served revision (recovery skips the signature)
        let bytes = k.encode_to_vec();
        assert!(matches!(
            recover(&bytes, &p.recovery_code, b"new", TREE, MEMBER, b"r", 0),
            Err(SealerError::RevisionOverflow)
        ));
    }

    #[test]
    fn change_passphrase_bumps_revision_and_rotates_the_recovery_code() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap();
        let re = change_passphrase(&p.keyring, b"old", b"new", TREE, MEMBER, 0).unwrap();
        assert_eq!(re.revision, 2);
        assert_ne!(re.recovery_code, p.recovery_code);

        assert!(unlock(&re.keyring, b"new", TREE, MEMBER, b"r").is_ok());
        assert!(unlock(&re.keyring, b"old", TREE, MEMBER, b"r").is_err());
        // The OLD recovery code no longer opens the tree; the NEW one does.
        assert!(recover(&re.keyring, &p.recovery_code, b"x", TREE, MEMBER, b"r", 0).is_err());
        assert!(recover(&re.keyring, &re.recovery_code, b"x", TREE, MEMBER, b"r", 0).is_ok());
    }

    #[test]
    fn change_passphrase_with_the_wrong_old_passphrase_fails() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap();
        assert!(change_passphrase(&p.keyring, b"wrong", b"new", TREE, MEMBER, 0).is_err());
    }

    #[test]
    fn absurd_kdf_params_are_rejected_before_running_argon2id() {
        let p = provision(b"pass", TREE, MEMBER, b"r").unwrap();
        let mut k = Keyring::decode(p.keyring.as_slice()).unwrap();
        k.epochs[0].wraps[0].kdf_params.as_mut().unwrap().memory_kib = 4_000_000; // ~4 GiB
        let bytes = k.encode_to_vec();
        assert!(matches!(
            unlock(&bytes, b"pass", TREE, MEMBER, b"r"),
            Err(SealerError::BadKdfParams)
        ));
    }

    #[test]
    fn provisioned_keyring_is_a_genesis_single_owner() {
        let p = provision(b"pass", TREE, MEMBER, b"r").unwrap();
        let k = Keyring::decode(p.keyring.as_slice()).unwrap();
        assert_eq!(k.layout_version, 1);
        assert_eq!(k.revision, 1);
        assert!(k.prev_keyring_hash.is_empty(), "genesis has no prior revision to chain onto");
        assert_eq!(k.authorized_signers.len(), 1);
        assert_eq!(k.authorized_signers[0].role, SignerRole::Founder as i32);
        assert_eq!(k.authorized_signers[0].member_id, MEMBER);
        assert_eq!(k.members.len(), 1);
        assert_eq!(k.members[0].role, MemberRole::Owner as i32);
        assert_eq!(k.signatures.len(), 1);
        // The lone signature is by the founder key named in the signer set.
        assert_eq!(k.signatures[0].signer_public_key, k.authorized_signers[0].public_key);
    }

    #[test]
    fn change_passphrase_chains_onto_the_prior_revision() {
        let p = provision(b"old", TREE, MEMBER, b"r").unwrap();
        let prior = Keyring::decode(p.keyring.as_slice()).unwrap();
        let re = change_passphrase(&p.keyring, b"old", b"new", TREE, MEMBER, 0).unwrap();
        let next = Keyring::decode(re.keyring.as_slice()).unwrap();
        assert_eq!(
            next.prev_keyring_hash,
            keyring_hash(&prior).to_vec(),
            "the re-signed keyring must chain onto the one it replaced"
        );
    }

    const MEMBER2: &str = "acct-2";

    #[test]
    fn owner_adds_a_member_who_unlocks_and_reads_the_tree() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let sealed = seal_open(&owner.sealer, b"our shared ancestry"); // owner writes

        // The joining member provisions their own identity and shares the public keys OOB.
        let m = provision_member(b"member pass").unwrap();
        let added = add_member(
            &owner.keyring,
            b"owner pass",
            TREE,
            MEMBER,
            0,
            MEMBER2,
            MemberRole::Editor,
            &m.hpke_public,
            &m.author_public,
        )
        .unwrap();
        assert_eq!(added.revision, 2);

        // The keyring now carries the member, with an HPKE wrap and their pinned keys.
        let k = Keyring::decode(added.keyring.as_slice()).unwrap();
        assert!(k.members.iter().any(|mm| mm.member_id == MEMBER2 && mm.role == MemberRole::Editor as i32));
        assert!(k.epochs[0].wraps.iter().any(|w| w.member_id == MEMBER2 && w.wrap_method == super::HPKE));

        // The member unlocks against the pinned founder key and reads the owner's data.
        let pinned = founder_key(&owner.keyring);
        let u = unlock_as_member(&added.keyring, b"member pass", &m.kdf_params, TREE, MEMBER2, &[pinned], b"r-mem", 0).unwrap();
        assert_eq!(u.revision, 2);
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"our shared ancestry");
    }

    #[test]
    fn a_member_unlock_needs_the_pinned_signer_and_right_passphrase() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let m = provision_member(b"member pass").unwrap();
        let added = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Viewer, &m.hpke_public, &m.author_public).unwrap();

        // Wrong pinned key (an attacker-substituted signer) → rejected before any unwrap.
        let wrong = provision(b"someone else", b"other-tree-16byt", "x", b"r").unwrap();
        let wrong_key = founder_key(&wrong.keyring);
        assert!(unlock_as_member(&added.keyring, b"member pass", &m.kdf_params, TREE, MEMBER2, &[wrong_key], b"r", 0).is_err());

        // Right pinned key, wrong passphrase → HPKE unwrap fails.
        let pinned = founder_key(&owner.keyring);
        assert!(unlock_as_member(&added.keyring, b"WRONG", &m.kdf_params, TREE, MEMBER2, &[pinned], b"r", 0).is_err());
    }

    #[test]
    fn adding_the_same_member_twice_is_rejected() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let m = provision_member(b"member pass").unwrap();
        let added = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &m.hpke_public, &m.author_public).unwrap();
        assert!(matches!(
            add_member(&added.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &m.hpke_public, &m.author_public),
            Err(SealerError::MemberExists)
        ));
        // ...and the owner can't be re-added under their own id either.
        assert!(matches!(
            add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER, MemberRole::Editor, &m.hpke_public, &m.author_public),
            Err(SealerError::MemberExists)
        ));
    }

    #[test]
    fn add_member_needs_the_owners_passphrase() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let m = provision_member(b"member pass").unwrap();
        assert!(add_member(&owner.keyring, b"WRONG", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &m.hpke_public, &m.author_public).is_err());
    }

    const MEMBER3: &str = "acct-3";

    #[test]
    fn removing_a_member_re_keys_and_denies_them_new_content() {
        // Owner with two members, A (to be removed) and B (stays).
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let a = provision_member(b"a pass").unwrap();
        let b = provision_member(b"b pass").unwrap();
        let k1 = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &a.hpke_public, &a.author_public).unwrap();
        let k2 = add_member(&k1.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER3, MemberRole::Viewer, &b.hpke_public, &b.author_public).unwrap();
        assert_eq!(k2.revision, 3);
        let pinned = founder_key(&owner.keyring);

        // Remove A → a re-key (new epoch), a new recovery code, revision 4.
        let removed = remove_member(&k2.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, b"r-owner2").unwrap();
        assert_eq!(removed.revision, 4);
        assert_ne!(removed.recovery_code, owner.recovery_code);

        // The owner seals NEW content under the new epoch.
        let new_sealed = seal_open(&removed.sealer, b"post-removal secret");

        // Forward secrecy: the removed member has no wrap in the new epoch and cannot unlock.
        assert!(matches!(
            unlock_as_member(&removed.keyring, b"a pass", &a.kdf_params, TREE, MEMBER2, &[pinned], b"r", 0),
            Err(SealerError::MissingWrap)
        ));

        // B (remaining) unlocks the new epoch and reads the owner's post-removal content.
        let bu = unlock_as_member(&removed.keyring, b"b pass", &b.kdf_params, TREE, MEMBER3, &[pinned], b"r-b", 0).unwrap();
        assert_eq!(bu.sealer.open_entry(EntryKind::Snapshot, &new_sealed).unwrap(), b"post-removal secret");

        // The owner still unlocks with their passphrase (identity/KEK preserved across re-key).
        assert!(unlock(&removed.keyring, b"owner pass", TREE, MEMBER, b"r").is_ok());

        // The re-key rotated the recovery code: the new one opens, the original no longer does.
        assert!(recover(&removed.keyring, &removed.recovery_code, b"x", TREE, MEMBER, b"r", 0).is_ok());
        assert!(recover(&removed.keyring, &owner.recovery_code, b"x", TREE, MEMBER, b"r", 0).is_err());
    }

    #[test]
    fn the_owner_cannot_be_removed_and_a_non_member_is_rejected() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        assert!(matches!(
            remove_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER, b"r"),
            Err(SealerError::CannotRemoveOwner)
        ));
        assert!(matches!(
            remove_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, "nobody", b"r"),
            Err(SealerError::MemberNotFound)
        ));
    }
}
