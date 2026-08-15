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
    default_kdf_params, derive_kek, derive_root, generate_dek, generate_hpke_keypair,
    generate_recovery_code, generate_salt, hpke_unwrap_dek, hpke_wrap_dek, keyring_hash,
    parse_recovery_code, recovery_kdf_params, sign_keyring, unwrap_rrk_secret, verify_keyring,
    verify_keyring_any, wrap_rrk_secret, Key32, RootKeys, SigningKey, VerifyingKey, KEY_LEN,
};
use openom_protocol::aad::wrap_aad;
use openom_protocol::v1::{
    AuthorizedSigner, KdfParams, KeyEpoch, KeyWrap, Keyring, Member, MemberRole, RecoveryKey,
    SignerRole, WrapMethod,
};
use openom_protocol::{Message, KEYRING_LAYOUT_VERSION};

use crate::{SealerError, SealerSet};

const PASSPHRASE: i32 = WrapMethod::PassphraseArgon2id as i32;
const RECOVERY: i32 = WrapMethod::RecoveryCodeArgon2id as i32;
const HPKE: i32 = WrapMethod::X25519Hpke as i32;
/// An epoch DEK wrapped to the founder's recovery root key — the founder's access to every
/// epoch (past, future, and co-owner-minted) via one recovery-key private key.
const RRK_HPKE: i32 = WrapMethod::RrkHpke as i32;
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
/// and the ready sealer set (built from the fresh DEK — one Argon2id, no second unlock).
pub struct Provisioned {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub sealer: SealerSet,
}

/// Result of [`unlock`]: the sealer set (all epochs the caller can reach) plus the keyring
/// `revision` the caller must watermark.
pub struct Unlocked {
    pub sealer: SealerSet,
    pub revision: u32,
}

/// Result of [`recover`]: a freshly re-provisioned keyring + a NEW recovery code (both to
/// store/show), the sealer set, and the new `revision`.
pub struct Recovered {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub sealer: SealerSet,
    pub revision: u32,
}

/// Result of [`change_passphrase`]: the new keyring + a rotated recovery code + new revision.
/// The DEK is unchanged, so the running sealer keeps working — no re-seal of the tree.
pub struct Rekeyed {
    pub keyring: Vec<u8>,
    pub recovery_code: String,
    pub revision: u32,
}

/// Create a brand-new encrypted tree: a fresh DEK under epoch 0, a fresh **recovery root
/// key** (RRK) escrowing that epoch (and every future one), the RRK private key wrapped
/// under the owner's passphrase and a fresh recovery code, all in a keyring signed by the
/// passphrase-derived identity (revision 1). The owner reaches epochs via the RRK, so the
/// keyring holds no per-epoch owner passphrase/recovery wrap.
pub fn provision(
    passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<Provisioned, SealerError> {
    let dek = generate_dek()?;
    let key_id = generate_salt()?.to_vec(); // 16 CSPRNG bytes as the epoch key id
    let (rrk_secret, rrk_public) = generate_hpke_keypair()?;
    let secrets = new_owner_secrets(passphrase)?;

    let epoch0 = KeyEpoch {
        key_id: key_id.clone(),
        epoch: 0,
        wraps: vec![rrk_wrap_epoch(&rrk_public, &dek, tree_id, member_id, &key_id, 0)?],
    };
    let recovery_key = build_recovery_key(&rrk_secret, &rrk_public, tree_id, member_id, &secrets)?;
    let identity_pub = secrets.root.identity.verifying_key().to_bytes().to_vec();

    let mut keyring = Keyring {
        tree_id: tree_id.to_vec(),
        revision: 1,
        layout_version: KEYRING_LAYOUT_VERSION,
        prev_keyring_hash: Vec::new(), // genesis
        authorized_signers: vec![AuthorizedSigner {
            public_key: identity_pub.clone(),
            member_id: member_id.to_string(),
            role: FOUNDER,
        }],
        members: vec![Member {
            member_id: member_id.to_string(),
            role: OWNER,
            author_public_key: identity_pub,
            hpke_public_key: secrets.root.hpke_public.to_vec(),
        }],
        signatures: Vec::new(),
        recovery_keys: vec![recovery_key],
        epochs: vec![epoch0],
    };
    sign_keyring(&mut keyring, &secrets.root.identity);

    let sealer = SealerSet::new(
        tree_id.to_vec(),
        replica_id.to_vec(),
        vec![(key_id.clone(), dek)],
        key_id,
    );
    Ok(Provisioned { keyring: keyring.encode_to_vec(), recovery_code: secrets.recovery_code, sealer })
}

/// Open an existing keyring with a passphrase and build a sealer set spanning every epoch
/// the owner can reach (via the recovery root key). Verifies the keyring with the caller's
/// own derived identity (§4a V1).
pub fn unlock(
    keyring_bytes: &[u8],
    passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<Unlocked, SealerError> {
    let Opened { key_id: write_key_id, revision, rrk_secret, keyring, .. } =
        open_with_passphrase(keyring_bytes, passphrase, tree_id, member_id)?;
    let epochs = epoch_deks(&keyring, tree_id, member_id, &rrk_secret)?
        .into_iter()
        .map(|(k, _e, d)| (k, d))
        .collect();
    let sealer = SealerSet::new(tree_id.to_vec(), replica_id.to_vec(), epochs, write_key_id);
    Ok(Unlocked { sealer, revision })
}

/// Recover with the recovery code and re-establish owner access under `new_passphrase`,
/// **preserving** every member, epoch, and the signer set. The code unwraps the recovery
/// root key, which reaches every epoch — so this is a single O(1) re-wrap of the RRK under
/// the new passphrase + a fresh recovery code, not a per-epoch walk. Verification is skipped
/// (the old identity is unrecoverable) — the recovery wrap's AEAD tag, bound to the trusted
/// `tree_id`, is the authentication.
///
/// No old signature is available, so the new keyring is signed only by the new owner
/// identity: members who pinned the old founder must **re-verify out-of-band** and re-pin —
/// the documented owner-succession boundary. `min_revision` is the caller's watermark floor.
pub fn recover(
    keyring_bytes: &[u8],
    recovery_code: &str,
    new_passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
) -> Result<Recovered, SealerError> {
    let mut keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(SealerError::TreeMismatch);
    }
    // Refuse a rollback BEFORE unwrapping (recovery has no signature to catch it).
    if keyring.revision < min_revision {
        return Err(SealerError::RevisionRollback { have: min_revision, got: keyring.revision });
    }
    // Pull the founder's recovery wrap of the RRK out (owned) so the keyring can be mutated.
    let (rrk_public, kdf, rec_nonce, rec_wrapped) = {
        let rk = recovery_key_for(&keyring, member_id)?;
        let w = rk
            .wraps
            .iter()
            .find(|w| w.wrap_method == RECOVERY)
            .ok_or(SealerError::MissingWrap)?;
        let kdf = w
            .kdf_params
            .clone()
            .ok_or_else(|| SealerError::BadKeyring("rrk recovery wrap missing kdf_params".into()))?;
        (rk.public_key.clone(), kdf, w.nonce.clone(), w.wrapped_dek.clone())
    };
    validate_kdf_params(&kdf)?;
    let entropy = parse_recovery_code(recovery_code)?; // checksum first — fail fast on a typo
    let recovery_kek = derive_kek(entropy.as_slice(), &kdf)?;
    let rrk_secret =
        unwrap_rrk_secret(&recovery_kek, &rec_nonce, &rec_wrapped, tree_id, member_id, RECOVERY)?;

    let new_revision = min_revision
        .max(keyring.revision)
        .checked_add(1)
        .ok_or(SealerError::RevisionOverflow)?;
    let prev_hash = keyring_hash(&keyring).to_vec();
    let secrets = new_owner_secrets(new_passphrase)?;

    // Re-wrap the RRK under the new passphrase + fresh recovery code (epochs untouched).
    let new_rk = build_recovery_key(&rrk_secret, &rrk_public, tree_id, member_id, &secrets)?;
    replace_recovery_key(&mut keyring, member_id, new_rk);
    refounder(&mut keyring, member_id, &secrets.root);
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, &secrets.root.identity);

    let deks = epoch_deks(&keyring, tree_id, member_id, &rrk_secret)?;
    let write_key_id = deks
        .iter()
        .max_by_key(|(_, e, _)| *e)
        .map(|(k, _, _)| k.clone())
        .ok_or_else(|| SealerError::BadKeyring("no epochs".into()))?;
    let epochs = deks.into_iter().map(|(k, _e, d)| (k, d)).collect();
    let sealer = SealerSet::new(tree_id.to_vec(), replica_id.to_vec(), epochs, write_key_id);
    Ok(Recovered { keyring: keyring.encode_to_vec(), recovery_code: secrets.recovery_code, sealer, revision: new_revision })
}

/// Change the passphrase: re-wrap the recovery root key under a new passphrase and a fresh
/// recovery code — a single O(1) operation, since the owner reaches every epoch through the
/// RRK. Members' wraps and every epoch are untouched; the DEKs are unchanged.
///
/// On a **shared** tree the owner's identity changes (new passphrase → new key), so the new
/// keyring is signed by **both** the old and new identity: a member who pinned the old
/// founder key can still verify it (bridging the transition) while the new founder key it now
/// names is what future revisions use. The member's client re-pins on seeing the change.
pub fn change_passphrase(
    keyring_bytes: &[u8],
    old_passphrase: &[u8],
    new_passphrase: &[u8],
    tree_id: &[u8],
    member_id: &str,
    min_revision: u32,
) -> Result<Rekeyed, SealerError> {
    let Opened { rrk_secret, revision, prev_hash, identity: old_identity, mut keyring, .. } =
        open_with_passphrase(keyring_bytes, old_passphrase, tree_id, member_id)?;
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(SealerError::RevisionOverflow)?;
    let secrets = new_owner_secrets(new_passphrase)?;

    let rrk_public = recovery_key_for(&keyring, member_id)?.public_key.clone();
    let new_rk = build_recovery_key(&rrk_secret, &rrk_public, tree_id, member_id, &secrets)?;
    replace_recovery_key(&mut keyring, member_id, new_rk);
    refounder(&mut keyring, member_id, &secrets.root);
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    // Continuity: the OLD identity signs first (so members pinned to it accept this revision),
    // then the new identity (so the owner and future revisions verify).
    sign_keyring(&mut keyring, &old_identity);
    sign_keyring(&mut keyring, &secrets.root.identity);
    Ok(Rekeyed { keyring: keyring.encode_to_vec(), recovery_code: secrets.recovery_code, revision: new_revision })
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
    let Opened { rrk_secret, revision, prev_hash, identity, mut keyring, .. } =
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

    // HPKE-wrap EVERY epoch's DEK to the member (they see the full photo history, not just
    // content from their join epoch forward). The owner reaches all epoch DEKs via the RRK.
    let deks = epoch_deks(&keyring, tree_id, owner_member_id, &rrk_secret)?;
    for (key_id, epoch, dek) in &deks {
        let info = wrap_aad(tree_id, key_id, new_member_id, HPKE, *epoch);
        let w = hpke_wrap_dek(member_hpke_public, dek.as_slice(), &info)?;
        let ep = keyring
            .epochs
            .iter_mut()
            .find(|e| e.epoch == *epoch)
            .ok_or_else(|| SealerError::BadKeyring("epoch vanished".into()))?;
        ep.wraps.push(KeyWrap {
            member_id: new_member_id.to_string(),
            wrap_method: HPKE,
            nonce: Vec::new(), // HPKE carries its own nonce internally
            wrapped_dek: w.ciphertext,
            kdf_params: None,
            ephemeral_public_key: w.encapped_key,
        });
    }
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
    validate_kdf_params(member_kdf)?;
    let root = derive_root(member_passphrase, member_kdf)?;

    // HPKE-unwrap every epoch the member holds a wrap for (they read the full history their
    // wraps cover); write under the latest such epoch. No wrap at all → a removed member.
    let mut epochs: Vec<(u32, Vec<u8>, Key32)> = Vec::new();
    for ep in &keyring.epochs {
        if let Some(w) = ep.wraps.iter().find(|w| w.member_id == member_id && w.wrap_method == HPKE) {
            let info = wrap_aad(tree_id, &ep.key_id, member_id, HPKE, ep.epoch);
            let dek =
                hpke_unwrap_dek(root.hpke_secret.as_slice(), &w.ephemeral_public_key, &w.wrapped_dek, &info)?;
            epochs.push((ep.epoch, ep.key_id.clone(), dek));
        }
    }
    let write_key_id = epochs
        .iter()
        .max_by_key(|(e, _, _)| *e)
        .map(|(_, k, _)| k.clone())
        .ok_or(SealerError::MissingWrap)?;
    let set_epochs = epochs.into_iter().map(|(_e, k, d)| (k, d)).collect();
    let sealer = SealerSet::new(tree_id.to_vec(), replica_id.to_vec(), set_epochs, write_key_id);
    Ok(Unlocked { sealer, revision: keyring.revision })
}

/// Result of [`remove_member`]: the re-keyed keyring to publish, the new revision, and a
/// sealer scoped to the **new** epoch so the caller re-seals the tree snapshot under the new
/// key. No recovery code — the RRK escrows the new epoch, so the code never rotates on a
/// removal.
pub struct MemberRemoved {
    pub keyring: Vec<u8>,
    pub revision: u32,
    pub sealer: SealerSet,
}

/// Remove a member with **forward-secure revocation**: mint a fresh DEK under a new epoch,
/// wrap it only for those who remain — the founder via the recovery root key (HPKE to the
/// RRK **public** key, which needs no secret and so also works for a co-owner-initiated
/// removal) and each other member via HPKE to their pinned key — drop the removed member
/// from the member list and signer set, and re-sign at the next chained revision. Old epochs
/// stay so remaining members still read pre-removal content; the removed member — who never
/// receives a new-epoch wrap — cannot read anything sealed after removal.
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
    let Opened { epoch: old_epoch, revision, prev_hash, identity, rrk_secret, mut keyring, .. } =
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

    // The founder's access: HPKE-wrap the new DEK to the RRK public key (public, in the
    // keyring — no secret needed, so a co-owner could mint this epoch too).
    let rrk_public = recovery_key_for(&keyring, owner_member_id)?.public_key.clone();
    let mut wraps = vec![rrk_wrap_epoch(&rrk_public, &new_dek, tree_id, owner_member_id, &new_key_id, new_epoch)?];

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
    // Strip the removed member's wraps from every (old) epoch too — hygiene, not a new
    // secrecy guarantee (they cached those keys while a member); forward secrecy comes from
    // their absence in the NEW epoch.
    for ep in &mut keyring.epochs {
        ep.wraps.retain(|w| w.member_id != remove_member_id);
    }

    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, &identity);

    // The owner re-seals the tree with a set spanning every epoch (reached via the RRK),
    // writing under the new epoch.
    let epochs = epoch_deks(&keyring, tree_id, owner_member_id, &rrk_secret)?
        .into_iter()
        .map(|(k, _e, d)| (k, d))
        .collect();
    let sealer = SealerSet::new(tree_id.to_vec(), replica_id.to_vec(), epochs, new_key_id);
    Ok(MemberRemoved { keyring: keyring.encode_to_vec(), revision: new_revision, sealer })
}

// ---- internals ----

struct Opened {
    /// The latest epoch's `key_id` (the write epoch) and number.
    key_id: Vec<u8>,
    epoch: u32,
    revision: u32,
    /// SHA-256 of this (opened) keyring's signing bytes — what a re-signed successor
    /// records as its `prev_keyring_hash` to chain the revision history.
    prev_hash: Vec<u8>,
    /// The opener's derived signing identity — to re-sign a mutated keyring (e.g. adding a
    /// member). This is the founder key already in the signer set.
    identity: SigningKey,
    /// The recovery root private key (unwrapped via the passphrase) — reaches every epoch's
    /// DEK, and is re-wrapped in place by change_passphrase.
    rrk_secret: Key32,
    /// The decoded prior keyring, so a mutating flow preserves its signers/members/epochs.
    keyring: Keyring,
}

/// Decode + verify + unwrap the founder's recovery root key via the passphrase, returning
/// the latest-epoch DEK, the RRK secret (which reaches every epoch), and coordinates.
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
    // The owner reaches DEKs through the recovery root key: find its passphrase wrap.
    let (kdf, nonce, wrapped) = {
        let rk = recovery_key_for(&keyring, member_id)?;
        let w = rk
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(SealerError::MissingWrap)?;
        let kdf = w
            .kdf_params
            .clone()
            .ok_or_else(|| SealerError::BadKeyring("rrk passphrase wrap missing kdf_params".into()))?;
        (kdf, w.nonce.clone(), w.wrapped_dek.clone())
    };
    validate_kdf_params(&kdf)?;
    let root = derive_root(passphrase, &kdf)?;
    // §4a V1 (single owner): the trusted signer set is our OWN derived identity — verify the
    // keyring carries a valid signature from it. A wrong passphrase yields a wrong identity →
    // verification fails here (before unwrap). (Sharing verifies against a pinned set.)
    verify_keyring(&keyring, &root.identity.verifying_key())?;
    let rrk_secret = unwrap_rrk_secret(&root.kek, &nonce, &wrapped, tree_id, member_id, PASSPHRASE)?;

    let latest = keyring
        .epochs
        .iter()
        .max_by_key(|e| e.epoch)
        .ok_or_else(|| SealerError::BadKeyring("no epochs".into()))?;
    let key_id = latest.key_id.clone();
    let epoch = latest.epoch;
    let prev_hash = keyring_hash(&keyring).to_vec();
    let revision = keyring.revision;
    Ok(Opened { key_id, epoch, revision, prev_hash, identity: root.identity, rrk_secret, keyring })
}

fn decode_keyring(bytes: &[u8]) -> Result<Keyring, SealerError> {
    if bytes.len() > MAX_KEYRING_BYTES {
        return Err(SealerError::BadKeyring("too large".into()));
    }
    Keyring::decode(bytes).map_err(|e| SealerError::BadKeyring(e.to_string()))
}

/// The new owner secrets minted by provision / passphrase change / recovery: the new
/// passphrase KEK + KDF (and derived identity/HPKE keys), plus a fresh recovery code + its
/// KEK/KDF. Used to (re)wrap the recovery root key under the owner's two credentials.
struct NewOwnerSecrets {
    root: RootKeys,
    pass_kdf: KdfParams,
    recovery_code: String,
    recovery_kek: Key32,
    recovery_kdf: KdfParams,
}

fn new_owner_secrets(new_passphrase: &[u8]) -> Result<NewOwnerSecrets, SealerError> {
    let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
    let root = derive_root(new_passphrase, &pass_kdf)?;
    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    Ok(NewOwnerSecrets { root, pass_kdf, recovery_code, recovery_kek, recovery_kdf })
}

/// Build the founder's [`RecoveryKey`]: the RRK private key wrapped under the new passphrase
/// KEK and the new recovery-code KEK (the only two ways to reach it), bound to the tree-
/// scoped rrk AAD.
fn build_recovery_key(
    rrk_secret: &[u8; KEY_LEN],
    rrk_public: &[u8],
    tree_id: &[u8],
    member_id: &str,
    s: &NewOwnerSecrets,
) -> Result<RecoveryKey, SealerError> {
    let pass = wrap_rrk_secret(&s.root.kek, rrk_secret, tree_id, member_id, PASSPHRASE)?;
    let rec = wrap_rrk_secret(&s.recovery_kek, rrk_secret, tree_id, member_id, RECOVERY)?;
    Ok(RecoveryKey {
        public_key: rrk_public.to_vec(),
        member_id: member_id.to_string(),
        wraps: vec![
            KeyWrap {
                member_id: member_id.to_string(),
                wrap_method: PASSPHRASE,
                nonce: pass.nonce,
                wrapped_dek: pass.wrapped_dek,
                kdf_params: Some(s.pass_kdf.clone()),
                ephemeral_public_key: Vec::new(),
            },
            KeyWrap {
                member_id: member_id.to_string(),
                wrap_method: RECOVERY,
                nonce: rec.nonce,
                wrapped_dek: rec.wrapped_dek,
                kdf_params: Some(s.recovery_kdf.clone()),
                ephemeral_public_key: Vec::new(),
            },
        ],
    })
}

/// HPKE-wrap an epoch's `dek` to the founder's recovery root **public** key (needs no
/// secret), as the `WRAP_METHOD_RRK_HPKE` wrap that gives the founder cross-epoch access.
fn rrk_wrap_epoch(
    rrk_public: &[u8],
    dek: &[u8; KEY_LEN],
    tree_id: &[u8],
    founder_id: &str,
    key_id: &[u8],
    epoch: u32,
) -> Result<KeyWrap, SealerError> {
    let info = wrap_aad(tree_id, key_id, founder_id, RRK_HPKE, epoch);
    let w = hpke_wrap_dek(rrk_public, dek, &info)?;
    Ok(KeyWrap {
        member_id: founder_id.to_string(),
        wrap_method: RRK_HPKE,
        nonce: Vec::new(),
        wrapped_dek: w.ciphertext,
        kdf_params: None,
        ephemeral_public_key: w.encapped_key,
    })
}

/// Open one epoch's DEK from its RRK wrap using the founder's recovery root secret.
fn open_epoch_dek(
    epoch: &KeyEpoch,
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &Key32,
) -> Result<Key32, SealerError> {
    let w = epoch
        .wraps
        .iter()
        .find(|w| w.wrap_method == RRK_HPKE)
        .ok_or_else(|| SealerError::BadKeyring("epoch missing rrk wrap".into()))?;
    let info = wrap_aad(tree_id, &epoch.key_id, founder_id, RRK_HPKE, epoch.epoch);
    Ok(hpke_unwrap_dek(rrk_secret.as_slice(), &w.ephemeral_public_key, &w.wrapped_dek, &info)?)
}

/// Every epoch's `(key_id, epoch, DEK)`, opened via the founder's recovery root secret.
fn epoch_deks(
    keyring: &Keyring,
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &Key32,
) -> Result<Vec<(Vec<u8>, u32, Key32)>, SealerError> {
    keyring
        .epochs
        .iter()
        .map(|ep| Ok((ep.key_id.clone(), ep.epoch, open_epoch_dek(ep, tree_id, founder_id, rrk_secret)?)))
        .collect()
}

/// The founder's recovery key entry (by member id).
fn recovery_key_for<'a>(keyring: &'a Keyring, member_id: &str) -> Result<&'a RecoveryKey, SealerError> {
    keyring
        .recovery_keys
        .iter()
        .find(|r| r.member_id == member_id)
        .ok_or(SealerError::MissingWrap)
}

/// Replace the founder's recovery key entry in place (used by change_passphrase / recover).
fn replace_recovery_key(keyring: &mut Keyring, member_id: &str, new: RecoveryKey) {
    for r in &mut keyring.recovery_keys {
        if r.member_id == member_id {
            *r = new;
            return;
        }
    }
    keyring.recovery_keys.push(new);
}

/// After the owner's key changes, point the founder signer entry and the owner's member
/// entry at the new identity/HPKE keys, so future verification and rotations use them.
fn refounder(keyring: &mut Keyring, member_id: &str, new: &RootKeys) {
    let new_pub = new.identity.verifying_key().to_bytes().to_vec();
    for s in &mut keyring.authorized_signers {
        if s.member_id == member_id {
            s.public_key = new_pub.clone();
        }
    }
    for m in &mut keyring.members {
        if m.member_id == member_id {
            m.author_public_key = new_pub.clone();
            m.hpke_public_key = new.hpke_public.to_vec();
        }
    }
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
    use crate::{EntryKind, SealContext, SealerError, SealerSet};
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

    fn seal_open(sealer: &SealerSet, plaintext: &[u8]) -> Vec<u8> {
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
        // The owner's KDF params live in the recovery key's passphrase wrap now.
        k.recovery_keys[0].wraps[0].kdf_params.as_mut().unwrap().memory_kib = 4_000_000; // ~4 GiB
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

        // Remove A → a re-key (new epoch), revision 4. The recovery code does NOT rotate
        // (the RRK escrows the new epoch), so it isn't returned here.
        let removed = remove_member(&k2.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, b"r-owner2").unwrap();
        assert_eq!(removed.revision, 4);

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
    }

    #[test]
    fn change_passphrase_on_a_shared_tree_keeps_the_member_and_bridges_trust() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let m = provision_member(b"member pass").unwrap();
        let shared = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &m.hpke_public, &m.author_public).unwrap();
        let sealed = {
            let owner_sealer = unlock(&shared.keyring, b"owner pass", TREE, MEMBER, b"r").unwrap().sealer;
            seal_open(&owner_sealer, b"family notes")
        };
        let old_founder = founder_key(&shared.keyring);

        // The owner changes their passphrase on the SHARED tree — no longer refused.
        let re = change_passphrase(&shared.keyring, b"owner pass", b"new pass", TREE, MEMBER, 0).unwrap();

        // The owner opens with the new passphrase, not the old.
        assert!(unlock(&re.keyring, b"new pass", TREE, MEMBER, b"r").is_ok());
        assert!(unlock(&re.keyring, b"owner pass", TREE, MEMBER, b"r").is_err());

        // Continuity: the member still verifies against the key they pinned BEFORE the change
        // (the old founder co-signed the transition), and reads the owner's content.
        let via_old = unlock_as_member(&re.keyring, b"member pass", &m.kdf_params, TREE, MEMBER2, &[old_founder], b"r-m", 0).unwrap();
        assert_eq!(via_old.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"family notes");
        // And also against the new founder key, once re-pinned.
        let new_founder = founder_key(&re.keyring);
        assert!(unlock_as_member(&re.keyring, b"member pass", &m.kdf_params, TREE, MEMBER2, &[new_founder], b"r-m2", 0).is_ok());
    }

    #[test]
    fn recover_on_a_shared_tree_keeps_members_but_forces_reverify() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-owner").unwrap();
        let m = provision_member(b"member pass").unwrap();
        let shared = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Viewer, &m.hpke_public, &m.author_public).unwrap();
        let old_founder = founder_key(&shared.keyring);

        // The owner recovers (lost passphrase) — members are preserved, not wiped.
        let rec = recover(&shared.keyring, &owner.recovery_code, b"new pass", TREE, MEMBER, b"r-o2", 0).unwrap();
        assert!(unlock(&rec.keyring, b"new pass", TREE, MEMBER, b"r").is_ok());

        // Recovery can't co-sign with the old identity, so the member's OLD pin no longer
        // verifies — they must re-verify out-of-band and re-pin the new founder key.
        assert!(unlock_as_member(&rec.keyring, b"member pass", &m.kdf_params, TREE, MEMBER2, &[old_founder], b"r-m", 0).is_err());
        let new_founder = founder_key(&rec.keyring);
        assert!(unlock_as_member(&rec.keyring, b"member pass", &m.kdf_params, TREE, MEMBER2, &[new_founder], b"r-m2", 0).is_ok());
    }

    #[test]
    fn recovery_survives_removals_and_change_passphrase_after_recover() {
        // A removal makes a second epoch. The recovery code does NOT rotate on a removal
        // (the RRK escrows the new epoch), so the ORIGINAL code still recovers afterward.
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-o").unwrap();
        let m = provision_member(b"m pass").unwrap();
        let k1 = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &m.hpke_public, &m.author_public).unwrap();
        let removed = remove_member(&k1.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, b"r-o2").unwrap();

        let rec = recover(&removed.keyring, &owner.recovery_code, b"new pass", TREE, MEMBER, b"r-o3", 0).unwrap();
        assert!(unlock(&rec.keyring, b"new pass", TREE, MEMBER, b"r").is_ok());

        // change_passphrase after a recover on a multi-epoch tree must not brick.
        let ch = change_passphrase(&rec.keyring, b"new pass", b"newer pass", TREE, MEMBER, 0).unwrap();
        assert!(unlock(&ch.keyring, b"newer pass", TREE, MEMBER, b"r").is_ok());
    }

    #[test]
    fn owner_reads_across_epochs_after_a_rotation() {
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-o").unwrap();
        let old = seal_open(&owner.sealer, b"old epoch content"); // epoch 0

        let m = provision_member(b"m pass").unwrap();
        let k1 = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Editor, &m.hpke_public, &m.author_public).unwrap();
        let removed = remove_member(&k1.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, b"r-o2").unwrap();
        let new = seal_open(&removed.sealer, b"new epoch content"); // epoch 1

        // The owner unlocks a set spanning BOTH epochs and reads old and new content.
        let u = unlock(&removed.keyring, b"owner pass", TREE, MEMBER, b"r").unwrap();
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &old).unwrap(), b"old epoch content");
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &new).unwrap(), b"new epoch content");
    }

    #[test]
    fn a_member_added_later_reads_the_pre_join_history() {
        // Content sealed before the member joins is readable by them (all-epoch wraps +
        // multi-epoch read), which is the family-archive behavior we chose.
        let owner = provision(b"owner pass", TREE, MEMBER, b"r-o").unwrap();
        let pre = seal_open(&owner.sealer, b"pre-join photo");
        let m = provision_member(b"m pass").unwrap();
        let added = add_member(&owner.keyring, b"owner pass", TREE, MEMBER, 0, MEMBER2, MemberRole::Viewer, &m.hpke_public, &m.author_public).unwrap();
        let pinned = founder_key(&owner.keyring);
        let u = unlock_as_member(&added.keyring, b"m pass", &m.kdf_params, TREE, MEMBER2, &[pinned], b"r-m", 0).unwrap();
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &pre).unwrap(), b"pre-join photo");
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
