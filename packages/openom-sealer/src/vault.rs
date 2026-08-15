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
    generate_salt, keyring_hash, parse_recovery_code, recovery_kdf_params, sign_keyring,
    verify_keyring, wrap_dek, unwrap_dek, Key32, WrapContext, KEY_LEN,
};
use openom_protocol::v1::{
    AuthorizedSigner, KeyEpoch, KeyWrap, Keyring, Member, MemberRole, SignerRole, WrapMethod,
};
use openom_protocol::{Message, ENVELOPE_VERSION, KEYRING_LAYOUT_VERSION};

use crate::{Sealer, SealerError};

const PASSPHRASE: i32 = WrapMethod::PassphraseArgon2id as i32;
const RECOVERY: i32 = WrapMethod::RecoveryCodeArgon2id as i32;
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

// ---- internals ----

struct Opened {
    dek: Key32,
    key_id: Vec<u8>,
    epoch: u32,
    revision: u32,
    /// SHA-256 of this (opened) keyring's signing bytes — what a re-signed successor
    /// records as its `prev_keyring_hash` to chain the revision history.
    prev_hash: Vec<u8>,
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
    Ok(Opened { dek, key_id: epoch_key_id, epoch, revision: keyring.revision, prev_hash })
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
            public_key: identity_pub,
            member_id: member_id.to_string(),
            role: FOUNDER,
        }],
        members: vec![Member {
            member_id: member_id.to_string(),
            role: OWNER,
            author_public_key: Vec::new(),
            hpke_public_key: Vec::new(),
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
    use super::{change_passphrase, provision, recover, unlock};
    use crate::{EntryKind, SealContext, Sealer, SealerError};
    use openom_crypto::{generate_recovery_code, keyring_hash};
    use openom_protocol::v1::{Keyring, MemberRole, SignerRole};
    use openom_protocol::Message;

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
}
