//! The engine-neutral **sealing core** — the DEK / epoch / recovery-root-key / KDF / recovery-code /
//! SealerSet machinery, extracted from `vault.rs` so BOTH keyring engines (the chain today, the dag under
//! OPE-273) share one implementation of the security-critical crypto path instead of duplicating it.
//! (OPE-273 gate decision, plan/keyring-dag/design.dag-vault.md.)
//!
//! **This module knows nothing about a keyring's membership, signing, or wire container.** It operates on
//! epochs (`&[KeyEpoch]`), member/founder ids + HPKE/RRK keys, and passphrases/recovery-codes — the inputs
//! an engine resolves from its own membership + recovery authority. It must never import `openom_keyring`
//! or `keyeo` (a one-line CI grep enforces the neutrality); each engine marshals the core's records into
//! its own persisted form.
//!
//! NOTE (OPE-273 build sequence): this first pass is a behavior-preserving extraction that still speaks the
//! shared protobuf DEK records (`KeyEpoch`/`KeyWrap`/`RecoveryKey`). The gate decided the core's PUBLIC API
//! should become its OWN plain value types (a proto-free, releasable-ready boundary) — that type
//! conversion is the next pass, non-behavioral. OPE-281 (engine-neutral wrap-AAD binding) also lands then.

use openom_crypto::{
    default_kdf_params, derive_kek, derive_root, generate_recovery_code, generate_salt,
    hpke_unwrap_dek, hpke_wrap_dek, parse_recovery_code, recovery_kdf_params, wrap_rrk_secret, Dek,
    HpkePrivate, Kek, RecoveryCode, RootKeys, RrkSecret,
};
use openom_protocol::aad::wrap_aad;
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_protocol::v1::{KdfParams, KeyEpoch, KeyWrap, RecoveryKey, WrapMethod};

use crate::{SealerError, SealerSet};

pub(crate) const PASSPHRASE: i32 = WrapMethod::PassphraseArgon2id as i32;
pub(crate) const RECOVERY: i32 = WrapMethod::RecoveryCodeArgon2id as i32;
pub(crate) const HPKE: i32 = WrapMethod::X25519Hpke as i32;
/// An epoch DEK wrapped to the founder's recovery root key — the founder's access to every
/// epoch (past, future, and co-owner-minted) via one recovery-key private key.
pub(crate) const RRK_HPKE: i32 = WrapMethod::RrkHpke as i32;

// The Argon2id window this build will actually run (checked before the KDF, on params read from an
// unverified keyring). Rejects absurd values rather than clamping — clamping could silently weaken; a
// legitimate future cost increase stays inside this ceiling.
const MIN_MEMORY_KIB: u32 = 8 * 1024; // 8 MiB — the recovery-wrap floor
const MAX_MEMORY_KIB: u32 = 256 * 1024; // 256 MiB — heavy but won't OOM a browser tab
const MAX_ITERATIONS: u32 = 16;
const MAX_PARALLELISM: u32 = 8;

/// The new owner secrets minted by provision / passphrase change / recovery: the new
/// passphrase KEK + KDF (and derived identity/HPKE keys), plus a fresh recovery code + its
/// KEK/KDF. Used to (re)wrap the recovery root key under the owner's two credentials.
pub(crate) struct NewOwnerSecrets {
    pub(crate) root: RootKeys,
    pub(crate) pass_kdf: KdfParams,
    pub(crate) recovery_code: RecoveryCode,
    pub(crate) recovery_kek: Kek,
    pub(crate) recovery_kdf: KdfParams,
}

pub(crate) fn new_owner_secrets(new_passphrase: &[u8]) -> Result<NewOwnerSecrets, SealerError> {
    let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
    let root = derive_root(new_passphrase, &pass_kdf)?;
    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    Ok(NewOwnerSecrets {
        root,
        pass_kdf,
        recovery_code,
        recovery_kek,
        recovery_kdf,
    })
}

/// Like [`new_owner_secrets`] but REUSING the existing passphrase KDF params (salt), so the derived root
/// — the founder identity and passphrase KEK — is UNCHANGED. Only the recovery code (and its KEK/salt) is
/// fresh. Used by `rotate_recovery`, which keeps the founder + passphrase and changes only the recovery
/// root, so it must not re-found the founder identity the way a passphrase change does.
pub(crate) fn owner_secrets_reusing_pass_kdf(
    passphrase: &[u8],
    pass_kdf: KdfParams,
) -> Result<NewOwnerSecrets, SealerError> {
    let root = derive_root(passphrase, &pass_kdf)?;
    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    Ok(NewOwnerSecrets {
        root,
        pass_kdf,
        recovery_code,
        recovery_kek,
        recovery_kdf,
    })
}

/// Build the founder's [`RecoveryKey`]: the RRK private key wrapped under the new passphrase
/// KEK and the new recovery-code KEK (the only two ways to reach it), bound to the tree-
/// scoped rrk AAD.
pub(crate) fn build_recovery_key(
    rrk_secret: &RrkSecret,
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
        // The Ed25519 recovery verifying key, derived from the RRK secret via the shared
        // openom_crypto::derive_rvk (so the chain and dag pin an identical RVK). Covered by the keyring
        // signature; a future reset is verified for continuity + authorization against it.
        recovery_verifying_key: openom_crypto::derive_rvk(rrk_secret.expose())
            .verifying_key()
            .to_bytes()
            .to_vec(),
    })
}

/// HPKE-wrap an epoch's `dek` to the founder's recovery root **public** key (needs no
/// secret), as the `WRAP_METHOD_RRK_HPKE` wrap that gives the founder cross-epoch access.
pub(crate) fn rrk_wrap_epoch(
    rrk_public: &[u8],
    dek: &Dek,
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
pub(crate) fn open_epoch_dek(
    epoch: &KeyEpoch,
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &RrkSecret,
) -> Result<Dek, SealerError> {
    let w = epoch
        .wraps
        .iter()
        .find(|w| w.wrap_method == RRK_HPKE)
        .ok_or_else(|| SealerError::BadKeyring("epoch missing rrk wrap".into()))?;
    let info = wrap_aad(tree_id, &epoch.key_id, founder_id, RRK_HPKE, epoch.epoch);
    Ok(hpke_unwrap_dek(
        rrk_secret.expose(),
        &w.ephemeral_public_key,
        &w.wrapped_dek,
        &info,
    )?)
}

/// Every epoch's `(key_id, epoch, DEK)`, opened via the founder's recovery root secret.
pub(crate) fn epoch_deks(
    epochs: &[KeyEpoch],
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &RrkSecret,
) -> Result<Vec<(Vec<u8>, u32, Dek)>, SealerError> {
    epochs
        .iter()
        .map(|ep| {
            Ok((
                ep.key_id.clone(),
                ep.epoch,
                open_epoch_dek(ep, tree_id, founder_id, rrk_secret)?,
            ))
        })
        .collect()
}

/// Re-wrap every epoch's DEK from the OLD recovery root to a NEW one (the RRK-HPKE wrap only; each
/// member's own HPKE wraps are untouched). Used by `rotate_recovery`: mint a fresh RRK, then move the
/// founder's cross-epoch access onto it so the old recovery secret no longer reaches any DEK.
pub(crate) fn rewrap_epochs_to_new_rrk(
    epochs: &mut [KeyEpoch],
    tree_id: &[u8],
    founder_id: &str,
    old_rrk: &RrkSecret,
    new_rrk_public: &[u8],
) -> Result<(), SealerError> {
    for ep in epochs.iter_mut() {
        let dek = open_epoch_dek(ep, tree_id, founder_id, old_rrk)?;
        let new_wrap = rrk_wrap_epoch(new_rrk_public, &dek, tree_id, founder_id, &ep.key_id, ep.epoch)?;
        ep.wraps.retain(|w| w.wrap_method != RRK_HPKE);
        ep.wraps.push(new_wrap);
    }
    Ok(())
}

/// Every `(key_id, epoch, DEK)` a MEMBER reaches via their per-epoch HPKE wraps (the epochs
/// their wraps cover — join-epoch-onward). Empty means a removed member.
pub(crate) fn member_epoch_deks(
    epochs: &[KeyEpoch],
    tree_id: &[u8],
    member_id: &str,
    hpke_secret: &HpkePrivate,
) -> Result<Vec<(Vec<u8>, u32, Dek)>, SealerError> {
    let mut out = Vec::new();
    for ep in epochs {
        if let Some(w) = ep
            .wraps
            .iter()
            .find(|w| w.member_id == member_id && w.wrap_method == HPKE)
        {
            let info = wrap_aad(tree_id, &ep.key_id, member_id, HPKE, ep.epoch);
            let dek = hpke_unwrap_dek(
                hpke_secret.expose(),
                &w.ephemeral_public_key,
                &w.wrapped_dek,
                &info,
            )?;
            out.push((ep.key_id.clone(), ep.epoch, dek));
        }
    }
    Ok(out)
}

/// Build a [`SealerSet`] from reachable epoch DEKs, writing under the latest one. Errors if
/// the caller reaches no epoch (e.g. a removed member).
pub(crate) fn sealer_set_from_deks(
    tree_id: &[u8],
    replica_id: &[u8],
    deks: Vec<(Vec<u8>, u32, Dek)>,
) -> Result<SealerSet, SealerError> {
    let write_key_id = deks
        .iter()
        .max_by_key(|(_, e, _)| *e)
        .map(|(k, _, _)| k.clone())
        .ok_or(SealerError::MissingWrap)?;
    // Convert to the sealer's raw DEK bag at the boundary (the sealer has no role to confuse a DEK with).
    let epochs = deks
        .into_iter()
        .map(|(k, _e, d)| (k, d.into_inner()))
        .collect();
    Ok(SealerSet::new(
        TreeId::new(tree_id),
        ReplicaId::new(replica_id),
        epochs,
        KeyId::new(write_key_id),
    ))
}

/// Reject Argon2id `kdf_params` outside the window this build will run — a hostile keyring could otherwise
/// OOM/CPU-burn the client before any verification. Rejects rather than clamps (clamping could silently
/// weaken).
pub(crate) fn validate_kdf_params(p: &KdfParams) -> Result<(), SealerError> {
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
