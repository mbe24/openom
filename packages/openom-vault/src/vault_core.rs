//! The engine-neutral **sealing core** — the DEK / epoch / recovery-root-key / KDF / recovery-code /
//! SealerSet machinery, extracted from `vault.rs` so BOTH keyring engines (the chain today, the dag under
//! OPE-273) share one implementation of the security-critical crypto path instead of duplicating it.
//! (OPE-273 gate decision, plan/keyring-dag/design.dag-vault.md.)
//!
//! **This module knows nothing about a keyring's membership, signing, or wire container.** It operates on
//! its OWN plain record types ([`SealedEpoch`] / [`CoreWrap`] / [`RecoveryEscrow`] / [`CoreKdf`]) — a
//! proto-free, releasable-ready API boundary that also serves as the DAG's op-payload record shape. Each
//! engine marshals these to its own persisted form: the chain via the `From` impls below (proto
//! `KeyEpoch`/`KeyWrap`/`RecoveryKey`), the dag by serializing them into ops (OPE-273).
//!
//! It must never import `openom_keyring` or `keyeo` — it stays the engine-neutral sealing core BOTH engines'
//! vaults share (a discipline kept by review; there is no CI grep for it, despite an earlier comment's
//! claim). It DOES still touch `openom_protocol` for the `From` marshaling + the wrap AAD + the sealer's id
//! types — that
//! residual proto coupling (and openom-crypto's own) is what OPE-283 removes to make this crate
//! standalone-publishable; it is a non-API-breaking follow-on, since these signatures are already proto-free.

use openom_crypto::{
    default_kdf_params, derive_kek, derive_root, generate_recovery_code, generate_salt,
    hpke_unwrap_dek, hpke_wrap_dek, parse_recovery_code, recovery_kdf_params, wrap_rrk_secret, Dek,
    HpkePrivate, Kek, RecoveryCode, RootKeys, RrkSecret,
};
use openom_protocol::aad::wrap_aad;
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_protocol::v1::{KdfParams, KeyEpoch, KeyWrap, RecoveryKey, WrapMethod};
use serde::{Deserialize, Serialize};

use crate::VaultError;
use openom_sealer::SealerSet;

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

// ---- the core's own record types (proto-free API boundary; also the dag's op-payload shape) ----

/// Argon2id parameters for a passphrase/recovery-code wrap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CoreKdf {
    pub salt: Vec<u8>,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// One wrap of a secret (a DEK, or the RRK secret) to a credential: a passphrase/recovery-code KEK
/// (`kdf` present) or an HPKE public key (`ephemeral_public_key` present). `wrap_method` is a
/// [`WrapMethod`] discriminant (a plain `i32` so the record stays a dumb data carrier).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CoreWrap {
    pub member_id: String,
    pub wrap_method: i32,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub kdf: Option<CoreKdf>,
    pub ephemeral_public_key: Vec<u8>,
    /// For HPKE / RRK-HPKE wraps: the RECIPIENT public key this wrap addresses (the member's or the RRK's).
    /// An UNAUTHENTICATED hint — the op author writes it, it is NOT cryptographically bound to the ciphertext
    /// — that the dag's `epoch_covers` heuristic reads to spot a wrap left addressed to a member's STALE key
    /// after a rekey race. Never a proof of decryptability (real addressing is enforced by HPKE) (OPE-290).
    pub recipient_public_key: Vec<u8>,
}

/// A DEK epoch: its random `key_id` (also the header's `key_id`), its ordinal, and the wraps that
/// distribute the DEK to members + the founder's RRK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedEpoch {
    pub key_id: Vec<u8>,
    pub epoch: u32,
    pub wraps: Vec<CoreWrap>,
}

/// The founder's recovery escrow: the RRK public key, the two wraps of the RRK secret (under the
/// passphrase KEK and the recovery-code KEK), and the pinned Ed25519 recovery verifying key (RVK).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoveryEscrow {
    pub public_key: Vec<u8>,
    pub member_id: String,
    pub wraps: Vec<CoreWrap>,
    pub recovery_verifying_key: Vec<u8>,
}

// ---- chain marshaling: the `From` impls that bridge the core records to the protobuf keyring wire ----

impl From<&KdfParams> for CoreKdf {
    fn from(p: &KdfParams) -> Self {
        Self {
            salt: p.salt.clone(),
            memory_kib: p.memory_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
        }
    }
}
impl From<&CoreKdf> for KdfParams {
    fn from(k: &CoreKdf) -> Self {
        Self {
            salt: k.salt.clone(),
            memory_kib: k.memory_kib,
            iterations: k.iterations,
            parallelism: k.parallelism,
        }
    }
}
impl From<&KeyWrap> for CoreWrap {
    fn from(w: &KeyWrap) -> Self {
        Self {
            member_id: w.member_id.clone(),
            wrap_method: w.wrap_method,
            nonce: w.nonce.clone(),
            wrapped_dek: w.wrapped_dek.clone(),
            kdf: w.kdf_params.as_ref().map(CoreKdf::from),
            ephemeral_public_key: w.ephemeral_public_key.clone(),
            recipient_public_key: w.recipient_public_key.clone(),
        }
    }
}
impl From<&CoreWrap> for KeyWrap {
    fn from(w: &CoreWrap) -> Self {
        Self {
            member_id: w.member_id.clone(),
            wrap_method: w.wrap_method,
            nonce: w.nonce.clone(),
            wrapped_dek: w.wrapped_dek.clone(),
            kdf_params: w.kdf.as_ref().map(KdfParams::from),
            ephemeral_public_key: w.ephemeral_public_key.clone(),
            recipient_public_key: w.recipient_public_key.clone(),
        }
    }
}
impl From<&KeyEpoch> for SealedEpoch {
    fn from(e: &KeyEpoch) -> Self {
        Self {
            key_id: e.key_id.clone(),
            epoch: e.epoch,
            wraps: e.wraps.iter().map(CoreWrap::from).collect(),
        }
    }
}
impl From<&SealedEpoch> for KeyEpoch {
    fn from(e: &SealedEpoch) -> Self {
        Self {
            key_id: e.key_id.clone(),
            epoch: e.epoch,
            wraps: e.wraps.iter().map(KeyWrap::from).collect(),
        }
    }
}
impl From<&RecoveryEscrow> for RecoveryKey {
    fn from(r: &RecoveryEscrow) -> Self {
        Self {
            public_key: r.public_key.clone(),
            member_id: r.member_id.clone(),
            wraps: r.wraps.iter().map(KeyWrap::from).collect(),
            recovery_verifying_key: r.recovery_verifying_key.clone(),
        }
    }
}

/// Convert a proto epoch list to the core's records — the chain's marshaling at every core call over
/// its epochs.
pub(crate) fn sealed_epochs(epochs: &[KeyEpoch]) -> Vec<SealedEpoch> {
    epochs.iter().map(SealedEpoch::from).collect()
}

// ---- owner secrets + recovery escrow ----

/// The new owner secrets minted by provision / passphrase change / recovery: the new
/// passphrase KEK + KDF (and derived identity/HPKE keys), plus a fresh recovery code + its
/// KEK/KDF. Used to (re)wrap the recovery root key under the owner's two credentials.
pub(crate) struct NewOwnerSecrets {
    pub(crate) root: RootKeys,
    pub(crate) pass_kdf: CoreKdf,
    pub(crate) recovery_code: RecoveryCode,
    pub(crate) recovery_kek: Kek,
    pub(crate) recovery_kdf: CoreKdf,
}

pub(crate) fn new_owner_secrets(new_passphrase: &[u8]) -> Result<NewOwnerSecrets, VaultError> {
    let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
    let root = derive_root(new_passphrase, &pass_kdf)?;
    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    Ok(NewOwnerSecrets {
        root,
        pass_kdf: CoreKdf::from(&pass_kdf),
        recovery_code,
        recovery_kek,
        recovery_kdf: CoreKdf::from(&recovery_kdf),
    })
}

/// Like [`new_owner_secrets`] but REUSING the existing passphrase KDF params (salt), so the derived root
/// — the founder identity and passphrase KEK — is UNCHANGED. Only the recovery code (and its KEK/salt) is
/// fresh. Used by `rotate_recovery`, which keeps the founder + passphrase and changes only the recovery
/// root, so it must not re-found the founder identity the way a passphrase change does.
pub(crate) fn owner_secrets_reusing_pass_kdf(
    passphrase: &[u8],
    pass_kdf: CoreKdf,
) -> Result<NewOwnerSecrets, VaultError> {
    let root = derive_root(passphrase, &KdfParams::from(&pass_kdf))?;
    let recovery_code = generate_recovery_code()?;
    let entropy = parse_recovery_code(&recovery_code)?;
    let recovery_kdf = recovery_kdf_params(generate_salt()?.to_vec());
    let recovery_kek = derive_kek(entropy.as_slice(), &recovery_kdf)?;
    Ok(NewOwnerSecrets {
        root,
        pass_kdf,
        recovery_code,
        recovery_kek,
        recovery_kdf: CoreKdf::from(&recovery_kdf),
    })
}

/// Build the founder's [`RecoveryEscrow`]: the RRK private key wrapped under the new passphrase
/// KEK and the new recovery-code KEK (the only two ways to reach it), bound to the tree-
/// scoped rrk AAD.
pub(crate) fn build_recovery_escrow(
    rrk_secret: &RrkSecret,
    rrk_public: &[u8],
    tree_id: &[u8],
    member_id: &str,
    s: &NewOwnerSecrets,
) -> Result<RecoveryEscrow, VaultError> {
    let pass = wrap_rrk_secret(&s.root.kek, rrk_secret, tree_id, member_id, PASSPHRASE)?;
    let rec = wrap_rrk_secret(&s.recovery_kek, rrk_secret, tree_id, member_id, RECOVERY)?;
    Ok(RecoveryEscrow {
        public_key: rrk_public.to_vec(),
        member_id: member_id.to_string(),
        wraps: vec![
            CoreWrap {
                member_id: member_id.to_string(),
                wrap_method: PASSPHRASE,
                nonce: pass.nonce,
                wrapped_dek: pass.wrapped_dek,
                kdf: Some(s.pass_kdf.clone()),
                ephemeral_public_key: Vec::new(),
                recipient_public_key: Vec::new(), // KDF wrap — no HPKE recipient
            },
            CoreWrap {
                member_id: member_id.to_string(),
                wrap_method: RECOVERY,
                nonce: rec.nonce,
                wrapped_dek: rec.wrapped_dek,
                kdf: Some(s.recovery_kdf.clone()),
                ephemeral_public_key: Vec::new(),
                recipient_public_key: Vec::new(),
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

// ---- epoch DEK wrap / unwrap ----

/// HPKE-wrap an epoch's `dek` to the founder's recovery root **public** key (needs no
/// secret), as the `WRAP_METHOD_RRK_HPKE` wrap that gives the founder cross-epoch access.
pub(crate) fn rrk_wrap_epoch(
    rrk_public: &[u8],
    dek: &Dek,
    tree_id: &[u8],
    founder_id: &str,
    key_id: &[u8],
) -> Result<CoreWrap, VaultError> {
    let info = wrap_aad(tree_id, key_id, founder_id, RRK_HPKE);
    let w = hpke_wrap_dek(rrk_public, dek, &info)?;
    Ok(CoreWrap {
        member_id: founder_id.to_string(),
        wrap_method: RRK_HPKE,
        nonce: Vec::new(),
        wrapped_dek: w.ciphertext,
        kdf: None,
        ephemeral_public_key: w.encapped_key,
        recipient_public_key: rrk_public.to_vec(),
    })
}

/// HPKE-wrap an epoch's `dek` to a MEMBER's public key — the per-member wrap giving them access to this
/// epoch (add-member). Mirror of [`rrk_wrap_epoch`] with the ordinary member HPKE method.
pub(crate) fn member_wrap_epoch(
    member_hpke_public: &[u8],
    dek: &Dek,
    tree_id: &[u8],
    member_id: &str,
    key_id: &[u8],
) -> Result<CoreWrap, VaultError> {
    let info = wrap_aad(tree_id, key_id, member_id, HPKE);
    let w = hpke_wrap_dek(member_hpke_public, dek, &info)?;
    Ok(CoreWrap {
        member_id: member_id.to_string(),
        wrap_method: HPKE,
        nonce: Vec::new(),
        wrapped_dek: w.ciphertext,
        kdf: None,
        ephemeral_public_key: w.encapped_key,
        recipient_public_key: member_hpke_public.to_vec(),
    })
}

/// Open one epoch's DEK from its RRK wrap using the founder's recovery root secret.
pub(crate) fn open_epoch_dek(
    epoch: &SealedEpoch,
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &RrkSecret,
) -> Result<Dek, VaultError> {
    let w = epoch
        .wraps
        .iter()
        .find(|w| w.wrap_method == RRK_HPKE)
        .ok_or_else(|| VaultError::BadKeyring("epoch missing rrk wrap".into()))?;
    let info = wrap_aad(tree_id, &epoch.key_id, founder_id, RRK_HPKE);
    Ok(hpke_unwrap_dek(
        rrk_secret.expose(),
        &w.ephemeral_public_key,
        &w.wrapped_dek,
        &info,
    )?)
}

/// Every epoch's `(key_id, epoch, DEK)`, opened via the founder's recovery root secret.
///
/// TOLERANT (OPE-287): an epoch whose RRK wrap won't open is SKIPPED, not fatal. On the dag any active
/// member can append an op carrying a fresh epoch, so a malicious member could plant a garbage one; opening
/// every epoch strictly (`?`) would let a single junk epoch brick `unlock` for the owner and everyone else.
/// A legitimate epoch always opens under the correct RRK (a wrong passphrase is already caught by the
/// anti-substitution check before this runs), so the chain — whose epochs are signature-protected — never
/// skips, and the owner still reaches every real epoch.
pub(crate) fn epoch_deks(
    epochs: &[SealedEpoch],
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &RrkSecret,
) -> Result<Vec<(Vec<u8>, u32, Dek)>, VaultError> {
    Ok(epochs
        .iter()
        .filter_map(|ep| {
            open_epoch_dek(ep, tree_id, founder_id, rrk_secret)
                .ok()
                .map(|dek| (ep.key_id.clone(), ep.epoch, dek))
        })
        .collect())
}

/// Re-wrap every epoch's DEK from the OLD recovery root to a NEW one (the RRK-HPKE wrap only; each
/// member's own HPKE wraps are untouched), returning the updated epochs. Used by `rotate_recovery`: mint
/// a fresh RRK, then move the founder's cross-epoch access onto it so the old recovery secret no longer
/// reaches any DEK.
pub(crate) fn rewrap_epochs_to_new_rrk(
    epochs: &[SealedEpoch],
    tree_id: &[u8],
    founder_id: &str,
    old_rrk: &RrkSecret,
    new_rrk_public: &[u8],
) -> Result<Vec<SealedEpoch>, VaultError> {
    epochs
        .iter()
        .map(|ep| {
            let dek = open_epoch_dek(ep, tree_id, founder_id, old_rrk)?;
            let new_wrap = rrk_wrap_epoch(new_rrk_public, &dek, tree_id, founder_id, &ep.key_id)?;
            let mut wraps: Vec<CoreWrap> = ep
                .wraps
                .iter()
                .filter(|w| w.wrap_method != RRK_HPKE)
                .cloned()
                .collect();
            wraps.push(new_wrap);
            Ok(SealedEpoch {
                key_id: ep.key_id.clone(),
                epoch: ep.epoch,
                wraps,
            })
        })
        .collect()
}

/// Every `(key_id, epoch, DEK)` a MEMBER reaches via their per-epoch HPKE wraps (the epochs
/// their wraps cover — join-epoch-onward). Empty means a removed member. TOLERANT (OPE-287): a wrap that
/// won't open (a garbage member-authored epoch, or one wrapping the member's stale key) is skipped, not
/// fatal — one junk epoch must not brick a member's unlock (see [`epoch_deks`]).
pub(crate) fn member_epoch_deks(
    epochs: &[SealedEpoch],
    tree_id: &[u8],
    member_id: &str,
    hpke_secret: &HpkePrivate,
) -> Result<Vec<(Vec<u8>, u32, Dek)>, VaultError> {
    let mut out = Vec::new();
    for ep in epochs {
        let info = wrap_aad(tree_id, &ep.key_id, member_id, HPKE);
        // Try EVERY HPKE wrap addressed to this member, not just the first (OPE-290). A backfill/retarget can
        // leave both a stale-key and a current-key wrap for the same member on one epoch; first-match could
        // land on the dead one and wrongly skip an epoch the member CAN open. Take the first that unwraps.
        let dek = ep
            .wraps
            .iter()
            .filter(|w| w.member_id == member_id && w.wrap_method == HPKE)
            .find_map(|w| {
                hpke_unwrap_dek(hpke_secret.expose(), &w.ephemeral_public_key, &w.wrapped_dek, &info).ok()
            });
        if let Some(dek) = dek {
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
    write_key_id: Vec<u8>,
) -> Result<SealerSet, VaultError> {
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

/// The chain's write epoch: the `key_id` of the highest-ordinal epoch. Chain epochs are a single linear
/// sequence, so ordinals never collide — no tiebreak is needed (unlike the dag, which breaks concurrent
/// same-ordinal ties by minting op-id). Choosing the write epoch is the ENGINE's call, not the neutral
/// core's, so it is threaded into [`sealer_set_from_deks`].
pub(crate) fn write_epoch_by_ordinal(deks: &[(Vec<u8>, u32, Dek)]) -> Result<Vec<u8>, VaultError> {
    deks.iter()
        .max_by_key(|(_, e, _)| *e)
        .map(|(k, _, _)| k.clone())
        .ok_or(VaultError::MissingWrap)
}

/// Reject Argon2id `kdf` outside the window this build will run — a hostile keyring could otherwise
/// OOM/CPU-burn the client before any verification. Rejects rather than clamps (clamping could silently
/// weaken).
pub(crate) fn validate_kdf(p: &CoreKdf) -> Result<(), VaultError> {
    let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&p.memory_kib)
        && (1..=MAX_ITERATIONS).contains(&p.iterations)
        && (1..=MAX_PARALLELISM).contains(&p.parallelism)
        && (8..=64).contains(&p.salt.len());
    if ok {
        Ok(())
    } else {
        Err(VaultError::BadKdfParams)
    }
}
