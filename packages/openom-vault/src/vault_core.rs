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
//! It stays the engine-neutral (as to *keyring engine*) sealing core BOTH engines' vaults share (a
//! discipline kept by review). It DOES marshal its records to the CHAIN keyring's proto shapes
//! (`openom_keyring_chain::wire::KeyEpoch`/`KeyWrap`/`RecoveryKey`, moved out of `openom-protocol` in
//! OPE-300) via the `From` impls below, and touches `openom_protocol` for the wrap AAD + sealer id types +
//! the crypto-path `KdfParams`, and `openom_crypto` for the KDF/AEAD. That is deliberate: OPE-283 scoped this
//! coupling as load-bearing, not incidental — the wrap AAD binds the proto `Envelope` (a compile-time
//! security control) and the KDF params are the proto's, so decoupling would re-derive the wire format and
//! scatter the crypto. `openom-vault` (and `openom-crypto`) are openom-coupled BY DESIGN and keep the
//! `openom-` prefix; only the engine layer below them (keyeo / openom-keyring-api / openom-keyring-dag) is openom-free.

use openom_crypto::{
    default_kdf_params, derive_kek, derive_root, generate_recovery_code, generate_salt,
    parse_recovery_code, recovery_kdf_params, Dek,
    HpkePrivate, Kek, RecoveryCode, RootKeys, RrkSecret,
};
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_protocol::v1::{KdfParams, WrapMethod};
// The keyring key-material layer the vault crypto is lifted onto (aliased to avoid the proto WrapMethod /
// openom KeyId name clashes).
use keyeo_crypto::{
    kek_wrap as keyeo_kek_wrap, member_wrap as keyeo_member_wrap, rrk_wrap as keyeo_rrk_wrap,
    unwrap_dek as keyeo_unwrap_dek, unwrap_kek as keyeo_unwrap_kek, Epoch as KeyeoEpoch,
    GroupContext, GroupId as KeyeoGroupId, KdfBounds, KdfParams as KeyeoKdfParams, KekKind,
    KeyId as KeyeoKeyId, Nonce as KeyeoNonce, Wrap as KeyeoWrap, WrapMethod as KeyeoWrapMethod,
    WrappedDek as KeyeoWrappedDek, X25519PublicKey,
};
// The chain keyring wire (openom-keyring-chain). `RecoveryKey` keeps its structural identity fields (public
// key, member id, RVK) as prost; its escrow KEK wraps ride as keyeo `codec` bytes, encoded at the boundary
// below. The DEK epochs are likewise keyeo `Epoch`s the chain stores as `codec` bytes — no proto sub-message
// marshaling remains here.
use openom_keyring_chain::wire::RecoveryKey;
use serde::{Deserialize, Serialize};

use crate::VaultError;
use openom_sealer::SealerSet;

// The credential-KEK discriminants `open_rrk_secret` maps to a keyeo `KekKind` (the escrow's passphrase /
// recovery-code wraps). The HPKE method discriminants moved into keyeo's `WrapMethod` enum (matched directly).
pub(crate) const PASSPHRASE: i32 = WrapMethod::PassphraseArgon2id as i32;
pub(crate) const RECOVERY: i32 = WrapMethod::RecoveryCodeArgon2id as i32;

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

/// The founder's recovery escrow: the RRK public key, the two KEK wraps of the RRK secret (under the
/// passphrase KEK and the recovery-code KEK — keyeo's native [`KeyeoWrap`], the shape the dag persists), and
/// the pinned Ed25519 recovery verifying key (RVK).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoveryEscrow {
    pub public_key: Vec<u8>,
    pub member_id: String,
    pub wraps: Vec<KeyeoWrap<String>>,
    pub recovery_verifying_key: Vec<u8>,
}

// ---- KDF marshaling to the crypto/derive path's proto `KdfParams` (the member-KDF paths) ----

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
impl From<&RecoveryEscrow> for RecoveryKey {
    fn from(r: &RecoveryEscrow) -> Self {
        Self {
            public_key: r.public_key.clone(),
            member_id: r.member_id.clone(),
            // The escrow's KEK wraps are keyeo `Wrap`s, stored as their canonical `codec` bytes (the chain's
            // `RecoveryKey.wraps` is a bytes field). The RVK stays a separate first-class field.
            wraps: keyeo_crypto::codec::encode_wraps(&r.wraps),
            recovery_verifying_key: r.recovery_verifying_key.clone(),
        }
    }
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
    let group_id = KeyeoGroupId::new(tree_id.to_vec());
    let pass = keyeo_kek_wrap(
        rrk_secret.expose(),
        member_id.to_string(),
        KekKind::Passphrase,
        &s.root.kek,
        keyeo_kdf(&s.pass_kdf),
        &group_id,
    )?;
    let rec = keyeo_kek_wrap(
        rrk_secret.expose(),
        member_id.to_string(),
        KekKind::RecoveryCode,
        &s.recovery_kek,
        keyeo_kdf(&s.recovery_kdf),
        &group_id,
    )?;
    Ok(RecoveryEscrow {
        public_key: rrk_public.to_vec(),
        member_id: member_id.to_string(),
        // keyeo's native KEK wraps — the dag persists these directly; the chain marshals them to proto via
        // `RecoveryKey::from`.
        wraps: vec![pass, rec],
        // The Ed25519 recovery verifying key, derived from the RRK secret via the shared
        // openom_crypto::derive_rvk (so the chain and dag pin an identical RVK). Covered by the keyring
        // signature; a future reset is verified for continuity + authorization against it.
        recovery_verifying_key: openom_crypto::derive_rvk(rrk_secret.expose())
            .verifying_key()
            .to_bytes()
            .to_vec(),
    })
}

// ---- epoch DEK wrap / unwrap (lifted onto keyeo's key-material layer) ----

fn keyeo_kdf(p: &CoreKdf) -> KeyeoKdfParams {
    KeyeoKdfParams {
        salt: p.salt.clone(),
        memory_kib: p.memory_kib,
        iterations: p.iterations,
        parallelism: p.parallelism,
    }
}

/// Open a recovery-escrow KEK wrap of the RRK secret via keyeo (tree-scoped rrk AAD; the derived `kek` is
/// supplied by the caller, so the wrap's `kdf` is irrelevant here).
pub(crate) fn open_rrk_secret(
    kek: &Kek,
    nonce: &[u8],
    wrapped: &[u8],
    tree_id: &[u8],
    member_id: &str,
    wrap_method: i32,
) -> Result<RrkSecret, VaultError> {
    let kind = if wrap_method == PASSPHRASE {
        KekKind::Passphrase
    } else if wrap_method == RECOVERY {
        KekKind::RecoveryCode
    } else {
        return Err(VaultError::BadKeyring("escrow wrap is not a KEK method".into()));
    };
    let wrap = KeyeoWrap {
        recipient: member_id.to_string(),
        method: KeyeoWrapMethod::Kek {
            kind,
            // Unused by unwrap (the KEK is already derived); a placeholder so the record is well-formed.
            kdf: KeyeoKdfParams { salt: Vec::new(), memory_kib: 0, iterations: 0, parallelism: 0 },
            nonce: KeyeoNonce::try_from(nonce).map_err(|_| VaultError::BadKeyring("escrow nonce length".into()))?,
        },
        ciphertext: KeyeoWrappedDek::try_from(wrapped)
            .map_err(|_| VaultError::BadKeyring("escrow ciphertext length".into()))?,
    };
    let group_id = KeyeoGroupId::new(tree_id.to_vec());
    let secret = keyeo_unwrap_kek(&wrap, kek, &group_id)?;
    Ok(RrkSecret::new(*secret))
}

/// The group-at-an-epoch binding context for the vault's `(tree_id, key_id)` pair.
fn epoch_ctx<'a>(group_id: &'a KeyeoGroupId, key_id: &'a KeyeoKeyId) -> GroupContext<'a> {
    GroupContext { group_id, key_id }
}

/// HPKE-wrap an epoch's `dek` to the founder's recovery root **public** key (needs no secret), as the
/// `RrkHpke` wrap that gives the founder cross-epoch access — keyeo's native [`KeyeoWrap`], which both
/// engines persist directly (the chain via its `codec` bytes).
pub(crate) fn rrk_wrap_keyeo(
    rrk_public: &[u8],
    dek: &Dek,
    tree_id: &[u8],
    founder_id: &str,
    key_id: &[u8],
) -> Result<KeyeoWrap<String>, VaultError> {
    let group_id = KeyeoGroupId::new(tree_id.to_vec());
    let kid = KeyeoKeyId::new(key_id.to_vec());
    let rrk_public = X25519PublicKey::try_from(rrk_public)
        .map_err(|_| VaultError::BadKeyring("rrk public key length".into()))?;
    Ok(keyeo_rrk_wrap(dek, founder_id.to_string(), rrk_public, &epoch_ctx(&group_id, &kid))?)
}

/// HPKE-wrap an epoch's `dek` to a MEMBER's public key — the per-member wrap giving them access to this
/// epoch — returning keyeo's native [`KeyeoWrap`]. Mirror of [`rrk_wrap_keyeo`] with the member HPKE method.
pub(crate) fn member_wrap_keyeo(
    member_hpke_public: &[u8],
    dek: &Dek,
    tree_id: &[u8],
    member_id: &str,
    key_id: &[u8],
) -> Result<KeyeoWrap<String>, VaultError> {
    let group_id = KeyeoGroupId::new(tree_id.to_vec());
    let kid = KeyeoKeyId::new(key_id.to_vec());
    let recipient_key = X25519PublicKey::try_from(member_hpke_public)
        .map_err(|_| VaultError::BadKeyring("member hpke key length".into()))?;
    Ok(keyeo_member_wrap(dek, member_id.to_string(), recipient_key, &epoch_ctx(&group_id, &kid))?)
}

/// Open one epoch's DEK from its RRK wrap using the founder's recovery root secret.
pub(crate) fn open_epoch_dek(
    epoch: &KeyeoEpoch<String>,
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &RrkSecret,
) -> Result<Dek, VaultError> {
    let mut w = epoch
        .wraps
        .iter()
        .find(|w| matches!(w.method, KeyeoWrapMethod::RrkHpke { .. }))
        .cloned()
        .ok_or_else(|| VaultError::BadKeyring("epoch missing rrk wrap".into()))?;
    let group_id = KeyeoGroupId::new(tree_id.to_vec());
    // Bind the AAD to the founder (the wrap's recipient IS the founder; making it explicit matches wrap time).
    w.recipient = founder_id.to_string();
    Ok(keyeo_unwrap_dek(&w, rrk_secret.expose(), &epoch_ctx(&group_id, &epoch.key_id))?)
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
    epochs: &[KeyeoEpoch<String>],
    tree_id: &[u8],
    founder_id: &str,
    rrk_secret: &RrkSecret,
) -> Result<Vec<(Vec<u8>, u64, Dek)>, VaultError> {
    Ok(epochs
        .iter()
        .filter_map(|ep| {
            open_epoch_dek(ep, tree_id, founder_id, rrk_secret)
                .ok()
                .map(|dek| (ep.key_id.as_bytes().to_vec(), ep.ordinal, dek))
        })
        .collect())
}

/// Re-wrap every epoch's DEK from the OLD recovery root to a NEW one (the RRK-HPKE wrap only; each
/// member's own HPKE wraps are untouched), returning the updated epochs. Used by `rotate_recovery`: mint
/// a fresh RRK, then move the founder's cross-epoch access onto it so the old recovery secret no longer
/// reaches any DEK.
pub(crate) fn rewrap_epochs_to_new_rrk(
    epochs: &[KeyeoEpoch<String>],
    tree_id: &[u8],
    founder_id: &str,
    old_rrk: &RrkSecret,
    new_rrk_public: &[u8],
) -> Result<Vec<KeyeoEpoch<String>>, VaultError> {
    epochs
        .iter()
        .map(|ep| {
            let dek = open_epoch_dek(ep, tree_id, founder_id, old_rrk)?;
            let new_wrap = rrk_wrap_keyeo(new_rrk_public, &dek, tree_id, founder_id, ep.key_id.as_bytes())?;
            let mut wraps: Vec<KeyeoWrap<String>> = ep
                .wraps
                .iter()
                .filter(|w| !matches!(w.method, KeyeoWrapMethod::RrkHpke { .. }))
                .cloned()
                .collect();
            wraps.push(new_wrap);
            Ok(KeyeoEpoch {
                key_id: ep.key_id.clone(),
                ordinal: ep.ordinal,
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
    epochs: &[KeyeoEpoch<String>],
    tree_id: &[u8],
    member_id: &str,
    hpke_secret: &HpkePrivate,
) -> Result<Vec<(Vec<u8>, u64, Dek)>, VaultError> {
    let group_id = KeyeoGroupId::new(tree_id.to_vec());
    let mut out = Vec::new();
    for ep in epochs {
        // Try EVERY HPKE wrap addressed to this member, not just the first (OPE-290). A backfill/retarget can
        // leave both a stale-key and a current-key wrap for the same member on one epoch; first-match could
        // land on the dead one and wrongly skip an epoch the member CAN open. Take the first that unwraps.
        let dek = ep
            .wraps
            .iter()
            .filter(|w| w.recipient == member_id && matches!(w.method, KeyeoWrapMethod::MemberHpke { .. }))
            .find_map(|w| keyeo_unwrap_dek(w, hpke_secret.expose(), &epoch_ctx(&group_id, &ep.key_id)).ok());
        if let Some(dek) = dek {
            out.push((ep.key_id.as_bytes().to_vec(), ep.ordinal, dek));
        }
    }
    Ok(out)
}

/// Build a [`SealerSet`] from reachable epoch DEKs, writing under the latest one. Errors if
/// the caller reaches no epoch (e.g. a removed member).
pub(crate) fn sealer_set_from_deks(
    tree_id: &[u8],
    replica_id: &[u8],
    deks: Vec<(Vec<u8>, u64, Dek)>,
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
pub(crate) fn write_epoch_by_ordinal(deks: &[(Vec<u8>, u64, Dek)]) -> Result<Vec<u8>, VaultError> {
    deks.iter()
        .max_by_key(|(_, e, _)| *e)
        .map(|(k, _, _)| k.clone())
        .ok_or(VaultError::MissingWrap)
}

/// The Argon2id window this build will run — anything outside it (a hostile keyring) could OOM/CPU-burn the
/// client before any verification, so both KDF validators reject rather than clamp (clamping could silently
/// weaken).
fn kdf_bounds() -> KdfBounds {
    KdfBounds {
        memory_kib: MIN_MEMORY_KIB..=MAX_MEMORY_KIB,
        iterations: 1..=MAX_ITERATIONS,
        parallelism: 1..=MAX_PARALLELISM,
        salt_len: 8..=64,
    }
}

/// Reject an out-of-window `CoreKdf` (a member's own passphrase KDF, proto-sourced).
pub(crate) fn validate_kdf(p: &CoreKdf) -> Result<(), VaultError> {
    if keyeo_kdf(p).validate(&kdf_bounds()) {
        Ok(())
    } else {
        Err(VaultError::BadKdfParams)
    }
}

/// Validate a keyeo KDF (from an escrow KEK wrap) against the same window and return the proto `KdfParams`
/// the crypto derivations (`derive_root` / `derive_kek`) consume.
pub(crate) fn validated_proto_kdf(k: &KeyeoKdfParams) -> Result<KdfParams, VaultError> {
    if !k.validate(&kdf_bounds()) {
        return Err(VaultError::BadKdfParams);
    }
    Ok(KdfParams {
        salt: k.salt.clone(),
        memory_kib: k.memory_kib,
        iterations: k.iterations,
        parallelism: k.parallelism,
    })
}

/// The escrow's KEK wrap of the RRK secret for a credential (`Passphrase` / `RecoveryCode`), returned as its
/// `(kdf, nonce, ciphertext)` — the pieces the owner/recoverer needs to re-derive the KEK and open the RRK
/// (via [`validated_proto_kdf`] + [`open_rrk_secret`]).
pub(crate) fn escrow_kek_wrap(
    wraps: &[KeyeoWrap<String>],
    kind: KekKind,
) -> Result<(&KeyeoKdfParams, &[u8], &[u8]), VaultError> {
    let wrap = wraps
        .iter()
        .find(|w| matches!(&w.method, KeyeoWrapMethod::Kek { kind: k, .. } if *k == kind))
        .ok_or(VaultError::MissingWrap)?;
    match &wrap.method {
        KeyeoWrapMethod::Kek { kdf, nonce, .. } => {
            Ok((kdf, nonce.as_ref(), wrap.ciphertext.as_ref()))
        }
        // `find` already matched a Kek wrap.
        _ => Err(VaultError::MissingWrap),
    }
}
