//! The **web binding** for the sealer — a thin `wasm-bindgen` veneer over the pure
//! [`Sealer`](openom_sealer::Sealer) core. Only compiled with `--features wasm --target wasm32-*`;
//! native (Tauri) callers use the core directly, so this file is the *only* web-specific
//! code and the crypto path stays identical across web and native.
//!
//! Marshalling is deliberately plain wasm-bindgen — no serde:
//! * enums cross as lowercase strings (`"snapshot"`, `"openom-json"`, `"none"`),
//! * bytes cross as `Uint8Array` (`&[u8]` in, `Vec<u8>` out),
//! * the two chain counters cross as JS `number`s, range-checked to a safe integer.
//!
//! That avoids serde-wasm-bindgen's u64-as-`BigInt` and byte-array-as-`Array` surprises;
//! the JS shim (`apps/app/src/core/sealer/`) wraps these calls with ergonomic defaults.

use wasm_bindgen::prelude::*;

use openom_crypto::{Key32, Passphrase, RecoveryCode, KEY_LEN};
use openom_keyring::{
    decode_governing_ref, keyring_hash, verify_reset, verify_walk, KeyringAnchor, VerifyingKey,
};
use crate::attribution::{epoch_is_attributed, verify_entry};
use openom_keyring_dag::client as dag_client;
use openom_protocol::ids::{KeyId, MemberId, ReplicaId, TreeId};
use openom_protocol::v1::{Aead, Compression, Envelope, Format, KdfParams, Keyring, MemberRole};
use openom_protocol::{Message, ENVELOPE_VERSION};

use crate::lifecycle::{KeyringLifecycle, VaultContext};
use crate::{vault, AppVault, DagVault, KeyringRole};
use openom_sealer::{EntryKind, SealContext, Sealer, SealerSet};
use openom_keyring_api::{EngineKind, MembershipEnvelope};

/// A sealing session, exported to JS. Wraps the core [`Sealer`]; the unlocked DEK lives
/// inside WASM linear memory for the session's lifetime (the web tier's documented
/// weaker-isolation trade-off vs. native — see the threat model / SERVER-DATA-FORMAT §16).
#[wasm_bindgen]
pub struct WasmSealer {
    inner: SealerSet,
}

/// The result of [`WasmSealer::seal_entry`]: the wire-ready envelope bytes and the
/// chain hash to thread into the next call. Both surface to JS as `Uint8Array`.
#[wasm_bindgen]
pub struct SealOutcome {
    envelope: Vec<u8>,
    ciphertext_hash: Vec<u8>,
}

#[wasm_bindgen]
impl SealOutcome {
    /// The prost-encoded `Envelope`, ready to upload.
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    /// `SHA-256(ciphertext)` — persist as the next entry's `prevCiphertextHash`.
    #[wasm_bindgen(getter, js_name = ciphertextHash)]
    pub fn ciphertext_hash(&self) -> Vec<u8> {
        self.ciphertext_hash.clone()
    }
}

#[wasm_bindgen]
impl WasmSealer {
    /// A local-development sealer (§16 reserved dev key): the full seal/open path with no
    /// server and no unlock flow, for fast UI iteration. Production refuses its `key_id`.
    pub fn dev(tree_id: &[u8], replica_id: &[u8]) -> WasmSealer {
        WasmSealer {
            inner: SealerSet::single(Sealer::dev(
                TreeId::new(tree_id),
                ReplicaId::new(replica_id),
            )),
        }
    }

    /// Build a sealer from an already-unwrapped 32-byte DEK and its scope. The unlock /
    /// provision flow (Argon2id KEK derivation, DEK unwrap, keyring verification) produces
    /// the DEK and calls this. `aead` is optional (`"xchacha20-poly1305"` default, or
    /// `"aes-256-gcm"`).
    #[wasm_bindgen(js_name = fromUnwrapped)]
    pub fn from_unwrapped(
        dek: &[u8],
        tree_id: &[u8],
        key_id: &[u8],
        replica_id: &[u8],
        aead: Option<String>,
    ) -> Result<WasmSealer, JsError> {
        if dek.len() != KEY_LEN {
            return Err(JsError::new("dek must be exactly 32 bytes"));
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(dek);
        let key: Key32 = zeroize::Zeroizing::new(bytes);

        let mut sealer = Sealer::from_unwrapped(
            ENVELOPE_VERSION,
            key,
            TreeId::new(tree_id),
            KeyId::new(key_id),
            ReplicaId::new(replica_id),
        );
        if let Some(name) = aead {
            sealer = sealer.with_aead(parse_aead(&name)?);
        }
        Ok(WasmSealer {
            inner: SealerSet::single(sealer),
        })
    }

    /// Seal `plaintext` under this sealer's DEK/scope with the caller-supplied chain state.
    /// `kind` ∈ {`snapshot`,`delta`,`media`}, `format` ∈ {`openom-json`}, `compression` ∈
    /// {`none`,`zstd`} (the caller compresses; the sealer only records the label).
    #[wasm_bindgen(js_name = sealEntry)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_entry(
        &self,
        kind: &str,
        format: &str,
        compression: &str,
        replica_counter: f64,
        prev_ciphertext_hash: &[u8],
        covers_through_seq: f64,
        blob_id: &[u8],
        plaintext: &[u8],
    ) -> Result<SealOutcome, JsError> {
        let ctx = SealContext {
            kind: parse_kind(kind)?,
            format: parse_format(format)?,
            compression: parse_compression(compression)?,
            replica_counter: as_u64(replica_counter, "replicaCounter")?,
            prev_ciphertext_hash: prev_ciphertext_hash.to_vec(),
            covers_through_seq: as_u64(covers_through_seq, "coversThroughSeq")?,
            blob_id: blob_id.to_vec(),
        };
        let out = self.inner.seal_entry(&ctx, plaintext).map_err(to_js)?;
        Ok(SealOutcome {
            envelope: out.envelope,
            ciphertext_hash: out.ciphertext_hash,
        })
    }

    /// Decode + scope/kind-verify + AEAD-open an envelope, returning the plaintext.
    #[wasm_bindgen(js_name = openEntry)]
    pub fn open_entry(&self, expect_kind: &str, envelope_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let kind = parse_kind(expect_kind)?;
        self.inner.open_entry(kind, envelope_bytes).map_err(to_js)
    }

    /// The tree this sealer is scoped to.
    #[wasm_bindgen(getter, js_name = treeId)]
    pub fn tree_id(&self) -> Vec<u8> {
        self.inner.tree_id().to_vec()
    }
}

fn parse_kind(s: &str) -> Result<EntryKind, JsError> {
    match s {
        "snapshot" => Ok(EntryKind::Snapshot),
        "delta" => Ok(EntryKind::Delta),
        "media" => Ok(EntryKind::Media),
        "proposal" => Ok(EntryKind::Proposal),
        other => Err(JsError::new(&format!("unknown kind: {other}"))),
    }
}

fn parse_format(s: &str) -> Result<Format, JsError> {
    match s {
        "openom-json" => Ok(Format::OpenomJson),
        "openom-ops" => Ok(Format::OpenomOps),
        "raw-bytes" => Ok(Format::RawBytes),
        other => Err(JsError::new(&format!("unknown format: {other}"))),
    }
}

fn parse_compression(s: &str) -> Result<Compression, JsError> {
    match s {
        "none" => Ok(Compression::None),
        "zstd" => Ok(Compression::Zstd),
        other => Err(JsError::new(&format!("unknown compression: {other}"))),
    }
}

fn parse_aead(s: &str) -> Result<Aead, JsError> {
    match s {
        "xchacha20-poly1305" => Ok(Aead::Xchacha20Poly1305),
        "aes-256-gcm" => Ok(Aead::Aes256Gcm),
        other => Err(JsError::new(&format!("unknown aead: {other}"))),
    }
}

/// A JS `number` is only exact up to 2^53; a u64 counter beyond that would silently
/// round. Reject non-integers and anything past the safe range rather than corrupt the
/// chain — a real openom counter never approaches this.
fn as_u64(n: f64, field: &str) -> Result<u64, JsError> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0; // 2^53 - 1
    if n.is_nan() || n < 0.0 || n.fract() != 0.0 || n > MAX_SAFE {
        return Err(JsError::new(&format!(
            "{field} must be a non-negative integer within 2^53"
        )));
    }
    Ok(n as u64)
}

// Generic over Display so it maps BOTH the vault flows' `VaultError` and a running sealer's lean
// `SealerError` (seal/open) — the veneer surfaces either as an opaque JS error string.
fn to_js(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// Parse the deployment's configured engine tag (a backend preset, never a per-tree user choice — OPE-278).
/// The tag mapping is [`EngineKind`]'s own `FromStr`, so this host and the Tauri host can't drift apart.
fn parse_engine(s: &str) -> Result<EngineKind, JsError> {
    s.parse().map_err(|e: openom_keyring_api::UnknownEngine| JsError::new(&e.to_string()))
}

// ---- the keyring vault (passphrase lifecycle) ----

/// The result of a vault flow. Carries only non-secret outputs — the keyring (to store), the
/// recovery code (to show ONCE), the revision (to watermark), the author `didKey` (a `did:key` over
/// the member's PUBLIC identity key — the claim `createdBy`), and the sealer HANDLE. No raw SECRET
/// key material (DEK/KEK/private identity key) ever crosses to JS; the DEK lives inside the sealer.
#[wasm_bindgen]
pub struct VaultResult {
    keyring: Vec<u8>,
    recovery_code: String,
    did_key: String,
    /// The engine-opaque anti-rollback cursor to persist (chain: the 4-byte revision; dag: the frontier).
    /// Replaces the old scalar `revision` so the same result serves both engines (OPE-278).
    watermark: Vec<u8>,
    /// Advisory: the dag write epoch is stale after a concurrent merge and a reseal is due (always `false`
    /// for the chain). Never blocks; the client repairs it out-of-band.
    needs_reseal: bool,
    /// Advisory: some retained epoch is missing a resolved member's wrap, so the owner should backfill
    /// historical read access (always `false` for the chain). Never blocks; repaired out-of-band (OPE-288).
    needs_backfill: bool,
    sealer: Option<WasmSealer>,
}

#[wasm_bindgen]
impl VaultResult {
    /// The encoded keyring to persist (empty for unlock).
    #[wasm_bindgen(getter)]
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }

    /// The recovery code to show once (empty for unlock).
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    pub fn recovery_code(&self) -> String {
        self.recovery_code.clone()
    }

    /// The author `did:key` (over the member's PUBLIC identity key) — stable across tabs; the claim
    /// `createdBy`. Empty for change-passphrase (no new session).
    #[wasm_bindgen(getter, js_name = didKey)]
    pub fn did_key(&self) -> String {
        self.did_key.clone()
    }

    /// The engine-opaque anti-rollback cursor the caller must persist and pass back as the floor.
    #[wasm_bindgen(getter)]
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }

    /// Whether the dag write epoch needs a reseal (always `false` for the chain).
    #[wasm_bindgen(getter, js_name = needsReseal)]
    pub fn needs_reseal(&self) -> bool {
        self.needs_reseal
    }

    /// Whether some retained epoch needs a historical-read backfill (always `false` for the chain).
    #[wasm_bindgen(getter, js_name = needsBackfill)]
    pub fn needs_backfill(&self) -> bool {
        self.needs_backfill
    }

    /// Take the sealer out to JS (once). `undefined` for change-passphrase (no new sealer).
    #[wasm_bindgen(js_name = takeSealer)]
    pub fn take_sealer(&mut self) -> Option<WasmSealer> {
        self.sealer.take()
    }
}

// Passphrases and recovery codes arrive as owned `String`s — wasm-bindgen hands us ownership
// of the copy it wrote into WASM linear memory. Wrapping a passphrase in `Passphrase` (itself
// zeroizing) immediately scrubs that copy on drop; a recovery code is shown to the user, so
// `RecoveryCode` doesn't zeroize. (The JS-side original string is GC-managed and can't be
// scrubbed; callers minimise its lifetime — documented in the JS shim.)

/// Create a new encrypted tree. Returns the keyring, the recovery code (show once), revision
/// 1, and the sealer.
#[wasm_bindgen]
pub fn provision(
    engine: &str,
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let p = vault
        .provision(&ctx, &Passphrase::new(passphrase.into_bytes()))
        .map_err(to_js)?;
    Ok(VaultResult {
        keyring: p.anchor,
        recovery_code: p.recovery_code.into_string(),
        did_key: p.did_key.into_string(),
        watermark: p.watermark,
        needs_reseal: false,
        needs_backfill: false,
        sealer: Some(WasmSealer { inner: p.sealer }),
    })
}

/// Open an existing keyring with a passphrase; returns the sealer + the opaque watermark.
#[wasm_bindgen]
pub fn unlock(
    engine: &str,
    keyring: &[u8],
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let u = vault
        .unlock(&ctx, keyring, &Passphrase::new(passphrase.into_bytes()))
        .map_err(to_js)?;
    Ok(VaultResult {
        keyring: Vec::new(),
        recovery_code: String::new(),
        did_key: u.did_key.into_string(),
        watermark: u.watermark,
        needs_reseal: u.needs_reseal,
        needs_backfill: u.needs_backfill,
        sealer: Some(WasmSealer { inner: u.sealer }),
    })
}

/// Recover with the recovery code, re-provisioning under a new passphrase. `floor` is the caller's
/// stored opaque watermark (empty if none) — a served anchor below it is refused inside the engine.
#[wasm_bindgen]
pub fn recover(
    engine: &str,
    keyring: &[u8],
    recovery_code: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    floor: &[u8],
) -> Result<VaultResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let r = vault
        .recover(
            &ctx,
            keyring,
            &RecoveryCode::new(recovery_code),
            &Passphrase::new(new_passphrase.into_bytes()),
            floor,
        )
        .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.anchor,
        recovery_code: r.recovery_code.into_string(),
        did_key: r.did_key.into_string(),
        watermark: r.watermark,
        needs_reseal: r.needs_reseal,
        needs_backfill: r.needs_backfill,
        sealer: Some(WasmSealer { inner: r.sealer }),
    })
}

/// Change the passphrase (rotates the recovery code, advances the watermark). No new sealer — the
/// DEK is unchanged, so the running one keeps working. `floor` is the caller's opaque watermark.
#[wasm_bindgen(js_name = changePassphrase)]
pub fn change_passphrase(
    engine: &str,
    keyring: &[u8],
    old_passphrase: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    floor: &[u8],
) -> Result<VaultResult, JsError> {
    let vault = AppVault::from_kind(parse_engine(engine)?);
    let (tree, member, replica) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &replica,
    };
    let re = vault
        .change_passphrase(
            &ctx,
            keyring,
            &Passphrase::new(old_passphrase.into_bytes()),
            &Passphrase::new(new_passphrase.into_bytes()),
            floor,
        )
        .map_err(to_js)?;
    Ok(VaultResult {
        keyring: re.anchor,
        recovery_code: re.recovery_code.into_string(),
        did_key: String::new(),
        watermark: re.watermark,
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

// ---- sharing (member provisioning, invite, unlock, removal) ----

/// The result of [`provision_member`]: the two public keys to share out-of-band with a
/// tree owner, and the opaque KDF params the member persists and passes back at unlock.
#[wasm_bindgen]
pub struct MemberIdentity {
    kdf_params: Vec<u8>,
    author_public: Vec<u8>,
    hpke_public: Vec<u8>,
}

#[wasm_bindgen]
impl MemberIdentity {
    /// The encoded KDF params to persist in the member's account record.
    #[wasm_bindgen(getter, js_name = kdfParams)]
    pub fn kdf_params(&self) -> Vec<u8> {
        self.kdf_params.clone()
    }
    /// The Ed25519 author verify-key to share OOB.
    #[wasm_bindgen(getter, js_name = authorPublic)]
    pub fn author_public(&self) -> Vec<u8> {
        self.author_public.clone()
    }
    /// The X25519 HPKE public key to share OOB.
    #[wasm_bindgen(getter, js_name = hpkePublic)]
    pub fn hpke_public(&self) -> Vec<u8> {
        self.hpke_public.clone()
    }
}

/// Provision a member identity from a passphrase. Stateless — touches no keyring.
#[wasm_bindgen(js_name = provisionMember)]
pub fn provision_member(passphrase: String) -> Result<MemberIdentity, JsError> {
    let m = vault::provision_member(&Passphrase::new(passphrase.into_bytes())).map_err(to_js)?;
    Ok(MemberIdentity {
        kdf_params: m.kdf_params.encode_to_vec(),
        author_public: m.author_public,
        hpke_public: m.hpke_public,
    })
}

/// Add a member (owner action): HPKE-wrap the DEK to their OOB-verified public key and
/// record them in the signed member list. Returns the new keyring to persist and the new
/// revision (no sealer — the owner's session is unchanged).
#[wasm_bindgen(js_name = addMember)]
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    min_revision: u32,
    new_member_id: &str,
    role: &str,
    member_hpke_public: &[u8],
    member_author_public: &[u8],
) -> Result<VaultResult, JsError> {
    let added = vault::add_member(
        keyring,
        &Passphrase::new(owner_passphrase.into_bytes()),
        &TreeId::new(tree_id),
        &MemberId::new(owner_member_id),
        min_revision,
        &MemberId::new(new_member_id),
        parse_member_role(role)?,
        member_hpke_public,
        member_author_public,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: added.keyring,
        recovery_code: String::new(),
        did_key: String::new(),
        watermark: chain_wm_pinned(added.revision, &added.write_key_id, &added.write_dek_hash),
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Unlock a shared tree as a member: verify against the caller's pinned signer keys
/// (`trusted_signers` = concatenated 32-byte Ed25519 verify-keys), then HPKE-unwrap with
/// the member's passphrase. `member_kdf_params` is the blob from [`provision_member`].
#[wasm_bindgen(js_name = unlockAsMember)]
#[allow(clippy::too_many_arguments)]
pub fn unlock_as_member(
    keyring: &[u8],
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    trusted_signers: &[u8],
    replica_id: &[u8],
    min_revision: u32,
) -> Result<VaultResult, JsError> {
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let trusted = parse_trusted_signers(trusted_signers)?;
    let u = vault::unlock_as_member(
        keyring,
        &Passphrase::new(passphrase.into_bytes()),
        &kdf,
        &TreeId::new(tree_id),
        &MemberId::new(member_id),
        &trusted,
        &ReplicaId::new(replica_id),
        min_revision,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: Vec::new(),
        recovery_code: String::new(),
        did_key: u.did_key.into_string(),
        watermark: chain_wm_pinned(u.revision, &u.write_key_id, &u.write_dek_hash),
        needs_reseal: false,
        needs_backfill: false,
        sealer: Some(WasmSealer { inner: u.sealer }),
    })
}

/// Remove a member (owner action) with forward-secure re-key. Returns the new keyring, a
/// rotated recovery code, the new revision, and a sealer scoped to the new epoch.
#[wasm_bindgen(js_name = removeMember)]
#[allow(clippy::too_many_arguments)]
pub fn remove_member(
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    min_revision: u32,
    remove_member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let r = vault::remove_member(
        keyring,
        &Passphrase::new(owner_passphrase.into_bytes()),
        &TreeId::new(tree_id),
        &MemberId::new(owner_member_id),
        min_revision,
        &MemberId::new(remove_member_id),
        &ReplicaId::new(replica_id),
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: String::new(), // removal no longer rotates the recovery code (RRK)
        did_key: String::new(),
        watermark: chain_wm_pinned(r.revision, &r.write_key_id, &r.write_dek_hash),
        needs_reseal: false,
        needs_backfill: false,
        sealer: Some(WasmSealer { inner: r.sealer }),
    })
}

// ---- dag membership authoring (OPE-278) ----
//
// The web-host counterpart to the native VaultHost's dag_* methods. The dag engine's membership + merge +
// reseal live off the shared lifecycle trait (their signatures differ from the chain's — no trusted-signer
// set, no scalar revision), so these dispatch straight to `DagVault`. The `keyring` argument/return is the
// opaque dag anchor; the watermark is its frontier. Anchors ARE the wire form here (unlike the chain, whose
// membership is a keyring blob), so a peer's anchor is merged in via [`dag_merge`].

/// Parse a role tag into the dag engine's [`KeyringRole`] (the openom-roles axis, lower is stronger).
fn parse_keyring_role(s: &str) -> Result<KeyringRole, JsError> {
    match s {
        "owner" => Ok(KeyringRole::OWNER),
        "co-owner" => Ok(KeyringRole::CO_OWNER),
        "maintainer" => Ok(KeyringRole::MAINTAINER),
        "editor" => Ok(KeyringRole::EDITOR),
        "viewer" => Ok(KeyringRole::VIEWER),
        other => Err(JsError::new(&format!("unknown role: {other}"))),
    }
}

/// A 32-byte public key from wire bytes, or an error naming the field.
fn key32(b: &[u8], what: &str) -> Result<[u8; 32], JsError> {
    b.try_into()
        .map_err(|_| JsError::new(&format!("{what} must be 32 bytes, got {}", b.len())))
}

/// The result of [`dag_reseal`]: the (possibly unchanged) anchor + its watermark, and whether a repair was
/// actually appended (`false` = nothing was stale, an idempotent no-op).
#[wasm_bindgen]
pub struct ResealResult {
    keyring: Vec<u8>,
    watermark: Vec<u8>,
    resealed: bool,
}

#[wasm_bindgen]
impl ResealResult {
    /// The anchor to persist (unchanged when `resealed` is false).
    #[wasm_bindgen(getter)]
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }
    /// The frontier watermark to persist.
    #[wasm_bindgen(getter)]
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }
    /// Whether a covering reseal op was appended (false = nothing was stale).
    #[wasm_bindgen(getter)]
    pub fn resealed(&self) -> bool {
        self.resealed
    }
}

/// Add a member to a dag tree (owner action): wrap the DEK to the joiner's OOB-verified keys and append a
/// signed Add op. Returns the new anchor + watermark; no sealer (Add mints no epoch, the owner's is intact).
#[wasm_bindgen(js_name = dagAddMember)]
#[allow(clippy::too_many_arguments)]
pub fn dag_add_member(
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    new_member_id: &str,
    role: &str,
    member_author_public: &[u8],
    member_hpke_public: &[u8],
) -> Result<VaultResult, JsError> {
    let (tree, member, rep) = (
        TreeId::new(tree_id),
        MemberId::new(owner_member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &rep,
    };
    let new_anchor = DagVault
        .add_member(
            &ctx,
            keyring,
            &Passphrase::new(owner_passphrase.into_bytes()),
            new_member_id,
            parse_keyring_role(role)?,
            key32(member_author_public, "member author key")?,
            key32(member_hpke_public, "member hpke key")?,
        )
        .map_err(to_js)?;
    let watermark = DagVault.watermark(&new_anchor).map_err(to_js)?;
    Ok(VaultResult {
        keyring: new_anchor,
        recovery_code: String::new(),
        did_key: String::new(),
        watermark,
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Remove a member from a dag tree (owner action) with forward secrecy: append a Remove op minting a fresh
/// epoch the removed member can't reach, then re-unlock under it — returns the new anchor + watermark + a
/// sealer scoped to the new epoch.
#[wasm_bindgen(js_name = dagRemoveMember)]
pub fn dag_remove_member(
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    remove_member_id: &str,
) -> Result<VaultResult, JsError> {
    let (tree, member, rep) = (
        TreeId::new(tree_id),
        MemberId::new(owner_member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &rep,
    };
    let pass = Passphrase::new(owner_passphrase.into_bytes());
    let new_anchor = DagVault
        .remove_member(&ctx, keyring, &pass, remove_member_id)
        .map_err(to_js)?;
    let watermark = DagVault.watermark(&new_anchor).map_err(to_js)?;
    let u = DagVault.unlock(&ctx, &new_anchor, &pass).map_err(to_js)?;
    Ok(VaultResult {
        keyring: new_anchor,
        recovery_code: String::new(),
        did_key: u.did_key.into_string(),
        watermark,
        needs_reseal: u.needs_reseal,
        needs_backfill: u.needs_backfill,
        sealer: Some(WasmSealer { inner: u.sealer }),
    })
}

/// Unlock a dag tree AS AN ORDINARY member: reach the DEKs via the member's own per-epoch HPKE wraps (not
/// the owner RRK), verifying their passphrase-derived identity against their RESOLVED key. No trusted-signer
/// set (dag membership resolves from the op-DAG). Returns a sealer + watermark + `needsReseal`.
#[wasm_bindgen(js_name = dagUnlockAsMember)]
pub fn dag_unlock_as_member(
    keyring: &[u8],
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let (tree, member, rep) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &rep,
    };
    let u = DagVault
        .unlock_as_member(&ctx, keyring, &Passphrase::new(passphrase.into_bytes()), &kdf)
        .map_err(to_js)?;
    Ok(VaultResult {
        keyring: Vec::new(),
        recovery_code: String::new(),
        did_key: u.did_key.into_string(),
        watermark: u.watermark,
        needs_reseal: u.needs_reseal,
        needs_backfill: u.needs_backfill,
        sealer: Some(WasmSealer { inner: u.sealer }),
    })
}

/// Merge a peer's dag anchor of the SAME tree into the local one (the causal set-union of their op closures)
/// and return the merged anchor + advanced watermark. Merge only ADDS ops, so it can't roll back — no floor.
/// Unlock the result to learn whether the merged write epoch needs a reseal.
#[wasm_bindgen(js_name = dagMerge)]
pub fn dag_merge(local: &[u8], remote: &[u8]) -> Result<VaultResult, JsError> {
    let merged = DagVault.merge(local, remote).map_err(to_js)?;
    let watermark = DagVault.watermark(&merged).map_err(to_js)?;
    Ok(VaultResult {
        keyring: merged,
        recovery_code: String::new(),
        did_key: String::new(),
        watermark,
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Repair a stale write epoch (OPE-282) after a concurrent membership merge: if the resolved keyring needs
/// it, append a covering Reseal op. Idempotent — `resealed=false` (anchor unchanged) when nothing is stale.
/// `floor` is the caller's stored watermark (the anti-rollback floor).
#[wasm_bindgen(js_name = dagReseal)]
pub fn dag_reseal(
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    floor: &[u8],
) -> Result<ResealResult, JsError> {
    let (tree, member, rep) = (
        TreeId::new(tree_id),
        MemberId::new(owner_member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &rep,
    };
    let r = DagVault
        .reseal(&ctx, keyring, &Passphrase::new(owner_passphrase.into_bytes()), floor)
        .map_err(to_js)?;
    Ok(ResealResult {
        keyring: r.anchor,
        watermark: r.watermark,
        resealed: r.resealed,
    })
}

/// Member-authored self-heal of a stale write epoch (OPE-290): the same repair as [`dag_reseal`], but any
/// ACTIVE member can drive it, authorizing with their own `passphrase` + account `member_kdf_params` instead
/// of the owner passphrase — so a member locked out by a concurrent merge doesn't wait for the owner.
/// Idempotent; `floor` is the anti-rollback watermark.
#[wasm_bindgen(js_name = dagResealAsMember)]
pub fn dag_reseal_as_member(
    keyring: &[u8],
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    floor: &[u8],
) -> Result<ResealResult, JsError> {
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let (tree, member, rep) = (
        TreeId::new(tree_id),
        MemberId::new(member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &rep,
    };
    let r = DagVault
        .reseal_as_member(&ctx, keyring, &Passphrase::new(passphrase.into_bytes()), &kdf, floor)
        .map_err(to_js)?;
    Ok(ResealResult {
        keyring: r.anchor,
        watermark: r.watermark,
        resealed: r.resealed,
    })
}

/// The result of [`dag_backfill`]: the (possibly unchanged) anchor + its watermark, and whether
/// historical-read wraps were actually added (`false` = nothing was missing, an idempotent no-op).
#[wasm_bindgen]
pub struct BackfillResult {
    keyring: Vec<u8>,
    watermark: Vec<u8>,
    backfilled: bool,
}

#[wasm_bindgen]
impl BackfillResult {
    /// The anchor to persist (unchanged when `backfilled` is false).
    #[wasm_bindgen(getter)]
    pub fn keyring(&self) -> Vec<u8> {
        self.keyring.clone()
    }
    /// The frontier watermark to persist.
    #[wasm_bindgen(getter)]
    pub fn watermark(&self) -> Vec<u8> {
        self.watermark.clone()
    }
    /// Whether a backfill op was appended (false = every epoch already wrapped every resolved member).
    #[wasm_bindgen(getter)]
    pub fn backfilled(&self) -> bool {
        self.backfilled
    }
}

/// Backfill historical READ access (OPE-288) after a concurrent membership merge: if some retained epoch is
/// missing a resolved member's wrap, the owner re-wraps it for them and appends an `added_wraps` op.
/// Idempotent — `backfilled=false` (anchor unchanged) when nothing is missing. `floor` is the anti-rollback
/// watermark. Owner-authored: only the RRK opens the old DEKs.
#[wasm_bindgen(js_name = dagBackfill)]
pub fn dag_backfill(
    keyring: &[u8],
    owner_passphrase: String,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    floor: &[u8],
) -> Result<BackfillResult, JsError> {
    let (tree, member, rep) = (
        TreeId::new(tree_id),
        MemberId::new(owner_member_id),
        ReplicaId::new(replica_id),
    );
    let ctx = VaultContext {
        tree_id: &tree,
        member_id: &member,
        replica_id: &rep,
    };
    let r = DagVault
        .backfill(&ctx, keyring, &Passphrase::new(owner_passphrase.into_bytes()), floor)
        .map_err(to_js)?;
    Ok(BackfillResult {
        keyring: r.anchor,
        watermark: r.watermark,
        backfilled: r.backfilled,
    })
}

// ---- keyring membership summary + basis (OPE-278/293 client hook) ----
//
// What the client pushes to the server's advisory /access endpoint after a keyring change: the resolved
// {memberId, role} view + the engine-opaque `basis` (its keyring frontier). Plus `keyringCovers` — the
// coverage check the client runs BEFORE asserting, so a causally-stale device doesn't overwrite a newer
// view (dag = check_floor on the frontier; chain = a revision compare). Both engine-neutral to JS: the
// caller (membershipSummary.js) feeds the summary + coversBasis to pushMembershipSummary.

#[derive(serde::Serialize)]
struct KeyringSummaryDto {
    members: Vec<SummaryMemberDto>,
    basis: Vec<String>,
}

#[derive(serde::Serialize)]
struct SummaryMemberDto {
    #[serde(rename = "memberId")]
    member_id: String,
    role: i16,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// A dag frontier (concatenated 32-byte op-ids) → `["op:<hex>", ...]`.
fn dag_basis_tokens(anchor: &[u8]) -> Result<Vec<String>, JsError> {
    let wm = dag_client::watermark(anchor).map_err(|e| JsError::new(&e.to_string()))?;
    if wm.len() % 32 != 0 {
        return Err(JsError::new("dag watermark is not a whole number of op-ids"));
    }
    Ok(wm.chunks_exact(32).map(|c| format!("op:{}", hex(c))).collect())
}

/// Decode `["op:<hex>", ...]` back to the concatenated 32-byte floor for `check_floor`. `None` if any token
/// is malformed (→ treated as "not covered", the safe default that triggers a refresh).
fn dag_floor_from_tokens(tokens: &[String]) -> Option<Vec<u8>> {
    let mut floor = Vec::with_capacity(tokens.len() * 32);
    for t in tokens {
        let h = t.strip_prefix("op:")?;
        if h.len() != 64 {
            return None;
        }
        for i in 0..32 {
            floor.push(u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?);
        }
    }
    Some(floor)
}

/// The resolved advisory membership + the engine-opaque basis for a keyring anchor, as a JSON string
/// `{"members":[{"memberId","role"}],"basis":[...]}` — what the client asserts to the server's /access.
#[wasm_bindgen(js_name = keyringSummary)]
pub fn keyring_summary(engine: &str, keyring: &[u8]) -> Result<String, JsError> {
    let dto = match parse_engine(engine)? {
        EngineKind::Dag => {
            let resolved = dag_client::resolve(keyring).map_err(|e| JsError::new(&e.to_string()))?;
            KeyringSummaryDto {
                members: resolved
                    .members
                    .members
                    .iter()
                    .map(|m| SummaryMemberDto {
                        member_id: m.member_id.clone(),
                        role: m.role,
                    })
                    .collect(),
                basis: dag_basis_tokens(keyring)?,
            }
        }
        EngineKind::Chain => {
            let k = Keyring::decode(keyring).map_err(|e| JsError::new(&format!("bad keyring: {e}")))?;
            KeyringSummaryDto {
                members: k
                    .members
                    .iter()
                    .map(|m| SummaryMemberDto {
                        member_id: m.member_id.clone(),
                        role: m.role as i16,
                    })
                    .collect(),
                basis: vec![format!("rev:{}:{}", k.revision, hex(keyring_hash(&k).as_slice()))],
            }
        }
    };
    serde_json::to_string(&dto).map_err(|e| JsError::new(&e.to_string()))
}

/// Whether this keyring's trust state COVERS `stored_basis` (the frontier a prior /access push was computed
/// from) — the client's pre-push staleness guard. dag: every stored tip op-id is in our op closure
/// (`check_floor`); chain: our revision ≥ the stored revision. An empty basis is trivially covered; a
/// malformed stored basis is treated as NOT covered (safe default — the caller then refreshes).
#[wasm_bindgen(js_name = keyringCovers)]
pub fn keyring_covers(engine: &str, keyring: &[u8], stored_basis: Vec<String>) -> Result<bool, JsError> {
    if stored_basis.is_empty() {
        return Ok(true);
    }
    Ok(match parse_engine(engine)? {
        EngineKind::Dag => match dag_floor_from_tokens(&stored_basis) {
            Some(floor) => dag_client::check_floor(keyring, &floor).is_ok(),
            None => false,
        },
        EngineKind::Chain => {
            let k = Keyring::decode(keyring).map_err(|e| JsError::new(&format!("bad keyring: {e}")))?;
            match stored_basis
                .first()
                .and_then(|t| t.strip_prefix("rev:"))
                .and_then(|s| s.split(':').next())
                .and_then(|n| n.parse::<u32>().ok())
            {
                Some(stored_rev) => k.revision >= stored_rev,
                None => false,
            }
        }
    })
}

/// Add a member **as a co-owner** (any-of): reaches keys via the co-owner's own wraps,
/// verifies against their pinned signer set (`trusted_signers` = concatenated 32-byte keys),
/// and signs with the co-owner's identity.
#[wasm_bindgen(js_name = addMemberAsCoOwner)]
#[allow(clippy::too_many_arguments)]
pub fn add_member_as_co_owner(
    keyring: &[u8],
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    co_owner_member_id: &str,
    trusted_signers: &[u8],
    min_revision: u32,
    new_member_id: &str,
    role: &str,
    member_hpke_public: &[u8],
    member_author_public: &[u8],
) -> Result<VaultResult, JsError> {
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let trusted = parse_trusted_signers(trusted_signers)?;
    let added = vault::add_member_as_co_owner(
        keyring,
        &Passphrase::new(passphrase.into_bytes()),
        &kdf,
        &TreeId::new(tree_id),
        &MemberId::new(co_owner_member_id),
        &trusted,
        min_revision,
        &MemberId::new(new_member_id),
        parse_member_role(role)?,
        member_hpke_public,
        member_author_public,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: added.keyring,
        recovery_code: String::new(),
        did_key: String::new(),
        watermark: chain_wm_pinned(added.revision, &added.write_key_id, &added.write_dek_hash),
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Remove an ordinary member **as a co-owner** (any-of). Returns the re-keyed keyring, new
/// revision, and a sealer scoped to the new epoch.
#[wasm_bindgen(js_name = removeMemberAsCoOwner)]
#[allow(clippy::too_many_arguments)]
pub fn remove_member_as_co_owner(
    keyring: &[u8],
    passphrase: String,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    co_owner_member_id: &str,
    trusted_signers: &[u8],
    min_revision: u32,
    remove_member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let trusted = parse_trusted_signers(trusted_signers)?;
    let r = vault::remove_member_as_co_owner(
        keyring,
        &Passphrase::new(passphrase.into_bytes()),
        &kdf,
        &TreeId::new(tree_id),
        &MemberId::new(co_owner_member_id),
        &trusted,
        min_revision,
        &MemberId::new(remove_member_id),
        &ReplicaId::new(replica_id),
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: String::new(),
        did_key: String::new(),
        watermark: chain_wm_pinned(r.revision, &r.write_key_id, &r.write_dek_hash),
        needs_reseal: false,
        needs_backfill: false,
        sealer: Some(WasmSealer { inner: r.sealer }),
    })
}

/// Promote an existing member to co-owner (founder action). Returns the new keyring +
/// revision (no sealer — signing authority, not keys).
#[wasm_bindgen(js_name = addCoOwner)]
pub fn add_co_owner(
    keyring: &[u8],
    founder_passphrase: String,
    tree_id: &[u8],
    founder_member_id: &str,
    min_revision: u32,
    target_member_id: &str,
) -> Result<VaultResult, JsError> {
    let r = vault::add_co_owner(
        keyring,
        &Passphrase::new(founder_passphrase.into_bytes()),
        &TreeId::new(tree_id),
        &MemberId::new(founder_member_id),
        min_revision,
        &MemberId::new(target_member_id),
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: String::new(),
        did_key: String::new(),
        // A signer-set change opens no epoch — the caller carries the stored write-epoch pin forward onto
        // this revision so a bare-revision watermark can't erase a recover pin (OPE-286 phase 2).
        watermark: r.revision.to_be_bytes().to_vec(),
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Demote a co-owner to an ordinary `new_role` (founder action). Revokes signing authority,
/// not read access (use removeMember to fully revoke).
#[wasm_bindgen(js_name = removeCoOwner)]
#[allow(clippy::too_many_arguments)]
pub fn remove_co_owner(
    keyring: &[u8],
    founder_passphrase: String,
    tree_id: &[u8],
    founder_member_id: &str,
    min_revision: u32,
    target_member_id: &str,
    new_role: &str,
) -> Result<VaultResult, JsError> {
    let r = vault::remove_co_owner(
        keyring,
        &Passphrase::new(founder_passphrase.into_bytes()),
        &TreeId::new(tree_id),
        &MemberId::new(founder_member_id),
        min_revision,
        &MemberId::new(target_member_id),
        parse_member_role(new_role)?,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: String::new(),
        did_key: String::new(),
        // Signer-set change, no epoch opened — caller carries the write-epoch pin forward (OPE-286 phase 2).
        watermark: r.revision.to_be_bytes().to_vec(),
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Accept a keyring run pulled from the **untrusted network** — the chain-walk read-side (its
/// primary purpose). `anchor` is the caller's currently-trusted keyring (its stored head);
/// Unwrap a served [`MembershipEnvelope`] to its chain `Keyring` body bytes. The server stores + returns
/// the engine-opaque envelope; the client's chain walk + per-revision retention operate on the inner
/// keyring. Refuses a non-chain envelope.
fn unwrap_chain_keyring(bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let env = MembershipEnvelope::decode(bytes)
        .map_err(|_| JsError::new("served keyring is not a valid membership envelope"))?;
    if env.engine_kind() != Ok(EngineKind::Chain) {
        return Err(JsError::new("served keyring envelope is not a chain keyring"));
    }
    Ok(env.body)
}

/// `hops` is the concatenation of the successor revisions, each framed as a 4-byte big-endian
/// length followed by its bytes, in ascending revision order with no gaps. Each is validated as
/// a legitimate successor of the last ([`verify_walk`]); a fork, rollback, withheld hop,
/// rogue-signer injection, or unendorsed change throws and the caller persists nothing. On
/// success returns the validated head keyring to store + its revision (no sealer — keyring state
/// only; re-unlock to read a newly-rotated epoch). An empty run is a no-op at the current head.
#[wasm_bindgen(js_name = acceptRemoteKeyring)]
pub fn accept_remote_keyring(
    anchor: &[u8],
    tree_id: &[u8],
    hops: &[u8],
) -> Result<VaultResult, JsError> {
    let anchor_keyring =
        Keyring::decode(anchor).map_err(|e| JsError::new(&format!("bad anchor keyring: {e}")))?;
    if anchor_keyring.tree_id != tree_id {
        return Err(JsError::new("anchor keyring is for a different tree"));
    }
    let raw = split_length_prefixed(hops)?;
    if raw.is_empty() {
        return Ok(VaultResult {
            keyring: Vec::new(),
            recovery_code: String::new(),
            did_key: String::new(),
            // No-op / accept opens no epoch — the caller carries the stored write-epoch pin forward onto
            // this revision rather than let a bare-revision watermark erase a recover pin (OPE-286 phase 2).
            watermark: anchor_keyring.revision.to_be_bytes().to_vec(),
            needs_reseal: false,
            needs_backfill: false,
            sealer: None,
        });
    }
    // Each served hop is now a MembershipEnvelope (the server's opaque stored payload); unwrap it to the
    // chain's Keyring body once here, at ingest, so the rest of the client keeps working on raw Keyring
    // bytes (what it stores + feeds §B3 verify).
    let bodies = raw
        .iter()
        .map(|b| unwrap_chain_keyring(b))
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    let decoded = bodies
        .iter()
        .map(|b| Keyring::decode(b.as_slice()).map_err(|e| JsError::new(&format!("bad served keyring: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let new_anchor = verify_walk(&KeyringAnchor::from_keyring(&anchor_keyring), &decoded)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(VaultResult {
        keyring: bodies.last().expect("non-empty run").clone(),
        recovery_code: String::new(),
        did_key: String::new(),
        watermark: new_anchor.revision.to_be_bytes().to_vec(),
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Verify a landed entry's author attribution (§B3 launch gate). `envelope` is the sealed entry (its
/// header carries the attribution fields), `plaintext` its AEAD-opened payload, `governing` the keyring
/// bytes the caller resolved from `header.governing_ref` (for the chain, the revision it decodes to;
/// fetched + chain-verified by the caller). Throws if the entry
/// wasn't validly authored by a member with the capability its kind requires at the governing revision —
/// the caller then refuses to merge it. The trust decision is the Rust `verify_entry`'s; this only marshals.
///
/// OPE-186 residual: the governing keyring's chain verification is currently the JS caller's
/// responsibility (it can't yet hold the chain-walk's verified Rust token across the wasm boundary), so
/// this wraps the decoded bytes with the deliberately-named `from_unverified_wasm_boundary`. When JS-side
/// verified handles land, this marshals a handle instead and the boundary stops trusting the caller.
#[wasm_bindgen(js_name = verifyEntry)]
pub fn verify_entry_wasm(
    version: u32,
    envelope: &[u8],
    plaintext: &[u8],
    governing: &[u8],
) -> Result<(), JsError> {
    let env =
        Envelope::decode(envelope).map_err(|e| JsError::new(&format!("bad envelope: {e}")))?;
    let header = env
        .header
        .as_ref()
        .ok_or_else(|| JsError::new("envelope has no header"))?;
    // The caller resolved + chain-verified this governing keyring (the chain-walk runs before this call);
    // a JS-side verified handle is the documented future improvement. verify_entry takes the Keyring
    // directly now (the attribution moved out of the chain engine, OPE-300).
    let kr = Keyring::decode(governing)
        .map_err(|e| JsError::new(&format!("bad governing keyring: {e}")))?;
    verify_entry(version, header, plaintext, &kr).map_err(|e| JsError::new(&e.to_string()))
}

/// An entry's attribution coordinates, read from its (AAD-bound) header — enough for the client to decide
/// which keyring revision governs it and whether its epoch requires signatures.
#[wasm_bindgen]
pub struct EntryAttribution {
    keyring_revision: u32,
    key_id: Vec<u8>,
}

#[wasm_bindgen]
impl EntryAttribution {
    /// The keyring revision that governed this entry when authored.
    #[wasm_bindgen(getter, js_name = keyringRevision)]
    pub fn keyring_revision(&self) -> u32 {
        self.keyring_revision
    }
    /// The DEK epoch (key_id) this entry was sealed under.
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> Vec<u8> {
        self.key_id.clone()
    }
}

/// Read an entry's attribution coordinates (governing keyring revision + sealing key_id) from its header,
/// so the client can pick the governing keyring + check whether the epoch is attributed. Both fields are
/// AAD-bound (a keyless server can't rewrite them without failing the AEAD open), so they're trustworthy.
///
/// The header stores the opaque `governing_ref`; this chain-side veneer decodes it to a revision for the
/// JS resolver (empty ⇒ 0, an unattributed V1 entry). A non-empty ref that isn't a valid chain reference
/// is rejected — the caller must not resolve a foreign/malformed ref to a keyring.
#[wasm_bindgen(js_name = entryAttribution)]
pub fn entry_attribution(envelope: &[u8]) -> Result<EntryAttribution, JsError> {
    let env =
        Envelope::decode(envelope).map_err(|e| JsError::new(&format!("bad envelope: {e}")))?;
    let header = env
        .header
        .as_ref()
        .ok_or_else(|| JsError::new("envelope has no header"))?;
    let keyring_revision = if header.governing_ref.is_empty() {
        0
    } else {
        decode_governing_ref(&header.governing_ref)
            .ok_or_else(|| JsError::new("governing_ref is not a valid chain reference"))?
    };
    Ok(EntryAttribution {
        keyring_revision,
        key_id: header.key_id.clone(),
    })
}

/// Whether the epoch `key_id` is attributed in `keyring` — i.e. its DEK was wrapped beyond the sole
/// founder (the tree is shared under it), so entries under it MUST be signed. The client uses this,
/// derived from the VERIFIED keyring (never an entry's own emptiness), to decide whether an unattributed
/// entry is acceptable — closing the downgrade attack.
#[wasm_bindgen(js_name = epochIsAttributed)]
pub fn epoch_is_attributed_wasm(keyring: &[u8], key_id: &[u8]) -> Result<bool, JsError> {
    let kr = Keyring::decode(keyring).map_err(|e| JsError::new(&format!("bad keyring: {e}")))?;
    Ok(epoch_is_attributed(&kr, key_id))
}

/// The moderator `did:key`s (members currently at Maintainer or above) from a keyring — the set the
/// claim engine's fold treats as authorized to remove/supersede/revoke any claim. Returns a JS
/// `string[]`. The caller MUST pass its VERIFIED, watermarked keyring head; feed the result to
/// `FamilyTree.setModerators` on unlock and on every accepted keyring-head change.
#[wasm_bindgen(js_name = moderatorsFromKeyring)]
pub fn moderators_from_keyring_wasm(keyring: &[u8]) -> Result<Vec<String>, JsError> {
    let kr = Keyring::decode(keyring).map_err(|e| JsError::new(&format!("bad keyring: {e}")))?;
    // Chain engine: fold the proto Keyring to the engine-neutral MembershipView, then read moderators off
    // it — the same path a dag-resolved view would take (OPE-308).
    let view = openom_keyring::membership_view(&kr);
    Ok(crate::membership::moderators(&view).into_iter().collect())
}

/// Validate a **recovery/succession reset** keyring against the caller's trusted `anchor` (§B3 slice 4) —
/// the read-side counterpart to the server accepting one. A reset changes the authorized-signer set
/// WITHOUT the old set's endorsement (the old key is lost), so `verify_walk`/`verify_transition` reject it
/// as an unendorsed change; this instead accepts it, but ONLY if it can't roll back or fork: it must be a
/// structurally valid, self-signed, wrap-complete keyring (`verify_reset`) that chains onto the anchor by
/// hash at exactly `anchor.revision + 1`. Trust in the *new signer set* is NOT established here — the
/// CALLER must have shown the new signer fingerprints for out-of-band re-verification and gotten explicit
/// user confirmation BEFORE calling this (it is the commit step). Returns the validated keyring to store.
#[wasm_bindgen(js_name = acceptResetKeyring)]
pub fn accept_reset_keyring(
    anchor: &[u8],
    tree_id: &[u8],
    candidate: &[u8],
) -> Result<VaultResult, JsError> {
    let anchor_kr =
        Keyring::decode(anchor).map_err(|e| JsError::new(&format!("bad anchor keyring: {e}")))?;
    let cand = Keyring::decode(candidate)
        .map_err(|e| JsError::new(&format!("bad candidate keyring: {e}")))?;
    if anchor_kr.tree_id != tree_id || cand.tree_id != tree_id {
        return Err(JsError::new("keyring is for a different tree"));
    }
    // Must supersede our trusted head — never roll back or fork.
    if cand.revision != anchor_kr.revision + 1 {
        return Err(JsError::new(
            "a reset must be exactly the next revision after the trusted head",
        ));
    }
    if cand.prev_keyring_hash.as_slice() != keyring_hash(&anchor_kr) {
        return Err(JsError::new("reset does not chain onto the trusted head"));
    }
    // Reader-side RVK continuity gate: the candidate must pin the SAME recovery authority the trusted head
    // pinned (and be signed by it), so a hostile server can't swap in a reset under an authority we never
    // endorsed. The prior authority is the trusted anchor's own RVK (empty ⇒ pre-RVK head ⇒ gate inert).
    let prior_rvk = KeyringAnchor::from_keyring(&anchor_kr).recovery_verifying_key;
    let new_anchor = verify_reset(
        (!prior_rvk.is_empty()).then_some(prior_rvk.as_slice()),
        &cand,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(VaultResult {
        keyring: candidate.to_vec(),
        recovery_code: String::new(),
        did_key: String::new(),
        watermark: new_anchor.revision.to_be_bytes().to_vec(),
        needs_reseal: false,
        needs_backfill: false,
        sealer: None,
    })
}

/// Split a buffer of `[u32-be length][bytes]…` frames into slices. The framing keeps a list of
/// variable-length keyrings marshallable over the plain-wasm-bindgen boundary (no serde).
fn split_length_prefixed(buf: &[u8]) -> Result<Vec<&[u8]>, JsError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        if i + 4 > buf.len() {
            return Err(JsError::new("truncated length prefix in hops buffer"));
        }
        let len = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        let end = i
            .checked_add(len)
            .ok_or_else(|| JsError::new("length prefix overflow"))?;
        if end > buf.len() {
            return Err(JsError::new("length prefix overruns hops buffer"));
        }
        out.push(&buf[i..end]);
        i = end;
    }
    Ok(out)
}

/// Build a chain watermark that pins the write epoch: `revision(4) ‖ write_key_id(16) ‖ H(DEK)(32)`, the
/// commitment recover authenticates the write epoch against (OPE-286 phase 2). Membership ops that open the
/// write epoch (add/remove member) know its key material, so they emit the full pin rather than a bare
/// revision that would erase a prior recover pin. Falls back to revision-only if the pin isn't sized right.
fn chain_wm_pinned(revision: u32, write_key_id: &[u8], write_dek_hash: &[u8]) -> Vec<u8> {
    let mut wm = revision.to_be_bytes().to_vec();
    if write_key_id.len() == 16 && write_dek_hash.len() == 32 {
        wm.extend_from_slice(write_key_id);
        wm.extend_from_slice(write_dek_hash);
    }
    wm
}

fn parse_member_role(s: &str) -> Result<MemberRole, JsError> {
    match s {
        "owner" => Ok(MemberRole::Owner),
        "co-owner" => Ok(MemberRole::CoOwner),
        "admin" => Ok(MemberRole::Admin),
        "editor" => Ok(MemberRole::Editor),
        "viewer" => Ok(MemberRole::Viewer),
        other => Err(JsError::new(&format!("unknown role: {other}"))),
    }
}

/// Split a flat buffer of concatenated 32-byte Ed25519 verify-keys into pinned signer keys.
/// At least one is required, and the length must be a whole multiple of 32.
fn parse_trusted_signers(bytes: &[u8]) -> Result<Vec<VerifyingKey>, JsError> {
    if bytes.is_empty() || bytes.len() % 32 != 0 {
        return Err(JsError::new(
            "trustedSigners must be one or more concatenated 32-byte keys",
        ));
    }
    bytes
        .chunks_exact(32)
        .map(|c| {
            let arr: [u8; 32] = c.try_into().expect("chunks_exact(32) yields 32 bytes");
            VerifyingKey::from_bytes(&arr).map_err(|_| JsError::new("invalid trusted signer key"))
        })
        .collect()
}
