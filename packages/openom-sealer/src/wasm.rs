//! The **web binding** for the sealer — a thin `wasm-bindgen` veneer over the pure
//! [`Sealer`](crate::Sealer) core. Only compiled with `--features wasm --target wasm32-*`;
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
use zeroize::Zeroizing;

use openom_crypto::{epoch_is_attributed, verify_entry, verify_walk, Key32, KeyringAnchor, VerifyingKey, KEY_LEN};
use openom_protocol::v1::{Aead, Compression, Envelope, Format, KdfParams, Keyring, MemberRole};
use openom_protocol::{Message, ENVELOPE_VERSION};

use crate::{vault, EntryKind, SealContext, Sealer, SealerError, SealerSet};

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
            inner: SealerSet::single(Sealer::dev(tree_id.to_vec(), replica_id.to_vec())),
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
            tree_id.to_vec(),
            key_id.to_vec(),
            replica_id.to_vec(),
        );
        if let Some(name) = aead {
            sealer = sealer.with_aead(parse_aead(&name)?);
        }
        Ok(WasmSealer { inner: SealerSet::single(sealer) })
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
        "openom-treelog" => Ok(Format::OpenomTreelog),
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

fn to_js(e: SealerError) -> JsError {
    JsError::new(&e.to_string())
}

// ---- the keyring vault (passphrase lifecycle) ----

/// The result of a vault flow. Carries only non-secret outputs — the keyring (to store), the
/// recovery code (to show ONCE), the revision (to watermark), and the sealer HANDLE. No raw
/// key material (DEK/KEK/identity) ever crosses to JS; the DEK lives inside the sealer.
#[wasm_bindgen]
pub struct VaultResult {
    keyring: Vec<u8>,
    recovery_code: String,
    revision: u32,
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

    /// The keyring revision the caller must watermark.
    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// Take the sealer out to JS (once). `undefined` for change-passphrase (no new sealer).
    #[wasm_bindgen(js_name = takeSealer)]
    pub fn take_sealer(&mut self) -> Option<WasmSealer> {
        self.sealer.take()
    }
}

// Passphrases and recovery codes arrive as owned `String`s — wasm-bindgen hands us ownership
// of the copy it wrote into WASM linear memory, so wrapping them in `Zeroizing` immediately
// scrubs that copy on drop. (The JS-side original string is GC-managed and can't be scrubbed;
// callers minimise its lifetime — documented in the JS shim.)

/// Create a new encrypted tree. Returns the keyring, the recovery code (show once), revision
/// 1, and the sealer.
#[wasm_bindgen]
pub fn provision(
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let passphrase = Zeroizing::new(passphrase);
    let p = vault::provision(passphrase.as_bytes(), tree_id, member_id, replica_id).map_err(to_js)?;
    Ok(VaultResult {
        keyring: p.keyring,
        recovery_code: p.recovery_code,
        revision: 1,
        sealer: Some(WasmSealer { inner: p.sealer }),
    })
}

/// Open an existing keyring with a passphrase; returns the sealer + revision.
#[wasm_bindgen]
pub fn unlock(
    keyring: &[u8],
    passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
) -> Result<VaultResult, JsError> {
    let passphrase = Zeroizing::new(passphrase);
    let u = vault::unlock(keyring, passphrase.as_bytes(), tree_id, member_id, replica_id).map_err(to_js)?;
    Ok(VaultResult {
        keyring: Vec::new(),
        recovery_code: String::new(),
        revision: u.revision,
        sealer: Some(WasmSealer { inner: u.sealer }),
    })
}

/// Recover with the recovery code, re-provisioning under a new passphrase. `min_revision` is
/// the caller's stored watermark (0 if none) — a served revision below it is refused.
#[wasm_bindgen]
pub fn recover(
    keyring: &[u8],
    recovery_code: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
) -> Result<VaultResult, JsError> {
    let recovery_code = Zeroizing::new(recovery_code);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let r = vault::recover(
        keyring,
        recovery_code.as_str(),
        new_passphrase.as_bytes(),
        tree_id,
        member_id,
        replica_id,
        min_revision,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: r.recovery_code,
        revision: r.revision,
        sealer: Some(WasmSealer { inner: r.sealer }),
    })
}

/// Change the passphrase (rotates the recovery code, bumps the revision). No new sealer — the
/// DEK is unchanged, so the running one keeps working.
#[wasm_bindgen(js_name = changePassphrase)]
pub fn change_passphrase(
    keyring: &[u8],
    old_passphrase: String,
    new_passphrase: String,
    tree_id: &[u8],
    member_id: &str,
    min_revision: u32,
) -> Result<VaultResult, JsError> {
    let old_passphrase = Zeroizing::new(old_passphrase);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let re = vault::change_passphrase(
        keyring,
        old_passphrase.as_bytes(),
        new_passphrase.as_bytes(),
        tree_id,
        member_id,
        min_revision,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: re.keyring,
        recovery_code: re.recovery_code,
        revision: re.revision,
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
    let passphrase = Zeroizing::new(passphrase);
    let m = vault::provision_member(passphrase.as_bytes()).map_err(to_js)?;
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
    let owner_passphrase = Zeroizing::new(owner_passphrase);
    let added = vault::add_member(
        keyring,
        owner_passphrase.as_bytes(),
        tree_id,
        owner_member_id,
        min_revision,
        new_member_id,
        parse_member_role(role)?,
        member_hpke_public,
        member_author_public,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: added.keyring,
        recovery_code: String::new(),
        revision: added.revision,
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
    let passphrase = Zeroizing::new(passphrase);
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let trusted = parse_trusted_signers(trusted_signers)?;
    let u = vault::unlock_as_member(
        keyring,
        passphrase.as_bytes(),
        &kdf,
        tree_id,
        member_id,
        &trusted,
        replica_id,
        min_revision,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: Vec::new(),
        recovery_code: String::new(),
        revision: u.revision,
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
    let owner_passphrase = Zeroizing::new(owner_passphrase);
    let r = vault::remove_member(
        keyring,
        owner_passphrase.as_bytes(),
        tree_id,
        owner_member_id,
        min_revision,
        remove_member_id,
        replica_id,
    )
    .map_err(to_js)?;
    Ok(VaultResult {
        keyring: r.keyring,
        recovery_code: String::new(), // removal no longer rotates the recovery code (RRK)
        revision: r.revision,
        sealer: Some(WasmSealer { inner: r.sealer }),
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
    let passphrase = Zeroizing::new(passphrase);
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let trusted = parse_trusted_signers(trusted_signers)?;
    let added = vault::add_member_as_co_owner(
        keyring,
        passphrase.as_bytes(),
        &kdf,
        tree_id,
        co_owner_member_id,
        &trusted,
        min_revision,
        new_member_id,
        parse_member_role(role)?,
        member_hpke_public,
        member_author_public,
    )
    .map_err(to_js)?;
    Ok(VaultResult { keyring: added.keyring, recovery_code: String::new(), revision: added.revision, sealer: None })
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
    let passphrase = Zeroizing::new(passphrase);
    let kdf = KdfParams::decode(member_kdf_params)
        .map_err(|e| JsError::new(&format!("bad kdf params: {e}")))?;
    let trusted = parse_trusted_signers(trusted_signers)?;
    let r = vault::remove_member_as_co_owner(
        keyring,
        passphrase.as_bytes(),
        &kdf,
        tree_id,
        co_owner_member_id,
        &trusted,
        min_revision,
        remove_member_id,
        replica_id,
    )
    .map_err(to_js)?;
    Ok(VaultResult { keyring: r.keyring, recovery_code: String::new(), revision: r.revision, sealer: Some(WasmSealer { inner: r.sealer }) })
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
    let founder_passphrase = Zeroizing::new(founder_passphrase);
    let r = vault::add_co_owner(
        keyring,
        founder_passphrase.as_bytes(),
        tree_id,
        founder_member_id,
        min_revision,
        target_member_id,
    )
    .map_err(to_js)?;
    Ok(VaultResult { keyring: r.keyring, recovery_code: String::new(), revision: r.revision, sealer: None })
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
    let founder_passphrase = Zeroizing::new(founder_passphrase);
    let r = vault::remove_co_owner(
        keyring,
        founder_passphrase.as_bytes(),
        tree_id,
        founder_member_id,
        min_revision,
        target_member_id,
        parse_member_role(new_role)?,
    )
    .map_err(to_js)?;
    Ok(VaultResult { keyring: r.keyring, recovery_code: String::new(), revision: r.revision, sealer: None })
}

/// Accept a keyring run pulled from the **untrusted network** — the chain-walk read-side (its
/// primary purpose). `anchor` is the caller's currently-trusted keyring (its stored head);
/// `hops` is the concatenation of the successor revisions, each framed as a 4-byte big-endian
/// length followed by its bytes, in ascending revision order with no gaps. Each is validated as
/// a legitimate successor of the last ([`verify_walk`]); a fork, rollback, withheld hop,
/// rogue-signer injection, or unendorsed change throws and the caller persists nothing. On
/// success returns the validated head keyring to store + its revision (no sealer — keyring state
/// only; re-unlock to read a newly-rotated epoch). An empty run is a no-op at the current head.
#[wasm_bindgen(js_name = acceptRemoteKeyring)]
pub fn accept_remote_keyring(anchor: &[u8], tree_id: &[u8], hops: &[u8]) -> Result<VaultResult, JsError> {
    let anchor_keyring = Keyring::decode(anchor).map_err(|e| JsError::new(&format!("bad anchor keyring: {e}")))?;
    if anchor_keyring.tree_id != tree_id {
        return Err(JsError::new("anchor keyring is for a different tree"));
    }
    let raw = split_length_prefixed(hops)?;
    if raw.is_empty() {
        return Ok(VaultResult { keyring: Vec::new(), recovery_code: String::new(), revision: anchor_keyring.revision, sealer: None });
    }
    let decoded = raw
        .iter()
        .map(|b| Keyring::decode(*b).map_err(|e| JsError::new(&format!("bad served keyring: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let new_anchor = verify_walk(&KeyringAnchor::from_keyring(&anchor_keyring), &decoded)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(VaultResult {
        keyring: raw.last().expect("non-empty run").to_vec(),
        recovery_code: String::new(),
        revision: new_anchor.revision,
        sealer: None,
    })
}

/// Verify a landed entry's author attribution (§B3 launch gate). `envelope` is the sealed entry (its
/// header carries the attribution fields), `plaintext` its AEAD-opened payload, `governing` the keyring
/// bytes at `header.keyring_revision` (which the caller fetched + chain-verified). Throws if the entry
/// wasn't validly authored by a member with the capability its kind requires at the governing revision —
/// the caller then refuses to merge it. The trust decision is the Rust `verify_entry`'s; this only marshals.
#[wasm_bindgen(js_name = verifyEntry)]
pub fn verify_entry_wasm(version: u32, envelope: &[u8], plaintext: &[u8], governing: &[u8]) -> Result<(), JsError> {
    let env = Envelope::decode(envelope).map_err(|e| JsError::new(&format!("bad envelope: {e}")))?;
    let header = env.header.as_ref().ok_or_else(|| JsError::new("envelope has no header"))?;
    let kr = Keyring::decode(governing).map_err(|e| JsError::new(&format!("bad governing keyring: {e}")))?;
    verify_entry(version, header, plaintext, &kr).map_err(|e| JsError::new(&e.to_string()))
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
        let end = i.checked_add(len).ok_or_else(|| JsError::new("length prefix overflow"))?;
        if end > buf.len() {
            return Err(JsError::new("length prefix overruns hops buffer"));
        }
        out.push(&buf[i..end]);
        i = end;
    }
    Ok(out)
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
        return Err(JsError::new("trustedSigners must be one or more concatenated 32-byte keys"));
    }
    bytes
        .chunks_exact(32)
        .map(|c| {
            let arr: [u8; 32] = c.try_into().expect("chunks_exact(32) yields 32 bytes");
            VerifyingKey::from_bytes(&arr).map_err(|_| JsError::new("invalid trusted signer key"))
        })
        .collect()
}
