//! The openom binding of `keyeo-chain`: `KeyringRole` (openom's ordinal role) + `KeyringDoc` (a `Keyring`
//! viewed as a [`keyeo_chain::Doc`]). The generic engine reasons over the accessors here and signs
//! the message it builds from them; the openom `Keyring` payload rides through `payload_commitment`.
//!
//! The engine owns the generic signed fields (group id, revision, prev-hash, layout, members, governance,
//! recovery authority — see `keyeo_chain::signing_bytes`). This binding owns [`KeyringDoc::payload_commit`]
//! (an exhaustive `#[deny(unused_variables)]` hash of the WHOLE keyring payload) and [`KeyringDoc::structure`]
//! (the payload/structural acceptance gate: layout bound, size caps, epochs, epoch ordinals,
//! signer-key length, wrap-completeness).

use keyeo_chain::Ed25519;
use keyeo_chain::{DocHash, GroupId, Governance, Doc, SignerRole, PayloadCommitment, Revision, Signer};
use keyeo_crypto::{missing, Epoch, RecipientDescriptor, Wrap, WrapMethod};
use sha2::{Digest, Sha256};

use crate::wire::{Keyring, Member, RecoveryKey, KEYRING_LAYOUT_VERSION, MEMBER_OWNER};

/// Bounds on an accepted keyring's list sizes — a family tree is far under these; they only stop a hostile
/// keyring from forcing pathological work before verification. (The signer set is a subset of `members`.)
pub(crate) const MAX_MEMBERS: usize = 4096;
pub(crate) const MAX_EPOCHS: usize = 4096;

/// Domain separation for the chain's payload commitment (bound into the engine's signed bytes).
const PAYLOAD_TAG: &[u8] = b"openom:keyring:payload:v1";

// Structure-gate sentinels the chain maps back to its `KeyringError` taxonomy (see `chain::map_linear_err`).
pub(crate) const S_LAYOUT_AHEAD: &str = "layout ahead";
pub(crate) const S_WRAP_INCOMPLETE: &str = "wrap incomplete";
pub(crate) const S_LIST_TOO_LARGE: &str = "list too large";
pub(crate) const S_NO_EPOCHS: &str = "no epochs";
pub(crate) const S_EPOCH_ORDINAL: &str = "epoch ordinal out of range";
pub(crate) const S_SIGNER_KEY: &str = "signer key malformed";
/// A stored key-material blob (epochs, or a recovery key's escrow wraps) is malformed, over-long, or has
/// trailing bytes — decode failed. A hard reject: the acceptance gate must never proceed on key material it
/// cannot read (an empty/defaulted fallback would silently drop epochs).
pub(crate) const S_BAD_KEY_MATERIAL: &str = "key material malformed";

/// openom's single ordinal role, wrapping the proto `MemberRole` value (lower is stronger). The engine
/// derives signer-ness/founder-ness from it; it never learns openom's specific ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct KeyringRole(pub i16);

impl keyeo_chain::Role for KeyringRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        // Lower ordinal = stronger (Owner==1 is strongest).
        self.0 <= other.0
    }
}
impl SignerRole for KeyringRole {
    fn is_founder(&self) -> bool {
        self.0 == i16::try_from(MEMBER_OWNER).unwrap_or(i16::MAX)
    }
    fn is_signer(&self) -> bool {
        (1..=2).contains(&self.0)
    }
}

/// Coerce an arbitrary-length public-key byte string to the engine's `[u8; 32]`. A signer's key is always
/// exactly 32 bytes (enforced in [`KeyringDoc::structure`] before the engine's key checks run); a non-signer
/// member's key is cosmetic to the engine (bound in full through `payload_commitment`), so padding/
/// truncation here is safe and cannot lose coverage.
pub(crate) fn to_pk32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// A `Keyring` presented as a [`Doc`]. Holds owned `GroupId` / `DocHash` / `PayloadCommitment` so the
/// by-reference accessors can hand out borrows (mirrors the reference `TestDoc`).
pub(crate) struct KeyringDoc<'a> {
    keyring: &'a Keyring,
    group_id: GroupId,
    prev_hash: DocHash,
    payload_commitment: PayloadCommitment,
}

impl<'a> KeyringDoc<'a> {
    pub(crate) fn new(keyring: &'a Keyring) -> Self {
        Self {
            group_id: GroupId(keyring.tree_id.clone()),
            prev_hash: DocHash(to_pk32(&keyring.prev_keyring_hash)),
            payload_commitment: PayloadCommitment(Self::payload_commit(keyring)),
            keyring,
        }
    }

    /// `SHA-256(PAYLOAD_TAG ‖ length-prefixed EXHAUSTIVE encode of the WHOLE keyring payload)`. The
    /// `#[deny(unused_variables)]` destructure of every message is the guard: a newly-added payload field
    /// is a compile error until it is written into the commitment. Covers the full payload (epochs, wraps,
    /// recovery keys incl. the RVK, member hpke keys, governance) — redundant with the engine's signed
    /// fields where they overlap (members/governance), which is free (hashed) and crack-proof. `signatures`
    /// is the one field excluded (it is not part of what is signed).
    fn payload_commit(k: &Keyring) -> [u8; 32] {
        let mut out = Vec::with_capacity(256);
        put_bytes(&mut out, PAYLOAD_TAG);
        #[deny(unused_variables)]
        let Keyring {
            tree_id,
            epochs,
            revision,
            layout_version,
            prev_keyring_hash,
            members,
            signatures: _, // excluded: not part of the signed payload
            recovery_keys,
            governance_kind,
            governance_threshold,
            first_shared_revision,
        } = k;
        put_bytes(&mut out, tree_id);
        put_u32(&mut out, *revision);
        put_u32(&mut out, *layout_version);
        put_bytes(&mut out, prev_keyring_hash);

        // Length prefix; fail-closed on the impossible >u32 count, so saturate.
        put_u32(&mut out, u32::try_from(members.len()).unwrap_or(u32::MAX));
        for m in members {
            #[deny(unused_variables)]
            let Member { member_id, role, author_public_key, hpke_public_key } = m;
            put_bytes(&mut out, member_id.as_bytes());
            // `role` is a non-negative proto tag: bit-identical to `as u32`, but sign-loss-free.
            put_u32(&mut out, u32::try_from(*role).unwrap_or(0));
            put_bytes(&mut out, author_public_key);
            put_bytes(&mut out, hpke_public_key);
        }

        // The DEK epochs are keyeo key material carried as their canonical `codec` bytes — hash them
        // DIRECTLY (length-prefixed), never decode+re-encode. The producer signs these exact bytes; every
        // verifier hashes the same stored bytes, so postcard canonicity is not load-bearing for the signature
        // (a mutated blob simply fails the signature), and serde-derive exhaustiveness — guarded by the
        // sentinel `_key_material_fields_are_exhaustively_accounted_for` below + the codec's per-field
        // mutation tests — keeps every field bound without a second hand-encoder that could drift.
        put_bytes(&mut out, epochs);

        put_u32(&mut out, u32::try_from(recovery_keys.len()).unwrap_or(u32::MAX));
        for rk in recovery_keys {
            #[deny(unused_variables)]
            let RecoveryKey { public_key, member_id, wraps, recovery_verifying_key } = rk;
            put_bytes(&mut out, public_key);
            put_bytes(&mut out, member_id.as_bytes());
            put_bytes(&mut out, wraps); // the escrow KEK wraps' canonical codec bytes, hashed directly
            put_bytes(&mut out, recovery_verifying_key);
        }
        put_u32(&mut out, *governance_kind);
        put_u32(&mut out, *governance_threshold);
        put_u32(&mut out, *first_shared_revision);

        let mut h = Sha256::new();
        h.update(&out);
        h.finalize().into()
    }

    /// The payload/structural acceptance gate (the engine calls it at EVERY entry point). Ordered to
    /// preserve the chain's historical rejection reasons: layout bound, then size caps, then no-epochs, the
    /// epoch-ordinal bound (OPE-289), signer-key length, and finally wrap-completeness.
    fn structure(k: &Keyring) -> Result<(), &'static str> {
        if k.layout_version > KEYRING_LAYOUT_VERSION {
            return Err(S_LAYOUT_AHEAD);
        }
        if k.members.len() > MAX_MEMBERS {
            return Err(S_LIST_TOO_LARGE);
        }
        // Every SIGNER-member must have a 32-byte author key (else it can't verify its own signatures);
        // the curve-point validity is the engine's `accepts_key` check, run right after this gate.
        for m in &k.members {
            if (1..=2).contains(&m.role) && m.author_public_key.len() != 32 {
                return Err(S_SIGNER_KEY);
            }
        }
        // Decode the key material ONCE, fail-closed: a malformed / over-long / trailing-byte blob is a hard
        // reject, never an empty fallback (which would silently drop epochs past this gate). Also validate
        // each recovery key's escrow-wrap blob decodes, so no unusable key material passes.
        let epochs = k.key_material().map_err(|_| S_BAD_KEY_MATERIAL)?;
        for rk in &k.recovery_keys {
            rk.escrow_wraps().map_err(|_| S_BAD_KEY_MATERIAL)?;
        }
        if epochs.len() > MAX_EPOCHS {
            return Err(S_LIST_TOO_LARGE);
        }
        if epochs.is_empty() {
            return Err(S_NO_EPOCHS);
        }
        // Epoch ordinals are plausibility-bounded: with N epochs every ordinal is in `0..N` (one per removal
        // via `max()+1`). Reject an ordinal at/above the epoch count — a grinding-a-huge-ordinal DoS. Compare
        // in u64: the keyeo ordinal is u64 and `as usize` would TRUNCATE on wasm32 (a hostile ordinal of
        // exactly 2^32 -> 0), silently bypassing the bound on the primary (browser) target.
        if epochs.iter().any(|e| e.ordinal >= epochs.len() as u64) {
            return Err(S_EPOCH_ORDINAL);
        }
        if !wrap_complete(&epochs, &k.members) {
            return Err(S_WRAP_INCOMPLETE);
        }
        Ok(())
    }
}

impl Doc for KeyringDoc<'_> {
    type Id = String;
    type R = KeyringRole;
    type S = Ed25519;

    fn group_id(&self) -> &GroupId {
        &self.group_id
    }
    fn revision(&self) -> Revision {
        Revision(self.keyring.revision)
    }
    fn prev_hash(&self) -> &DocHash {
        &self.prev_hash
    }
    fn layout_version(&self) -> u32 {
        self.keyring.layout_version
    }
    fn members(&self) -> Vec<Signer<String, KeyringRole, [u8; 32]>> {
        self.keyring
            .members
            .iter()
            .map(|m| Signer {
                id: m.member_id.clone(),
                role: KeyringRole(i16::try_from(m.role).unwrap_or(i16::MAX)),
                public_key: to_pk32(&m.author_public_key),
            })
            .collect()
    }
    fn governance(&self) -> Governance {
        Governance {
            kind: self.keyring.governance_kind,
            threshold: self.keyring.governance_threshold,
        }
    }
    fn recovery_authority(&self) -> Option<[u8; 32]> {
        reset_rvk(self.keyring).map(to_pk32)
    }
    fn signatures(&self) -> Vec<[u8; 64]> {
        // A malformed (non-64-byte) signature is SKIPPED, not an error — the chain's historical behavior.
        self.keyring
            .signatures
            .iter()
            .filter_map(|s| s.signature.as_slice().try_into().ok())
            .collect()
    }
    fn payload_commitment(&self) -> PayloadCommitment {
        self.payload_commitment
    }
    fn structure_ok(&self) -> Result<(), &'static str> {
        Self::structure(self.keyring)
    }
}

/// §2.6 wrap-completeness: in the newest epoch, the founder is reachable via a recovery-root (RRK) wrap and
/// every other member via their own HPKE wrap. Stops a signature-valid revision that rotates the epoch but
/// wraps the new key only to a subset — a silent lock-out. Expressed as keyeo's `missing(..).is_empty()` so
/// both engines share the completeness predicate.
///
/// The chain's descriptors are ID-LEVEL (`expected_key = None`), and this is EXACT for the chain, not a
/// weakening of the dag's key-bound check: a linear signed chain has no concurrent-branch stale-key rekey
/// race, and the only post-hoc `hpke_public_key` mutation is `refounder` (owner-only, so the founder — who
/// is reached via the RRK, not a member wrap — is excluded anyway). There is NO non-founder member
/// HPKE-rotation flow, so key-binding would be dead code; revisit only if one is added. Unlike the dag's
/// `coverage_descriptors`, empty-hpke-key members are NOT excluded: this is an acceptance gate on a signed
/// document, so a revision that strips a member's key and their wrap in one step must be REJECTED (the dag
/// excludes them because a transient empty-key state is legitimate mid-merge — not so here).
fn wrap_complete(epochs: &[Epoch<String>], members: &[Member]) -> bool {
    let Some(newest) = epochs.iter().max_by_key(|e| e.ordinal) else {
        return false;
    };
    let Some(founder) = members.iter().find(|m| m.role == MEMBER_OWNER) else {
        return false;
    };
    let required: Vec<RecipientDescriptor<String>> = members
        .iter()
        .filter(|m| m.member_id != founder.member_id)
        .map(|m| RecipientDescriptor { id: m.member_id.clone(), expected_key: None })
        .collect();
    // The RRK wrap must be addressed to the founder id — a strictening over the old any-RRK-wrap check
    // (keyeo's `rrk_covers` binds the recipient); producers always address the founder.
    let rrk = RecipientDescriptor { id: founder.member_id.clone(), expected_key: None };
    missing(newest, &required, &rrk).is_empty()
}

/// Compile-time tripwire (never called): an exhaustive, no-`..` destructure of keyeo's key-material records.
/// `payload_commit` hashes these records as OPAQUE codec bytes, so a field/variant added to `Epoch`/`Wrap`/
/// `WrapMethod` would otherwise ride into (or, via `#[serde(skip)]`, fall out of) the signature with no
/// signal in this crate. This fn forces a compile error in exactly the file that owns the chain's signing,
/// pointing whoever added the field at the guard tests (per-field mutation in `keyeo_crypto::codec`, the
/// golden-bytes + per-field signature-fails tests here) they must extend.
#[allow(dead_code)]
fn _key_material_fields_are_exhaustively_accounted_for(epoch: &Epoch<String>, wrap: &Wrap<String>) {
    let Epoch { key_id, ordinal, wraps } = epoch;
    let _ = (key_id, ordinal, wraps);
    let Wrap { recipient, method, ciphertext } = wrap;
    let _ = (recipient, ciphertext);
    match method {
        WrapMethod::MemberHpke { encapped, recipient_key }
        | WrapMethod::RrkHpke { encapped, recipient_key } => {
            let _ = (encapped, recipient_key);
        }
        WrapMethod::Kek { kind, kdf, nonce } => {
            let _ = (kind, kdf, nonce);
        }
    }
}

/// The recovery verifying key (RVK) pinned in the keyring — the first non-empty
/// `RecoveryKey.recovery_verifying_key` (V1 has one, the founder's). `None` on a pre-RVK keyring.
pub(crate) fn reset_rvk(keyring: &Keyring) -> Option<&[u8]> {
    keyring
        .recovery_keys
        .iter()
        .map(|rk| rk.recovery_verifying_key.as_slice())
        .find(|rvk| !rvk.is_empty())
}

// ---- length-prefixed encoders for the structural payload fields (shared by `payload_commit`); the key
// material itself rides through as its opaque `codec` bytes, hashed directly ----

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    // Length prefix; a >u32 field would only change the signing bytes (fail-closed), so saturate.
    let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
}
