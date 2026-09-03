//! The openom binding of `keyeo-linear`: `ChainRole` (openom's ordinal role) + `ChainDoc` (a `Keyring`
//! viewed as a [`keyeo_linear::LinearDoc`]). The generic engine reasons over the accessors here and signs
//! the message it builds from them; the openom `Keyring` payload rides through `payload_commitment`.
//!
//! The engine owns the generic signed fields (group id, revision, prev-hash, layout, members, governance,
//! recovery authority — see `keyeo_linear::signing_bytes`). This binding owns [`ChainDoc::payload_commit`]
//! (an exhaustive `#[deny(unused_variables)]` hash of the WHOLE keyring payload) and [`ChainDoc::structure`]
//! (the payload/structural acceptance gate: layout bound, size caps, epochs, epoch ordinals,
//! signer-key length, wrap-completeness).

use keyeo_core::Ed25519;
use keyeo_linear::{DocHash, GroupId, Governance, LinearDoc, LinearRole, PayloadCommitment, Revision, Signer};
use sha2::{Digest, Sha256};

use crate::wire::{
    KdfParams, KeyEpoch, KeyWrap, Keyring, Member, RecoveryKey, KEYRING_LAYOUT_VERSION, MEMBER_OWNER,
    WRAP_RRK_HPKE, WRAP_X25519_HPKE,
};

/// Bounds on an accepted keyring's list sizes — a family tree is far under these; they only stop a hostile
/// keyring from forcing pathological work before verification. (The signer set is a subset of `members`.)
pub(crate) const MAX_MEMBERS: usize = 4096;
pub(crate) const MAX_EPOCHS: usize = 4096;

/// Domain separation for the chain's payload commitment (bound into the engine's signed bytes).
const PAYLOAD_TAG: &[u8] = b"openom:keyring:payload:v1";

// Structure-gate sentinels the chain maps back to its `ChainError` taxonomy (see `chain::map_linear_err`).
pub(crate) const S_LAYOUT_AHEAD: &str = "layout ahead";
pub(crate) const S_WRAP_INCOMPLETE: &str = "wrap incomplete";
pub(crate) const S_LIST_TOO_LARGE: &str = "list too large";
pub(crate) const S_NO_EPOCHS: &str = "no epochs";
pub(crate) const S_EPOCH_ORDINAL: &str = "epoch ordinal out of range";
pub(crate) const S_SIGNER_KEY: &str = "signer key malformed";

/// openom's single ordinal role, wrapping the proto `MemberRole` value (lower is stronger). The engine
/// derives signer-ness/founder-ness from it; it never learns openom's specific ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct ChainRole(pub i16);

impl keyeo_core::Role for ChainRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        // Lower ordinal = stronger (Owner==1 is strongest).
        self.0 <= other.0
    }
}
impl LinearRole for ChainRole {
    fn is_founder(&self) -> bool {
        self.0 == MEMBER_OWNER as i16
    }
    fn is_signer(&self) -> bool {
        (1..=2).contains(&self.0)
    }
}

/// Coerce an arbitrary-length public-key byte string to the engine's `[u8; 32]`. A signer's key is always
/// exactly 32 bytes (enforced in [`ChainDoc::structure`] before the engine's key checks run); a non-signer
/// member's key is cosmetic to the engine (bound in full through `payload_commitment`), so padding/
/// truncation here is safe and cannot lose coverage.
pub(crate) fn to_pk32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// A `Keyring` presented as a [`LinearDoc`]. Holds owned `GroupId` / `DocHash` / `PayloadCommitment` so the
/// by-reference accessors can hand out borrows (mirrors the reference `TestDoc`).
pub(crate) struct ChainDoc<'a> {
    keyring: &'a Keyring,
    group_id: GroupId,
    prev_hash: DocHash,
    payload_commitment: PayloadCommitment,
}

impl<'a> ChainDoc<'a> {
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
        } = k;
        put_bytes(&mut out, tree_id);
        put_u32(&mut out, *revision);
        put_u32(&mut out, *layout_version);
        put_bytes(&mut out, prev_keyring_hash);

        put_u32(&mut out, members.len() as u32);
        for m in members {
            #[deny(unused_variables)]
            let Member { member_id, role, author_public_key, hpke_public_key } = m;
            put_bytes(&mut out, member_id.as_bytes());
            put_u32(&mut out, *role as u32);
            put_bytes(&mut out, author_public_key);
            put_bytes(&mut out, hpke_public_key);
        }

        put_u32(&mut out, epochs.len() as u32);
        for ep in epochs {
            #[deny(unused_variables)]
            let KeyEpoch { key_id, epoch, wraps } = ep;
            put_bytes(&mut out, key_id);
            put_u32(&mut out, *epoch);
            put_u32(&mut out, wraps.len() as u32);
            for w in wraps {
                put_wrap(&mut out, w);
            }
        }

        put_u32(&mut out, recovery_keys.len() as u32);
        for rk in recovery_keys {
            #[deny(unused_variables)]
            let RecoveryKey { public_key, member_id, wraps, recovery_verifying_key } = rk;
            put_bytes(&mut out, public_key);
            put_bytes(&mut out, member_id.as_bytes());
            put_u32(&mut out, wraps.len() as u32);
            for w in wraps {
                put_wrap(&mut out, w);
            }
            put_bytes(&mut out, recovery_verifying_key);
        }
        put_u32(&mut out, *governance_kind);
        put_u32(&mut out, *governance_threshold);

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
        if k.members.len() > MAX_MEMBERS || k.epochs.len() > MAX_EPOCHS {
            return Err(S_LIST_TOO_LARGE);
        }
        // Every SIGNER-member must have a 32-byte author key (else it can't verify its own signatures);
        // the curve-point validity is the engine's `accepts_key` check, run right after this gate.
        for m in &k.members {
            if (1..=2).contains(&m.role) && m.author_public_key.len() != 32 {
                return Err(S_SIGNER_KEY);
            }
        }
        if k.epochs.is_empty() {
            return Err(S_NO_EPOCHS);
        }
        // Epoch ordinals are plausibility-bounded: with N epochs every ordinal is in `0..N` (one per
        // removal via `max()+1`). Reject an ordinal at/above the epoch count — a grinding-a-huge-ordinal DoS.
        if k.epochs.iter().any(|e| e.epoch as usize >= k.epochs.len()) {
            return Err(S_EPOCH_ORDINAL);
        }
        if !wrap_complete(k) {
            return Err(S_WRAP_INCOMPLETE);
        }
        Ok(())
    }
}

impl LinearDoc for ChainDoc<'_> {
    type Id = String;
    type R = ChainRole;
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
    fn members(&self) -> Vec<Signer<String, ChainRole, [u8; 32]>> {
        self.keyring
            .members
            .iter()
            .map(|m| Signer {
                id: m.member_id.clone(),
                role: ChainRole(m.role as i16),
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
/// wraps the new key only to a subset — a silent lock-out.
fn wrap_complete(k: &Keyring) -> bool {
    let Some(newest) = k.epochs.iter().max_by_key(|e| e.epoch) else {
        return false;
    };
    let founder_id = match k.members.iter().find(|m| m.role == MEMBER_OWNER) {
        Some(m) => &m.member_id,
        None => return false,
    };
    if !newest.wraps.iter().any(|w| w.wrap_method == WRAP_RRK_HPKE) {
        return false;
    }
    for m in &k.members {
        // The founder reaches epochs via the RRK, not a per-epoch member wrap.
        if &m.member_id == founder_id && m.role == MEMBER_OWNER {
            continue;
        }
        if !newest
            .wraps
            .iter()
            .any(|w| w.member_id == m.member_id && w.wrap_method == WRAP_X25519_HPKE)
        {
            return false;
        }
    }
    true
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

// ---- exhaustive payload encoders (shared by `payload_commit`) ----

#[deny(unused_variables)]
fn put_wrap(out: &mut Vec<u8>, w: &KeyWrap) {
    let KeyWrap {
        member_id,
        wrap_method,
        nonce,
        wrapped_dek,
        kdf_params,
        ephemeral_public_key,
        recipient_public_key,
    } = w;
    put_bytes(out, member_id.as_bytes());
    put_u32(out, *wrap_method as u32);
    put_bytes(out, nonce);
    put_bytes(out, wrapped_dek);
    match kdf_params {
        Some(k) => {
            let KdfParams { salt, memory_kib, iterations, parallelism } = k;
            put_u32(out, 1);
            put_bytes(out, salt);
            put_u32(out, *memory_kib);
            put_u32(out, *iterations);
            put_u32(out, *parallelism);
        }
        None => {
            put_u32(out, 0);
            put_bytes(out, &[]);
            put_u32(out, 0);
            put_u32(out, 0);
            put_u32(out, 0);
        }
    }
    put_bytes(out, ephemeral_public_key);
    // Unlike the old chain signing bytes, the payload commitment DOES cover recipient_public_key (a
    // coverage hint) — it's part of the payload, and binding it costs nothing.
    put_bytes(out, recipient_public_key);
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}
