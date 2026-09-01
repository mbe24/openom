//! Keyring chain-walk (§2.4, §10) — the client-side enforcement that a keyring served by
//! the (untrusted) network is a **legitimate successor** of the one the client already
//! trusts.
//!
//! The open paths verify a keyring's signature against a signer set. That is only safe if
//! some component has checked that the set got there legitimately. This module is that
//! component: given the client's trusted **anchor** (the last keyring it accepted) and a
//! candidate keyring, it enforces —
//!
//! - the candidate advances the revision by exactly one and chains onto the anchor by hash
//!   (fork / rollback / withholding become evidence, not silent acceptance);
//! - the candidate is signed by the **prior** trusted signer set — never the set the
//!   candidate itself claims — under the founder-or-unanimity policy: an ordinary revision
//!   by any prior signer, a signer-set change by the prior founder (or, founder gone,
//!   unanimity of the prior set), with a self-removal carve-out;
//! - structural invariants (exactly one founder, signers are members, wrap-completeness),
//!   so a signature-valid-but-lockout revision can't slip through.
//!
//! The trusted set is only ever adopted from a candidate **after** it has been validated by
//! the prior set — that ordering is the whole trick. On success the new anchor carries the
//! candidate's now-validated signer set forward.

use openom_protocol::v1::{AuthorizedSigner, Keyring, WrapMethod};
use openom_protocol::KEYRING_LAYOUT_VERSION;
// The role constants live in openom-roles (one definition); aliased here to the local names so the
// comparisons below read unchanged.
use openom_roles::{
    MEMBER_OWNER as OWNER_MEMBER, SIGNER_CO_OWNER as CO_OWNER, SIGNER_FOUNDER as FOUNDER,
};

use crate::{
    keyring_hash, verify_keyring, verify_keyring_all, verify_keyring_any, verify_keyring_threshold,
    VerifyingKey,
};

const HPKE: i32 = WrapMethod::X25519Hpke as i32;
const RRK_HPKE: i32 = WrapMethod::RrkHpke as i32;

/// Bounds on an accepted keyring's list sizes — a family tree is far under these; they only
/// stop a hostile keyring from forcing pathological work before verification.
const MAX_SIGNERS: usize = 64;
const MAX_MEMBERS: usize = 4096;
const MAX_EPOCHS: usize = 4096;

/// The client's trusted keyring state for one tree — the last keyring it accepted. Everything
/// here is derivable from that keyring, so the store persists the keyring itself and rebuilds
/// the anchor with [`KeyringAnchor::from_keyring`]; there is no separate on-disk anchor blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringAnchor {
    pub tree_id: Vec<u8>,
    pub revision: u32,
    pub keyring_hash: [u8; 32],
    pub trusted_signers: Vec<AuthorizedSigner>,
    /// The governance rule this keyring pins (see `Keyring.governance_kind`): 0 = founder-or-unanimity
    /// (default), 1 = founder-only, 2 = founder-or-threshold, 3 = threshold. The PRIOR anchor's rule
    /// authorizes the NEXT privileged change (anti-downgrade).
    pub governance_kind: u32,
    pub governance_threshold: u32,
    /// The recovery verifying key (RVK) pinned in this keyring, or empty if none. Carried on the anchor
    /// so a caller adopting a reset can pass the PRIOR RVK to [`verify_reset`] for the continuity +
    /// authorization gate.
    pub recovery_verifying_key: Vec<u8>,
}

impl KeyringAnchor {
    /// Build an anchor from an **already-trusted** keyring (a locally stored, previously
    /// accepted one). Performs no policy check — the keyring is the trust root here. Use the
    /// `bootstrap_*` functions for a first-sight keyring, and [`verify_transition`] for a
    /// candidate served against an existing anchor.
    pub fn from_keyring(keyring: &Keyring) -> Self {
        KeyringAnchor {
            tree_id: keyring.tree_id.clone(),
            revision: keyring.revision,
            keyring_hash: keyring_hash(keyring),
            trusted_signers: keyring.authorized_signers.clone(),
            governance_kind: keyring.governance_kind,
            governance_threshold: keyring.governance_threshold,
            recovery_verifying_key: reset_rvk(keyring).map(<[u8]>::to_vec).unwrap_or_default(),
        }
    }

    fn founder(&self) -> Option<&AuthorizedSigner> {
        self.trusted_signers.iter().find(|s| s.role == FOUNDER)
    }
}

/// A **full keyring whose legitimacy has been established by the chain-walk** — the token
/// [`verify_entry`](crate::verify_entry) requires. Unlike [`KeyringAnchor`] (which keeps only the trust
/// state to persist), this carries the whole verified keyring, so entry verification can read its
/// members / epochs / signers. The inner keyring is private and there is no public unchecked
/// constructor: the only way to mint one is a verifying constructor below (each delegates to the
/// matching chain check), so a raw, wire-decoded `Keyring` cannot be passed as the governing keyring by
/// mistake — the "the caller chain-verified this" guarantee is a type, not a doc comment.
///
/// (The single deliberate exception, [`from_unverified_wasm_boundary`](Self::from_unverified_wasm_boundary),
/// is the documented OPE-186 residual for the wasm boundary, where JS cannot yet hold a verified token.)
/// Chain engine: encode a governing keyring's **revision** as the entry's opaque `governing_ref` — 4
/// big-endian bytes. The ref is opaque to every layer but this adapter; the verifier [`decodes`] it back
/// to a revision, then walks the chain to that revision to mint the [`GoverningKeyring`]. (OPE-277
/// GoverningRef; the dag engine encodes an era+commitment instead, behind the same opaque bytes.)
///
/// Encoding is intentionally minimal (revision only) to preserve V1 resolution semantics; binding the
/// keyring hash into the ref later is a change confined to this adapter alone — the point of the seam.
///
/// [`decodes`]: decode_governing_ref
pub fn encode_governing_ref(revision: u32) -> Vec<u8> {
    revision.to_be_bytes().to_vec()
}

/// Decode a chain [`encode_governing_ref`] back to a revision. `None` if the bytes aren't exactly a
/// 4-byte big-endian revision (a malformed or foreign ref — the caller refuses to resolve it).
pub fn decode_governing_ref(governing_ref: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = governing_ref.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[derive(Clone, Debug)]
pub struct GoverningKeyring {
    keyring: Keyring,
}

impl GoverningKeyring {
    /// The verified keyring — read access for entry verification within the crate.
    pub(crate) fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The revision this keyring governs.
    pub fn revision(&self) -> u32 {
        self.keyring.revision
    }

    /// This keyring's [`governing reference`](encode_governing_ref) — the opaque per-entry ref an author
    /// stamps into an entry sealed under it, and what the verifier resolves back to this keyring.
    pub fn governing_ref(&self) -> Vec<u8> {
        encode_governing_ref(self.revision())
    }

    /// The trust anchor to persist (so the next transition can chain onto it).
    pub fn anchor(&self) -> KeyringAnchor {
        KeyringAnchor::from_keyring(&self.keyring)
    }

    /// Mint by validating `candidate` as the successor of `prior` — see [`verify_transition`]. A
    /// multi-hop walk to a governing revision is this applied per hop (each against the prior anchor).
    pub fn from_transition(prior: &KeyringAnchor, candidate: Keyring) -> Result<Self, ChainError> {
        verify_transition(prior, &candidate)?;
        Ok(Self { keyring: candidate })
    }

    /// Mint a first-sight genesis the founder trusts by its own key — see [`bootstrap_from_genesis`].
    pub fn from_genesis(
        genesis: Keyring,
        own_founder_key: &VerifyingKey,
    ) -> Result<Self, ChainError> {
        bootstrap_from_genesis(&genesis, own_founder_key)?;
        Ok(Self { keyring: genesis })
    }

    /// Mint a first-sight head pinned out-of-band — see [`bootstrap_from_oob`].
    pub fn from_oob(
        head: Keyring,
        pinned_tree_id: &[u8],
        pinned_revision: u32,
        pinned_hash: &[u8; 32],
    ) -> Result<Self, ChainError> {
        bootstrap_from_oob(&head, pinned_tree_id, pinned_revision, pinned_hash)?;
        Ok(Self { keyring: head })
    }

    /// Mint a recovery / succession reset validated on its own terms — see [`verify_reset`].
    pub fn from_reset(keyring: Keyring) -> Result<Self, ChainError> {
        // The writer's own self-check has no prior to compare against, so no continuity gate here — the
        // continuity + RVK-authorization gate runs where a PRIOR is known (a reader adopting a served
        // reset passes the prior RVK to `verify_reset`).
        verify_reset(None, &keyring)?;
        Ok(Self { keyring })
    }

    /// **Unverified boundary shim — OPE-186 residual, do not use from native code.** Wraps a keyring the
    /// *caller* promises it chain-verified, WITHOUT re-checking here. The sole sanctioned caller is the
    /// wasm `verifyEntry` boundary (`openom-sealer`), where JS cannot yet hold the chain-walk's verified
    /// token; OPE-186 replaces this with a JS-side verified handle. Named to stand out in a security
    /// audit; native callers must use a verifying constructor instead.
    #[doc(hidden)]
    pub fn from_unverified_wasm_boundary(keyring: Keyring) -> Self {
        Self { keyring }
    }

    /// Test-only wrap of a hand-built fixture keyring (the verifying constructors reject the minimal
    /// non-genesis fixtures the entry tests use).
    #[cfg(test)]
    pub(crate) fn from_keyring_for_test(keyring: Keyring) -> Self {
        Self { keyring }
    }
}

/// Why a candidate keyring was refused as a successor. Distinct variants so the client can
/// react differently (a fork/rollback is an attack; a gap is availability; an unendorsed
/// change is tampering) and so each guard gets a one-to-one negative test.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("candidate is for a different tree")]
    TreeMismatch,
    #[error("keyring layout is newer than this build understands")]
    LayoutAhead,
    #[error("keyring is structurally invalid: {0}")]
    BadStructure(&'static str),
    #[error("revision is not exactly one past the anchor (rollback or skip)")]
    NonSequential,
    #[error("prev_keyring_hash does not chain onto the anchor (fork / rewritten history)")]
    Fork,
    #[error("an ordinary revision not signed by any prior authorized signer")]
    UnendorsedOrdinaryChange,
    #[error("a signer-set change not authorized by the founder or prior-set unanimity")]
    UnendorsedSetChange,
    #[error("a live signer or member lacks a wrap in the newest epoch")]
    WrapIncomplete,
    #[error("bootstrap anchor did not match the pinned head / genesis")]
    BadBootstrap,
    #[error("the revision would overflow")]
    RevisionOverflow,
}

/// Validate `candidate` as the successor of `prior` and return the new anchor. Pure; no I/O.
pub fn verify_transition(
    prior: &KeyringAnchor,
    candidate: &Keyring,
) -> Result<KeyringAnchor, ChainError> {
    if candidate.tree_id != prior.tree_id {
        return Err(ChainError::TreeMismatch);
    }
    if candidate.layout_version > KEYRING_LAYOUT_VERSION {
        return Err(ChainError::LayoutAhead);
    }
    check_structure(candidate)?;

    // Exactly one past the anchor — never `>=`, so a withheld hop can't hide a set change.
    let expected = prior
        .revision
        .checked_add(1)
        .ok_or(ChainError::RevisionOverflow)?;
    if candidate.revision != expected {
        return Err(ChainError::NonSequential);
    }
    // Chain onto the anchor's signing-bytes hash.
    if candidate.prev_keyring_hash.as_slice() != prior.keyring_hash {
        return Err(ChainError::Fork);
    }

    // Signature policy — always against the PRIOR trusted set, never the candidate's own.
    let prior_keys = signer_keys(&prior.trusted_signers);
    let new_rvk = reset_rvk(candidate).unwrap_or(&[]);
    let old_rvk = prior.recovery_verifying_key.as_slice();
    // Establishing a recovery authority where there was none plants a standing bearer-credential for
    // future resets — a PRIVILEGED change, gated like a signer-set/governance change (not the ordinary
    // any-of path), so a lone co-owner can't seize the recovery path on a pre-RVK keyring (OPE-277 review).
    let rvk_establishment = old_rvk.is_empty() && !new_rvk.is_empty();
    let signer_change = signer_set_differs(&prior.trusted_signers, &candidate.authorized_signers);
    // Changing the governance rule ITSELF is a privileged change too — so weakening it (e.g. 3-of-4 ->
    // 1-of-4) must still satisfy the CURRENT (prior) rule. Anti-downgrade.
    let governance_change = candidate.governance_kind != prior.governance_kind
        || candidate.governance_threshold != prior.governance_threshold;
    if signer_change || governance_change || rvk_establishment {
        let self_removal = signer_change
            && is_self_removal(&prior.trusted_signers, &candidate.authorized_signers, candidate);
        if !(self_removal || prior_governance_met(prior, candidate, &prior_keys)) {
            return Err(ChainError::UnendorsedSetChange);
        }
        // Lockout guard: the candidate's own signer set must be able to satisfy its own rule, or
        // governance is permanently bricked (no future privileged change could ever pass).
        if !rule_is_satisfiable(candidate) {
            return Err(ChainError::UnendorsedSetChange);
        }
    } else {
        verify_keyring_any(candidate, &prior_keys)
            .map_err(|_| ChainError::UnendorsedOrdinaryChange)?;
    }

    if !wrap_complete(candidate) {
        return Err(ChainError::WrapIncomplete);
    }

    // ROTATING an existing recovery authority (old non-empty → different new) requires the OLD RVK's
    // signature — proving possession of the current recovery secret; the only genuine way to revoke a
    // prior recovery-key holder (the chain analogue of the dag's RotateRecoveryAuthority). An unchanged
    // RVK needs no such signature; ESTABLISHING a first RVK was gated as a privileged change above.
    if new_rvk != old_rvk && !old_rvk.is_empty() {
        let old_key = old_rvk
            .try_into()
            .ok()
            .and_then(|b: [u8; 32]| VerifyingKey::from_bytes(&b).ok())
            .ok_or(ChainError::BadStructure("prior recovery verifying key"))?;
        verify_keyring_any(candidate, &[old_key]).map_err(|_| ChainError::UnendorsedSetChange)?;
    }

    Ok(KeyringAnchor {
        tree_id: candidate.tree_id.clone(),
        revision: candidate.revision,
        keyring_hash: keyring_hash(candidate),
        trusted_signers: candidate.authorized_signers.clone(),
        governance_kind: candidate.governance_kind,
        governance_threshold: candidate.governance_threshold,
        recovery_verifying_key: reset_rvk(candidate).map(<[u8]>::to_vec).unwrap_or_default(),
    })
}

/// Fold [`verify_transition`] over a contiguous run of candidates (revision N+1, N+2, …).
/// Hop-by-hop is mandatory — a signature at N+k proves authorship under the set at N+k−1, so
/// skipping a hop would trust a set no anchor endorsed. `hops` must be in ascending revision
/// order with no gaps; a gap surfaces as `NonSequential`.
pub fn verify_walk(prior: &KeyringAnchor, hops: &[Keyring]) -> Result<KeyringAnchor, ChainError> {
    let mut anchor = prior.clone();
    for hop in hops {
        anchor = verify_transition(&anchor, hop)?;
    }
    Ok(anchor)
}

/// Seed an anchor from a **genesis** keyring (revision 1) as the founder: it must be a valid
/// revision 1, have exactly one founder whose key is the caller's own, and be signed by it.
/// This is cryptographic (the founder's own key signs it), so it closes the first-sight gap
/// for the founder path with no out-of-band material.
pub fn bootstrap_from_genesis(
    genesis: &Keyring,
    own_founder_key: &VerifyingKey,
) -> Result<KeyringAnchor, ChainError> {
    check_structure(genesis)?;
    if genesis.revision != 1 || !genesis.prev_keyring_hash.is_empty() {
        return Err(ChainError::BadBootstrap);
    }
    let founder = genesis
        .authorized_signers
        .iter()
        .find(|s| s.role == FOUNDER)
        .ok_or(ChainError::BadStructure("no founder"))?;
    if founder.public_key.as_slice() != &own_founder_key.to_bytes()[..] {
        return Err(ChainError::BadBootstrap);
    }
    verify_keyring(genesis, own_founder_key).map_err(|_| ChainError::BadBootstrap)?;
    if !wrap_complete(genesis) {
        return Err(ChainError::WrapIncomplete);
    }
    Ok(KeyringAnchor::from_keyring(genesis))
}

/// Seed an anchor from a keyring a member received, pinned out-of-band (§4a): the invite
/// carries the chain head `(revision, keyring_hash)`. The keyring must match that head
/// exactly — the OOB channel, not any signature, is the trust root for this first revision
/// (the honestly-stated §10 first-sight residual). Structural + a hygiene self-signature are
/// still checked. The caller then [`verify_walk`]s from here to the current head.
pub fn bootstrap_from_oob(
    head: &Keyring,
    pinned_tree_id: &[u8],
    pinned_revision: u32,
    pinned_hash: &[u8; 32],
) -> Result<KeyringAnchor, ChainError> {
    if head.tree_id != pinned_tree_id {
        return Err(ChainError::TreeMismatch);
    }
    check_structure(head)?;
    if head.revision != pinned_revision || &keyring_hash(head) != pinned_hash {
        return Err(ChainError::BadBootstrap);
    }
    // Hygiene: the pinned keyring must be self-consistently signed by one of its own signers
    // (non-circular — the whole document is pinned by the OOB hash).
    verify_keyring_any(head, &signer_keys(&head.authorized_signers))
        .map_err(|_| ChainError::BadBootstrap)?;
    if !wrap_complete(head) {
        return Err(ChainError::WrapIncomplete);
    }
    Ok(KeyringAnchor::from_keyring(head))
}

/// Validate a keyring that establishes a **new anchor on its own terms** — a genesis (revision
/// 1), or a recovery / succession reset whose new founder identity deliberately carries no
/// endorsement from the old one (the §6 owner-succession boundary, where the old signing key is
/// presumed lost). Unlike [`verify_transition`] it does not chain onto a prior anchor: it checks
/// the keyring is structurally sound, wrap-complete, and self-signed by one of its own current
/// authorized signers. The trust that this reset is *legitimate* comes from the CALLER — the
/// founder's own passphrase produced it, or a member re-verified it out-of-band — never from a
/// prior chain link. This is the writer's self-check for the provision and recover flows, whose
/// output is a valid keyring but (for recover) intentionally not a valid transition.
pub fn verify_reset(prior_rvk: Option<&[u8]>, keyring: &Keyring) -> Result<KeyringAnchor, ChainError> {
    if keyring.layout_version > KEYRING_LAYOUT_VERSION {
        return Err(ChainError::LayoutAhead);
    }
    check_structure(keyring)?;
    // Self-consistency: signed by one of its own signers (non-circular here because the caller,
    // not a signature, supplies the trust that this reset is authorized).
    verify_keyring_any(keyring, &signer_keys(&keyring.authorized_signers))
        .map_err(|_| ChainError::BadBootstrap)?;
    if !wrap_complete(keyring) {
        return Err(ChainError::WrapIncomplete);
    }
    // RVK gate — active once the PRIOR keyring pinned a recovery authority. This is what makes a chain
    // reset cryptographically verifiable rather than OOB-trusted: the reset must carry the SAME recovery
    // verifying key (continuity — no forged takeover under a fresh recovery root) AND be signed by it
    // (authorization — the resetter possesses the recovery secret). If the prior pinned no RVK
    // (pre-RVK / genuine first sight), fall back to the self-signed-by-own-signer check above.
    if let Some(prior) = prior_rvk {
        let rvk = reset_rvk(keyring).ok_or(ChainError::UnendorsedSetChange)?;
        if rvk != prior {
            return Err(ChainError::UnendorsedSetChange);
        }
        let rvk_bytes: [u8; 32] = rvk
            .try_into()
            .map_err(|_| ChainError::BadStructure("recovery verifying key length"))?;
        let rvk_key = VerifyingKey::from_bytes(&rvk_bytes)
            .map_err(|_| ChainError::BadStructure("recovery verifying key"))?;
        verify_keyring_any(keyring, &[rvk_key]).map_err(|_| ChainError::UnendorsedSetChange)?;
    }
    Ok(KeyringAnchor::from_keyring(keyring))
}

// ---- structural + policy helpers ----

fn check_structure(k: &Keyring) -> Result<(), ChainError> {
    if k.authorized_signers.len() > MAX_SIGNERS
        || k.members.len() > MAX_MEMBERS
        || k.epochs.len() > MAX_EPOCHS
    {
        return Err(ChainError::BadStructure("list too large"));
    }
    // Exactly one founder.
    if k.authorized_signers
        .iter()
        .filter(|s| s.role == FOUNDER)
        .count()
        != 1
    {
        return Err(ChainError::BadStructure("must have exactly one founder"));
    }
    // No duplicate signer member_id or public_key; every signer key is 32 bytes and parses.
    for (i, s) in k.authorized_signers.iter().enumerate() {
        if s.public_key.len() != 32 || signer_key(s).is_none() {
            return Err(ChainError::BadStructure("signer key malformed"));
        }
        if k.authorized_signers[..i]
            .iter()
            .any(|o| o.member_id == s.member_id || o.public_key == s.public_key)
        {
            return Err(ChainError::BadStructure("duplicate signer"));
        }
        // Every signer must be a member whose author key is this signer key (signers can't be
        // ghosts, and the key must be the one the member's author_signature would use).
        let member = k.members.iter().find(|m| m.member_id == s.member_id);
        match member {
            Some(m) if m.author_public_key == s.public_key => {}
            _ => {
                return Err(ChainError::BadStructure(
                    "signer is not a member with a matching key",
                ))
            }
        }
    }
    // At least one epoch, and the newest carries the founder's recovery-root wrap.
    if k.epochs.is_empty() {
        return Err(ChainError::BadStructure("no epochs"));
    }
    // Epoch ordinals are plausibility-bounded (OPE-289). The linear chain assigns each new epoch ordinal
    // `max(existing)+1` (one per removal), so with N epochs every ordinal is in `0..N`. A signer grinding a
    // huge ordinal (e.g. `u32::MAX`) would otherwise brick every future `max()+1` re-epoch with
    // `RevisionOverflow` — a permanent, unrecoverable DoS. Reject any ordinal at/above the epoch count; this
    // holds for every honest keyring and runs on the server's admission path too.
    if k.epochs.iter().any(|e| e.epoch as usize >= k.epochs.len()) {
        return Err(ChainError::BadStructure("epoch ordinal out of range"));
    }
    Ok(())
}

/// §2.6 wrap-completeness: in the newest epoch, the founder is reachable via a recovery-root
/// wrap and every other member via their own HPKE wrap. Stops a signature-valid revision that
/// rotates the epoch but wraps the new key only to a subset — a silent lock-out.
fn wrap_complete(k: &Keyring) -> bool {
    let Some(newest) = k.epochs.iter().max_by_key(|e| e.epoch) else {
        return false;
    };
    let founder_id = match k.authorized_signers.iter().find(|s| s.role == FOUNDER) {
        Some(s) => &s.member_id,
        None => return false,
    };
    if !newest.wraps.iter().any(|w| w.wrap_method == RRK_HPKE) {
        return false;
    }
    for m in &k.members {
        // The founder reaches epochs via the RRK, not a per-epoch member wrap.
        if &m.member_id == founder_id && m.role == OWNER_MEMBER {
            continue;
        }
        if !newest
            .wraps
            .iter()
            .any(|w| w.member_id == m.member_id && w.wrap_method == HPKE)
        {
            return false;
        }
    }
    true
}

fn same_signer(a: &AuthorizedSigner, b: &AuthorizedSigner) -> bool {
    a.public_key == b.public_key && a.member_id == b.member_id && a.role == b.role
}

/// True if the signer sets differ as sets (no duplicates by structural invariant). Any
/// in-place change — a founder key rotation, a role flip, add/remove — counts.
fn signer_set_differs(prior: &[AuthorizedSigner], candidate: &[AuthorizedSigner]) -> bool {
    prior.len() != candidate.len()
        || prior
            .iter()
            .any(|p| !candidate.iter().any(|c| same_signer(p, c)))
        || candidate
            .iter()
            .any(|c| !prior.iter().any(|p| same_signer(p, c)))
}

/// The signer-set delta is **exactly** one CO_OWNER entry removed (nothing else added or
/// changed) and that co-owner's own key signed the candidate. Scoped tightly so a mutineer
/// can't bundle "remove myself AND the founder" — any second signer-set change fails this.
fn is_self_removal(
    prior: &[AuthorizedSigner],
    candidate: &[AuthorizedSigner],
    keyring: &Keyring,
) -> bool {
    let removed: Vec<&AuthorizedSigner> = prior
        .iter()
        .filter(|p| !candidate.iter().any(|c| same_signer(p, c)))
        .collect();
    let added = candidate
        .iter()
        .any(|c| !prior.iter().any(|p| same_signer(p, c)));
    if added || removed.len() != 1 || removed[0].role != CO_OWNER {
        return false;
    }
    match signer_key(removed[0]) {
        Some(k) => verify_keyring(keyring, &k).is_ok(),
        None => false,
    }
}

fn signer_key(s: &AuthorizedSigner) -> Option<VerifyingKey> {
    let arr: [u8; 32] = s.public_key.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Parse + **deduplicate** the signer keys (so a corrupted set with a repeated key can't make
/// unanimity easier to satisfy).
/// The recovery verifying key (RVK) pinned in the keyring — the first non-empty
/// `RecoveryKey.recovery_verifying_key` (V1 has one, the founder's). `None` on a pre-RVK keyring.
fn reset_rvk(keyring: &Keyring) -> Option<&[u8]> {
    keyring
        .recovery_keys
        .iter()
        .map(|rk| rk.recovery_verifying_key.as_slice())
        .find(|rvk| !rvk.is_empty())
}

fn signer_keys(signers: &[AuthorizedSigner]) -> Vec<VerifyingKey> {
    let mut out: Vec<VerifyingKey> = Vec::new();
    for s in signers {
        if let Some(k) = signer_key(s) {
            if !out.iter().any(|e| e.to_bytes() == k.to_bytes()) {
                out.push(k);
            }
        }
    }
    out
}

/// Does the candidate meet the **PRIOR** keyring's governance rule for a privileged change? Every check is
/// against the PRIOR trusted set (never the candidate's own claim), and both the rule kind and the
/// threshold are read from the prior anchor — that's the anti-downgrade discipline. A signer this
/// candidate is REMOVING is excluded from the threshold denominator (target-exclusion: you don't need a
/// member's consent to evict them).
fn prior_governance_met(prior: &KeyringAnchor, candidate: &Keyring, prior_keys: &[VerifyingKey]) -> bool {
    let founder_key = prior.founder().and_then(signer_key);
    let founder_signed = founder_key
        .as_ref()
        .map(|k| verify_keyring(candidate, k).is_ok())
        .unwrap_or(false);
    // The co-owner denominator for a threshold: prior signers, minus the founder, minus any signer this
    // candidate removes.
    let departing: Vec<[u8; 32]> = prior
        .trusted_signers
        .iter()
        .filter(|p| !candidate.authorized_signers.iter().any(|c| same_signer(p, c)))
        .filter_map(|p| signer_key(p).map(|k| k.to_bytes()))
        .collect();
    let is_founder = |k: &VerifyingKey| {
        founder_key.as_ref().map(|f| f.to_bytes() == k.to_bytes()).unwrap_or(false)
    };
    let co_owner_keys: Vec<VerifyingKey> = prior_keys
        .iter()
        .filter(|k| !is_founder(k) && !departing.contains(&k.to_bytes()))
        .cloned()
        .collect();
    let m = prior.governance_threshold as usize;
    match prior.governance_kind {
        1 => founder_signed, // founder-only
        2 => founder_signed || verify_keyring_threshold(candidate, &co_owner_keys, m).is_ok(), // founder-or-threshold(m)
        3 => verify_keyring_threshold(candidate, prior_keys, m).is_ok(), // threshold(m), no founder path
        _ => founder_signed || verify_keyring_all(candidate, prior_keys).is_ok(), // 0/unknown = founder-or-unanimity
    }
}

/// Can this keyring's own signer set ever satisfy its own governance rule? A rule no set can meet bricks
/// governance forever. Founder-or-* kinds are always satisfiable (a founder exists per `check_structure`
/// and can act alone); a pure threshold(m) needs at least m signers.
fn rule_is_satisfiable(k: &Keyring) -> bool {
    let signers = k.authorized_signers.len();
    let m = k.governance_threshold as usize;
    match k.governance_kind {
        0..=2 => true,
        3 => m > 0 && signers >= m,
        _ => false, // unknown kind: fail-closed
    }
}

/// Kani proof harnesses for the keyring's structural gate — compiled only under `cargo kani`
/// (`--cfg kani`), never the normal build. Run: `node scripts/kani.mjs -p openom-keyring`. These are
/// OPE-238 Step B: `check_structure`'s crypto-FREE checks, proven exhaustively. The one crypto call in
/// `check_structure` is `signer_key` (an Ed25519 point-decode Kani can't model) inside the per-signer
/// loop; the checks proven here (`list too large`, `exactly one founder`) all run BEFORE that loop, so
/// they need no crypto stub. The signer-loop checks (dup detection, signer-is-member) are Step A — they
/// require stubbing `signer_key`, which is blocked on constructing a `VerifyingKey` symbolically.
#[cfg(kani)]
mod structure_verification {
    use super::*;

    /// A minimal keyring with two signers carrying the given roles. Every list is empty: the
    /// founder-count gate returns before the per-signer loop ever reads a signer's key/id, so their
    /// contents are irrelevant — which also keeps the only unrolled loop the two-element founder filter.
    fn two_signers(r0: i32, r1: i32) -> Keyring {
        let sig = |role: i32| AuthorizedSigner {
            public_key: Vec::new(),
            member_id: String::new(),
            role,
        };
        Keyring {
            tree_id: Vec::new(),
            revision: 1,
            layout_version: KEYRING_LAYOUT_VERSION,
            prev_keyring_hash: Vec::new(),
            authorized_signers: vec![sig(r0), sig(r1)],
            members: Vec::new(),
            signatures: Vec::new(),
            recovery_keys: Vec::new(),
            epochs: Vec::new(),
        }
    }

    /// Soundness of the "exactly one founder" structural gate: a two-signer set whose founder count is
    /// not exactly one is rejected with THAT specific reason. Pinning the exact `BadStructure` message —
    /// not a wildcard — is what gives this teeth: the founder gate runs *before* the per-signer key
    /// checks, so if it were weakened or deleted, execution would fall through and reject with a
    /// DIFFERENT message ("signer key malformed", from the empty public keys here), failing this
    /// assertion. Reaches only the size + founder checks (no crypto), hardening the OPE-228 founder
    /// mutant with a proof. (Scope: the two-signer case — founder counts 0 and 2; larger and empty
    /// sets are left to the test suite.)
    #[kani::proof]
    // Longest loop is the assert_eq!'s byte comparison of the 29-char BadStructure message (str::eq);
    // the founder filter is only 2. Bound clears both (+1 for the termination check).
    #[kani::unwind(32)]
    fn a_two_signer_set_without_exactly_one_founder_is_rejected_by_the_founder_gate() {
        let r0: i32 = kani::any();
        let r1: i32 = kani::any();
        let founders = (r0 == FOUNDER) as u32 + (r1 == FOUNDER) as u32;
        kani::assume(founders != 1);
        assert_eq!(
            check_structure(&two_signers(r0, r1)),
            Err(ChainError::BadStructure("must have exactly one founder")),
        );
    }
}

/// Kani proofs for `verify_transition`'s revision-ordering gates — OPE-238 Step A (Fable+Sonnet
/// design-reviewed). See `plan/kani.md` for the scope reasoning. The endorsement block's ACCEPTANCE
/// arm is PERMANENTLY out of Kani scope: it runs real Ed25519 (`verify_keyring*`) and the success path
/// hashes (`keyring_hash`), neither of which Kani can model — that arm belongs to the differential
/// proptest oracle + cargo-mutants. Only the rejection gates that fire BEFORE the first crypto
/// (`signer_keys`, line ~208) are reachable here.
///
/// These harnesses use `#[kani::stub]`, an UNSTABLE Kani feature — run with `-Z stubbing`:
///   `node scripts/kani.mjs -p openom-keyring -Z stubbing`
#[cfg(kani)]
mod transition_verification {
    use super::*;

    /// Models "the candidate is structurally valid." SOUND not because Step B proved `check_structure`
    /// (it proved only one sub-gate), but because the gates proven here read ONLY `candidate.revision` /
    /// `prev_keyring_hash` and the prior — nothing `check_structure` validates — and forcing `Ok`
    /// over-approximates the real program (which rejects some of these candidates earlier, still
    /// rejecting). NOTE: with a fixed-`Ok` stub, nothing here proves `verify_transition` even *calls*
    /// `check_structure` (delete that line and these still pass) — Step B's harness + the unit tests own
    /// that composition fact.
    fn structure_ok(_k: &Keyring) -> Result<(), ChainError> {
        Ok(())
    }

    /// Prior anchor + candidate keyring, everything empty/concrete except the two revisions. Built
    /// FIELD-WISE — never `KeyringAnchor::from_keyring` (it would call `keyring_hash` = SHA-256). Empty
    /// rosters + signatures so a mutated gate falls through to a crypto-free error, never an
    /// unmodellable `VerifyingKey`. No `.to_vec()`/non-empty Vec anywhere → no loops on these paths.
    fn prior_and_candidate(prior_rev: u32, cand_rev: u32) -> (KeyringAnchor, Keyring) {
        let prior = KeyringAnchor {
            tree_id: Vec::new(),
            revision: prior_rev,
            keyring_hash: [0u8; 32],
            trusted_signers: Vec::new(),
        };
        let candidate = Keyring {
            tree_id: Vec::new(), // == prior.tree_id (concrete-equal → past the tree check, no byte loop)
            revision: cand_rev,
            layout_version: KEYRING_LAYOUT_VERSION,
            prev_keyring_hash: Vec::new(),
            authorized_signers: Vec::new(),
            members: Vec::new(),
            signatures: Vec::new(),
            recovery_keys: Vec::new(),
            epochs: Vec::new(),
        };
        (prior, candidate)
    }

    /// At the maximum revision, NO candidate is accepted: `prior.revision.checked_add(1)` overflows to
    /// `RevisionOverflow`, so a low-revision candidate can't splice onto a `u32::MAX` anchor. The one
    /// gate of the three with no existing test. Diagnostic: mutate `checked_add` to `wrapping_add` and
    /// `expected` wraps to 0, letting a revision-0 candidate through — this proof then fails.
    #[kani::proof]
    #[kani::stub(check_structure, structure_ok)]
    fn at_max_revision_every_candidate_overflows() {
        let cand_rev: u32 = kani::any();
        let (prior, candidate) = prior_and_candidate(u32::MAX, cand_rev);
        assert_eq!(
            verify_transition(&prior, &candidate),
            Err(ChainError::RevisionOverflow),
        );
    }

    /// A candidate that does not advance the revision by exactly one is rejected as `NonSequential`
    /// (never `>=`, so a withheld hop can't hide a set change). `prior.revision < u32::MAX` so
    /// `checked_add` succeeds and execution reaches the sequential check.
    #[kani::proof]
    #[kani::stub(check_structure, structure_ok)]
    fn a_non_sequential_revision_is_rejected() {
        let prior_rev: u32 = kani::any();
        let cand_rev: u32 = kani::any();
        kani::assume(prior_rev < u32::MAX); // else RevisionOverflow fires first
        kani::assume(cand_rev != prior_rev + 1); // not exactly one past
        let (prior, candidate) = prior_and_candidate(prior_rev, cand_rev);
        assert_eq!(
            verify_transition(&prior, &candidate),
            Err(ChainError::NonSequential),
        );
    }

    /// A signer with a symbolic role but a fixed, position-distinct 1-byte key (enough to make two
    /// signers unequal under `same_signer`; empty `member_id` keeps the String compare O(1)).
    fn signer(tag: u8, role: i32) -> AuthorizedSigner {
        AuthorizedSigner {
            public_key: vec![tag],
            member_id: String::new(),
            role,
        }
    }

    /// An unchanged signer set is NOT a "set change": `signer_set_differs(s, s) == false`, for any
    /// roles. This is the gate (line ~209) that routes a revision to the ordinary-signature policy
    /// (any prior signer) vs the founder-or-unanimity policy — a false positive here would force needless
    /// unanimity (an availability bug), a false negative would let a signer-set change slip through under
    /// a single ordinary signature (a security bug). Pure, no crypto. Diagnostic: a broken `same_signer`
    /// (a dropped or inverted field compare) makes a signer fail to match itself → `differs` → fails.
    ///
    /// NOTE on `is_self_removal`'s deeper anti-mutiny scoping: it is a POOR Kani target and stays with
    /// the differential proptest oracle + mutants. Its structural gate is masked by the downstream
    /// `signer_key` (a wrong-length key → `None` → `false`, so a gate mutation still returns `false`),
    /// and every construction that would isolate a single gate term needs a candidate that is either
    /// founder-less (structurally impossible post-`check_structure` → vacuous) or reaches the
    /// un-modellable `VerifyingKey`.
    #[kani::proof]
    #[kani::unwind(3)] // the nested any() over the two-element set (2 iterations + 1)
    fn an_unchanged_signer_set_does_not_differ() {
        let (r0, r1): (i32, i32) = (kani::any(), kani::any());
        let s = vec![signer(0, r0), signer(1, r1)];
        assert!(!signer_set_differs(&s, &s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity, sign_keyring, SigningKey};
    use openom_protocol::v1::{KeyEpoch, KeyWrap, Member, MemberRole};

    const TREE: &[u8] = b"tree-uuid-16byte";
    const EDITOR: i32 = MemberRole::Editor as i32;
    const CO_OWNER_MEMBER: i32 = MemberRole::CoOwner as i32;

    fn key() -> SigningKey {
        generate_identity().unwrap()
    }
    fn pubv(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_bytes().to_vec()
    }
    fn signer(k: &SigningKey, id: &str, role: i32) -> AuthorizedSigner {
        AuthorizedSigner {
            public_key: pubv(k),
            member_id: id.into(),
            role,
        }
    }
    fn keyed_member(k: &SigningKey, id: &str, role: i32) -> Member {
        Member {
            member_id: id.into(),
            role,
            author_public_key: pubv(k),
            hpke_public_key: vec![9; 32],
        }
    }
    fn dummy_member(id: &str) -> Member {
        Member {
            member_id: id.into(),
            role: EDITOR,
            author_public_key: vec![7; 32],
            hpke_public_key: vec![9; 32],
        }
    }
    fn wrap(id: &str, method: i32) -> KeyWrap {
        KeyWrap {
            member_id: id.into(),
            wrap_method: method,
            nonce: vec![],
            wrapped_dek: vec![1],
            kdf_params: None,
            ephemeral_public_key: vec![],
            recipient_public_key: vec![],
        }
    }

    /// A genesis keyring: founder "owner" + the given co-owner signers + the given plain
    /// (keyless-dummy) members, with a matching wrap for each in epoch 0.
    fn genesis(founder: &SigningKey, co_owners: &[(&SigningKey, &str)], plain: &[&str]) -> Keyring {
        let mut signers = vec![signer(founder, "owner", FOUNDER)];
        let mut members = vec![keyed_member(founder, "owner", OWNER_MEMBER)];
        let mut wraps = vec![wrap("owner", RRK_HPKE)];
        for (k, id) in co_owners {
            signers.push(signer(k, id, CO_OWNER));
            members.push(keyed_member(k, id, CO_OWNER_MEMBER));
            wraps.push(wrap(id, HPKE));
        }
        for id in plain {
            members.push(dummy_member(id));
            wraps.push(wrap(id, HPKE));
        }
        let mut k = Keyring {
            tree_id: TREE.to_vec(),
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: signers,
            members,
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![0],
                epoch: 0,
                wraps,
            }],
            ..Default::default()
        };
        sign_keyring(&mut k, founder);
        k
    }

    #[test]
    fn verify_reset_rvk_gate_enforces_continuity_and_the_recovery_signature() {
        use openom_protocol::v1::RecoveryKey;
        let rvk = openom_crypto::derive_rvk(&[42u8; 32]); // the pinned recovery authority
        let rvk_pub = rvk.verifying_key().to_bytes().to_vec();

        // A reset keyring under a fresh founder (seed 7), pinning `pinned_rvk`, founder-signed and
        // optionally RVK-co-signed.
        let build = |pinned_rvk: Vec<u8>, rvk_co_signs: bool| -> Keyring {
            let f = sk(7);
            let mut k = genesis(&f, &[], &[]);
            k.recovery_keys = vec![RecoveryKey {
                public_key: vec![5; 32],
                member_id: "owner".into(),
                wraps: vec![],
                recovery_verifying_key: pinned_rvk,
            }];
            k.signatures.clear();
            sign_keyring(&mut k, &f);
            if rvk_co_signs {
                sign_keyring(&mut k, &rvk);
            }
            k
        };

        // continuity + RVK-signature both satisfied → accepted.
        assert!(
            verify_reset(Some(&rvk_pub), &build(rvk_pub.clone(), true)).is_ok(),
            "a continuous, RVK-signed reset is accepted"
        );
        // signed by the fresh founder but NOT the RVK → rejected (authorization).
        assert!(
            verify_reset(Some(&rvk_pub), &build(rvk_pub.clone(), false)).is_err(),
            "a reset not signed by the pinned recovery authority is rejected"
        );
        // a DIFFERENT recovery root pinned — a forged takeover → rejected (continuity), before signatures.
        let other = openom_crypto::derive_rvk(&[99u8; 32]).verifying_key().to_bytes().to_vec();
        assert!(
            verify_reset(Some(&rvk_pub), &build(other, true)).is_err(),
            "a reset under a fresh recovery root breaks continuity and is rejected"
        );
        // with NO prior RVK (pre-RVK keyring), the gate is inert — the self-signed reset is accepted.
        assert!(
            verify_reset(None, &build(rvk_pub.clone(), false)).is_ok(),
            "no prior recovery authority → the gate is inactive (backward-compatible)"
        );
    }

    #[test]
    fn verify_transition_allows_an_rvk_rotation_only_when_signed_by_the_old_authority() {
        use openom_protocol::v1::RecoveryKey;
        let rvk1 = openom_crypto::derive_rvk(&[42u8; 32]);
        let rvk1_pub = rvk1.verifying_key().to_bytes().to_vec();
        let rvk2_pub = openom_crypto::derive_rvk(&[99u8; 32]).verifying_key().to_bytes().to_vec();

        // Prior: a founder-only genesis pinning rvk1.
        let f = sk(1);
        let mut prior = genesis(&f, &[], &[]);
        prior.recovery_keys = vec![RecoveryKey {
            public_key: vec![5; 32],
            member_id: "owner".into(),
            wraps: vec![],
            recovery_verifying_key: rvk1_pub.clone(),
        }];
        prior.signatures.clear();
        sign_keyring(&mut prior, &f);
        let anchor = KeyringAnchor::from_keyring(&prior);
        assert_eq!(anchor.recovery_verifying_key, rvk1_pub);

        // A rev-2 that rotates the recovery authority rvk1 → rvk2, founder-signed and optionally OLD-RVK-signed.
        let rotate = |old_rvk_signs: bool| -> Keyring {
            let mut k = prior.clone();
            k.revision = 2;
            k.prev_keyring_hash = keyring_hash(&prior).to_vec();
            k.recovery_keys[0].recovery_verifying_key = rvk2_pub.clone();
            k.signatures.clear();
            sign_keyring(&mut k, &f);
            if old_rvk_signs {
                sign_keyring(&mut k, &rvk1);
            }
            k
        };

        // Signed by the OLD authority → the rotation takes effect; the anchor now carries rvk2.
        let ok = verify_transition(&anchor, &rotate(true)).unwrap();
        assert_eq!(ok.recovery_verifying_key, rvk2_pub, "an old-RVK-signed rotation is accepted");
        // Not signed by the OLD authority → rejected (can't rotate the recovery root out from under it).
        assert!(
            verify_transition(&anchor, &rotate(false)).is_err(),
            "a rotation not signed by the old recovery authority is rejected"
        );
    }

    #[test]
    fn establishing_a_first_rvk_needs_governance_not_a_lone_co_owner() {
        use openom_protocol::v1::RecoveryKey;
        // A pre-RVK genesis with the founder + TWO co-owners (so a lone co-owner is not unanimity).
        let (f, bob, carol) = (sk(1), sk(2), sk(3));
        let prior = genesis(&f, &[(&bob, "bob"), (&carol, "carol")], &[]);
        let anchor = KeyringAnchor::from_keyring(&prior);
        assert!(anchor.recovery_verifying_key.is_empty(), "the prior keyring pins no recovery authority");

        let rvk_pub = openom_crypto::derive_rvk(&[7u8; 32]).verifying_key().to_bytes().to_vec();
        let establish = |signer_seed: u8| -> Keyring {
            let mut k = prior.clone();
            k.revision = 2;
            k.prev_keyring_hash = keyring_hash(&prior).to_vec();
            k.recovery_keys = vec![RecoveryKey {
                public_key: vec![5; 32],
                member_id: "owner".into(),
                wraps: vec![],
                recovery_verifying_key: rvk_pub.clone(),
            }];
            k.signatures.clear();
            sign_keyring(&mut k, &sk(signer_seed));
            k
        };
        // A lone co-owner cannot plant a recovery authority — it's a privileged change (founder-or-unanimity).
        assert!(
            verify_transition(&anchor, &establish(2)).is_err(),
            "a lone co-owner cannot establish the recovery authority"
        );
        // The founder can (satisfies founder-or-unanimity alone).
        assert!(
            verify_transition(&anchor, &establish(1)).is_ok(),
            "the founder may establish the recovery authority"
        );
    }

    /// A mutation adding co-owner "d" (signer + member + epoch wrap) — a signer-set change.
    fn add_coowner(dk: &SigningKey) -> impl FnOnce(&mut Keyring) + '_ {
        move |k: &mut Keyring| {
            k.authorized_signers.push(signer(dk, "d", CO_OWNER));
            k.members.push(keyed_member(dk, "d", CO_OWNER_MEMBER));
            k.epochs[0].wraps.push(wrap("d", HPKE));
        }
    }

    #[test]
    fn governance_founder_or_threshold_gates_a_signer_change() {
        let (founder, a, b, c, d) = (key(), key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let anchor0 = KeyringAnchor::from_keyring(&g);

        // The founder sets founder-or-threshold(2) — itself a privileged change, authorized under the
        // prior (default founder-or-unanimity) rule by the founder.
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let anchor = verify_transition(&anchor0, &ruled).expect("founder may set the rule");
        assert_eq!((anchor.governance_kind, anchor.governance_threshold), (2, 2));

        // Adding a co-owner now needs 2 co-owners OR the founder.
        assert!(verify_transition(&anchor, &next(&ruled, add_coowner(&d), &[&a, &b])).is_ok(), "2 co-owners meet 2-of");
        assert!(verify_transition(&anchor, &next(&ruled, add_coowner(&d), &[&founder])).is_ok(), "the founder alone still works");
        assert!(
            matches!(
                verify_transition(&anchor, &next(&ruled, add_coowner(&d), &[&a])),
                Err(ChainError::UnendorsedSetChange)
            ),
            "1 co-owner is not 2-of, and the founder didn't sign"
        );
    }

    #[test]
    fn governance_change_is_anti_downgrade() {
        let (founder, a, b, c) = (key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let anchor = verify_transition(&KeyringAnchor::from_keyring(&g), &ruled).unwrap();

        // Weakening the rule (2-of -> founder-or-unanimity) is itself gated by the CURRENT (2-of) rule.
        assert!(
            matches!(
                verify_transition(&anchor, &next(&ruled, |k| k.governance_kind = 0, &[&a])),
                Err(ChainError::UnendorsedSetChange)
            ),
            "1 co-owner cannot weaken a 2-of rule"
        );
        assert!(
            verify_transition(&anchor, &next(&ruled, |k| k.governance_kind = 0, &[&a, &b])).is_ok(),
            "2 co-owners may change the rule"
        );
    }

    #[test]
    fn governance_lockout_is_refused() {
        let (founder, a, b, c) = (key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let anchor = verify_transition(&KeyringAnchor::from_keyring(&g), &ruled).unwrap();

        // threshold(5) with only 4 signers can never be satisfied → the lockout guard refuses it, even
        // though 2 co-owners authorized the change under the current rule.
        assert!(
            matches!(
                verify_transition(
                    &anchor,
                    &next(&ruled, |k| { k.governance_kind = 3; k.governance_threshold = 5; }, &[&a, &b]),
                ),
                Err(ChainError::UnendorsedSetChange)
            ),
            "a rule the candidate's own signer set can't satisfy is rejected (lockout)"
        );
    }

    #[test]
    fn draft_exchange_collects_signatures_then_promotes() {
        use crate::blob_sync::{KeyringChainBlobSync, Promotion};
        use blobstore::MemoryBlob;
        use openom_protocol::Message;
        use std::sync::Arc;

        let (founder, a, b, c, d) = (key(), key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);

        let store = Arc::new(MemoryBlob::new());
        let mut owner = KeyringChainBlobSync::new(store.clone());
        owner.publish(&g.encode_to_vec()).unwrap();
        owner.publish(&ruled.encode_to_vec()).unwrap(); // head = founder-or-threshold(2), rev 2

        // Co-owner "a" proposes adding co-owner "d" and signs it (1 of 2).
        let candidate = next(&ruled, add_coowner(&d), &[&a]);
        owner.propose("p1", &candidate.encode_to_vec()).unwrap();

        // A promoter bootstraps to the head and finds the draft not yet ready (1 < 2).
        let mut promoter = KeyringChainBlobSync::new(store.clone());
        promoter.bootstrap().unwrap();
        assert_eq!(promoter.promote("p1").unwrap(), Promotion::NotReady);

        // Co-owner "b" reviews the proposed candidate and countersigns it → 2 of 2 → promotes.
        owner.countersign("p1", &candidate.encode_to_vec(), &b).unwrap();
        assert_eq!(promoter.promote("p1").unwrap(), Promotion::Promoted);
        assert_eq!(promoter.revision(), Some(candidate.revision));
        assert!(promoter.get_draft("p1").unwrap().is_none(), "the promoted draft is cleaned up");
    }

    #[test]
    fn countersign_refuses_a_draft_swapped_since_review() {
        use crate::blob_sync::{KeyringChainBlobSync, SyncError};
        use blobstore::MemoryBlob;
        use openom_protocol::Message;
        use std::sync::Arc;

        let (founder, a, b, d) = (key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);

        let store = Arc::new(MemoryBlob::new());
        let mut owner = KeyringChainBlobSync::new(store.clone());
        owner.publish(&g.encode_to_vec()).unwrap();
        owner.publish(&ruled.encode_to_vec()).unwrap();

        // The draft actually sitting in the store escalates "d" to co-owner (a new signer), signed by "a".
        let in_store = next(&ruled, add_coowner(&d), &[&a]);
        owner.propose("p1", &in_store.encode_to_vec()).unwrap();

        // But co-owner "b" reviewed a DIFFERENT candidate — a benign governance tweak, no new signer.
        let reviewed = next(&ruled, |k| { k.governance_threshold = 1; }, &[&a]);

        // b countersigns what THEY reviewed; the store's content differs → refused, no signature harvested
        // over the unseen escalation.
        assert!(matches!(
            owner.countersign("p1", &reviewed.encode_to_vec(), &b),
            Err(SyncError::DraftContentChanged)
        ));

        // The store's draft never gained b's countersignature — it still carries only "a"'s.
        let after = Keyring::decode(owner.get_draft("p1").unwrap().unwrap().as_slice()).unwrap();
        assert_eq!(
            after.signatures.len(),
            1,
            "the swapped draft did not collect b's countersignature"
        );
    }

    #[test]
    fn a_stale_draft_is_detected_not_corrupting() {
        use crate::blob_sync::{KeyringChainBlobSync, Promotion};
        use blobstore::MemoryBlob;
        use openom_protocol::Message;
        use std::sync::Arc;

        let (founder, a, b, c, d) = (key(), key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let store = Arc::new(MemoryBlob::new());
        let mut owner = KeyringChainBlobSync::new(store.clone());
        owner.publish(&g.encode_to_vec()).unwrap();
        owner.publish(&ruled.encode_to_vec()).unwrap();

        // A fully-signed draft (a + b), built on rev 2.
        let candidate = next(&ruled, add_coowner(&d), &[&a, &b]);
        owner.propose("p1", &candidate.encode_to_vec()).unwrap();

        // Meanwhile a COMPETING revision advances the head to a different rev 3.
        let competing = next(&ruled, |k| k.members[1].role = EDITOR, &[&founder]);
        owner.publish(&competing.encode_to_vec()).unwrap();

        // The draft chained onto rev 2, but the head is now a different rev 3 → stale, not corrupting.
        assert_eq!(owner.promote("p1").unwrap(), Promotion::Stale);
    }

    #[test]
    fn a_non_curve_point_signer_key_is_rejected_as_malformed() {
        // A 32-byte public key that isn't a valid Ed25519 point must be rejected AS malformed — kills
        // check_structure's `len != 32 || signer_key.is_none()` -> `&&` (which would let a 32-byte
        // non-point slip past to a different, later error).
        let mut bad = [0u8; 32];
        bad[0] = 2; // y = 2 has no matching x on the curve (see openom-sign)
        let mut k = genesis(&key(), &[], &[]);
        k.authorized_signers[0].public_key = bad.to_vec();
        assert_eq!(
            check_structure(&k),
            Err(ChainError::BadStructure("signer key malformed"))
        );
    }

    #[test]
    fn exactly_max_signers_does_not_trip_the_size_cap() {
        // A signer list of EXACTLY MAX_SIGNERS is not "too large" — kills `> MAX_SIGNERS` -> `>=`. These
        // signers are otherwise invalid, so check_structure still rejects, just not for size.
        let signers: Vec<AuthorizedSigner> = (0..MAX_SIGNERS)
            .map(|i| AuthorizedSigner {
                public_key: vec![],
                member_id: format!("m{i}"),
                role: 0,
            })
            .collect();
        let k = Keyring {
            tree_id: TREE.to_vec(),
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: signers,
            members: vec![],
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![],
            ..Default::default()
        };
        assert_ne!(
            check_structure(&k),
            Err(ChainError::BadStructure("list too large"))
        );
    }

    /// A well-formed successor: revision+1, chained hash, `mutate` applied, then signed by
    /// each key in `sign_with`.
    fn next(
        prior: &Keyring,
        mutate: impl FnOnce(&mut Keyring),
        sign_with: &[&SigningKey],
    ) -> Keyring {
        let mut k = prior.clone();
        k.revision = prior.revision + 1;
        k.prev_keyring_hash = keyring_hash(prior).to_vec();
        mutate(&mut k);
        k.signatures.clear();
        for s in sign_with {
            sign_keyring(&mut k, s);
        }
        k
    }

    fn anchor(k: &Keyring) -> KeyringAnchor {
        KeyringAnchor::from_keyring(k)
    }

    // ---- boundary/negative coverage for the chain-verification predicates (mutation hardening) ----

    #[test]
    fn a_signer_whose_member_key_mismatches_is_rejected() {
        // check_structure's guard: a signer must be a member whose author key IS the signer key. If that
        // guard always matched, a signer could claim a member_id whose real key differs — impersonation.
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let bad = next(
            &g,
            |k| {
                let owner = k.members.iter_mut().find(|m| m.member_id == "owner").unwrap();
                owner.author_public_key = vec![8; 32]; // != the founder signer's key
            },
            &[&f],
        );
        assert!(matches!(
            verify_transition(&a, &bad),
            Err(ChainError::BadStructure(_))
        ));
    }

    #[test]
    fn a_duplicate_signer_member_id_is_rejected() {
        // Duplicate detection is member_id OR public_key; an AND would miss a second signer reusing a
        // member_id under a different key.
        let f = key();
        let x = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let bad = next(
            &g,
            |k| k.authorized_signers.push(signer(&x, "owner", CO_OWNER)),
            &[&f],
        );
        assert!(matches!(
            verify_transition(&a, &bad),
            Err(ChainError::BadStructure(_))
        ));
    }

    #[test]
    fn an_out_of_range_epoch_ordinal_is_rejected() {
        // OPE-289: for the linear chain, epoch ordinals are `0..N` (one per removal via max()+1). A signer
        // grinding an ordinal at/above the epoch count would brick every future re-epoch with
        // RevisionOverflow — a permanent DoS — so check_structure rejects it. The honest genesis passes.
        let f = key();
        let g = genesis(&f, &[], &[]);
        assert!(check_structure(&g).is_ok(), "honest genesis (epoch 0, len 1) is in range");
        let a = anchor(&g);
        let bad = next(&g, |k| k.epochs[0].epoch = u32::MAX, &[&f]);
        assert!(matches!(
            verify_transition(&a, &bad),
            Err(ChainError::BadStructure(_))
        ));
    }

    #[test]
    fn bootstrap_from_genesis_requires_revision_1_and_empty_prev_hash() {
        // The guard is (revision != 1 OR prev_hash non-empty); an AND would accept a non-genesis
        // revision as long as its prev_hash happened to be empty.
        let f = key();
        let mut g = genesis(&f, &[], &[]);
        g.revision = 2; // not a genesis revision, though prev_hash is still empty
        g.signatures.clear();
        sign_keyring(&mut g, &f);
        assert_eq!(
            bootstrap_from_genesis(&g, &f.verifying_key()),
            Err(ChainError::BadBootstrap)
        );
    }

    #[test]
    fn a_layout_version_ahead_is_rejected_on_both_paths() {
        // `layout_version > KEYRING_LAYOUT_VERSION` rejects a future layout; flipping the comparison
        // would let an ahead layout through (and spuriously reject the current one).
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let ahead = next(&g, |k| k.layout_version = KEYRING_LAYOUT_VERSION + 1, &[&f]);
        assert_eq!(verify_transition(&a, &ahead), Err(ChainError::LayoutAhead));

        let mut reset = genesis(&f, &[], &[]);
        reset.layout_version = KEYRING_LAYOUT_VERSION + 1;
        reset.signatures.clear();
        sign_keyring(&mut reset, &f);
        assert_eq!(verify_reset(None, &reset), Err(ChainError::LayoutAhead));
    }

    #[test]
    fn wrap_complete_requires_each_members_own_wrap_not_just_any_hpke_wrap() {
        // A member is covered only by a wrap matching (their member_id AND HPKE); an OR would let a
        // stray HPKE wrap for someone else satisfy a member who has no wrap — a silent lock-out.
        let f = key();
        let g = genesis(&f, &[], &["bob"]); // bob has his own HPKE wrap
        let a = anchor(&g);
        let bad = next(
            &g,
            |k| {
                // Reassign bob's wrap to a non-member: bob now has no wrap of his own, but an HPKE wrap
                // is still present in the epoch.
                let w = k.epochs[0]
                    .wraps
                    .iter_mut()
                    .find(|w| w.member_id == "bob")
                    .unwrap();
                w.member_id = "carol".into();
            },
            &[&f],
        );
        assert_eq!(verify_transition(&a, &bad), Err(ChainError::WrapIncomplete));
    }

    #[test]
    fn signer_set_differs_detects_a_role_flip_of_the_same_length() {
        // same_signer compares role, so a role escalation (same id+key) is a set change — flipping the
        // ORs to ANDs would classify it as an ordinary change (any single signer could sign it).
        let k1 = key();
        let prior = vec![signer(&k1, "m", CO_OWNER)];
        let candidate = vec![signer(&k1, "m", FOUNDER)];
        assert!(signer_set_differs(&prior, &candidate));
    }

    #[test]
    fn an_oversized_signer_list_is_rejected() {
        // The size caps are a three-way OR (signers/members/epochs); an AND would need all three over
        // the cap, and `>` must be `>` (not `==`/`>=`). One over-cap list alone must be rejected.
        let f = key();
        let mut k = genesis(&f, &[], &[]);
        let dummy = AuthorizedSigner {
            public_key: vec![1; 32],
            member_id: "x".into(),
            role: CO_OWNER,
        };
        while k.authorized_signers.len() <= MAX_SIGNERS {
            k.authorized_signers.push(dummy.clone());
        }
        assert_eq!(
            verify_reset(None, &k),
            Err(ChainError::BadStructure("list too large"))
        );
    }

    #[test]
    fn an_oversized_member_list_is_rejected() {
        let f = key();
        let mut k = genesis(&f, &[], &[]);
        let d = dummy_member("x");
        while k.members.len() <= MAX_MEMBERS {
            k.members.push(d.clone());
        }
        assert_eq!(
            verify_reset(None, &k),
            Err(ChainError::BadStructure("list too large"))
        );
    }

    #[test]
    fn an_oversized_epoch_list_is_rejected() {
        let f = key();
        let mut k = genesis(&f, &[], &[]);
        let e = k.epochs[0].clone();
        while k.epochs.len() <= MAX_EPOCHS {
            k.epochs.push(e.clone());
        }
        assert_eq!(
            verify_reset(None, &k),
            Err(ChainError::BadStructure("list too large"))
        );
    }

    #[test]
    fn ordinary_change_by_a_prior_signer_is_accepted_by_a_stranger_rejected() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);

        let ok = next(
            &g,
            |k| {
                k.members.push(dummy_member("bob"));
                k.epochs[0].wraps.push(wrap("bob", HPKE));
            },
            &[&f],
        );
        let out = verify_transition(&a, &ok).unwrap();
        assert_eq!(out.revision, 2);

        let stranger = key();
        let bad = next(
            &g,
            |k| {
                k.members.push(dummy_member("bob"));
                k.epochs[0].wraps.push(wrap("bob", HPKE));
            },
            &[&stranger],
        );
        assert_eq!(
            verify_transition(&a, &bad),
            Err(ChainError::UnendorsedOrdinaryChange)
        );
    }

    #[test]
    fn co_owner_can_sign_an_ordinary_change() {
        let f = key();
        let c = key();
        let g = genesis(&f, &[(&c, "carol")], &[]);
        let a = anchor(&g);
        let ok = next(
            &g,
            |k| {
                k.members.push(dummy_member("bob"));
                k.epochs[0].wraps.push(wrap("bob", HPKE));
            },
            &[&c],
        );
        verify_transition(&a, &ok).unwrap();
    }

    #[test]
    fn rollback_fork_and_gap_are_distinct_errors() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);

        // Revision jump (a withheld hop hidden as a skip).
        let mut skip = g.clone();
        skip.revision = 3;
        skip.prev_keyring_hash = keyring_hash(&g).to_vec();
        skip.signatures.clear();
        sign_keyring(&mut skip, &f);
        assert_eq!(verify_transition(&a, &skip), Err(ChainError::NonSequential));

        // Correct revision, wrong prev hash.
        let fork = next(&g, |k| k.prev_keyring_hash = vec![9; 32], &[&f]);
        assert_eq!(verify_transition(&a, &fork), Err(ChainError::Fork));
    }

    #[test]
    fn founder_gated_set_changes() {
        let f = key();
        let carol = key();
        // Carol starts as a keyed (promotable) member.
        let mut g = genesis(&f, &[], &[]);
        g.members.push(keyed_member(&carol, "carol", EDITOR));
        g.epochs[0].wraps.push(wrap("carol", HPKE));
        g.signatures.clear();
        sign_keyring(&mut g, &f);
        let a = anchor(&g);

        // Founder promotes carol → accepted.
        let promote = next(
            &g,
            |k| k.authorized_signers.push(signer(&carol, "carol", CO_OWNER)),
            &[&f],
        );
        verify_transition(&a, &promote).unwrap();

        // Carol signs her own promotion (mutiny) → rejected.
        let mutiny = next(
            &g,
            |k| k.authorized_signers.push(signer(&carol, "carol", CO_OWNER)),
            &[&carol],
        );
        assert_eq!(
            verify_transition(&a, &mutiny),
            Err(ChainError::UnendorsedSetChange)
        );
    }

    #[test]
    fn rogue_signer_injection_is_rejected() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let rogue = key();
        // The attacker adds the rogue as member AND signer (so structure passes) and signs
        // with the rogue — the headline attack.
        let attack = next(
            &g,
            |k| {
                k.members.push(keyed_member(&rogue, "rogue", EDITOR));
                k.epochs[0].wraps.push(wrap("rogue", HPKE));
                k.authorized_signers.push(signer(&rogue, "rogue", CO_OWNER));
            },
            &[&rogue],
        );
        assert_eq!(
            verify_transition(&a, &attack),
            Err(ChainError::UnendorsedSetChange)
        );
    }

    #[test]
    fn a_signer_who_is_not_a_member_is_structural_reject() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let rogue = key();
        let bad = next(
            &g,
            |k| k.authorized_signers.push(signer(&rogue, "ghost", CO_OWNER)),
            &[&f],
        );
        assert!(matches!(
            verify_transition(&a, &bad),
            Err(ChainError::BadStructure(_))
        ));
    }

    #[test]
    fn co_owner_can_remove_themselves_but_not_bundle_others() {
        let f = key();
        let carol = key();
        let dave = key();
        let g = genesis(&f, &[(&carol, "carol"), (&dave, "dave")], &[]);
        let a = anchor(&g);

        // Carol removes only herself, self-signed → accepted.
        let ok = next(
            &g,
            |k| k.authorized_signers.retain(|s| s.member_id != "carol"),
            &[&carol],
        );
        verify_transition(&a, &ok).unwrap();

        // Carol tries to remove herself AND dave, self-signed → rejected (not a lone self-removal).
        let bundled = next(
            &g,
            |k| {
                k.authorized_signers
                    .retain(|s| s.member_id != "carol" && s.member_id != "dave")
            },
            &[&carol],
        );
        assert_eq!(
            verify_transition(&a, &bundled),
            Err(ChainError::UnendorsedSetChange)
        );
    }

    #[test]
    fn founder_key_rotation_needs_the_old_key() {
        let f = key();
        let f2 = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let rotate = |k: &mut Keyring| {
            for s in &mut k.authorized_signers {
                if s.role == FOUNDER {
                    s.public_key = pubv(&f2);
                }
            }
            for m in &mut k.members {
                if m.member_id == "owner" {
                    m.author_public_key = pubv(&f2);
                }
            }
        };
        // Dual-signed (old + new) → accepted (alive succession / change_passphrase).
        verify_transition(&a, &next(&g, rotate, &[&f, &f2])).unwrap();
        // Signed only by the new key (recover / server splice) → rejected.
        assert_eq!(
            verify_transition(&a, &next(&g, rotate, &[&f2])),
            Err(ChainError::UnendorsedSetChange)
        );
    }

    #[test]
    fn wrap_incompleteness_and_double_founder_are_rejected() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        // Add a member with NO wrap in the newest epoch.
        let no_wrap = next(&g, |k| k.members.push(dummy_member("bob")), &[&f]);
        assert_eq!(
            verify_transition(&a, &no_wrap),
            Err(ChainError::WrapIncomplete)
        );
        // Two founders.
        let carol = key();
        let two = next(
            &g,
            |k| {
                k.members.push(keyed_member(&carol, "carol", EDITOR));
                k.epochs[0].wraps.push(wrap("carol", HPKE));
                k.authorized_signers.push(signer(&carol, "carol", FOUNDER));
            },
            &[&f],
        );
        assert!(matches!(
            verify_transition(&a, &two),
            Err(ChainError::BadStructure(_))
        ));
    }

    #[test]
    fn verify_reset_accepts_a_genesis_and_a_reset_but_not_an_unsigned_one() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        // A genesis validates on its own terms.
        assert_eq!(verify_reset(None, &g).unwrap().revision, 1);

        // A recovery-style reset: a later revision, a fresh (unendorsed) founder identity, self-
        // signed only by that new key — verify_transition would reject it, verify_reset accepts.
        let f2 = key();
        let mut reset = g.clone();
        reset.revision = 5;
        reset.prev_keyring_hash = vec![9; 32];
        reset.authorized_signers[0].public_key = pubv(&f2);
        reset.members[0].author_public_key = pubv(&f2);
        reset.signatures.clear();
        sign_keyring(&mut reset, &f2);
        assert_eq!(verify_reset(None, &reset).unwrap().revision, 5);
        assert_eq!(
            verify_transition(&anchor(&g), &reset).unwrap_err(),
            ChainError::NonSequential // (and even at the right revision it's an UnendorsedSetChange)
        );

        // A keyring signed by nobody in its own signer set is not a valid reset.
        let mut unsigned = g.clone();
        unsigned.signatures.clear();
        sign_keyring(&mut unsigned, &key());
        assert_eq!(verify_reset(None, &unsigned), Err(ChainError::BadBootstrap));
    }

    // --- Differential oracle -------------------------------------------------------------
    //
    // A second, independent accept/reject predicate over the *known facts* of a constructed
    // scenario (which mutation, who signed), asserted to agree with `verify_transition` over
    // random inputs. Every candidate is built structurally valid with the correct
    // revision/hash/wraps, so the only thing in play is the signature policy — which is
    // exactly the part worth cross-checking against a hand-written oracle.

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }
    // Fixed, distinct identities (deterministic, so proptest shrinking reproduces).
    fn founder_k() -> SigningKey {
        sk(1)
    }
    fn co_k(i: usize) -> SigningKey {
        sk(2 + i as u8)
    } // co0=2, co1=3, co2=4
    fn pend_k() -> SigningKey {
        sk(5)
    }
    fn new_founder_k() -> SigningKey {
        sk(6)
    }
    fn stranger_k() -> SigningKey {
        sk(7)
    }

    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        Ordinary,
        Promote,
        RemoveCoOwner,
        RotateFounder,
    }

    /// Prior keyring: founder + `n_co` co-owners + a promotable keyed member "pend".
    fn scenario_prior(n_co: usize) -> Keyring {
        let f = founder_k();
        let mut signers = vec![signer(&f, "owner", FOUNDER)];
        let mut members = vec![keyed_member(&f, "owner", OWNER_MEMBER)];
        let mut wraps = vec![wrap("owner", RRK_HPKE)];
        for i in 0..n_co {
            let id = format!("co{i}");
            signers.push(signer(&co_k(i), &id, CO_OWNER));
            members.push(keyed_member(&co_k(i), &id, CO_OWNER_MEMBER));
            wraps.push(wrap(&id, HPKE));
        }
        members.push(keyed_member(&pend_k(), "pend", EDITOR));
        wraps.push(wrap("pend", HPKE));
        let mut k = Keyring {
            tree_id: TREE.to_vec(),
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: signers,
            members,
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![0],
                epoch: 0,
                wraps,
            }],
            ..Default::default()
        };
        sign_keyring(&mut k, &f);
        k
    }

    fn scenario_candidate(prior: &Keyring, m: Mutation, sign_mask: u8) -> Keyring {
        let mutate = |k: &mut Keyring| match m {
            Mutation::Ordinary => {
                k.members.push(dummy_member("new"));
                k.epochs[0].wraps.push(wrap("new", HPKE));
            }
            Mutation::Promote => k
                .authorized_signers
                .push(signer(&pend_k(), "pend", CO_OWNER)),
            Mutation::RemoveCoOwner => k.authorized_signers.retain(|s| s.member_id != "co0"),
            Mutation::RotateFounder => {
                let np = pubv(&new_founder_k());
                for s in &mut k.authorized_signers {
                    if s.role == FOUNDER {
                        s.public_key = np.clone();
                    }
                }
                for mem in &mut k.members {
                    if mem.member_id == "owner" {
                        mem.author_public_key = np.clone();
                    }
                }
            }
        };
        // The signer roster the mask can draw from, bit 0..=5.
        let roster: [SigningKey; 6] = [
            founder_k(),
            co_k(0),
            co_k(1),
            co_k(2),
            pend_k(),
            stranger_k(),
        ];
        let signers: Vec<&SigningKey> = (0..6)
            .filter(|i| sign_mask & (1 << i) != 0)
            .map(|i| &roster[i])
            .collect();
        next(prior, mutate, &signers)
    }

    /// The independent predicate: does the signature policy authorize this transition?
    fn oracle_accepts(n_co: usize, m: Mutation, sign_mask: u8) -> bool {
        let bit = |i: usize| sign_mask & (1 << i) != 0;
        let founder_signed = bit(0);
        // Prior signer keys are the founder (bit 0) + co-owners (bits 1..=n_co).
        let unanimity = founder_signed && (0..n_co).all(|i| bit(1 + i));
        match m {
            Mutation::Ordinary => founder_signed || (0..n_co).any(|i| bit(1 + i)),
            // Set changes: founder-signed, unanimity of the prior set, or a lone self-removal.
            Mutation::Promote | Mutation::RotateFounder => founder_signed || unanimity,
            // RemoveCoOwner removes exactly co0 and adds nothing → self-removal if co0 signed.
            Mutation::RemoveCoOwner => founder_signed || unanimity || bit(1),
        }
    }

    proptest::proptest! {
        #[test]
        fn verify_transition_matches_the_oracle(
            n_co in 0usize..=3,
            mut_sel in 0u8..4,
            sign_mask in 0u8..64,
        ) {
            let mut m = match mut_sel {
                0 => Mutation::Ordinary,
                1 => Mutation::Promote,
                2 => Mutation::RemoveCoOwner,
                _ => Mutation::RotateFounder,
            };
            // Nothing to remove without a co-owner: fold that case into Ordinary so builder
            // and oracle stay in lockstep.
            if matches!(m, Mutation::RemoveCoOwner) && n_co == 0 {
                m = Mutation::Ordinary;
            }
            let prior = scenario_prior(n_co);
            let anchor = KeyringAnchor::from_keyring(&prior);
            let candidate = scenario_candidate(&prior, m, sign_mask);

            let accepted = verify_transition(&anchor, &candidate).is_ok();
            proptest::prop_assert_eq!(
                accepted,
                oracle_accepts(n_co, m, sign_mask),
                "mismatch: n_co={} mutation={:?} mask={:06b}",
                n_co, m, sign_mask
            );
        }
    }

    #[test]
    fn bootstrap_and_walk() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        // Founder bootstraps from genesis with their own key.
        let a = bootstrap_from_genesis(&g, &f.verifying_key()).unwrap();
        assert_eq!(a.revision, 1);
        assert!(bootstrap_from_genesis(&g, &key().verifying_key()).is_err());

        // OOB member bootstrap: pinned (revision, hash) must match.
        let h = keyring_hash(&g);
        bootstrap_from_oob(&g, TREE, 1, &h).unwrap();
        assert!(matches!(
            bootstrap_from_oob(&g, TREE, 1, &[0u8; 32]),
            Err(ChainError::BadBootstrap)
        ));

        // Walk two hops; a gap (skipping a hop) is rejected.
        let c1 = next(
            &g,
            |k| {
                k.members.push(dummy_member("bob"));
                k.epochs[0].wraps.push(wrap("bob", HPKE));
            },
            &[&f],
        );
        let c2 = next(
            &c1,
            |k| {
                k.members.push(dummy_member("eve"));
                k.epochs[0].wraps.push(wrap("eve", HPKE));
            },
            &[&f],
        );
        assert_eq!(
            verify_walk(&a, &[c1.clone(), c2.clone()]).unwrap().revision,
            3
        );
        assert_eq!(verify_walk(&a, &[c2]), Err(ChainError::NonSequential));
    }

    #[test]
    fn governing_keyring_mints_only_from_a_verified_chain() {
        let f = key();
        let g = genesis(&f, &[], &[]);

        // from_genesis mints for a founder-trusted genesis, and exposes the revision + persistable anchor.
        let gk = GoverningKeyring::from_genesis(g.clone(), &f.verifying_key()).unwrap();
        assert_eq!(gk.revision(), 1);
        assert_eq!(gk.anchor(), KeyringAnchor::from_keyring(&g));
        // …and rejects a genesis the caller's own founder key didn't sign.
        assert!(GoverningKeyring::from_genesis(g.clone(), &key().verifying_key()).is_err());

        // from_transition mints for a valid successor…
        let a = anchor(&g);
        let add_bob = |k: &mut Keyring| {
            k.members.push(dummy_member("bob"));
            k.epochs[0].wraps.push(wrap("bob", HPKE));
        };
        let ok = next(&g, add_bob, &[&f]);
        assert_eq!(
            GoverningKeyring::from_transition(&a, ok)
                .unwrap()
                .revision(),
            2
        );
        // …and rejects a successor signed by a stranger (no verified token, so verify_entry can't run).
        let bad = next(&g, add_bob, &[&key()]);
        assert_eq!(
            GoverningKeyring::from_transition(&a, bad).unwrap_err(),
            ChainError::UnendorsedOrdinaryChange
        );
    }
}
