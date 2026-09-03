#![doc = include_str!("../README.md")]
//! (See the crate README, included above, for the model overview.)

mod signing;

pub use signing::{doc_hash, signing_bytes};
use signing::{sha256, verify_all, verify_any, verify_threshold};

use keyeo_core::{Role, SignatureScheme};
use serde::Serialize;

/// Convenience aliases for a doc's public-key / signature types.
type Pk<D> = <<D as LinearDoc>::S as SignatureScheme>::PublicKey;
type Sig<D> = <<D as LinearDoc>::S as SignatureScheme>::Signature;

// ---- newtypes (zero-cost; a caller can't cross a group-id for a hash, a revision for a version, …) ----

/// The identifier of the membership group this chain governs (the chain's `tree_id`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupId(pub Vec<u8>);

/// The monotonic revision number. Each transition advances it by exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(pub u32);

/// SHA-256 of a doc's [`signing_bytes`] — the chain-link hash. A genesis's `prev_hash` is all-zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DocHash(pub [u8; 32]);

/// The binding's commitment over its ENTIRE payload (computed, never wire-carried; opaque to the engine).
/// Bound into the signed bytes so the payload is tamper-evident even though its shape is the binding's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PayloadCommitment(pub [u8; 32]);

// ---- membership + governance ----

/// A member of the group: an identity, its role, and its author public key. The engine derives the SIGNER
/// set from the full member set by [`LinearRole::is_signer`] — signer authority and member role can never
/// drift apart (there is no separate signer roster).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer<Id, R, PK> {
    pub id: Id,
    pub role: R,
    pub public_key: PK,
}

/// The per-group governance rule pinned in a doc. `kind`: 0 = founder-or-unanimity (default), 1 =
/// founder-only, 2 = founder-or-threshold(`threshold`), 3 = threshold(`threshold`) with no founder path.
/// The PRIOR anchor's rule authorizes the NEXT privileged change (anti-downgrade).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Governance {
    pub kind: u32,
    pub threshold: u32,
}

/// A [`Role`](keyeo_core::Role) with the two predicates the linear engine needs, kept abstract so the
/// engine never learns a domain's specific role ladder. `is_founder` marks the unique strongest role
/// (exactly one member must hold it); `is_signer` marks founder-or-co-owner (who may author revisions).
/// In openom's chain these are `role == 1` and `role in 1..=2`, but the engine only ever calls these.
pub trait LinearRole: Role + Copy {
    /// The unique strongest role — the founder. Exactly one member must hold it (enforced structurally).
    fn is_founder(&self) -> bool;
    /// A role that may author revisions — founder or co-owner. Signers are DERIVED via this predicate.
    fn is_signer(&self) -> bool;
}

/// A **doc whose legitimacy the chain-walk has established** — the generalization of the chain's
/// `KeyringAnchor`. It carries only the trust state a caller persists and passes back as `prior`: the
/// group id, the accepted revision, its [`DocHash`], the DERIVED signer set, the governance rule, and the
/// pinned recovery authority. A [`verify_transition`] (etc.) is the *only* way to obtain one over a
/// candidate, so an unverified doc cannot be mistaken for a trusted anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor<Id, R, PK> {
    pub group_id: GroupId,
    pub revision: Revision,
    pub doc_hash: DocHash,
    pub signers: Vec<Signer<Id, R, PK>>,
    pub governance: Governance,
    pub recovery_authority: Option<PK>,
}

/// A candidate membership doc the engine reasons over. The binding implements it; the engine builds its
/// signed message from these SAME accessor values (see [`signing_bytes`]), so "what decides == what is
/// signed". `structure_ok` is the binding's payload/structural gate (wrap-completeness, epoch ordinals,
/// layout-version bound) and the engine invokes it at EVERY entry point.
pub trait LinearDoc {
    /// A member identity — comparable and canonically-serializable (it is signed).
    type Id: Clone + std::fmt::Debug + Eq + Ord + Serialize;
    type R: LinearRole;
    type S: SignatureScheme;

    fn group_id(&self) -> &GroupId;
    fn revision(&self) -> Revision;
    fn prev_hash(&self) -> &DocHash;
    /// Engine-owned, fail-closed pre-signature layout selector — signed, so a future layout is byte-disjoint.
    fn layout_version(&self) -> u32;
    /// ALL members with roles + author keys; the engine derives the signer set via [`LinearRole::is_signer`].
    fn members(&self) -> Vec<Signer<Self::Id, Self::R, Pk<Self>>>;
    fn governance(&self) -> Governance;
    fn recovery_authority(&self) -> Option<Pk<Self>>;
    /// The unattributed signature set over [`signing_bytes`].
    fn signatures(&self) -> Vec<Sig<Self>>;
    /// The binding's commitment over its full payload (computed, opaque to the engine).
    fn payload_commitment(&self) -> PayloadCommitment;
    /// The binding's payload/structural acceptance gate. The engine calls it at every entry point (incl.
    /// per hop in [`verify_walk`]); a binding cannot forget to wire it. Return `Err(&'static str)` to
    /// reject with [`LinearError::Structure`].
    fn structure_ok(&self) -> Result<(), &'static str>;
}

/// Why a candidate doc was refused. Distinct variants so a caller can react differently (a fork/rollback
/// is an attack; a gap is availability; an unendorsed change is tampering) and each guard gets a 1-to-1
/// negative test. Generalizes openom-keyring-chain's `ChainError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinearError {
    #[error("candidate is for a different group")]
    GroupMismatch,
    #[error("doc layout is newer than this build understands")]
    LayoutAhead,
    #[error("doc is structurally invalid: {0}")]
    BadStructure(&'static str),
    #[error("the binding's structural gate rejected the doc: {0}")]
    Structure(&'static str),
    #[error("revision is not exactly one past the anchor (rollback or skip)")]
    NonSequential,
    #[error("the revision would overflow")]
    RevisionOverflow,
    #[error("prev_hash does not chain onto the anchor (fork / rewritten history)")]
    Fork,
    #[error("an ordinary revision not signed by any prior authorized signer")]
    UnendorsedOrdinaryChange,
    #[error("a signer-set / governance change not authorized by the prior rule")]
    UnendorsedSetChange,
    #[error("a live signer or member lacks a wrap in the newest epoch")]
    WrapIncomplete,
    #[error("bootstrap did not match the pinned head / genesis")]
    BadBootstrap,
}

// ---- structural + policy helpers (generalize chain.rs verbatim) ----

/// The engine-generic structural checks (from chain.rs `check_structure`): exactly one founder, members
/// deduped by id, each signer's key accepted by the scheme, and signers deduped by public key. Payload
/// checks (size caps, epoch ordinals, wrap-completeness, layout bound) are the binding's `structure_ok`.
fn check_structure_generic<D: LinearDoc>(doc: &D) -> Result<(), LinearError> {
    let members = doc.members();
    // Exactly one founder — a co-owner can't masquerade as the founder, and zero/two founders is malformed.
    if members.iter().filter(|m| m.role.is_founder()).count() != 1 {
        return Err(LinearError::BadStructure("must have exactly one founder"));
    }
    for (i, m) in members.iter().enumerate() {
        // No two members share an id (a decoy duplicate could otherwise inject a shadow role).
        if members[..i].iter().any(|o| o.id == m.id) {
            return Err(LinearError::BadStructure("duplicate member"));
        }
        if m.role.is_signer() {
            // A signer's key must be well-formed (else it could never verify its own signatures).
            if !<D::S>::accepts_key(&m.public_key) {
                return Err(LinearError::BadStructure("signer key malformed"));
            }
            // No two signers share a key (a repeated key must not make a quorum easier).
            if members[..i]
                .iter()
                .any(|o| o.role.is_signer() && o.public_key.as_ref() == m.public_key.as_ref())
            {
                return Err(LinearError::BadStructure("duplicate signer"));
            }
        }
    }
    Ok(())
}

/// The signer set derived from a member set: every member whose role [`is_signer`](LinearRole::is_signer).
fn derived_signers<Id: Clone, R: LinearRole, PK: Clone>(
    members: &[Signer<Id, R, PK>],
) -> Vec<Signer<Id, R, PK>> {
    members.iter().filter(|m| m.role.is_signer()).cloned().collect()
}

fn same_signer<Id: Eq, R: PartialEq, PK: AsRef<[u8]>>(
    a: &Signer<Id, R, PK>,
    b: &Signer<Id, R, PK>,
) -> bool {
    a.id == b.id && a.role == b.role && a.public_key.as_ref() == b.public_key.as_ref()
}

/// True if the signer sets differ as sets. Any in-place change — a key rotation, a role flip, add/remove —
/// counts (generalizes chain.rs `signer_set_differs`).
fn signer_set_differs<Id: Eq, R: PartialEq, PK: AsRef<[u8]>>(
    prior: &[Signer<Id, R, PK>],
    candidate: &[Signer<Id, R, PK>],
) -> bool {
    prior.len() != candidate.len()
        || prior.iter().any(|p| !candidate.iter().any(|c| same_signer(p, c)))
        || candidate.iter().any(|c| !prior.iter().any(|p| same_signer(p, c)))
}

/// The signer-set delta is EXACTLY one non-founder (co-owner) signer removed — nothing else added or
/// changed — and that signer's own key signed the doc. Scoped tightly so a mutineer can't bundle "remove
/// myself AND the founder" (generalizes chain.rs `is_self_removal`).
fn is_self_removal<Id, R, S>(
    prior: &[Signer<Id, R, S::PublicKey>],
    candidate: &[Signer<Id, R, S::PublicKey>],
    msg: &[u8],
    sigs: &[S::Signature],
) -> bool
where
    Id: Eq,
    R: LinearRole,
    S: SignatureScheme,
{
    let removed: Vec<&Signer<Id, R, S::PublicKey>> = prior
        .iter()
        .filter(|p| !candidate.iter().any(|c| same_signer(p, c)))
        .collect();
    let added = candidate.iter().any(|c| !prior.iter().any(|p| same_signer(p, c)));
    // Removing exactly one co-owner (never the founder), adding nothing.
    if added || removed.len() != 1 || removed[0].role.is_founder() {
        return false;
    }
    verify_any::<S>(msg, sigs, std::slice::from_ref(&removed[0].public_key))
}

/// Does the doc meet the PRIOR anchor's governance rule for a privileged change? Every check is against
/// the PRIOR trusted set (never the candidate's own claim) and BOTH the rule kind and threshold are read
/// from the prior anchor — the anti-downgrade discipline. A signer this doc REMOVES is excluded from the
/// threshold denominator (target-exclusion: you don't need a member's consent to evict them). Generalizes
/// chain.rs `prior_governance_met` verbatim.
fn prior_governance_met<Id, R, S>(
    prior: &Anchor<Id, R, S::PublicKey>,
    candidate_signers: &[Signer<Id, R, S::PublicKey>],
    msg: &[u8],
    sigs: &[S::Signature],
) -> bool
where
    Id: Eq,
    R: LinearRole,
    S: SignatureScheme,
{
    let founder = prior.signers.iter().find(|s| s.role.is_founder());
    let founder_signed = founder
        .map(|f| verify_any::<S>(msg, sigs, std::slice::from_ref(&f.public_key)))
        .unwrap_or(false);

    // Target-exclusion: the co-owner denominator is the prior signers, minus the founder, minus any signer
    // this doc removes. Computed against the DERIVED candidate signer set.
    let departing: Vec<&S::PublicKey> = prior
        .signers
        .iter()
        .filter(|p| !candidate_signers.iter().any(|c| same_signer(p, c)))
        .map(|p| &p.public_key)
        .collect();
    let is_founder_key = |k: &S::PublicKey| {
        founder.map(|f| f.public_key.as_ref() == k.as_ref()).unwrap_or(false)
    };
    let co_owner_keys: Vec<S::PublicKey> = prior
        .signers
        .iter()
        .map(|s| &s.public_key)
        .filter(|k| !is_founder_key(k) && !departing.iter().any(|d| d.as_ref() == k.as_ref()))
        .cloned()
        .collect();
    let prior_keys: Vec<S::PublicKey> = prior.signers.iter().map(|s| s.public_key.clone()).collect();

    let m = prior.governance.threshold as usize;
    match prior.governance.kind {
        1 => founder_signed,                                                            // founder-only
        2 => founder_signed || verify_threshold::<S>(msg, sigs, &co_owner_keys, m), // founder-or-threshold(m)
        3 => verify_threshold::<S>(msg, sigs, &prior_keys, m),                       // threshold(m), no founder
        _ => founder_signed || verify_all::<S>(msg, sigs, &prior_keys),             // 0/unknown: founder-or-unanimity
    }
}

/// Can this doc's own signer set ever satisfy its own governance rule? A rule no set can meet bricks
/// governance forever. Founder-or-* kinds are always satisfiable (a founder exists per
/// [`check_structure_generic`]); a pure threshold(m) needs at least m signers (generalizes
/// chain.rs `rule_is_satisfiable`).
fn rule_is_satisfiable(g: Governance, signer_count: usize) -> bool {
    let m = g.threshold as usize;
    match g.kind {
        0..=2 => true,
        3 => m > 0 && signer_count >= m,
        _ => false, // unknown kind: fail-closed
    }
}

/// The revision-successor rule as a pure helper: a legitimate successor's revision is EXACTLY `prior + 1`.
/// `u32::MAX` has no in-range successor (→ `None`, surfaced as [`LinearError::RevisionOverflow`]); every
/// other prior maps to `Some(prior + 1)`. Extracted so the arithmetic is provable in isolation and so
/// [`verify_transition`] and the proof share one definition — behaviour is identical to the inline
/// `checked_add(1)` it replaced.
fn next_revision(prior: u32) -> Option<u32> {
    prior.checked_add(1)
}

fn anchor_from_doc<D: LinearDoc>(doc: &D, msg: &[u8]) -> Anchor<D::Id, D::R, Pk<D>> {
    Anchor {
        group_id: doc.group_id().clone(),
        revision: doc.revision(),
        doc_hash: DocHash(sha256(msg)),
        signers: derived_signers(&doc.members()),
        governance: doc.governance(),
        recovery_authority: doc.recovery_authority(),
    }
}

// ---- engine entry points ----

/// Validate `cand` as the successor of `prior` and return the new verified [`Anchor`]. Pure; no I/O.
/// Reproduces chain.rs `verify_transition` generalized over `<Id, Role, Sig>`.
pub fn verify_transition<D: LinearDoc>(
    prior: &Anchor<D::Id, D::R, Pk<D>>,
    cand: &D,
) -> Result<Anchor<D::Id, D::R, Pk<D>>, LinearError> {
    if cand.group_id() != &prior.group_id {
        return Err(LinearError::GroupMismatch);
    }
    // The binding's payload/structural gate (wrap-completeness, epoch ordinals, layout bound), then the
    // engine-generic structural checks. Structure runs BEFORE the signature policy at every entry point.
    cand.structure_ok().map_err(LinearError::Structure)?;
    check_structure_generic(cand)?;

    // Exactly one past the anchor — never `>=`, so a withheld hop can't hide a set change.
    let expected = next_revision(prior.revision.0).ok_or(LinearError::RevisionOverflow)?;
    if cand.revision().0 != expected {
        return Err(LinearError::NonSequential);
    }
    if cand.prev_hash() != &prior.doc_hash {
        return Err(LinearError::Fork);
    }

    // The signed message + policy — always against the PRIOR trusted set, never the candidate's own claim.
    let msg = signing_bytes(cand);
    let sigs = cand.signatures();
    let members = cand.members();
    let candidate_signers = derived_signers(&members);
    let prior_keys: Vec<Pk<D>> = prior.signers.iter().map(|s| s.public_key.clone()).collect();

    let new_rvk = cand.recovery_authority();
    let old_rvk = prior.recovery_authority.as_ref();
    // Establishing a recovery authority where there was none plants a standing bearer-credential — a
    // PRIVILEGED change (not the ordinary any-of path), so a lone co-owner can't seize it on a pre-RVK doc.
    let rvk_establishment = old_rvk.is_none() && new_rvk.is_some();
    let signer_change = signer_set_differs(&prior.signers, &candidate_signers);
    // Changing the governance rule itself is privileged too — weakening it must still satisfy the CURRENT
    // (prior) rule (anti-downgrade).
    let governance_change = cand.governance() != prior.governance;

    if signer_change || governance_change || rvk_establishment {
        let self_removal = signer_change
            && is_self_removal::<D::Id, D::R, D::S>(&prior.signers, &candidate_signers, &msg, &sigs);
        if !(self_removal
            || prior_governance_met::<D::Id, D::R, D::S>(prior, &candidate_signers, &msg, &sigs))
        {
            return Err(LinearError::UnendorsedSetChange);
        }
        // Lockout guard: the doc's own signer set must be able to satisfy its own rule, or governance is
        // permanently bricked (no future privileged change could ever pass).
        if !rule_is_satisfiable(cand.governance(), candidate_signers.len()) {
            return Err(LinearError::UnendorsedSetChange);
        }
    } else if !verify_any::<D::S>(&msg, &sigs, &prior_keys) {
        return Err(LinearError::UnendorsedOrdinaryChange);
    }

    // ROTATING an existing recovery authority (old present, new differs — a change or a removal) requires
    // the OLD RVK's own signature — the only genuine way to revoke a prior recovery-key holder. An
    // unchanged RVK needs no such signature; ESTABLISHING a first one was gated as privileged above.
    if let Some(old) = old_rvk {
        if new_rvk.as_ref() != Some(old)
            && !verify_any::<D::S>(&msg, &sigs, std::slice::from_ref(old))
        {
            return Err(LinearError::UnendorsedSetChange);
        }
    }

    Ok(Anchor {
        group_id: cand.group_id().clone(),
        revision: cand.revision(),
        doc_hash: DocHash(sha256(&msg)),
        signers: candidate_signers,
        governance: cand.governance(),
        recovery_authority: new_rvk,
    })
}

/// Fold [`verify_transition`] over a contiguous run of candidates (revision N+1, N+2, …). Hop-by-hop is
/// mandatory — a signature at N+k proves authorship under the set at N+k−1 — so `structure_ok` runs each
/// hop (via `verify_transition`). `hops` must be ascending with no gaps; a gap surfaces as `NonSequential`.
pub fn verify_walk<D: LinearDoc>(
    prior: &Anchor<D::Id, D::R, Pk<D>>,
    hops: &[D],
) -> Result<Anchor<D::Id, D::R, Pk<D>>, LinearError> {
    let mut anchor = prior.clone();
    for hop in hops {
        anchor = verify_transition(&anchor, hop)?;
    }
    Ok(anchor)
}

/// Validate a doc that establishes a NEW anchor on its own terms — a genesis, or a recovery / succession
/// reset whose new founder identity deliberately carries no endorsement from the old one. Unlike
/// [`verify_transition`] it does not chain onto a prior anchor: it checks the doc is structurally sound and
/// self-signed by one of its own current signers. When `prior_rvk` is present (the PRIOR doc pinned a
/// recovery authority) the reset must carry the SAME authority (continuity) AND be signed by it
/// (authorization). Generalizes chain.rs `verify_reset`.
pub fn verify_reset<D: LinearDoc>(
    prior_rvk: Option<&Pk<D>>,
    doc: &D,
) -> Result<Anchor<D::Id, D::R, Pk<D>>, LinearError> {
    doc.structure_ok().map_err(LinearError::Structure)?;
    check_structure_generic(doc)?;

    let msg = signing_bytes(doc);
    let sigs = doc.signatures();
    let members = doc.members();
    let signer_keys: Vec<Pk<D>> = derived_signers(&members)
        .into_iter()
        .map(|s| s.public_key)
        .collect();
    // Self-consistency: signed by one of its own signers (the CALLER, not a signature, supplies the trust
    // that this reset is authorized).
    if !verify_any::<D::S>(&msg, &sigs, &signer_keys) {
        return Err(LinearError::BadBootstrap);
    }
    if let Some(prior) = prior_rvk {
        let rvk = doc.recovery_authority().ok_or(LinearError::UnendorsedSetChange)?;
        if rvk.as_ref() != prior.as_ref() {
            return Err(LinearError::UnendorsedSetChange); // continuity: no forged takeover under a fresh root
        }
        if !verify_any::<D::S>(&msg, &sigs, std::slice::from_ref(prior)) {
            return Err(LinearError::UnendorsedSetChange); // authorization: the resetter holds the recovery secret
        }
    }
    Ok(anchor_from_doc(doc, &msg))
}

/// Seed an anchor from a GENESIS doc (revision 1, all-zero `prev_hash`) as the founder: exactly one
/// founder whose key is the caller's own, signed by it. Cryptographic first-sight for the founder path.
/// Generalizes chain.rs `bootstrap_from_genesis`.
pub fn bootstrap_genesis<D: LinearDoc>(
    genesis: &D,
    own_founder_key: &Pk<D>,
) -> Result<Anchor<D::Id, D::R, Pk<D>>, LinearError> {
    genesis.structure_ok().map_err(LinearError::Structure)?;
    check_structure_generic(genesis)?;
    if genesis.revision().0 != 1 || genesis.prev_hash() != &DocHash([0u8; 32]) {
        return Err(LinearError::BadBootstrap);
    }
    let members = genesis.members();
    let founder = members
        .iter()
        .find(|m| m.role.is_founder())
        .ok_or(LinearError::BadStructure("no founder"))?;
    if founder.public_key.as_ref() != own_founder_key.as_ref() {
        return Err(LinearError::BadBootstrap);
    }
    let msg = signing_bytes(genesis);
    let sigs = genesis.signatures();
    if !verify_any::<D::S>(&msg, &sigs, std::slice::from_ref(own_founder_key)) {
        return Err(LinearError::BadBootstrap);
    }
    Ok(anchor_from_doc(genesis, &msg))
}

/// Seed an anchor from a head doc pinned OUT-OF-BAND: the caller supplies `(group_id, revision, doc_hash)`
/// and the doc must match exactly — the OOB channel, not any signature, is the trust root for this first
/// revision. A hygiene self-signature is still checked. Generalizes chain.rs `bootstrap_from_oob`.
pub fn bootstrap_pinned<D: LinearDoc>(
    head: &D,
    pinned_group: &GroupId,
    pinned_revision: Revision,
    pinned_hash: &DocHash,
) -> Result<Anchor<D::Id, D::R, Pk<D>>, LinearError> {
    if head.group_id() != pinned_group {
        return Err(LinearError::GroupMismatch);
    }
    head.structure_ok().map_err(LinearError::Structure)?;
    check_structure_generic(head)?;
    let msg = signing_bytes(head);
    let hash = DocHash(sha256(&msg));
    if head.revision() != pinned_revision || &hash != pinned_hash {
        return Err(LinearError::BadBootstrap);
    }
    let sigs = head.signatures();
    let members = head.members();
    let signer_keys: Vec<Pk<D>> = derived_signers(&members)
        .into_iter()
        .map(|s| s.public_key)
        .collect();
    if !verify_any::<D::S>(&msg, &sigs, &signer_keys) {
        return Err(LinearError::BadBootstrap);
    }
    Ok(anchor_from_doc(head, &msg))
}

/// Kani proof harnesses — bit-precise model checking (CBMC backend). Compiled ONLY under `cargo kani`
/// (which sets `--cfg kani`); the normal build and `cargo test` never see them, so there is no `kani`
/// dependency in `Cargo.toml`. Run them with `node scripts/kani.mjs -p keyeo-linear` (Docker image or a
/// local Kani install).
///
/// keyeo-linear is a deliberate good-first Kani target: the policy predicates it decides on are pure and
/// primitive-typed. These harnesses cover the branch-free, crypto-free core — the governance-satisfiability
/// classifier, the revision-successor arithmetic, and the signer-set diff's set semantics — proving each
/// property for ALL inputs in a bounded range at once (not sampled, as a proptest would). We deliberately do
/// NOT prove `verify_transition`/`verify_walk` end-to-end, `bootstrap_*`/`verify_reset`, or the
/// `check_structure_generic` path: those route through the `SignatureScheme` crypto (SHA-256 + Ed25519
/// verify) and `LinearDoc` trait dispatch, which Kani cannot bit-blast tractably.
#[cfg(kani)]
mod verification {
    use super::*;

    /// A tiny concrete signer over primitive fields — no crypto, no trait objects — so the set-diff
    /// helpers (which are generic only over `Id: Eq`, `R: PartialEq`, `PK: AsRef<[u8]>`) can be exercised
    /// with fully symbolic contents. `[u8; 1]` is the smallest `AsRef<[u8]>` public key.
    type TinySigner = Signer<u8, i16, [u8; 1]>;

    fn any_signer() -> TinySigner {
        Signer {
            id: kani::any(),
            role: kani::any(),
            public_key: [kani::any()],
        }
    }

    /// Governance kind 3 (pure threshold, no founder path) is satisfiable IFF `threshold > 0` AND the
    /// signer set is at least `threshold` large — a rule of `threshold(0)` or one needing more signers than
    /// exist can never be met, so it would brick governance. Proven for every `(threshold, signer_count)`.
    /// `threshold as usize` is lossless on Kani's 64-bit target, so the spec can read `threshold` directly.
    #[kani::proof]
    fn rule_kind3_satisfiable_iff_threshold_positive_and_enough_signers() {
        let threshold: u32 = kani::any();
        let signer_count: usize = kani::any();
        let g = Governance { kind: 3, threshold };
        let expected = threshold > 0 && signer_count >= threshold as usize;
        assert_eq!(rule_is_satisfiable(g, signer_count), expected);
    }

    /// The founder-bearing kinds (0 = founder-or-unanimity, 1 = founder-only, 2 = founder-or-threshold) are
    /// ALWAYS satisfiable — `check_structure_generic` guarantees a founder exists, so the founder path can
    /// always be walked regardless of threshold or signer count. Proven for every threshold/count.
    #[kani::proof]
    fn rule_founder_kinds_are_always_satisfiable() {
        let kind: u32 = kani::any();
        kani::assume(kind <= 2);
        let threshold: u32 = kani::any();
        let signer_count: usize = kani::any();
        assert!(rule_is_satisfiable(Governance { kind, threshold }, signer_count));
    }

    /// Fail-closed: any governance `kind` this build does not recognise (anything outside `0..=3`) is NEVER
    /// treated as satisfiable — an unknown rule must not silently pass the lockout guard. Proven for every
    /// unknown kind, threshold, and signer count.
    #[kani::proof]
    fn rule_unknown_kind_fails_closed() {
        let kind: u32 = kani::any();
        kani::assume(kind >= 4); // 0..=2 founder kinds, 3 the threshold kind; everything else is unknown
        let threshold: u32 = kani::any();
        let signer_count: usize = kani::any();
        assert!(!rule_is_satisfiable(Governance { kind, threshold }, signer_count));
    }

    /// The revision-successor rule: exactly one prior (`u32::MAX`) has no in-range successor and is the only
    /// value rejected; every other prior yields precisely `prior + 1`, which is strictly greater (so a
    /// rollback or a skip can never be mistaken for the successor). Proven for every `u32` prior.
    #[kani::proof]
    fn next_revision_rejects_only_max_and_yields_exactly_prior_plus_one() {
        let prior: u32 = kani::any();
        match next_revision(prior) {
            None => assert_eq!(prior, u32::MAX),
            Some(next) => {
                assert!(prior != u32::MAX);
                assert_eq!(next, prior + 1);
                assert!(next > prior);
            }
        }
    }

    /// `signer_set_differs` is reflexive: a set never differs from itself, whatever its (symbolic) members.
    /// A false positive here would flag every no-op revision as a privileged signer-set change. Two members
    /// with fully symbolic id/role/key is enough to exercise the cross-membership matching both ways.
    #[kani::proof]
    #[kani::unwind(3)] // the diff's `.any` loops run over a fixed 2-element slice
    fn signer_set_differs_is_reflexive() {
        let set: [TinySigner; 2] = [any_signer(), any_signer()];
        assert!(!signer_set_differs(&set, &set));
    }

    /// A length change is always detected: sets of different sizes always differ (the `len()` short-circuit
    /// — an added or removed signer can never be hidden). Proven for symbolic contents on both sides.
    #[kani::proof]
    #[kani::unwind(3)]
    fn signer_set_differs_detects_a_length_change() {
        let shorter: [TinySigner; 1] = [any_signer()];
        let longer: [TinySigner; 2] = [any_signer(), any_signer()];
        assert!(signer_set_differs(&shorter, &longer));
        assert!(signer_set_differs(&longer, &shorter));
    }

    /// An in-place key rotation (same length, one member's key changed) is detected as a set difference —
    /// this is what forces a key rotation down the privileged `UnendorsedSetChange` path. Two singleton
    /// sets whose sole members share id+role but hold DISTINCT keys must differ.
    #[kani::proof]
    #[kani::unwind(3)]
    fn signer_set_differs_detects_a_key_rotation() {
        let id: u8 = kani::any();
        let role: i16 = kani::any();
        let (k_old, k_new): (u8, u8) = (kani::any(), kani::any());
        kani::assume(k_old != k_new);
        let before: [TinySigner; 1] = [Signer { id, role, public_key: [k_old] }];
        let after: [TinySigner; 1] = [Signer { id, role, public_key: [k_new] }];
        assert!(signer_set_differs(&before, &after));
    }
}

#[cfg(test)]
mod tests;
