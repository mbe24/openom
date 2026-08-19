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

use openom_protocol::v1::{AuthorizedSigner, Keyring, MemberRole, SignerRole, WrapMethod};
use openom_protocol::KEYRING_LAYOUT_VERSION;

use crate::{keyring_hash, verify_keyring, verify_keyring_all, verify_keyring_any, VerifyingKey};

const FOUNDER: i32 = SignerRole::Founder as i32;
const CO_OWNER: i32 = SignerRole::CoOwner as i32;
const OWNER_MEMBER: i32 = MemberRole::Owner as i32;
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
        }
    }

    fn founder(&self) -> Option<&AuthorizedSigner> {
        self.trusted_signers.iter().find(|s| s.role == FOUNDER)
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
    if signer_set_differs(&prior.trusted_signers, &candidate.authorized_signers) {
        let founder_signed = prior
            .founder()
            .and_then(|s| signer_key(s))
            .map(|k| verify_keyring(candidate, &k).is_ok())
            .unwrap_or(false);
        let unanimous = verify_keyring_all(candidate, &prior_keys).is_ok();
        let self_removal = is_self_removal(
            &prior.trusted_signers,
            &candidate.authorized_signers,
            candidate,
        );
        if !(founder_signed || unanimous || self_removal) {
            return Err(ChainError::UnendorsedSetChange);
        }
    } else {
        verify_keyring_any(candidate, &prior_keys)
            .map_err(|_| ChainError::UnendorsedOrdinaryChange)?;
    }

    if !wrap_complete(candidate) {
        return Err(ChainError::WrapIncomplete);
    }

    Ok(KeyringAnchor {
        tree_id: candidate.tree_id.clone(),
        revision: candidate.revision,
        keyring_hash: keyring_hash(candidate),
        trusted_signers: candidate.authorized_signers.clone(),
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
pub fn verify_reset(keyring: &Keyring) -> Result<KeyringAnchor, ChainError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity, sign_keyring, SigningKey};
    use openom_protocol::v1::{KeyEpoch, KeyWrap, Member};

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
        };
        sign_keyring(&mut k, founder);
        k
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
        assert_eq!(verify_reset(&g).unwrap().revision, 1);

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
        assert_eq!(verify_reset(&reset).unwrap().revision, 5);
        assert_eq!(
            verify_transition(&anchor(&g), &reset).unwrap_err(),
            ChainError::NonSequential // (and even at the right revision it's an UnendorsedSetChange)
        );

        // A keyring signed by nobody in its own signer set is not a valid reset.
        let mut unsigned = g.clone();
        unsigned.signatures.clear();
        sign_keyring(&mut unsigned, &key());
        assert_eq!(verify_reset(&unsigned), Err(ChainError::BadBootstrap));
    }

    // --- Differential oracle -------------------------------------------------------------
    //
    // A second, independent accept/reject predicate over the *known facts* of a constructed
    // scenario (which mutation, who signed), asserted to agree with `verify_transition` over
    // random inputs. Every candidate is built structurally valid with the correct
    // revision/hash/wraps, so the only thing in play is the signature policy — which is
    // exactly the part worth cross-checking against a hand-written oracle.

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
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
}
