//! Keyring chain-walk (§2.4, §10) — the client-side enforcement that a keyring served by the (untrusted)
//! network is a **legitimate successor** of the one the client already trusts.
//!
//! Since OPE-300 the transition/walk/reset/bootstrap/governance/quorum LOGIC lives in the generic
//! `keyeo-linear` engine; this module is the openom binding around it: it maps the chain's `KeyringAnchor`
//! and proto `Keyring` (via [`ChainDoc`](crate::doc::ChainDoc)) to and from the engine's `Anchor`/
//! `LinearDoc`, and classes the engine's `LinearError` back into the chain's `ChainError` taxonomy so the
//! accept/reject behavior is unchanged. The engine owns its signed bytes + a payload commitment; this
//! binding owns the wire, the payload gates, and the governing-ref adapter.

use keyeo_linear::{
    Anchor, DocHash, Governance, GroupId, LinearError, Revision, Signer,
};

use crate::doc::{reset_rvk, to_pk32, ChainDoc, ChainRole, S_LAYOUT_AHEAD, S_WRAP_INCOMPLETE};
use crate::keyring::{keyring_hash, VerifyingKey};
use crate::wire::Keyring;

/// An authorized signer — a founder or co-owner who may author keyring revisions. **Not a wire message**:
/// the signer set is DERIVED from `members` (a member at CO_OWNER or stronger IS a signer), so signer
/// authority and member role can never drift apart (OPE-309). This is the in-memory shape the persisted
/// anchor's trust set works over; `role` carries the member's role value (Owner==Founder==1, CoOwner==2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedSigner {
    pub public_key: Vec<u8>,
    pub member_id: String,
    pub role: i32,
}

/// The signer set **derived** from a keyring's members: every member at CO_OWNER or stronger (role in
/// `1..=2`), carrying that member's own author key. This — not a separate roster — is the trust set the
/// chain-walk verifies against.
fn derived_signers(k: &Keyring) -> Vec<AuthorizedSigner> {
    k.members
        .iter()
        .filter(|m| (1..=2).contains(&m.role))
        .map(|m| AuthorizedSigner {
            public_key: m.author_public_key.clone(),
            member_id: m.member_id.clone(),
            role: m.role,
        })
        .collect()
}

/// The client's trusted keyring state for one tree — the last keyring it accepted. Everything here is
/// derivable from that keyring, so the store persists the keyring itself and rebuilds the anchor with
/// [`KeyringAnchor::from_keyring`]; there is no separate on-disk anchor blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringAnchor {
    pub tree_id: Vec<u8>,
    pub revision: u32,
    pub keyring_hash: [u8; 32],
    pub trusted_signers: Vec<AuthorizedSigner>,
    /// The governance rule this keyring pins (see `Keyring.governance_kind`). The PRIOR anchor's rule
    /// authorizes the NEXT privileged change (anti-downgrade).
    pub governance_kind: u32,
    pub governance_threshold: u32,
    /// The recovery verifying key (RVK) pinned in this keyring, or empty if none.
    pub recovery_verifying_key: Vec<u8>,
}

impl KeyringAnchor {
    /// Build an anchor from an **already-trusted** keyring (a locally stored, previously accepted one).
    /// Performs no policy check — the keyring is the trust root here.
    pub fn from_keyring(keyring: &Keyring) -> Self {
        KeyringAnchor {
            tree_id: keyring.tree_id.clone(),
            revision: keyring.revision,
            keyring_hash: keyring_hash(keyring),
            trusted_signers: derived_signers(keyring),
            governance_kind: keyring.governance_kind,
            governance_threshold: keyring.governance_threshold,
            recovery_verifying_key: reset_rvk(keyring).map(<[u8]>::to_vec).unwrap_or_default(),
        }
    }
}

// ---- KeyringAnchor <-> keyeo_linear::Anchor ----

type LinAnchor = Anchor<String, ChainRole, [u8; 32]>;

fn to_linear_anchor(prior: &KeyringAnchor) -> LinAnchor {
    Anchor {
        group_id: GroupId(prior.tree_id.clone()),
        revision: Revision(prior.revision),
        doc_hash: DocHash(prior.keyring_hash),
        signers: prior
            .trusted_signers
            .iter()
            .map(|s| Signer {
                id: s.member_id.clone(),
                role: ChainRole(s.role as i16),
                public_key: to_pk32(&s.public_key),
            })
            .collect(),
        governance: Governance {
            kind: prior.governance_kind,
            threshold: prior.governance_threshold,
        },
        recovery_authority: (!prior.recovery_verifying_key.is_empty())
            .then(|| to_pk32(&prior.recovery_verifying_key)),
    }
}

fn from_linear_anchor(out: LinAnchor) -> KeyringAnchor {
    KeyringAnchor {
        tree_id: out.group_id.0,
        revision: out.revision.0,
        keyring_hash: out.doc_hash.0,
        trusted_signers: out
            .signers
            .into_iter()
            .map(|s| AuthorizedSigner {
                public_key: s.public_key.to_vec(),
                member_id: s.id,
                role: s.role.0 as i32,
            })
            .collect(),
        governance_kind: out.governance.kind,
        governance_threshold: out.governance.threshold,
        recovery_verifying_key: out.recovery_authority.map(|k| k.to_vec()).unwrap_or_default(),
    }
}

/// Class the generic engine's `LinearError` into the chain's own error taxonomy, preserving the exact
/// accept/reject behavior. The binding's `structure_ok` sentinels (see `crate::doc`) map back to the
/// specific chain reasons (`LayoutAhead` / `WrapIncomplete` / else `BadStructure`).
fn map_linear_err(e: LinearError) -> ChainError {
    match e {
        LinearError::GroupMismatch => ChainError::TreeMismatch,
        LinearError::LayoutAhead => ChainError::LayoutAhead,
        LinearError::BadStructure(s) => ChainError::BadStructure(s),
        LinearError::Structure(s) => match s {
            S_LAYOUT_AHEAD => ChainError::LayoutAhead,
            S_WRAP_INCOMPLETE => ChainError::WrapIncomplete,
            other => ChainError::BadStructure(other),
        },
        LinearError::NonSequential => ChainError::NonSequential,
        LinearError::RevisionOverflow => ChainError::RevisionOverflow,
        LinearError::Fork => ChainError::Fork,
        LinearError::UnendorsedOrdinaryChange => ChainError::UnendorsedOrdinaryChange,
        LinearError::UnendorsedSetChange => ChainError::UnendorsedSetChange,
        LinearError::WrapIncomplete => ChainError::WrapIncomplete,
        LinearError::BadBootstrap => ChainError::BadBootstrap,
    }
}

/// Chain engine: encode a governing keyring's **revision** as the entry's opaque `governing_ref` — 4
/// big-endian bytes. Opaque to every layer but this adapter (the verifier decodes it back to a revision,
/// then walks the chain to that revision). Intentionally minimal to preserve V1 resolution semantics.
pub fn encode_governing_ref(revision: u32) -> Vec<u8> {
    revision.to_be_bytes().to_vec()
}

/// Decode a chain [`encode_governing_ref`] back to a revision. `None` if the bytes aren't exactly a 4-byte
/// big-endian revision (a malformed or foreign ref — the caller refuses to resolve it).
pub fn decode_governing_ref(governing_ref: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = governing_ref.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[derive(Clone, Debug)]
pub struct GoverningKeyring {
    keyring: Keyring,
}

impl GoverningKeyring {
    /// The revision this keyring governs.
    pub fn revision(&self) -> u32 {
        self.keyring.revision
    }

    /// This keyring's [`governing reference`](encode_governing_ref).
    pub fn governing_ref(&self) -> Vec<u8> {
        encode_governing_ref(self.revision())
    }

    /// The trust anchor to persist (so the next transition can chain onto it).
    pub fn anchor(&self) -> KeyringAnchor {
        KeyringAnchor::from_keyring(&self.keyring)
    }

    /// Mint by validating `candidate` as the successor of `prior` — see [`verify_transition`].
    pub fn from_transition(prior: &KeyringAnchor, candidate: Keyring) -> Result<Self, ChainError> {
        verify_transition(prior, &candidate)?;
        Ok(Self { keyring: candidate })
    }

    /// Mint a first-sight genesis the founder trusts by its own key — see [`bootstrap_from_genesis`].
    pub fn from_genesis(genesis: Keyring, own_founder_key: &VerifyingKey) -> Result<Self, ChainError> {
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
        verify_reset(None, &keyring)?;
        Ok(Self { keyring })
    }
}

/// Why a candidate keyring was refused as a successor. Distinct variants so the client can react
/// differently (a fork/rollback is an attack; a gap is availability; an unendorsed change is tampering).
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

/// Validate `candidate` as the successor of `prior` and return the new anchor. Pure; no I/O. Delegates to
/// [`keyeo_linear::verify_transition`] over the chain's [`ChainDoc`].
pub fn verify_transition(
    prior: &KeyringAnchor,
    candidate: &Keyring,
) -> Result<KeyringAnchor, ChainError> {
    let anchor = to_linear_anchor(prior);
    let out = keyeo_linear::verify_transition(&anchor, &ChainDoc::new(candidate))
        .map_err(map_linear_err)?;
    Ok(from_linear_anchor(out))
}

/// Fold [`verify_transition`] over a contiguous run of candidates (revision N+1, N+2, …). Hop-by-hop is
/// mandatory. `hops` must be in ascending revision order with no gaps; a gap surfaces as `NonSequential`.
pub fn verify_walk(prior: &KeyringAnchor, hops: &[Keyring]) -> Result<KeyringAnchor, ChainError> {
    let mut anchor = prior.clone();
    for hop in hops {
        anchor = verify_transition(&anchor, hop)?;
    }
    Ok(anchor)
}

/// Seed an anchor from a **genesis** keyring (revision 1) as the founder. Delegates to
/// [`keyeo_linear::bootstrap_genesis`].
pub fn bootstrap_from_genesis(
    genesis: &Keyring,
    own_founder_key: &VerifyingKey,
) -> Result<KeyringAnchor, ChainError> {
    let out = keyeo_linear::bootstrap_genesis(&ChainDoc::new(genesis), &own_founder_key.to_bytes())
        .map_err(map_linear_err)?;
    Ok(from_linear_anchor(out))
}

/// Seed an anchor from a keyring pinned out-of-band (§4a). Delegates to
/// [`keyeo_linear::bootstrap_pinned`].
pub fn bootstrap_from_oob(
    head: &Keyring,
    pinned_tree_id: &[u8],
    pinned_revision: u32,
    pinned_hash: &[u8; 32],
) -> Result<KeyringAnchor, ChainError> {
    let out = keyeo_linear::bootstrap_pinned(
        &ChainDoc::new(head),
        &GroupId(pinned_tree_id.to_vec()),
        Revision(pinned_revision),
        &DocHash(*pinned_hash),
    )
    .map_err(map_linear_err)?;
    Ok(from_linear_anchor(out))
}

/// Validate a keyring that establishes a **new anchor on its own terms** — a genesis, or a recovery /
/// succession reset. Delegates to [`keyeo_linear::verify_reset`]; when `prior_rvk` is present the reset
/// must carry the SAME authority AND be signed by it (continuity + authorization).
pub fn verify_reset(
    prior_rvk: Option<&[u8]>,
    keyring: &Keyring,
) -> Result<KeyringAnchor, ChainError> {
    let rvk = prior_rvk.map(to_pk32);
    let out = keyeo_linear::verify_reset(rvk.as_ref(), &ChainDoc::new(keyring))
        .map_err(map_linear_err)?;
    Ok(from_linear_anchor(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keyring_hash, sign_keyring, SigningKey};
    use crate::wire::{KeyEpoch, KeyWrap, Member, RecoveryKey};
    use crate::wire::{MEMBER_CO_OWNER, MEMBER_OWNER, WRAP_RRK_HPKE, WRAP_X25519_HPKE};

    const TREE: &[u8] = b"tree-uuid-16byte";
    const HPKE: i32 = WRAP_X25519_HPKE;
    const RRK_HPKE: i32 = WRAP_RRK_HPKE;
    const EDITOR: i32 = 4;
    const CO_OWNER_MEMBER: i32 = MEMBER_CO_OWNER;
    const OWNER_MEMBER: i32 = MEMBER_OWNER;

    fn key() -> SigningKey {
        crate::generate_identity().unwrap()
    }
    fn pubv(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_bytes().to_vec()
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

    /// A genesis keyring: founder "owner" + the given co-owner signers + the given plain members, with a
    /// matching wrap for each in epoch 0.
    fn genesis(founder: &SigningKey, co_owners: &[(&SigningKey, &str)], plain: &[&str]) -> Keyring {
        let mut members = vec![keyed_member(founder, "owner", OWNER_MEMBER)];
        let mut wraps = vec![wrap("owner", RRK_HPKE)];
        for (k, id) in co_owners {
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
            members,
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch { key_id: vec![0], epoch: 0, wraps }],
            ..Default::default()
        };
        sign_keyring(&mut k, founder);
        k
    }

    #[test]
    fn verify_reset_rvk_gate_enforces_continuity_and_the_recovery_signature() {
        // The chain treats the RVK as an opaque Ed25519 key, so any edsign key stands in for the
        // derived recovery key (the chain dropped the openom-crypto dep in OPE-300).
        let rvk = sk(42);
        let rvk_pub = rvk.verifying_key().to_bytes().to_vec();

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

        assert!(verify_reset(Some(&rvk_pub), &build(rvk_pub.clone(), true)).is_ok());
        assert!(verify_reset(Some(&rvk_pub), &build(rvk_pub.clone(), false)).is_err());
        let other = sk(99).verifying_key().to_bytes().to_vec();
        assert!(verify_reset(Some(&rvk_pub), &build(other, true)).is_err());
        assert!(verify_reset(None, &build(rvk_pub.clone(), false)).is_ok());
    }

    #[test]
    fn verify_transition_allows_an_rvk_rotation_only_when_signed_by_the_old_authority() {
        let rvk1 = sk(42);
        let rvk1_pub = rvk1.verifying_key().to_bytes().to_vec();
        let rvk2_pub = sk(99).verifying_key().to_bytes().to_vec();

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

        let ok = verify_transition(&anchor, &rotate(true)).unwrap();
        assert_eq!(ok.recovery_verifying_key, rvk2_pub, "an old-RVK-signed rotation is accepted");
        assert!(verify_transition(&anchor, &rotate(false)).is_err());
    }

    #[test]
    fn establishing_a_first_rvk_needs_governance_not_a_lone_co_owner() {
        let (f, bob, carol) = (sk(1), sk(2), sk(3));
        let prior = genesis(&f, &[(&bob, "bob"), (&carol, "carol")], &[]);
        let anchor = KeyringAnchor::from_keyring(&prior);
        assert!(anchor.recovery_verifying_key.is_empty());

        let rvk_pub = sk(7).verifying_key().to_bytes().to_vec();
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
        assert!(verify_transition(&anchor, &establish(2)).is_err());
        assert!(verify_transition(&anchor, &establish(1)).is_ok());
    }

    /// A mutation adding co-owner "d" (signer member + epoch wrap) — a signer-set change.
    fn add_coowner(dk: &SigningKey) -> impl FnOnce(&mut Keyring) + '_ {
        move |k: &mut Keyring| {
            k.members.push(keyed_member(dk, "d", CO_OWNER_MEMBER));
            k.epochs[0].wraps.push(wrap("d", HPKE));
        }
    }

    #[test]
    fn governance_founder_or_threshold_gates_a_signer_change() {
        let (founder, a, b, c, d) = (key(), key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let anchor0 = KeyringAnchor::from_keyring(&g);

        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let anchor = verify_transition(&anchor0, &ruled).expect("founder may set the rule");
        assert_eq!((anchor.governance_kind, anchor.governance_threshold), (2, 2));

        assert!(verify_transition(&anchor, &next(&ruled, add_coowner(&d), &[&a, &b])).is_ok());
        assert!(verify_transition(&anchor, &next(&ruled, add_coowner(&d), &[&founder])).is_ok());
        assert!(matches!(
            verify_transition(&anchor, &next(&ruled, add_coowner(&d), &[&a])),
            Err(ChainError::UnendorsedSetChange)
        ));
    }

    #[test]
    fn governance_change_is_anti_downgrade() {
        let (founder, a, b, c) = (key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let anchor = verify_transition(&KeyringAnchor::from_keyring(&g), &ruled).unwrap();

        assert!(matches!(
            verify_transition(&anchor, &next(&ruled, |k| k.governance_kind = 0, &[&a])),
            Err(ChainError::UnendorsedSetChange)
        ));
        assert!(verify_transition(&anchor, &next(&ruled, |k| k.governance_kind = 0, &[&a, &b])).is_ok());
    }

    #[test]
    fn governance_lockout_is_refused() {
        let (founder, a, b, c) = (key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let anchor = verify_transition(&KeyringAnchor::from_keyring(&g), &ruled).unwrap();

        assert!(matches!(
            verify_transition(
                &anchor,
                &next(&ruled, |k| { k.governance_kind = 3; k.governance_threshold = 5; }, &[&a, &b]),
            ),
            Err(ChainError::UnendorsedSetChange)
        ));
    }

    #[test]
    fn draft_exchange_collects_signatures_then_promotes() {
        use crate::blob_sync::{KeyringChainBlobSync, Promotion};
        use blobstore::MemoryBlob;
        use prost::Message;
        use std::sync::Arc;

        let (founder, a, b, c, d) = (key(), key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);

        let store = Arc::new(MemoryBlob::new());
        let mut owner = KeyringChainBlobSync::new(store.clone());
        owner.publish(&g.encode_to_vec()).unwrap();
        owner.publish(&ruled.encode_to_vec()).unwrap();

        let candidate = next(&ruled, add_coowner(&d), &[&a]);
        owner.propose("p1", &candidate.encode_to_vec()).unwrap();

        let mut promoter = KeyringChainBlobSync::new(store.clone());
        promoter.bootstrap().unwrap();
        assert_eq!(promoter.promote("p1").unwrap(), Promotion::NotReady);

        owner.countersign("p1", &candidate.encode_to_vec(), &b).unwrap();
        assert_eq!(promoter.promote("p1").unwrap(), Promotion::Promoted);
        assert_eq!(promoter.revision(), Some(candidate.revision));
        assert!(promoter.get_draft("p1").unwrap().is_none());
    }

    #[test]
    fn countersign_refuses_a_draft_swapped_since_review() {
        use crate::blob_sync::{KeyringChainBlobSync, SyncError};
        use blobstore::MemoryBlob;
        use prost::Message;
        use std::sync::Arc;

        let (founder, a, b, d) = (key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);

        let store = Arc::new(MemoryBlob::new());
        let mut owner = KeyringChainBlobSync::new(store.clone());
        owner.publish(&g.encode_to_vec()).unwrap();
        owner.publish(&ruled.encode_to_vec()).unwrap();

        let in_store = next(&ruled, add_coowner(&d), &[&a]);
        owner.propose("p1", &in_store.encode_to_vec()).unwrap();

        let reviewed = next(&ruled, |k| { k.governance_threshold = 1; }, &[&a]);
        assert!(matches!(
            owner.countersign("p1", &reviewed.encode_to_vec(), &b),
            Err(SyncError::DraftContentChanged)
        ));

        let after = Keyring::decode(owner.get_draft("p1").unwrap().unwrap().as_slice()).unwrap();
        assert_eq!(after.signatures.len(), 1);
    }

    #[test]
    fn a_stale_draft_is_detected_not_corrupting() {
        use crate::blob_sync::{KeyringChainBlobSync, Promotion};
        use blobstore::MemoryBlob;
        use prost::Message;
        use std::sync::Arc;

        let (founder, a, b, c, d) = (key(), key(), key(), key(), key());
        let g = genesis(&founder, &[(&a, "a"), (&b, "b"), (&c, "c")], &[]);
        let ruled = next(&g, |k| { k.governance_kind = 2; k.governance_threshold = 2; }, &[&founder]);
        let store = Arc::new(MemoryBlob::new());
        let mut owner = KeyringChainBlobSync::new(store.clone());
        owner.publish(&g.encode_to_vec()).unwrap();
        owner.publish(&ruled.encode_to_vec()).unwrap();

        let candidate = next(&ruled, add_coowner(&d), &[&a, &b]);
        owner.propose("p1", &candidate.encode_to_vec()).unwrap();

        let competing = next(&ruled, |k| k.members[1].role = EDITOR, &[&founder]);
        owner.publish(&competing.encode_to_vec()).unwrap();

        assert_eq!(owner.promote("p1").unwrap(), Promotion::Stale);
    }

    #[test]
    fn a_non_curve_point_signer_key_is_rejected_as_malformed() {
        // A 32-byte public key that isn't a valid Ed25519 point is rejected AS malformed (the engine's
        // accepts_key gate). Goes through verify_reset now (check_structure is the engine's, not exported).
        let mut bad = [0u8; 32];
        bad[0] = 2; // y = 2 has no matching x on the curve
        let mut k = genesis(&key(), &[], &[]);
        k.members[0].author_public_key = bad.to_vec();
        assert_eq!(
            verify_reset(None, &k),
            Err(ChainError::BadStructure("signer key malformed"))
        );
    }

    /// A well-formed successor: revision+1, chained hash, `mutate` applied, then signed by each key.
    fn next(prior: &Keyring, mutate: impl FnOnce(&mut Keyring), sign_with: &[&SigningKey]) -> Keyring {
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
    fn a_duplicate_member_id_is_rejected() {
        // No two members may share a member_id. (A wrap for the duplicate is added so wrap-completeness —
        // which the engine now checks in `structure_ok`, BEFORE the generic dup gate — passes and the
        // duplicate-id rejection is the sole failure. OPE-300: preserves the reject outcome.)
        let f = key();
        let x = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let bad = next(
            &g,
            |k| {
                k.members.push(keyed_member(&x, "owner", CO_OWNER_MEMBER));
                k.epochs[0].wraps.push(wrap("owner", HPKE));
            },
            &[&f],
        );
        assert!(matches!(verify_transition(&a, &bad), Err(ChainError::BadStructure(_))));
    }

    #[test]
    fn a_signer_member_with_a_non_point_key_is_rejected() {
        let f = key();
        let x = key();
        let g = genesis(&f, &[(&x, "carol")], &[]);
        let a = anchor(&g);
        let mut bad_pt = [0u8; 32];
        bad_pt[0] = 2;
        let bad = next(
            &g,
            |k| {
                let carol = k.members.iter_mut().find(|m| m.member_id == "carol").unwrap();
                carol.author_public_key = bad_pt.to_vec();
            },
            &[&f],
        );
        assert!(matches!(verify_transition(&a, &bad), Err(ChainError::BadStructure(_))));
    }

    #[test]
    fn an_out_of_range_epoch_ordinal_is_rejected() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        assert!(verify_reset(None, &g).is_ok(), "honest genesis (epoch 0, len 1) is in range");
        let a = anchor(&g);
        let bad = next(&g, |k| k.epochs[0].epoch = u32::MAX, &[&f]);
        assert!(matches!(verify_transition(&a, &bad), Err(ChainError::BadStructure(_))));
    }

    #[test]
    fn bootstrap_from_genesis_requires_revision_1_and_empty_prev_hash() {
        let f = key();
        let mut g = genesis(&f, &[], &[]);
        g.revision = 2;
        g.signatures.clear();
        sign_keyring(&mut g, &f);
        assert_eq!(bootstrap_from_genesis(&g, &f.verifying_key()), Err(ChainError::BadBootstrap));
    }

    #[test]
    fn a_layout_version_ahead_is_rejected_on_both_paths() {
        use crate::wire::KEYRING_LAYOUT_VERSION;
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
        let f = key();
        let g = genesis(&f, &[], &["bob"]);
        let a = anchor(&g);
        let bad = next(
            &g,
            |k| {
                let w = k.epochs[0].wraps.iter_mut().find(|w| w.member_id == "bob").unwrap();
                w.member_id = "carol".into();
            },
            &[&f],
        );
        assert_eq!(verify_transition(&a, &bad), Err(ChainError::WrapIncomplete));
    }

    #[test]
    fn an_oversized_member_list_is_rejected() {
        use crate::doc::MAX_MEMBERS;
        let f = key();
        let mut k = genesis(&f, &[], &[]);
        let d = dummy_member("x");
        while k.members.len() <= MAX_MEMBERS {
            k.members.push(d.clone());
        }
        assert_eq!(verify_reset(None, &k), Err(ChainError::BadStructure("list too large")));
    }

    #[test]
    fn an_oversized_epoch_list_is_rejected() {
        use crate::doc::MAX_EPOCHS;
        let f = key();
        let mut k = genesis(&f, &[], &[]);
        let e = k.epochs[0].clone();
        while k.epochs.len() <= MAX_EPOCHS {
            k.epochs.push(e.clone());
        }
        assert_eq!(verify_reset(None, &k), Err(ChainError::BadStructure("list too large")));
    }

    #[test]
    fn ordinary_change_by_a_prior_signer_is_accepted_by_a_stranger_rejected() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);

        let ok = next(&g, |k| { k.members.push(dummy_member("bob")); k.epochs[0].wraps.push(wrap("bob", HPKE)); }, &[&f]);
        assert_eq!(verify_transition(&a, &ok).unwrap().revision, 2);

        let stranger = key();
        let bad = next(&g, |k| { k.members.push(dummy_member("bob")); k.epochs[0].wraps.push(wrap("bob", HPKE)); }, &[&stranger]);
        assert_eq!(verify_transition(&a, &bad), Err(ChainError::UnendorsedOrdinaryChange));
    }

    #[test]
    fn co_owner_can_sign_an_ordinary_change() {
        let f = key();
        let c = key();
        let g = genesis(&f, &[(&c, "carol")], &[]);
        let a = anchor(&g);
        let ok = next(&g, |k| { k.members.push(dummy_member("bob")); k.epochs[0].wraps.push(wrap("bob", HPKE)); }, &[&c]);
        verify_transition(&a, &ok).unwrap();
    }

    #[test]
    fn rollback_fork_and_gap_are_distinct_errors() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);

        let mut skip = g.clone();
        skip.revision = 3;
        skip.prev_keyring_hash = keyring_hash(&g).to_vec();
        skip.signatures.clear();
        sign_keyring(&mut skip, &f);
        assert_eq!(verify_transition(&a, &skip), Err(ChainError::NonSequential));

        let fork = next(&g, |k| k.prev_keyring_hash = vec![9; 32], &[&f]);
        assert_eq!(verify_transition(&a, &fork), Err(ChainError::Fork));
    }

    #[test]
    fn founder_gated_set_changes() {
        let f = key();
        let carol = key();
        let mut g = genesis(&f, &[], &[]);
        g.members.push(keyed_member(&carol, "carol", EDITOR));
        g.epochs[0].wraps.push(wrap("carol", HPKE));
        g.signatures.clear();
        sign_keyring(&mut g, &f);
        let a = anchor(&g);

        let promote = next(&g, |k| k.members.iter_mut().find(|m| m.member_id == "carol").unwrap().role = CO_OWNER_MEMBER, &[&f]);
        verify_transition(&a, &promote).unwrap();

        let mutiny = next(&g, |k| k.members.iter_mut().find(|m| m.member_id == "carol").unwrap().role = CO_OWNER_MEMBER, &[&carol]);
        assert_eq!(verify_transition(&a, &mutiny), Err(ChainError::UnendorsedSetChange));
    }

    #[test]
    fn rogue_signer_injection_is_rejected() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let rogue = key();
        let attack = next(
            &g,
            |k| {
                k.members.push(keyed_member(&rogue, "rogue", CO_OWNER_MEMBER));
                k.epochs[0].wraps.push(wrap("rogue", HPKE));
            },
            &[&rogue],
        );
        assert_eq!(verify_transition(&a, &attack), Err(ChainError::UnendorsedSetChange));
    }

    #[test]
    fn an_editor_member_is_not_a_derived_signer_and_cannot_authorize_a_privileged_change() {
        let f = key();
        let carol = key();
        let mut g = genesis(&f, &[], &[]);
        g.members.push(keyed_member(&carol, "carol", EDITOR));
        g.epochs[0].wraps.push(wrap("carol", HPKE));
        g.signatures.clear();
        sign_keyring(&mut g, &f);
        let a = anchor(&g);

        let ordinary = next(&g, |k| { k.members.push(dummy_member("bob")); k.epochs[0].wraps.push(wrap("bob", HPKE)); }, &[&carol]);
        assert_eq!(verify_transition(&a, &ordinary), Err(ChainError::UnendorsedOrdinaryChange));

        let promote_self = next(&g, |k| k.members.iter_mut().find(|m| m.member_id == "carol").unwrap().role = CO_OWNER_MEMBER, &[&carol]);
        assert_eq!(verify_transition(&a, &promote_self), Err(ChainError::UnendorsedSetChange));
    }

    #[test]
    fn a_normal_owner_plus_co_owner_keyring_still_verifies() {
        let f = key();
        let bob = key();
        let g = genesis(&f, &[(&bob, "bob")], &[]);
        assert!(verify_reset(None, &g).is_ok());
        let a = anchor(&g);
        let ok = next(&g, |k| { k.members.push(dummy_member("carol")); k.epochs[0].wraps.push(wrap("carol", HPKE)); }, &[&bob]);
        assert_eq!(verify_transition(&a, &ok).unwrap().revision, 2);
    }

    #[test]
    fn co_owner_can_remove_themselves_but_not_bundle_others() {
        let f = key();
        let carol = key();
        let dave = key();
        let g = genesis(&f, &[(&carol, "carol"), (&dave, "dave")], &[]);
        let a = anchor(&g);

        let ok = next(&g, |k| k.members.iter_mut().find(|m| m.member_id == "carol").unwrap().role = EDITOR, &[&carol]);
        verify_transition(&a, &ok).unwrap();

        let bundled = next(
            &g,
            |k| {
                for m in &mut k.members {
                    if m.member_id == "carol" || m.member_id == "dave" {
                        m.role = EDITOR;
                    }
                }
            },
            &[&carol],
        );
        assert_eq!(verify_transition(&a, &bundled), Err(ChainError::UnendorsedSetChange));
    }

    #[test]
    fn founder_key_rotation_needs_the_old_key() {
        let f = key();
        let f2 = key();
        let g = genesis(&f, &[], &[]);
        let a = anchor(&g);
        let rotate = |k: &mut Keyring| {
            for m in &mut k.members {
                if m.member_id == "owner" {
                    m.author_public_key = pubv(&f2);
                }
            }
        };
        verify_transition(&a, &next(&g, rotate, &[&f, &f2])).unwrap();
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
        let no_wrap = next(&g, |k| k.members.push(dummy_member("bob")), &[&f]);
        assert_eq!(verify_transition(&a, &no_wrap), Err(ChainError::WrapIncomplete));

        let carol = key();
        let two = next(&g, |k| { k.members.push(keyed_member(&carol, "carol", OWNER_MEMBER)); k.epochs[0].wraps.push(wrap("carol", HPKE)); }, &[&f]);
        assert!(matches!(verify_transition(&a, &two), Err(ChainError::BadStructure(_))));
    }

    #[test]
    fn verify_reset_accepts_a_genesis_and_a_reset_but_not_an_unsigned_one() {
        let f = key();
        let g = genesis(&f, &[], &[]);
        assert_eq!(verify_reset(None, &g).unwrap().revision, 1);

        let f2 = key();
        let mut reset = g.clone();
        reset.revision = 5;
        reset.prev_keyring_hash = vec![9; 32];
        reset.members[0].author_public_key = pubv(&f2);
        reset.signatures.clear();
        sign_keyring(&mut reset, &f2);
        assert_eq!(verify_reset(None, &reset).unwrap().revision, 5);
        assert_eq!(verify_transition(&anchor(&g), &reset).unwrap_err(), ChainError::NonSequential);

        let mut unsigned = g.clone();
        unsigned.signatures.clear();
        sign_keyring(&mut unsigned, &key());
        assert_eq!(verify_reset(None, &unsigned), Err(ChainError::BadBootstrap));
    }

    // --- Differential oracle ---------------------------------------------------------------

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }
    fn founder_k() -> SigningKey {
        sk(1)
    }
    fn co_k(i: usize) -> SigningKey {
        sk(2 + i as u8)
    }
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

    fn scenario_prior(n_co: usize) -> Keyring {
        let f = founder_k();
        let mut members = vec![keyed_member(&f, "owner", OWNER_MEMBER)];
        let mut wraps = vec![wrap("owner", RRK_HPKE)];
        for i in 0..n_co {
            let id = format!("co{i}");
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
            members,
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch { key_id: vec![0], epoch: 0, wraps }],
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
            Mutation::Promote => {
                k.members.iter_mut().find(|m| m.member_id == "pend").unwrap().role = CO_OWNER_MEMBER
            }
            Mutation::RemoveCoOwner => {
                k.members.iter_mut().find(|m| m.member_id == "co0").unwrap().role = EDITOR
            }
            Mutation::RotateFounder => {
                let np = pubv(&new_founder_k());
                for mem in &mut k.members {
                    if mem.member_id == "owner" {
                        mem.author_public_key = np.clone();
                    }
                }
            }
        };
        let roster: [SigningKey; 6] =
            [founder_k(), co_k(0), co_k(1), co_k(2), pend_k(), stranger_k()];
        let signers: Vec<&SigningKey> =
            (0..6).filter(|i| sign_mask & (1 << i) != 0).map(|i| &roster[i]).collect();
        next(prior, mutate, &signers)
    }

    fn oracle_accepts(n_co: usize, m: Mutation, sign_mask: u8) -> bool {
        let bit = |i: usize| sign_mask & (1 << i) != 0;
        let founder_signed = bit(0);
        let unanimity = founder_signed && (0..n_co).all(|i| bit(1 + i));
        match m {
            Mutation::Ordinary => founder_signed || (0..n_co).any(|i| bit(1 + i)),
            Mutation::Promote | Mutation::RotateFounder => founder_signed || unanimity,
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
        let a = bootstrap_from_genesis(&g, &f.verifying_key()).unwrap();
        assert_eq!(a.revision, 1);
        assert!(bootstrap_from_genesis(&g, &key().verifying_key()).is_err());

        let h = keyring_hash(&g);
        bootstrap_from_oob(&g, TREE, 1, &h).unwrap();
        assert!(matches!(
            bootstrap_from_oob(&g, TREE, 1, &[0u8; 32]),
            Err(ChainError::BadBootstrap)
        ));

        let c1 = next(&g, |k| { k.members.push(dummy_member("bob")); k.epochs[0].wraps.push(wrap("bob", HPKE)); }, &[&f]);
        let c2 = next(&c1, |k| { k.members.push(dummy_member("eve")); k.epochs[0].wraps.push(wrap("eve", HPKE)); }, &[&f]);
        assert_eq!(verify_walk(&a, &[c1.clone(), c2.clone()]).unwrap().revision, 3);
        assert_eq!(verify_walk(&a, &[c2]), Err(ChainError::NonSequential));
    }

    #[test]
    fn governing_keyring_mints_only_from_a_verified_chain() {
        let f = key();
        let g = genesis(&f, &[], &[]);

        let gk = GoverningKeyring::from_genesis(g.clone(), &f.verifying_key()).unwrap();
        assert_eq!(gk.revision(), 1);
        assert_eq!(gk.anchor(), KeyringAnchor::from_keyring(&g));
        assert!(GoverningKeyring::from_genesis(g.clone(), &key().verifying_key()).is_err());

        let a = anchor(&g);
        let add_bob = |k: &mut Keyring| {
            k.members.push(dummy_member("bob"));
            k.epochs[0].wraps.push(wrap("bob", HPKE));
        };
        let ok = next(&g, add_bob, &[&f]);
        assert_eq!(GoverningKeyring::from_transition(&a, ok).unwrap().revision(), 2);
        let bad = next(&g, add_bob, &[&key()]);
        assert_eq!(
            GoverningKeyring::from_transition(&a, bad).unwrap_err(),
            ChainError::UnendorsedOrdinaryChange
        );
    }
}
