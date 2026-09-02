//! Epoch-scoped group keys — per-member HPKE wraps of a fresh per-epoch DEK.
//!
//! ## Model B: the epoch is a DAG-resolved artifact, not a derivation
//!
//! A group's data key (DEK) rotates on membership change. This module implements the **crypto core**
//! of that rotation the way keyeo-chain does, adapted to keyeo's multi-writer DAG:
//!
//! - Each epoch carries a **fresh random DEK** (never re-derived, never shared as plaintext).
//! - That DEK is **wrapped individually to each active member's HPKE public key** (`DekWrap`).
//!   A member holds their own X25519 secret and unwraps the epoch DEK for themselves.
//! - Forward secrecy is a property of **which members have a wrap** — a removed member is simply
//!   absent from the new epoch's wraps and cannot unwrap it. No "retained group secret" trips this up.
//!
//! ## Why this is convergent AND forward-secret (the thing a naive design gets wrong)
//!
//! The DEK does **not** need to be the same across peers via deterministic derivation. openom's keyring
//! (and every multi-`recipient` envelope scheme) ships the *same* fresh DEK, wrapped per recipient:
//! what each peer derives is the *wrap* it can open with its own key. In a DAG, the wraps are authored
//! once (replicated data), and which epoch is "current" is settled by the resolver's precedence — so
//! all peers that resolve the same membership converge on the same epoch and its wraps.
//!
//! The one commitment this module adds, `membership_commitment`, is a deterministic, order-independent
//! hash of the active membership. It serves as the epoch's stable identity and is bound into every
//! wrap's HPKE `info` (alongside the epoch number), so a wrap cannot be transplanted across epochs or
//! memberships — the same binding role openom's wrap-context `info` plays.
//!
//! ## Out of scope today: the async "ghost-block" decryption window
//!
//! keyeo currently models **membership only** — it has no data-block layer. Once one exists, a real
//! concern arises that this crate does not yet address: because DAG replication is asynchronous, a
//! member may author a data block encrypted under epoch *N* (DEK_N) while a concurrent Strong Remove
//! is already causing a rotation to epoch *N+1*. During the resolution window such in-flight blocks
//! must remain decryptable without permanently compromising forward secrecy. That requires a
//! data-block layer that (a) stamps blocks with the epoch/commitment they were sealed under, and (b)
//! retains the block author's just-rotated DEK only long enough to serve concurrent readers — a
//! retention policy, not an epoch-rotation guarantee. It is a documented follow-up for when data
//! blocks land, not implemented here.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::dag::resolver::{DekWrap, MemberId, OpId};
use crate::hpke_wrap::{hpke_unwrap_dek, hpke_wrap_dek};
use crate::kdf::{generate_dek, Key32};
use crate::roles::Role;
use crate::signature::SignatureScheme;
use crate::CryptoError;

const EPOCH_WRAP_INFO: &[u8] = b"flowcontrol:epoch:wraps:v1";
const COMMITMENT_PREFIX: &[u8] = b"flowcontrol:epoch:members:v1";

/// Deterministic bytes binding an epoch (number + membership commitment) — the HPKE `info` used for
/// both wrapping and unwrapping, so the writer and reader agree without exchanging anything else.
pub fn epoch_context(epoch: u64, commitment: &[u8; 32]) -> Vec<u8> {
    let mut v = EPOCH_WRAP_INFO.to_vec();
    v.push(0);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(commitment);
    v
}

/// A deterministic, input- and arrival-order-independent commitment to the active membership:
/// `SHA-256(prefix ‖ count ‖ sort[{id ‖ role ‖ hpke_key}])`. The epoch's stable identity and a
/// tamper-evident handle on who the epoch is for.
pub fn membership_commitment<Id: MemberId, R: Role>(active: &[(Id, R, [u8; 32])]) -> [u8; 32] {
    let mut blobs: Vec<(Vec<u8>, Vec<u8>, [u8; 32])> = active
        .iter()
        .map(|(id, role, hpke)| {
            let id_bytes = postcard::to_allocvec(id).expect("member id serializes");
            let role_bytes = postcard::to_allocvec(role).expect("role serializes");
            (id_bytes, role_bytes, *hpke)
        })
        .collect();
    blobs.sort(); // set semantics: order-independent by construction
    let mut h = Sha256::new();
    h.update(COMMITMENT_PREFIX);
    h.update((blobs.len() as u64).to_le_bytes());
    for (id_bytes, role_bytes, hpke) in blobs {
        h.update((id_bytes.len() as u64).to_le_bytes());
        h.update(&id_bytes);
        h.update((role_bytes.len() as u64).to_le_bytes());
        h.update(&role_bytes);
        h.update(hpke);
    }
    h.finalize().into()
}

/// Generate a new epoch: a **fresh random DEK** wrapped to each active member's HPKE public key.
///
/// Returns the per-member wraps (safe to store/replicate in the group state) **and** the DEK itself,
/// which the rotating caller keeps as the group's data key. Only the wraps are replicated; the DEK
/// never leaves the holder except inside each member's wrap.
pub fn generate_epoch<Id: MemberId>(
    epoch: u64,
    commitment: &[u8; 32],
    active_hpke: &[(Id, [u8; 32])],
) -> Result<(Vec<DekWrap<Id>>, Key32), CryptoError> {
    let dek = generate_dek()?;
    let info = epoch_context(epoch, commitment);
    let mut wraps: Vec<DekWrap<Id>> = Vec::with_capacity(active_hpke.len());
    for (id, hpke_public) in active_hpke {
        let w = hpke_wrap_dek(hpke_public, dek.as_slice(), info.as_slice())?;
        wraps.push(DekWrap {
            member: id.clone(),
            hpke_public_key: *hpke_public,
            encapped_key: w.encapped_key,
            ciphertext: w.ciphertext,
        });
    }
    wraps.sort_by(|a, b| a.member.cmp(&b.member));
    Ok((wraps, dek))
}

/// A signed epoch artifact, authored once into the op DAG.
///
/// This is the reconciliation unit (Option 1). An authorized member authors an `Epoch` carrying a
/// fresh random DEK already wrapped to each active member (forward-secret — a removed member has no
/// wrap), and replicates it like any DAG node. When concurrent members race to rotate, the DAG holds
/// several candidate epochs for the same membership; the resolver deterministically picks ONE via
/// [`reconcile_epochs`], so all replicas that have replicated the same candidates converge on the same
/// winning epoch and hence the same DEK. The signer is the authorizing member, so a fork is a signed,
/// auditable artifact — not an unexplained derivation divergence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epoch<OId: OpId, MId: MemberId, S: SignatureScheme> {
    pub id: OId,
    /// The membership op(s) this epoch causally follows — the DAG position it reconciles at.
    pub parents: Vec<OId>,
    pub author: MId,
    /// The membership commitment this epoch's wraps cover (deterministic under arrival order).
    pub commitment: [u8; 32],
    pub epoch: u64,
    /// The per-member DEK wraps for this epoch (replicated data, never recomputed).
    pub wraps: Vec<DekWrap<MId>>,
    /// Author signature binding `(parents, commitment, epoch, wraps)` to the authoring member.
    pub signature: <S as SignatureScheme>::Signature,
    pub author_public_key: <S as SignatureScheme>::PublicKey,
}

impl<OId: OpId, MId: MemberId, S: SignatureScheme> Epoch<OId, MId, S> {
    /// Author a new epoch artifact (Option 1 reconciliation unit). A caller-side authorized member
    /// generates a fresh random DEK, wraps it to each active member's HPKE key (forward-secret — a
    /// removed member has no wrap), and signs the bound content with their Ed25519 key. The signed
    /// artifact is what replicates; concurrent authors of the same frontier are reconciled by
    /// `reconcile_epochs`.
    ///
    /// `id` is caller-assigned (in practice a content hash of the signed content); `active_hpke` is
    /// the `(member, hpke_public_key)` pairs of the members this epoch is for.
    pub fn author(
        id: OId,
        parents: Vec<OId>,
        author: MId,
        commitment: [u8; 32],
        epoch: u64,
        active_hpke: &[(MId, [u8; 32])],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, CryptoError>
    where
        S: SignatureScheme<PublicKey = [u8; 32], Signature = [u8; 64]>,
    {
        let (wraps, _dek) = generate_epoch(epoch, &commitment, active_hpke)?;
        let canon = epoch_signing_bytes::<OId, MId>(&parents, &commitment, epoch, &wraps);
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&canon).to_bytes();
        let author_public_key = signing_key.verifying_key().to_bytes();
        Ok(Epoch {
            id,
            parents,
            author,
            commitment,
            epoch,
            wraps,
            signature,
            author_public_key,
        })
    }
}

/// The canonical bytes an epoch's author signs over: `(parents, commitment, epoch, wraps)`. Both the
/// author ([`Epoch::author`]) and the verifier ([`verify_epoch`]) build these from the epoch's own
/// fields, so a signature binds to exactly this content and can't be transplanted. Delegates to the
/// shared [`crate::canonical::CanonicalBytes`] seam (G-S5) — there is no second hand-rolled encoder.
pub fn epoch_signing_bytes<OId: OpId, MId: MemberId>(
    parents: &[OId],
    commitment: &[u8; 32],
    epoch: u64,
    wraps: &[DekWrap<MId>],
) -> Vec<u8> {
    crate::canonical::canonical_encode_epoch::<OId, MId>(parents, commitment, epoch, wraps)
}

/// Verify an epoch's **author signature** over its canonical content (goal G-E1): proves the artifact
/// was signed by the holder of its self-asserted `author_public_key`. This is self-contained and does
/// NOT establish authority — the engine additionally checks, against the resolved membership, that this
/// key is the author member's *registered* key (G-E2) and that the wraps are complete (G-E3). Run this
/// at ingest so a bad-signature artifact never enters the candidate set.
pub fn verify_epoch<OId: OpId, MId: MemberId, S: SignatureScheme>(
    epoch: &Epoch<OId, MId, S>,
) -> bool {
    let canon = epoch_signing_bytes::<OId, MId>(
        &epoch.parents,
        &epoch.commitment,
        epoch.epoch,
        &epoch.wraps,
    );
    S::verify(&epoch.author_public_key, &canon, &epoch.signature).is_ok()
}

/// Reconcile a set of candidate epochs for the **same** membership to a single winner by the
/// deterministic key `(parent-count, content id)`, smallest first. Because the candidates, their
/// parent sets, and their ids are all replicated DAG data, every replica that has seen the same set
/// computes the same winner — the reconciliation is order-independent and needs no coordination.
/// Returns `None` only when no candidate is present.
///
/// **G-S1 note:** `parents.len()` is the epoch's in-degree, **not** causal (lamport) depth — an
/// earlier revision of this doc mislabelled it. Convergence needs only a *deterministic* total order
/// over the candidate set, which `(parent-count, id)` provides; it does not need to be causal, because
/// all candidates already share the same resolved membership (they only race on the DEK, and any one
/// of them is a valid key for that membership). Computing true depth would require threading the op
/// DAG in here for no convergence benefit. If a causal preference is ever wanted (e.g. "prefer the
/// rotation authored latest"), switch the key to the resolver's `compute_depths` — a behaviour change,
/// not a correctness fix.
pub fn reconcile_epochs<OId: OpId, MId: MemberId, S: SignatureScheme>(
    candidates: &[Epoch<OId, MId, S>],
) -> Option<&Epoch<OId, MId, S>> {
    candidates.iter().min_by_key(|e| (e.parents.len(), e.id))
}

/// A helper for tests: pick the "winning" epoch by the same key, returning its DEK's recipient set
/// (for assertion convenience).
pub fn winner_members<OId: OpId, MId: MemberId, S: SignatureScheme>(
    candidates: &[Epoch<OId, MId, S>],
) -> Option<Vec<MId>> {
    reconcile_epochs(candidates).map(|e| e.wraps.iter().map(|w| w.member.clone()).collect())
}

/// A member recovers the epoch DEK with their own HPKE secret and the wrap addressed to them.
/// `epoch`/`commitment` come from the shared resolved group state; reconstructing the same `info` is
/// what makes recovery work even though the wrap is standalone data.
pub fn recover_epoch_dek<Id: MemberId>(
    hpke_secret: &[u8; 32],
    wrap: &DekWrap<Id>,
    epoch: u64,
    commitment: &[u8; 32],
) -> Result<Key32, CryptoError> {
    let info = epoch_context(epoch, commitment);
    hpke_unwrap_dek(
        hpke_secret,
        wrap.encapped_key.as_slice(),
        wrap.ciphertext.as_slice(),
        &info,
    )
}

/// The openom `wrap_complete` invariant, adapted: every active member has exactly one wrap, and no
/// wrap targets a non-active member. Catches a "signature-valid but lockout" epoch that wraps the new
/// DEK to the wrong set — including the forward-secrecy guarantee that a removed member has no wrap.
pub fn wraps_complete<Id: MemberId>(wraps: &[DekWrap<Id>], active: &[Id]) -> bool {
    if wraps.len() != active.len() {
        return false;
    }
    let mut seen: HashSet<&Id> = HashSet::new();
    for w in wraps {
        if !seen.insert(&w.member) {
            return false; // duplicate wraps to the same member
        }
        if !active.contains(&w.member) {
            return false; // wrap to a non-active member (e.g. a removed one)
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke_wrap::derive_hpke_keypair;
    use crate::kdf::Key32;
    use crate::signature::Ed25519;
    use serde::Serialize;
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
    enum TRole {
        Admin,
        Editor,
    }
    impl Role for TRole {
        fn grants_at_least(&self, other: &Self) -> bool {
            matches!(
                (self, other),
                (TRole::Admin, _) | (TRole::Editor, TRole::Editor)
            )
        }
    }

    fn hpke(ikm: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        derive_hpke_keypair(ikm)
    }

    #[test]
    fn fresh_epoch_round_trips_for_its_members() {
        let (a_secret, a_public) = hpke(&[1u8; 32]);
        let (b_secret, b_public) = hpke(&[2u8; 32]);
        let commitment = membership_commitment::<[u8; 32], TRole>(&[
            ([1u8; 32], TRole::Admin, a_public),
            ([2u8; 32], TRole::Editor, b_public),
        ]);
        let (wraps, _dek) = generate_epoch::<[u8; 32]>(
            0,
            &commitment,
            &[([1u8; 32], a_public), ([2u8; 32], b_public)],
        )
        .unwrap();
        assert!(wraps_complete(&wraps, &[[1u8; 32], [2u8; 32]]));

        let a_wrap = wraps.iter().find(|w| w.member == [1u8; 32]).unwrap();
        let b_wrap = wraps.iter().find(|w| w.member == [2u8; 32]).unwrap();
        let a_dek = recover_epoch_dek(&a_secret, a_wrap, 0, &commitment).unwrap();
        let b_dek = recover_epoch_dek(&b_secret, b_wrap, 0, &commitment).unwrap();
        assert_eq!(&*a_dek, &*b_dek, "every member receives the same epoch DEK");
    }

    #[test]
    fn removed_member_cannot_unwrap_the_next_epoch() {
        // Alice, Bob share epoch 0. Bob is removed; epoch 1 wraps only to Alice.
        let (a_secret, a_public) = hpke(&[1u8; 32]);
        let (b_secret, _b_public) = hpke(&[2u8; 32]);
        let commitment =
            membership_commitment::<[u8; 32], TRole>(&[([1u8; 32], TRole::Admin, a_public)]);
        let (wraps, _dek) =
            generate_epoch::<[u8; 32]>(1, &commitment, &[([1u8; 32], a_public)]).unwrap();
        assert_eq!(wraps.len(), 1, "only Alice has a wrap in the new epoch");
        assert!(wraps_complete(&wraps, &[[1u8; 32]]));

        let a_wrap = wraps.iter().find(|w| w.member == [1u8; 32]).unwrap();
        let a_dek = recover_epoch_dek(&a_secret, a_wrap, 1, &commitment).unwrap();
        assert_eq!(a_dek.len(), 32);

        // Bob — removed — has no wrap, and trying to use another member's wrap fails.
        let b_wrap = wraps[0].clone();
        assert!(matches!(
            recover_epoch_dek(&b_secret, &b_wrap, 1, &commitment),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn wrap_is_tied_to_epoch_and_membership() {
        let (secret, public) = hpke(&[1u8; 32]);
        let c1 = membership_commitment::<[u8; 32], TRole>(&[([1u8; 32], TRole::Admin, public)]);
        let c2 = membership_commitment::<[u8; 32], TRole>(&[([1u8; 32], TRole::Editor, public)]);
        let (wraps, _dek) = generate_epoch::<[u8; 32]>(0, &c1, &[([1u8; 32], public)]).unwrap();
        let wrap = wraps[0].clone();
        // Different membership commitment or different epoch -> wrong info -> cannot open.
        assert!(matches!(
            recover_epoch_dek(&secret, &wrap, 0, &c2),
            Err(CryptoError::Hpke)
        ));
        assert!(matches!(
            recover_epoch_dek(&secret, &wrap, 1, &c1),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn commitment_is_order_independent() {
        let (_, a_public) = hpke(&[1u8; 32]);
        let (_, b_public) = hpke(&[2u8; 32]);
        let one = membership_commitment::<[u8; 32], TRole>(&[
            ([1u8; 32], TRole::Admin, a_public),
            ([2u8; 32], TRole::Editor, b_public),
        ]);
        let two = membership_commitment::<[u8; 32], TRole>(&[
            ([2u8; 32], TRole::Editor, b_public),
            ([1u8; 32], TRole::Admin, a_public),
        ]);
        assert_eq!(
            one, two,
            "turnover/arrival order must not change the commitment"
        );
    }

    #[test]
    fn wraps_complete_rejects_lockout_and_ghost_wraps() {
        let (_, a_public) = hpke(&[1u8; 32]);
        let commitment =
            membership_commitment::<[u8; 32], TRole>(&[([1u8; 32], TRole::Admin, a_public)]);
        let (full, _dek) =
            generate_epoch::<[u8; 32]>(0, &commitment, &[([1u8; 32], a_public)]).unwrap();

        // A member missing a wrap (lockout).
        assert!(!wraps_complete(&[], &[[1u8; 32]]));
        // A wrap to someone not active (e.g. a removed member that slipped in).
        let ghost = DekWrap {
            member: [9u8; 32],
            hpke_public_key: a_public,
            encapped_key: full[0].encapped_key.clone(),
            ciphertext: full[0].ciphertext.clone(),
        };
        assert!(!wraps_complete(&[ghost], &[[1u8; 32]]));
        // The honest epoch is complete.
        assert!(wraps_complete(&full, &[[1u8; 32]]));
    }

    // Silence unused-import warning for Key32 (used by an assert on `.len()` above).
    fn _assert_key(_k: &Key32) {}

    #[test]
    fn reconcile_picks_one_winner_deterministically() {
        // Two members race to rotate the same membership: same frontier (parents), same commitment,
        // different authoring ids. The resolver must pick ONE deterministically, and replicas holding
        // both candidates must pick the SAME one regardless of candidate order.
        let mk = |id: u64, parents: Vec<u64>| Epoch::<u64, [u8; 32], Ed25519> {
            id,
            parents,
            author: [1u8; 32],
            commitment: [7u8; 32],
            epoch: 1,
            wraps: Vec::new(),
            signature: [0u8; 64],
            author_public_key: [0u8; 32],
        };
        let cands = [mk(50, vec![9u64]), mk(40, vec![9u64]), mk(60, vec![9u64])];
        // Same parents -> tiebreak on id; smallest id wins regardless of order.
        assert_eq!(
            reconcile_epochs(&cands).unwrap().id,
            40u64,
            "same depth, smallest content id wins"
        );
        let shuffled = vec![mk(60, vec![9u64]), mk(40, vec![9u64]), mk(50, vec![9u64])];
        assert_eq!(
            reconcile_epochs(&shuffled).unwrap().id,
            40u64,
            "reconciliation is order-independent"
        );
        // A deeper parents set loses to a shallower one (reconciles at the same frontier).
        let deeper = vec![mk(40, vec![9u64]), mk(30, vec![9u64, 8u64])];
        assert_eq!(
            reconcile_epochs(&deeper).unwrap().id,
            40u64,
            "shallower frontier (same membership) is reconciled first"
        );
    }

    #[test]
    fn concurrent_epochs_reconcile_to_a_single_shared_dek() {
        // Two replicas race to rotate the same membership (same frontier, same commitment). Each
        // authors a signed Epoch with a FRESH random DEK wrapped to the active members. After both
        // artifacts are replicated, both replicas must reconcile to the SAME winner — and that
        // winner's DEK is the single key every remaining member recovers.
        let a_sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let b_sk = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let (a_sec, a_pub) = hpke(&[1u8; 32]);
        let (b_sec, b_pub) = hpke(&[2u8; 32]);
        let commitment = membership_commitment::<[u8; 32], TRole>(&[
            ([1u8; 32], TRole::Admin, a_pub),
            ([2u8; 32], TRole::Editor, b_pub),
        ]);
        let active: Vec<([u8; 32], [u8; 32])> = vec![([1u8; 32], a_pub), ([2u8; 32], b_pub)];

        // Replica A authors an epoch; Replica B authors a DIFFERENT epoch (same frontier, high ids).
        let e_a = Epoch::<u64, [u8; 32], Ed25519>::author(
            500,
            vec![9u64],
            [1u8; 32],
            commitment,
            1,
            &active,
            &a_sk,
        )
        .unwrap();
        let e_b = Epoch::<u64, [u8; 32], Ed25519>::author(
            499,
            vec![9u64],
            [2u8; 32],
            commitment,
            1,
            &active,
            &b_sk,
        )
        .unwrap();

        // Both replicas have BOTH artifacts (replicated) — reconcile in either order to the same winner.
        let ab = [e_a.clone(), e_b.clone()];
        let ba = [e_b.clone(), e_a.clone()];
        let w1 = reconcile_epochs(&ab).unwrap();
        let w2 = reconcile_epochs(&ba).unwrap();
        assert_eq!(
            w1, w2,
            "reconciliation is order-independent across replicas"
        );

        // The winner is deterministic (smallest id at equal depth): e_b (id 499) wins.
        assert_eq!(w1.id, 499u64);

        // Every remaining member unwraps the SAME DEK from the winning epoch (single shared key).
        let wrap_a = w1.wraps.iter().find(|w| w.member == [1u8; 32]).unwrap();
        let wrap_b = w1.wraps.iter().find(|w| w.member == [2u8; 32]).unwrap();
        let dek_a = recover_epoch_dek(&a_sec, wrap_a, w1.epoch, &w1.commitment).unwrap();
        let dek_b = recover_epoch_dek(&b_sec, wrap_b, w1.epoch, &w1.commitment).unwrap();
        assert_eq!(
            &*dek_a, &*dek_b,
            "both members recover the same shared DEK from the winner"
        );
    }

    #[test]
    fn verify_epoch_accepts_authored_and_rejects_tampered() {
        // G-E1: an authored epoch verifies against its own author key; any change to the signed
        // content (wraps, commitment, epoch, parents) or the signature breaks verification.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let (_sec, pubk) = hpke(&[1u8; 32]);
        let commitment =
            membership_commitment::<[u8; 32], TRole>(&[([1u8; 32], TRole::Admin, pubk)]);
        let e = Epoch::<u64, [u8; 32], Ed25519>::author(
            1,
            vec![9u64],
            [1u8; 32],
            commitment,
            1,
            &[([1u8; 32], pubk)],
            &sk,
        )
        .unwrap();
        assert!(
            verify_epoch::<u64, [u8; 32], Ed25519>(&e),
            "honest epoch verifies"
        );

        // Flip a signature byte -> rejected.
        let mut bad_sig = e.clone();
        bad_sig.signature[0] ^= 0x01;
        assert!(!verify_epoch::<u64, [u8; 32], Ed25519>(&bad_sig));

        // A different author key (spoof) -> the signature no longer matches.
        let mut spoof = e.clone();
        spoof.author_public_key = [0u8; 32];
        assert!(!verify_epoch::<u64, [u8; 32], Ed25519>(&spoof));

        // Tamper with signed content (bump the epoch counter) without re-signing -> rejected.
        let mut retag = e.clone();
        retag.epoch = 2;
        assert!(!verify_epoch::<u64, [u8; 32], Ed25519>(&retag));

        // Swap in a ghost wrap (content change) without re-signing -> rejected.
        let mut reweap = e.clone();
        if let Some(w) = reweap.wraps.first_mut() {
            w.member = [9u8; 32];
        }
        assert!(!verify_epoch::<u64, [u8; 32], Ed25519>(&reweap));
    }
}
