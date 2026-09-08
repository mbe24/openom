//! §B3 verify-on-ingest — the engine-NEUTRAL trust decision + a per-engine membership seam.
//!
//! On a shared tree, before a peer's delta is folded into local state, the client verifies it was
//! authored by a member who held the required capability in the keyring revision that governed it (see
//! [`crate::attribution`]). The *decision* (rev-0 / shared / hold / reject / accept — a faithful port of
//! the JS `entryVerifier`) is engine-neutral and lives here; only resolving an entry's governing
//! membership is engine-specific, behind the [`MembershipResolver`] trait. Chain implements it now
//! ([`chain::ChainMembershipResolver`]); the dag engine adds one more impl behind the same seam — nothing in the
//! neutral policy or the caller (`openom-app-core`'s `ingest`) changes.

use openom_keyring_api::{EngineKind, MembershipView};
use openom_protocol::v1::Header;

use crate::attribution::verify_entry;
use crate::VaultError;

/// The governing membership an engine resolved for an entry's `governing_ref`.
pub enum Governing {
    /// No governing membership is expected — a chain rev-0 / dag-genesis entry (unattributed).
    Unattributed,
    /// Resolved: verify the author against this view + the epoch the engine demands for the entry.
    Resolved {
        /// The engine-neutral member/role set that governed the entry.
        view: MembershipView,
        /// The `key_id` [`verify_entry`]'s epoch-consistency check must see for THIS entry. Chain fills its
        /// governing revision's newest epoch (an entry stamping an older epoch is a forge → `EpochMismatch`).
        /// Dag echoes the entry's own `key_id` once it is confirmed present in the tree's retained epoch set
        /// (there is one governing view, so the check is epoch-integrity, not authority) — so a legitimate
        /// prior-epoch entry passes while an epoch the tree never minted is routed to Hold/Reject before here.
        expected_key_id: Vec<u8>,
        /// Whether that epoch requires signatures (its DEK was wrapped beyond the founder).
        epoch_attributed: bool,
    },
    /// A legitimate revision we simply don't retain yet — HOLD and retry after the next keyring sync.
    NotYetRetained,
    /// A reference the engine can't legitimately reach (beyond the verified head) — REJECT.
    Illegitimate,
}

/// The per-engine seam. `shared` is monotonic (once a tree has been shared it stays shared, so a mid-
/// session keyring withhold can't downgrade the rule); `resolve` maps an entry's header coordinates to a
/// [`Governing`].
pub trait MembershipResolver {
    /// Whether the tree has ever been shared (a signature-requiring, multi-member tree).
    fn shared(&self) -> bool;
    /// Resolve the governing membership for an entry sealed under `key_id` with header `governing_ref`.
    fn resolve(&self, governing_ref: &[u8], key_id: &[u8]) -> Governing;
}

/// What to do with a pulled entry after §B3 verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The author (or lack of one, where allowed) is valid — merge it.
    Accept,
    /// Valid but its governing keyring isn't retained yet — buffer and re-verify after a keyring sync.
    Hold,
    /// Forged / unattributed-on-shared / illegitimate — drop it (never let it stall the tail).
    Reject,
}

/// The engine-NEUTRAL §B3 decision for one entry (a faithful port of `entryVerifier.js`).
///
/// `open` yields the AEAD-opened plaintext; it is called ONLY when an author signature must actually be
/// verified — never for an accept that needs no signature (rev-0, or an unsigned V1 epoch) — so the
/// common accept path pays no decrypt. A failed `open` is a `Reject` (an entry we can't even open on a
/// shared tree is not trustworthy).
pub fn verify_ingest<E>(
    version: u32,
    membership: &dyn MembershipResolver,
    header: &Header,
    governing_ref: &[u8],
    key_id: &[u8],
    open: impl FnOnce() -> Result<Vec<u8>, E>,
) -> Disposition {
    let shared = membership.shared();
    // A security decision TABLE, enumerated row-by-row by (shared, governing) so it reads 1:1 against the
    // ported `entryVerifier.js` and every case is individually auditable. `match_same_arms` would have us
    // merge the arms that happen to share a Disposition (e.g. the two Holds) across the shared/!shared axis —
    // that collapses the table and hides which branch each rule lives in, on a gate we can't afford to blur.
    #[allow(clippy::match_same_arms)]
    match (shared, membership.resolve(governing_ref, key_id)) {
        // Shared tree: every entry must be attributed to a member with the role.
        (true, Governing::Unattributed) => Disposition::Reject, // rev-0 backdate forge — never a hold (would stall forever)
        (true, Governing::Illegitimate) => Disposition::Reject,
        (true, Governing::NotYetRetained) => Disposition::Hold,
        (true, Governing::Resolved { view, expected_key_id, .. }) => {
            verify_or_reject(version, header, &view, &expected_key_id, open)
        }
        // Never-shared (V1 single-owner): unattributed / unsigned-epoch entries are the norm.
        (false, Governing::Unattributed) => Disposition::Accept,
        (false, Governing::Illegitimate) => Disposition::Reject,
        (false, Governing::NotYetRetained) => Disposition::Hold,
        (false, Governing::Resolved { epoch_attributed: false, .. }) => Disposition::Accept,
        (false, Governing::Resolved { view, expected_key_id, .. }) => {
            verify_or_reject(version, header, &view, &expected_key_id, open)
        }
    }
}

fn verify_or_reject<E>(
    version: u32,
    header: &Header,
    view: &MembershipView,
    expected_key_id: &[u8],
    open: impl FnOnce() -> Result<Vec<u8>, E>,
) -> Disposition {
    let Ok(plaintext) = open() else {
        return Disposition::Reject;
    };
    match verify_entry(version, header, &plaintext, view, expected_key_id) {
        Ok(()) => Disposition::Accept,
        Err(_) => Disposition::Reject,
    }
}

/// The chain engine's [`MembershipResolver`] implementation.
pub mod chain {
    use std::collections::BTreeMap;

    use openom_keyring_chain::wire::Keyring;
    use openom_protocol::Message;

    use super::{Governing, MembershipResolver};
    use crate::attribution::{epoch_is_attributed, has_been_shared};

    /// Resolves an entry's governing keyring from the retained per-revision chain the client keeps.
    pub struct ChainMembershipResolver {
        head: Keyring,
        head_revision: u32,
        retained: BTreeMap<u32, Keyring>,
    }

    impl ChainMembershipResolver {
        /// Build from the current head keyring + the retained governing revisions (both are wire
        /// `Keyring` bytes the caller has already chain-verified and persisted).
        ///
        /// # Errors
        /// Returns a decode error string if any keyring blob is malformed.
        pub fn new(head_bytes: &[u8], retained: &[(u32, Vec<u8>)]) -> Result<Self, String> {
            let head = Keyring::decode(head_bytes).map_err(|e| format!("bad head keyring: {e}"))?;
            let head_revision = head.revision;
            let mut map = BTreeMap::new();
            for (rev, bytes) in retained {
                let kr =
                    Keyring::decode(bytes.as_slice()).map_err(|e| format!("bad keyring rev {rev}: {e}"))?;
                map.insert(*rev, kr);
            }
            Ok(Self {
                head,
                head_revision,
                retained: map,
            })
        }
    }

    impl MembershipResolver for ChainMembershipResolver {
        fn shared(&self) -> bool {
            has_been_shared(&self.head)
        }

        fn resolve(&self, governing_ref: &[u8], key_id: &[u8]) -> Governing {
            let rev = openom_keyring_chain::decode_governing_ref(governing_ref).unwrap_or(0);
            if rev == 0 {
                return Governing::Unattributed;
            }
            match self.retained.get(&rev) {
                Some(kr) => Governing::Resolved {
                    view: openom_keyring_chain::membership_view(kr),
                    expected_key_id: newest_key_id(kr),
                    epoch_attributed: epoch_is_attributed(kr, key_id),
                },
                // A ref above the verified head can't be legitimately reachable; at/below head it's a
                // transient retention gap (we haven't synced that revision yet).
                None if rev > self.head_revision => Governing::Illegitimate,
                None => Governing::NotYetRetained,
            }
        }
    }

    /// The newest epoch's `key_id` in a keyring (the B+ epoch-consistency input for `verify_entry`).
    fn newest_key_id(kr: &Keyring) -> Vec<u8> {
        kr.key_material()
            .ok()
            .and_then(|epochs| {
                epochs
                    .iter()
                    .max_by_key(|e| e.ordinal)
                    .map(|e| e.key_id.as_bytes().to_vec())
            })
            .unwrap_or_default()
    }
}

/// The dag engine's [`MembershipResolver`] implementation (OPE-382; §8.5 of `design.phase-c-dag-attribution.md`).
///
/// Always-current: a dag entry's governing membership is the CURRENTLY resolved anchor — the dag has no linear
/// revisions to retain per entry. This is admission-control sound (verifying against current membership can
/// only be MORE restrictive than a correct at-authoring model, so no forgery slips through); its cost is that a
/// since-removed member's history is dropped on a fresh replay, which the data-channel self-heal closes
/// separately. The epoch-consistency check accepts ANY epoch the tree has folded (`retained_epochs`), not only
/// the write-winner, so a legitimate prior-epoch entry (the norm after any `Remove`/`Reseal`) is not falsely
/// `EpochMismatch`-rejected.
pub mod dag {
    use std::collections::BTreeSet;

    use openom_keyring_api::MembershipView;

    use super::{Governing, MembershipResolver};
    use crate::VaultError;

    /// Resolves an entry's governing membership as the current dag anchor: one resolve + fold at construction.
    pub struct DagMembershipResolver {
        view: MembershipView,
        has_been_shared: bool,
        retained_epochs: BTreeSet<Vec<u8>>,
    }

    impl DagMembershipResolver {
        /// Build from the current, FLOOR-CHECKED dag anchor bytes — the persisted anchor the caller's watermark
        /// discipline protects, never raw server bytes (else `shared()`'s monotonicity is a construction-time
        /// fiction). Rebuilt after every keyring sync, which also releases any Held entries.
        ///
        /// # Errors
        /// Returns [`VaultError`] if the anchor is malformed or its sealing does not fold.
        pub fn new(anchor: &[u8]) -> Result<Self, VaultError> {
            let (view, has_been_shared, epoch_ids) = crate::dag_vault::verify_inputs(anchor)?;
            Ok(Self {
                view,
                has_been_shared,
                retained_epochs: epoch_ids.into_iter().collect(),
            })
        }
    }

    impl MembershipResolver for DagMembershipResolver {
        fn shared(&self) -> bool {
            self.has_been_shared
        }

        fn resolve(&self, governing_ref: &[u8], key_id: &[u8]) -> Governing {
            // The dag writer stamps a governing_ref (its unlock frontier) ONLY once the tree has been shared, so
            // an empty ref is a pre-share (unattributed) entry.
            if governing_ref.is_empty() {
                return Governing::Unattributed;
            }
            // Epoch-integrity: the entry must be sealed under an epoch the tree has actually minted. An epoch we
            // don't hold is either a forge OR the data channel outran the keyring channel (a not-yet-synced
            // re-epoch) — indistinguishable here, so HOLD (bounded by the caller's held buffer) and re-verify
            // after the next keyring sync rebuilds this with the new epoch. Present ⇒ echo it as the expected
            // key so `verify_entry`'s equality passes; membership + role are still checked against the current
            // view, so an ex-member holding an old epoch key still fails `UnknownAuthor`.
            if !self.retained_epochs.contains(key_id) {
                return Governing::NotYetRetained;
            }
            Governing::Resolved {
                view: self.view.clone(),
                expected_key_id: key_id.to_vec(),
                // Consulted only on the !shared path; a shared dag entry — the only kind carrying a non-empty
                // ref — takes the shared arms where this is ignored. Fail-closed `true` regardless.
                epoch_attributed: true,
            }
        }
    }
}

/// Build the engine-appropriate [`MembershipResolver`] from the persisted keyring material the worker holds:
/// the current head keyring/anchor, plus (chain only) the retained per-revision keyrings. This is the single
/// place the engine → resolver choice is made — a third engine adds one arm here and its own resolver impl,
/// and nothing else in the verify path changes.
///
/// # Errors
/// Returns [`VaultError`] if the keyring / anchor bytes are malformed.
pub fn resolver_from(
    engine: EngineKind,
    head: &[u8],
    retained: &[(u32, Vec<u8>)],
) -> Result<Box<dyn MembershipResolver>, VaultError> {
    match engine {
        EngineKind::Chain => Ok(Box::new(
            chain::ChainMembershipResolver::new(head, retained).map_err(VaultError::BadKeyring)?,
        )),
        // The dag resolves the whole membership from the single current anchor (always-current); it keeps no
        // per-revision retention, so `retained` is unused for it.
        EngineKind::Dag => Ok(Box::new(dag::DagMembershipResolver::new(head)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::chain::ChainMembershipResolver;
    use super::{resolver_from, verify_ingest, Disposition, MembershipResolver};
    use openom_keyring_api::EngineKind;

    use edsign::SigningKey;
    use keyeo_crypto::{codec, Epoch as KeyeoEpoch, KeyId};
    use openom_crypto::aad::author_signing_bytes;
    use openom_keyring_chain::wire::{Keyring, Member};
    use openom_keyring_chain::{encode_governing_ref, generate_identity};
    use openom_protocol::v1::{Aead, Header, Kind, MemberRole};
    use openom_protocol::Message;
    use sha2::{Digest, Sha256};

    const KID: &[u8] = b"epoch-key-0";
    const VERSION: u32 = 1;

    /// One epoch (ordinal 0) under `key_id` as the canonical `codec` bytes the keyring stores.
    fn enc_epoch(key_id: &[u8]) -> Vec<u8> {
        codec::encode_epochs(&[KeyeoEpoch::<String> {
            key_id: KeyId::new(key_id.to_vec()),
            ordinal: 0,
            wraps: vec![],
        }])
    }

    fn member(id: &str, role: MemberRole, key: &SigningKey) -> Member {
        Member {
            member_id: id.into(),
            role: role as i32,
            author_public_key: key.verifying_key().to_bytes().to_vec(),
            hpke_public_key: vec![9; 32],
        }
    }

    /// A minimal governing keyring at `revision`, with `first_shared_revision` set iff `shared` (so
    /// `has_been_shared` — the sticky attributed-writes gate — reports it). Its newest epoch uses KID.
    fn keyring(revision: u32, shared: bool, members: Vec<Member>) -> Keyring {
        Keyring {
            tree_id: vec![1; 16],
            revision,
            layout_version: 1,
            members,
            epochs: enc_epoch(KID),
            first_shared_revision: u32::from(shared),
            ..Default::default()
        }
    }

    /// An entry header authored by `author` under KID, stamped at `rev`, signed over `plaintext`.
    fn signed(kind: Kind, author: &str, key: &SigningKey, rev: u32, plaintext: &[u8]) -> Header {
        let mut h = Header {
            kind: kind as i32,
            aead: Aead::Xchacha20Poly1305 as i32,
            key_id: KID.to_vec(),
            tree_id: vec![1; 16],
            replica_id: vec![2; 4],
            replica_counter: 1,
            author_member_id: author.into(),
            governing_ref: encode_governing_ref(rev),
            ..Default::default()
        };
        let msg = author_signing_bytes(VERSION, &h, Sha256::digest(plaintext).as_slice());
        h.author_signature = key.sign(&msg).to_bytes().to_vec();
        h
    }

    /// An UNSIGNED header stamping `rev` (rev 0 ⇒ empty governing_ref, the pre-share / backdate shape).
    fn unsigned(rev: u32) -> Header {
        Header {
            kind: Kind::Delta as i32,
            aead: Aead::Xchacha20Poly1305 as i32,
            key_id: KID.to_vec(),
            tree_id: vec![1; 16],
            replica_id: vec![2; 4],
            replica_counter: 1,
            governing_ref: if rev == 0 {
                vec![]
            } else {
                encode_governing_ref(rev)
            },
            ..Default::default()
        }
    }

    fn cm(head: &Keyring, retained: &[(u32, &Keyring)]) -> ChainMembershipResolver {
        let retained: Vec<(u32, Vec<u8>)> = retained
            .iter()
            .map(|(rev, kr)| (*rev, kr.encode_to_vec()))
            .collect();
        ChainMembershipResolver::new(&head.encode_to_vec(), &retained).unwrap()
    }

    fn ingest(m: &dyn MembershipResolver, h: &Header, plaintext: &[u8]) -> Disposition {
        verify_ingest(VERSION, m, h, &h.governing_ref, &h.key_id, || {
            Ok::<_, ()>(plaintext.to_vec())
        })
    }

    #[test]
    fn solo_tree_accepts_an_unattributed_entry() {
        let k = generate_identity().unwrap();
        let kr = keyring(3, false, vec![member("m1", MemberRole::Admin, &k)]);
        let m = cm(&kr, &[(3, &kr)]);
        assert_eq!(ingest(&m, &unsigned(0), b"x"), Disposition::Accept);
    }

    #[test]
    fn resolver_from_builds_a_working_chain_resolver() {
        let k = generate_identity().unwrap();
        let kr = keyring(3, true, vec![member("m1", MemberRole::Admin, &k)]);
        let m = resolver_from(EngineKind::Chain, &kr.encode_to_vec(), &[(3, kr.encode_to_vec())]).unwrap();
        let h = signed(Kind::Delta, "m1", &k, 3, b"payload");
        assert_eq!(ingest(m.as_ref(), &h, b"payload"), Disposition::Accept);
    }

    #[test]
    fn shared_tree_rejects_a_rev0_backdate_forge() {
        let k = generate_identity().unwrap();
        let kr = keyring(3, true, vec![member("m1", MemberRole::Admin, &k)]);
        let m = cm(&kr, &[(3, &kr)]);
        assert_eq!(ingest(&m, &unsigned(0), b"x"), Disposition::Reject);
    }

    #[test]
    fn shared_tree_accepts_a_valid_maintainer_entry() {
        let k = generate_identity().unwrap();
        let kr = keyring(3, true, vec![member("m1", MemberRole::Admin, &k)]);
        let m = cm(&kr, &[(3, &kr)]);
        let h = signed(Kind::Delta, "m1", &k, 3, b"payload");
        assert_eq!(ingest(&m, &h, b"payload"), Disposition::Accept);
    }

    #[test]
    fn shared_tree_rejects_a_wrong_signer() {
        let k = generate_identity().unwrap();
        let mallory = generate_identity().unwrap();
        let kr = keyring(3, true, vec![member("m1", MemberRole::Admin, &k)]);
        let m = cm(&kr, &[(3, &kr)]);
        let h = signed(Kind::Delta, "m1", &mallory, 3, b"x");
        assert_eq!(ingest(&m, &h, b"x"), Disposition::Reject);
    }

    #[test]
    fn shared_tree_rejects_an_insufficient_role() {
        let k = generate_identity().unwrap();
        let kr = keyring(3, true, vec![member("e1", MemberRole::Editor, &k)]);
        let m = cm(&kr, &[(3, &kr)]);
        let h = signed(Kind::Delta, "e1", &k, 3, b"x");
        assert_eq!(ingest(&m, &h, b"x"), Disposition::Reject);
    }

    #[test]
    fn a_ref_beyond_the_head_is_rejected_not_held() {
        let k = generate_identity().unwrap();
        let head = keyring(3, true, vec![member("m1", MemberRole::Admin, &k)]);
        let m = cm(&head, &[(3, &head)]);
        // The entry stamps rev 4, above the verified head (3): illegitimate, a hard reject (not a hold that
        // would stall the tail forever).
        let h = signed(Kind::Delta, "m1", &k, 4, b"x");
        assert_eq!(ingest(&m, &h, b"x"), Disposition::Reject);
    }

    #[test]
    fn a_retention_gap_holds_then_accepts_once_the_revision_is_retained() {
        let k = generate_identity().unwrap();
        // Head is at rev 5; the entry's governing rev 4 is legitimate (<= head) but not retained yet.
        let head = keyring(5, true, vec![member("m1", MemberRole::Admin, &k)]);
        let gov4 = keyring(4, true, vec![member("m1", MemberRole::Admin, &k)]);
        let h = signed(Kind::Delta, "m1", &k, 4, b"x");
        assert_eq!(ingest(&cm(&head, &[(5, &head)]), &h, b"x"), Disposition::Hold);
        assert_eq!(
            ingest(&cm(&head, &[(5, &head), (4, &gov4)]), &h, b"x"),
            Disposition::Accept
        );
    }
}
