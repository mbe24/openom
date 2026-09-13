//! §B3 verify-on-ingest — the engine-NEUTRAL trust decision + a per-engine membership seam.
//!
//! On a shared tree, before a peer's delta is folded into local state, the client verifies it was
//! authored by a member who held the required capability in the keyring revision that governed it (see
//! [`crate::attribution`]). The *decision* (rev-0 / shared / hold / reject / accept — a faithful port of
//! the JS `entryVerifier`) is engine-neutral and lives here; only resolving an entry's governing
//! membership is engine-specific, behind the [`MembershipResolver`] trait. Chain implements it now
//! ([`chain::ChainMembershipResolver`]); the dag engine adds one more impl behind the same seam — nothing in the
//! neutral policy or the caller (`openom-app-core`'s `ingest`) changes.

use openom_keyring_api::{EngineKind, EverMemberInfo, MembershipView};
use openom_protocol::v1::{Header, Kind};
use openom_roles::required_role_for_kind;

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
        /// The CURRENT head membership, for the `governing_ref` LOOK-BEHIND (OPE-421): an entry's author must
        /// satisfy its required role at head, not just at the governing revision, so a since-demoted/removed
        /// member can't backdate a pre-demote ref to reclaim authority. The chain (which resolves a historical
        /// per-revision view) fills `Some(head_view)`; the dag leaves it `None` (its `view` IS the current
        /// head — the governing check already enforces the current role).
        head_view: Option<MembershipView>,
    },
    /// A legitimate revision we simply don't retain yet — HOLD and retry after the next keyring sync.
    NotYetRetained,
    /// A reference the engine can't legitimately reach (beyond the verified head) — REJECT.
    Illegitimate,
}

/// The per-engine seam. `shared` is monotonic (once a tree has been shared it stays shared, so a mid-
/// session keyring withhold can't downgrade the rule); `resolve` maps an entry's header coordinates to a
/// [`Governing`].
///
/// `Send + Sync`: an `AppCore` holding a `Box<dyn MembershipResolver>` must be movable across threads and
/// guarded by a `Mutex` on the native (Tauri) host, where invokes dispatch on a thread pool. Both impls
/// (chain/dag resolvers) are plain owned data, so the bound is trivially satisfied and is a no-op for the
/// single-threaded wasm worker.
pub trait MembershipResolver: Send + Sync {
    /// Whether the tree has ever been shared (a signature-requiring, multi-member tree).
    fn shared(&self) -> bool;
    /// Resolve the governing membership for an entry sealed under `key_id` with header `governing_ref`.
    fn resolve(&self, governing_ref: &[u8], key_id: &[u8]) -> Governing;
    /// Everything the self-heal covered-accept gate (pin P6) needs about a member who was EVER legitimately
    /// admitted — resolved from THIS client's verified membership, never from an (untrusted) cover: every author
    /// key they ever held + the strongest role they ever held (see [`EverMemberInfo`]). `None` if the id was
    /// never a legitimate member (a carve-out-voided thief or a never-member) — so a cover can never bless their
    /// entries. This is the SINGLE source of truth for an ever-member's facts, so a caller can't assemble a
    /// mismatched (id present, wrong key, wrong role) tuple — the split that let a forged cover-bound key hide.
    /// Defaults to `None` (fail-closed): only the dag resolver, whose always-current model drops legitimately-
    /// removed members' history, returns `Some`; the chain resolver retains history so covered-accept never
    /// fires there.
    fn ever_member_info(&self, _member_id: &str) -> Option<EverMemberInfo> {
        None
    }
    /// Whether `member_id` is a member RIGHT NOW — the writer covers only entries whose author is no longer
    /// current (a current member's entries verify normally, no cover needed). Defaults to `true` (permissive:
    /// a resolver that can't answer shouldn't cause spurious covers).
    fn current_member(&self, _member_id: &str) -> bool {
        true
    }
}

/// What to do with a pulled entry after §B3 verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The author (or lack of one, where allowed) is valid — merge it.
    Accept,
    /// Valid but its governing keyring isn't retained yet — buffer and re-verify after a keyring sync.
    Hold,
    /// Forged / unattributed-on-shared / illegitimate — reject it. A `Reject` is RETRYABLE: it pins the
    /// subsumed frontier (so it can't forge coverage over an unmerged dot) and is re-attempted on a membership
    /// change (a later cover / retained keyring can turn it valid).
    Reject,
    /// Valid at its governing revision but its author no longer holds the required role/key at the CURRENT head
    /// (OPE-421 look-behind) — a backdated forge by a since-demoted or since-removed member. TERMINAL and
    /// NON-resurrecting, distinct from `Reject`: never merged, NOT re-attempted by `retry_stalled` (a re-promote
    /// must re-mint fresh, never resurrect a backdated dot at its old HLC), and NON-pinning for GC (a forge must
    /// not freeze the subsumed frontier). A dropped coordinate BELOW an authenticated snapshot's covered frontier
    /// still triggers adoption, so a legit HELD pre-demote delta dropped here is recovered from the pin, not lost.
    Drop,
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
        (true, Governing::Resolved { view, expected_key_id, head_view, .. }) => {
            // Governing-revision verification first (Reject-precedence for real forgeries), THEN the OPE-421
            // head look-behind: an otherwise-valid entry whose author no longer holds the role at head is a
            // backdated forge by a since-demoted/removed member → `Drop` (terminal, non-resurrecting).
            match verify_or_reject(version, header, &view, &expected_key_id, open) {
                Disposition::Accept => head_disposition(header, &view, head_view.as_ref()),
                d => d,
            }
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

/// OPE-421 `governing_ref` LOOK-BEHIND: an entry's author must satisfy its required role at the CURRENT head,
/// not only at its governing revision — so a since-demoted or since-removed member can't backdate a pre-demote
/// `governing_ref` to reclaim authority. Also binds the KEY: the head member's `author_public_key` must equal
/// the governing view's key that verified the signature (no laundering a revoked key through a re-admitted
/// same-`member_id` member). `head_view = None` (the dag, always-current) ⇒ always authorized (the governing
/// check already used the current role).
///
/// Applies to ALL role-gated kinds (Slice 2 un-gated it from the Slice-1 snapshot-only). Called ONLY on an
/// entry that already passed the governing check (`verify_or_reject == Accept`), so `Kind::try_from` and
/// `required_role_for_kind` cannot actually fail here (`verify_entry` already rejected `UnsupportedKind`); those
/// arms are defensive and map to `Reject` (malformed), never `Drop`. A genuine look-behind failure — author
/// under-role, key-mismatched, or absent at head — is a backdated forge → `Drop` (terminal, non-resurrecting).
fn head_disposition(
    header: &Header,
    governing: &MembershipView,
    head_view: Option<&MembershipView>,
) -> Disposition {
    let Some(head_view) = head_view else {
        return Disposition::Accept; // dag / always-current — the governing check already enforced the current role
    };
    let Ok(kind) = Kind::try_from(header.kind) else {
        return Disposition::Reject; // defensive: verify_entry already gated this
    };
    let Some(required) = required_role_for_kind(kind) else {
        return Disposition::Reject; // defensive: Unspecified was already rejected by verify_entry
    };
    let governing_key = governing
        .members
        .iter()
        .find(|m| m.member_id == header.author_member_id)
        .map(|m| m.author_public_key.as_slice());
    match head_view
        .members
        .iter()
        .find(|m| m.member_id == header.author_member_id)
    {
        // Present at head, strong enough, AND the same key that verified the signature at the governing view.
        Some(hm)
            if hm.role <= required && Some(hm.author_public_key.as_slice()) == governing_key =>
        {
            Disposition::Accept
        }
        // Under-role / key-mismatched (a re-admitted same-id member with a fresh key), or absent at head
        // (removed) — a backdated forge by a since-demoted or since-removed member.
        _ => Disposition::Drop,
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

/// Verify a since-removed member's entry against a **cover binding** (SH-2 covered-accept, pin P2): the entry
/// must STILL carry a valid author signature over its content, made by a key the author ACTUALLY held, and its
/// kind must be permitted by the strongest role the author ACTUALLY held — a cover WAIVES only the
/// *current-membership* check, never integrity and never role.
///
/// **This is the ONE function that decides covered-acceptance.** Its only two callers are the reader
/// (`openom_app_core::classify_entry`, the fold-time gate) and the writer (`openom_app_core::author_cover`,
/// which covers a candidate only if this returns true for it). Both source `author_public_key` and
/// `author_role` from their OWN resolver's [`MembershipResolver::ever_member_info`] — NEVER from the (untrusted)
/// cover — so a forged cover can neither bind an attacker key to a real removed id nor waive the role check.
/// Keep this the sole decision site; do not inline a second copy.
///
/// Reuses the audited [`verify_entry`] with a SYNTHETIC single-member view (never escapes this call), so no
/// crypto is duplicated: the author id must match the entry's `author_member_id`, the signature must verify
/// against `author_public_key`, `author_role` gates the entry's kind (a `Delta` needs Maintainer), and the epoch
/// echoes the entry's own `key_id` (accept any epoch it was legitimately sealed under, as the dag resolver
/// does). `plaintext` is the AEAD-opened body — the caller must have opened it, which itself proves integrity of
/// the ciphertext the recomputed hash pinned. `author_role` is in the [`openom_keyring_api`] convention (lower is
/// stronger); pass the author's STRONGEST-ever role.
#[must_use]
pub fn verify_covered_entry(
    version: u32,
    header: &Header,
    plaintext: &[u8],
    author_member_id: &str,
    author_public_key: &[u8],
    author_role: i16,
) -> bool {
    let view = MembershipView::new(
        vec![openom_keyring_api::MemberView {
            member_id: author_member_id.to_string(),
            role: author_role,
            author_public_key: author_public_key.to_vec(),
            hpke_public_key: Vec::new(),
        }],
        false,
    );
    verify_entry(version, header, plaintext, &view, &header.key_id).is_ok()
}

/// The chain engine's [`MembershipResolver`] implementation.
pub mod chain {
    use std::collections::BTreeMap;

    use openom_keyring_chain::wire::Keyring;
    use openom_protocol::Message;

    use super::{Governing, MembershipResolver};
    use crate::attribution::{epoch_is_attributed, has_been_shared};

    /// How many revisions past the verified head a `governing_ref` may be before it is deemed fabricated
    /// (Reject) rather than a not-yet-synced keyring race (Hold). A membership op is one revision, so a
    /// handful of look-ahead covers any realistic keyring-behind-data race; beyond it the ref is bogus.
    const HEAD_LOOKAHEAD: u32 = 16;

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
        /// Returns a decode error string if any keyring blob is malformed, a retained keyring's own revision
        /// disagrees with its `(rev, bytes)` key (a caller transposition would otherwise verify entries
        /// against the WRONG revision's membership silently), or a retained keyring is for a different tree.
        pub fn new(head_bytes: &[u8], retained: &[(u32, Vec<u8>)]) -> Result<Self, String> {
            let head = Keyring::decode(head_bytes).map_err(|e| format!("bad head keyring: {e}"))?;
            let head_revision = head.revision;
            let mut map = BTreeMap::new();
            for (rev, bytes) in retained {
                let kr =
                    Keyring::decode(bytes.as_slice()).map_err(|e| format!("bad keyring rev {rev}: {e}"))?;
                if kr.revision != *rev {
                    return Err(format!("retained keyring at key {rev} declares revision {}", kr.revision));
                }
                if kr.tree_id != head.tree_id {
                    return Err(format!("retained keyring rev {rev} is for a different tree than the head"));
                }
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
                    // OPE-421 look-behind: the author must ALSO satisfy the role at the CURRENT head.
                    head_view: Some(openom_keyring_chain::membership_view(&self.head)),
                },
                // Beyond a small look-ahead of the verified head the ref is fabricated → hard Reject. WITHIN
                // it, a rev just past the head is the benign "keyring channel hasn't caught up with the data
                // channel" race (owner shared + immediately wrote): HOLD and re-verify after the next keyring
                // sync — like the dag's unknown-epoch case — rather than terminally dropping a legit racing
                // entry (the two engines otherwise disagree on the identical race).
                None if rev > self.head_revision.saturating_add(HEAD_LOOKAHEAD) => Governing::Illegitimate,
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
/// revisions to retain per entry. This is admission-control sound in the common direction (an ex-member or a
/// forger who was never a member fails `UnknownAuthor`). It is NOT strictly "only more restrictive," though: it
/// is current-dependent in BOTH directions — a member later PROMOTED to a role they lacked when they authored
/// an old (still re-pullable) entry has that backdated entry retroactively ACCEPTED, keeping its original
/// causal/HLC position (so it can win a supersede race it shouldn't and falsifies audit history). That residue
/// is bounded (a now-authorised author could re-mint equivalent content) and is closed by the snapshot-boundary
/// (a signed checkpoint pins what was accepted below it), not here. Its OTHER cost is that a since-removed
/// member's history is dropped on a fresh replay, which the data-channel self-heal closes separately. The
/// epoch-consistency check accepts ANY epoch the tree has folded (`retained_epochs`), not only the write-winner,
/// so a legitimate prior-epoch entry (the norm after any `Remove`/`Reseal`) is not falsely `EpochMismatch`-rejected.
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
        ever_members: std::collections::BTreeMap<String, super::EverMemberInfo>,
    }

    impl DagMembershipResolver {
        /// Build from the current, FLOOR-CHECKED dag anchor bytes — the persisted anchor the caller's watermark
        /// discipline protects, never raw server bytes (else `shared()`'s monotonicity is a construction-time
        /// fiction). Rebuilt after every keyring sync, which also releases any Held entries.
        ///
        /// # Errors
        /// Returns [`VaultError`] if the anchor is malformed or its sealing does not fold.
        pub fn new(anchor: &[u8]) -> Result<Self, VaultError> {
            let inputs = crate::dag_vault::verify_inputs(anchor)?;
            Ok(Self {
                view: inputs.view,
                has_been_shared: inputs.shared,
                retained_epochs: inputs.epoch_ids.into_iter().collect(),
                ever_members: inputs.ever_members,
            })
        }
    }

    impl MembershipResolver for DagMembershipResolver {
        fn shared(&self) -> bool {
            self.has_been_shared
        }

        fn ever_member_info(&self, member_id: &str) -> Option<super::EverMemberInfo> {
            self.ever_members.get(member_id).cloned()
        }

        fn current_member(&self, member_id: &str) -> bool {
            self.view.members.iter().any(|m| m.member_id == member_id)
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
                // The dag is always-current: `view` IS the head, so the governing check already enforces the
                // current role — no separate look-behind (OPE-421).
                head_view: None,
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
            dek_commitment: [0u8; 32],
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

    /// An UNSIGNED header stamping `rev` (rev 0 ⇒ empty `governing_ref`, the pre-share / backdate shape).
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

    // ── OPE-421: the governing_ref look-behind (role at head). Slice 1 gated it to Snapshot; Slice 2 un-gated
    //    it to all kinds and a failure is now `Drop` (terminal, non-resurrecting) rather than `Reject`. ──

    #[test]
    fn a_demoted_authors_backdated_snapshot_is_dropped() {
        // carol is a Maintainer at rev 3 (governing) but demoted to Editor at head rev 4. A Snapshot she signs
        // stamping the pre-demote ref passes the governing-revision check but MUST fail the head look-behind.
        let owner = generate_identity().unwrap();
        let carol = generate_identity().unwrap();
        let gov3 = keyring(3, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("carol", MemberRole::Admin, &carol),
        ]);
        let head4 = keyring(4, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("carol", MemberRole::Editor, &carol), // demoted
        ]);
        let m = cm(&head4, &[(3, &gov3), (4, &head4)]);
        let snap = signed(Kind::Snapshot, "carol", &carol, 3, b"snap");
        assert_eq!(ingest(&m, &snap, b"snap"), Disposition::Drop, "backdated snapshot by a demoted member");
    }

    #[test]
    fn a_current_maintainers_snapshot_is_accepted() {
        let owner = generate_identity().unwrap();
        let head4 = keyring(4, true, vec![member("owner", MemberRole::Owner, &owner)]);
        let m = cm(&head4, &[(4, &head4)]);
        let snap = signed(Kind::Snapshot, "owner", &owner, 4, b"snap");
        assert_eq!(ingest(&m, &snap, b"snap"), Disposition::Accept);
    }

    #[test]
    fn a_re_admitted_member_cannot_launder_a_revoked_key_via_a_backdated_snapshot() {
        // carol's OLD key was a Maintainer at rev 3; she is re-admitted at head rev 4 with a FRESH key (same
        // member_id). A snapshot signed by the OLD key stamping rev 3 passes the governing check (the old key
        // is in the rev-3 view) but the head member carries the NEW key → key mismatch → Reject.
        let owner = generate_identity().unwrap();
        let carol_old = generate_identity().unwrap();
        let carol_new = generate_identity().unwrap();
        let gov3 = keyring(3, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("carol", MemberRole::Admin, &carol_old),
        ]);
        let head4 = keyring(4, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("carol", MemberRole::Admin, &carol_new), // re-admitted, fresh key
        ]);
        let m = cm(&head4, &[(3, &gov3), (4, &head4)]);
        let snap = signed(Kind::Snapshot, "carol", &carol_old, 3, b"snap");
        assert_eq!(ingest(&m, &snap, b"snap"), Disposition::Drop, "revoked key laundered via a re-admit");
    }

    #[test]
    fn a_demoted_authors_backdated_delta_is_dropped() {
        // Slice 2: the look-behind now covers DELTAs (not just snapshots). carol is a Maintainer at rev 3 but
        // demoted to Editor at head rev 4; a Delta she signs stamping the pre-demote ref passes the governing
        // check but fails the head look-behind → Drop (terminal, non-resurrecting), NOT Reject.
        let owner = generate_identity().unwrap();
        let carol = generate_identity().unwrap();
        let gov3 = keyring(3, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("carol", MemberRole::Admin, &carol),
        ]);
        let head4 = keyring(4, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("carol", MemberRole::Editor, &carol),
        ]);
        let m = cm(&head4, &[(3, &gov3), (4, &head4)]);
        let delta = signed(Kind::Delta, "carol", &carol, 3, b"d");
        assert_eq!(ingest(&m, &delta, b"d"), Disposition::Drop, "demoted member's backdated delta");
    }

    #[test]
    fn a_removed_members_backdated_delta_is_dropped() {
        // Chain removal: bob is a Maintainer at rev 3 (governing) but ABSENT at head rev 4 (removed). His delta
        // stamping the pre-removal ref passes the governing check but fails the head look-behind (absent at
        // head) → Drop. This is the deliberate Slice-2 regression: chain removal is now lossy in-transit for a
        // not-yet-folded delta, bounded by Slice 3's compact-before-remove.
        let owner = generate_identity().unwrap();
        let bob = generate_identity().unwrap();
        let gov3 = keyring(3, true, vec![
            member("owner", MemberRole::Owner, &owner),
            member("bob", MemberRole::Admin, &bob),
        ]);
        let head4 = keyring(4, true, vec![member("owner", MemberRole::Owner, &owner)]); // bob removed
        let m = cm(&head4, &[(3, &gov3), (4, &head4)]);
        let delta = signed(Kind::Delta, "bob", &bob, 3, b"d");
        assert_eq!(ingest(&m, &delta, b"d"), Disposition::Drop, "removed member's backdated delta");
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
    fn a_ref_just_past_the_head_holds_but_a_far_future_ref_is_rejected() {
        let k = generate_identity().unwrap();
        let head = keyring(3, true, vec![member("m1", MemberRole::Admin, &k)]);
        let m = cm(&head, &[(3, &head)]);
        // rev 4 is one past the verified head (3) — the benign "keyring channel hasn't caught up" race → Hold
        // and re-verify after the next keyring sync, not a terminal drop.
        assert_eq!(ingest(&m, &signed(Kind::Delta, "m1", &k, 4, b"x"), b"x"), Disposition::Hold);
        // A ref far past the head is fabricated → hard Reject (can't stall the tail forever).
        assert_eq!(ingest(&m, &signed(Kind::Delta, "m1", &k, 100, b"x"), b"x"), Disposition::Reject);
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
