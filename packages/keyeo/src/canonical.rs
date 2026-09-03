//! Canonical, versioned encoding of an operation's signed content — the byte layout that
//! signatures and content-addressed ids bind to.
//!
//! The [`CanonicalBytes`] seam and its postcard default ([`Postcard`]) live in `keyeo-core`; this module
//! owns the concrete block-layout encoders ([`canonical_encode`] / [`canonical_encode_epoch`]) and the
//! by-hand impls for keyeo's own payload types (`MemberInit`, `MembershipAction`, `DekWrap`), which name
//! engine types and route their `Serialize` sub-fields through `Postcard`.
//!
//! The signed content is `(parents, author, action)` — **not** the op id. A content-addressed id is
//! `H(this ‖ signature ‖ author_public_key)`, so signing over the id would be circular; and a
//! signature must bind the content, not a caller-chosen label.

use keyeo_core::{CanonicalBytes, Postcard, Role, SignatureScheme};

use crate::dag::resolver::{DekWrap, GroupId, MemberId, MemberInit, MembershipAction, OpId};

impl<Id: MemberId, R: Role, S: SignatureScheme> CanonicalBytes for MemberInit<Id, R, S> {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure (no `..`): a new MemberInit field is a compile error until it's encoded
        // into the signed/content-addressed bytes (OPE-277 crypto-review hardening). Byte order unchanged.
        let MemberInit { id, role, author_public_key, hpke_public_key } = self;
        Postcard(id).write_canonical(out);
        Postcard(role).write_canonical(out);
        out.extend_from_slice(author_public_key.as_ref());
        out.extend_from_slice(hpke_public_key);
    }
}

impl<Id: MemberId, R: Role, S: SignatureScheme> CanonicalBytes for MembershipAction<Id, R, S> {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            MembershipAction::Create { initial_members } => {
                out.push(0);
                out.extend_from_slice(&(initial_members.len() as u64).to_le_bytes());
                for m in initial_members {
                    m.write_canonical(out);
                }
            }
            MembershipAction::Add {
                member,
                role,
                author_public_key,
                hpke_public_key,
                member_proof,
            } => {
                out.push(1);
                Postcard(member).write_canonical(out);
                Postcard(role).write_canonical(out);
                out.extend_from_slice(author_public_key.as_ref());
                out.extend_from_slice(hpke_public_key);
                match member_proof {
                    Some(sig) => {
                        out.push(1);
                        out.extend_from_slice(sig.as_ref());
                    }
                    None => out.push(0),
                }
            }
            MembershipAction::Remove { member } => {
                out.push(2);
                Postcard(member).write_canonical(out);
            }
            MembershipAction::ChangeRole { member, new_role } => {
                out.push(3);
                Postcard(member).write_canonical(out);
                Postcard(new_role).write_canonical(out);
            }
            MembershipAction::Propose { proposal_id, target } => {
                out.push(4);
                out.extend_from_slice(proposal_id);
                target.write_canonical(out); // binds the target into the proposal's signed bytes
            }
            MembershipAction::Approve { proposal_id } => {
                out.push(5);
                out.extend_from_slice(proposal_id);
            }
            MembershipAction::Commit { proposal_id } => {
                out.push(6);
                out.extend_from_slice(proposal_id);
            }
            MembershipAction::ReFound {
                member,
                new_author_public_key,
                new_hpke_public_key,
                era,
            } => {
                out.push(7);
                Postcard(member).write_canonical(out);
                out.extend_from_slice(new_author_public_key.as_ref());
                out.extend_from_slice(new_hpke_public_key);
                out.extend_from_slice(&era.to_le_bytes());
            }
            MembershipAction::RotateRecoveryAuthority {
                new_reset_authority,
            } => {
                out.push(8);
                out.extend_from_slice(new_reset_authority.as_ref());
            }
            MembershipAction::Retarget {
                member,
                new_author_public_key,
                new_hpke_public_key,
            } => {
                out.push(9);
                Postcard(member).write_canonical(out);
                out.extend_from_slice(new_author_public_key.as_ref());
                out.extend_from_slice(new_hpke_public_key);
            }
            // Membership-inert; the reseal delta rides the op's `sealing` envelope, not the action bytes.
            MembershipAction::Reseal => {
                out.push(10);
            }
        }
    }
}

impl<Id: MemberId> CanonicalBytes for DekWrap<Id> {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // The member label is bound too: otherwise an attacker could permute which member each wrap
        // targets on a signed epoch and it would still verify, handing members wraps under the wrong
        // HPKE key — a group-wide lockout via a still-"valid" artifact. The variable-length byte
        // fields are length-prefixed so adjacent wraps can't be re-partitioned into a colliding blob.
        // Exhaustive destructure (no `..`): a new field can't slip out of the signed bytes. Order unchanged.
        let DekWrap { member, hpke_public_key, encapped_key, ciphertext } = self;
        Postcard(member).write_canonical(out);
        out.extend_from_slice(hpke_public_key);
        out.extend_from_slice(&(encapped_key.len() as u64).to_le_bytes());
        out.extend_from_slice(encapped_key);
        out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(ciphertext);
    }
}

/// Deterministically encode the **signed content** of a block: a version tag followed by the postcard
/// encoding of `parents` and `author`, then the action's own canonical bytes, then the opaque `sealing`
/// payload. Excludes the op id (see module docs). Both the signer ([`crate::op::Op::sign`]) and the
/// verifier (the engine) call this over the block's own fields.
///
/// `sealing` is an OPAQUE application payload the engine signs + content-addresses but never interprets —
/// keyeo stays domain-free (openom rides its DEK-epoch / recovery-escrow records here; OPE-273). It is
/// length-prefixed so it can't be re-partitioned against the action's trailing bytes. Empty (`&[]`) for
/// ops that carry none.
///
/// Generic over the payload via the [`CanonicalBytes`] seam — the byte layout of a blocklace block is
/// defined independently of *what* the block carries. keyeo's payload is [`MembershipAction`], but this
/// function (and hence the block-id / signature machinery) is payload-agnostic and testable with any
/// `CanonicalBytes` action.
pub fn canonical_encode<OId: OpId, MId: MemberId, A: CanonicalBytes>(
    group_id: &GroupId,
    parents: &[OId],
    author: &MId,
    action: &A,
    sealing: &[u8],
) -> Vec<u8> {
    let group_id = group_id.as_bytes();
    // v3 adds the leading length-prefixed `group_id` — a first-class binding of every op to its group, so
    // the resolver can REFUSE an op minted for a different group (an op for group A can never resolve into
    // group B) rather than relying on the incidental "foreign parents don't resolve". Placed first (right
    // after the version tag) and covered by both the signature and the content-id. keyeo stays domain-free:
    // `group_id` is an opaque identifier the caller assigns (openom sets it to the tree id). v2→v3 keeps the
    // layouts byte-disjoint — pre-release, no persisted ops, so no migration. (v2 added trailing `sealing`.)
    let mut buf = b"keyeo:op:v3".to_vec();
    buf.extend_from_slice(&(group_id.len() as u64).to_le_bytes());
    buf.extend_from_slice(group_id);
    buf.extend_from_slice(&(parents.len() as u64).to_le_bytes());
    for p in parents {
        Postcard(p).write_canonical(&mut buf);
    }
    Postcard(author).write_canonical(&mut buf);
    action.write_canonical(&mut buf);
    buf.extend_from_slice(&(sealing.len() as u64).to_le_bytes());
    buf.extend_from_slice(sealing);
    buf
}

/// Deterministically encode the **signed content** of an epoch artifact: a version tag followed by
/// `(parents, commitment, epoch, wraps)`, through the same [`CanonicalBytes`] seam as ops (G-S5 — no
/// second hand-rolled encoder). Both the author ([`crate::epoch::Epoch::author`]) and the verifier
/// ([`crate::epoch::verify_epoch`]) call this over the epoch's own fields, so a signature binds to
/// exactly this content and can't be transplanted to a different frontier, membership, or wrap set.
pub fn canonical_encode_epoch<OId: OpId, MId: MemberId>(
    group_id: &GroupId,
    parents: &[OId],
    commitment: &[u8; 32],
    epoch: u64,
    wraps: &[DekWrap<MId>],
) -> Vec<u8> {
    // v2 adds the leading length-prefixed group_id — an epoch artifact is signature-bound to its group, so
    // an epoch authored for group A can never be admitted into group B (two groups with an identical active
    // membership have an identical membership_commitment; without this, group A's signed epoch could be
    // transplanted into B and win reconciliation — a cross-tree DEK collapse). Matches the op layout (v3).
    let group_id = group_id.as_bytes();
    let mut buf = b"keyeo:epoch:v2".to_vec();
    buf.extend_from_slice(&(group_id.len() as u64).to_le_bytes());
    buf.extend_from_slice(group_id);
    buf.extend_from_slice(&(parents.len() as u64).to_le_bytes());
    for p in parents {
        Postcard(p).write_canonical(&mut buf);
    }
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&(wraps.len() as u64).to_le_bytes());
    for w in wraps {
        w.write_canonical(&mut buf);
    }
    buf
}
