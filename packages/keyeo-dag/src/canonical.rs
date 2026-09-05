//! Canonical, versioned encoding of an operation's signed content — the byte layout that
//! signatures and content-addressed ids bind to.
//!
//! The [`CanonicalBytes`] seam and its postcard default ([`Postcard`]) live in `keyeo-core`; this module
//! owns the concrete block-layout encoder ([`canonical_encode`]) and the by-hand impls for keyeo's own
//! payload types (`MemberInit`, `MembershipAction`), which name engine types and route their `Serialize`
//! sub-fields through `Postcard`.
//!
//! The signed content is `(parents, author, action)` — **not** the op id. A content-addressed id is
//! `H(this ‖ signature ‖ author_public_key)`, so signing over the id would be circular; and a
//! signature must bind the content, not a caller-chosen label.

use keyeo_core::{CanonicalBytes, Postcard, Role, SignatureScheme};

use crate::dag::resolver::{
    GroupId, GroupState, MemberInit, MemberState, MemberId, MembershipAction, OpId,
};

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

impl<R: Role, S: SignatureScheme> CanonicalBytes for MemberState<R, S> {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure (no `..`): a new MemberState field is a compile error until it's bound into
        // the signed snapshot bytes — the same crypto-review guard the op/epoch encoders carry.
        let MemberState { role, member_counter, access_counter, author_public_key, hpke_public_key } = self;
        Postcard(role).write_canonical(out);
        out.extend_from_slice(&member_counter.to_le_bytes());
        out.extend_from_slice(&access_counter.to_le_bytes());
        out.extend_from_slice(author_public_key.as_ref());
        out.extend_from_slice(hpke_public_key);
    }
}

impl<Id: MemberId, R: Role, S: SignatureScheme> CanonicalBytes for GroupState<Id, R, S> {
    #[deny(unused_variables)]
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure: a snapshot's signature must cover EVERY trust-relevant field of the state it
        // checkpoints (membership + roles + keys, and the recovery authority), so a new field can't slip out of
        // the signed bytes and be tampered on a pruned root.
        let GroupState {
            members,
            reset_authority,
            group_id,
        } = self;
        // `members` is a HashMap (no stable iteration order) — sort by id so the encoding is deterministic
        // across replicas, the property a content-addressed / signed artifact requires.
        let mut ms: Vec<(&Id, &MemberState<R, S>)> = members.iter().collect();
        ms.sort_by(|a, b| a.0.cmp(b.0));
        out.extend_from_slice(&(ms.len() as u64).to_le_bytes());
        for (id, st) in ms {
            Postcard(id).write_canonical(out);
            st.write_canonical(out);
        }
        match reset_authority {
            Some(pk) => {
                out.push(1);
                out.extend_from_slice(pk.as_ref());
            }
            None => out.push(0),
        }
        let gid = group_id.as_bytes();
        out.extend_from_slice(&(gid.len() as u64).to_le_bytes());
        out.extend_from_slice(gid);
    }
}
