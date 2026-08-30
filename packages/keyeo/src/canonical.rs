//! Canonical, versioned encoding of an operation's signed content — the byte layout that
//! signatures and content-addressed ids bind to.
//!
//! **Design "A":** [`CanonicalBytes`] is the seam — the single definition of "the bytes".
//! **Default "B":** a blanket impl over `serde::Serialize` via **postcard**, a compact,
//! deterministic binary format that is byte-identical across native and wasm Rust builds. (The old
//! `format!("{:?}")` encoding was never guaranteed stable across builds, so it could never back a
//! content hash.) To adopt a non-postcard layout for a specific type later, drop the blanket and
//! implement the trait by hand — a versioned change, since every id/signature over that type moves.
//!
//! The signed content is `(parents, author, action)` — **not** the op id. A content-addressed id is
//! `H(this ‖ signature ‖ author_public_key)`, so signing over the id would be circular; and a
//! signature must bind the content, not a caller-chosen label.

use serde::Serialize;

use crate::dag::resolver::{DekWrap, MemberId, MemberInit, MembershipAction, OpId};
use crate::roles::Role;
use crate::signature::SignatureScheme;

/// The canonical-bytes seam. The default ("B") is a deterministic postcard encoding for anything
/// `Serialize` — used for the primitive `Id`/`Role`/`OpId` values. Types that embed non-serde
/// crypto byte-arrays (`MemberInit`, `MembershipAction`) implement it by hand below.
pub trait CanonicalBytes {
    fn write_canonical(&self, out: &mut Vec<u8>);
}

/// A newtype so the postcard default doesn't blanket-cover *every* `Serialize` type — which would
/// collide (coherence) with the hand impls below. Wrap a `Serialize` value to get its postcard bytes.
struct Postcard<'a, T: Serialize>(&'a T);

impl<T: Serialize> CanonicalBytes for Postcard<'_, T> {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(
            &postcard::to_allocvec(self.0)
                .expect("postcard serialization of canonical op content is infallible"),
        );
    }
}

impl<Id: MemberId, R: Role, S: SignatureScheme> CanonicalBytes for MemberInit<Id, R, S> {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        Postcard(&self.id).write_canonical(out);
        Postcard(&self.role).write_canonical(out);
        out.extend_from_slice(self.author_public_key.as_ref());
        out.extend_from_slice(&self.hpke_public_key);
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
        }
    }
}

impl<Id: MemberId> CanonicalBytes for DekWrap<Id> {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        // The member label is bound too: otherwise an attacker could permute which member each wrap
        // targets on a signed epoch and it would still verify, handing members wraps under the wrong
        // HPKE key — a group-wide lockout via a still-"valid" artifact. The variable-length byte
        // fields are length-prefixed so adjacent wraps can't be re-partitioned into a colliding blob.
        Postcard(&self.member).write_canonical(out);
        out.extend_from_slice(&self.hpke_public_key);
        out.extend_from_slice(&(self.encapped_key.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.encapped_key);
        out.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
    }
}

/// Deterministically encode the **signed content** of an op: a version tag followed by the postcard
/// encoding of `(parents, author, action)`. Excludes the op id (see module docs). Both the signer
/// ([`crate::op::Op::sign`]) and the verifier (the engine) call this over the op's own fields.
pub fn canonical_encode<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme>(
    parents: &[OId],
    author: &MId,
    action: &MembershipAction<MId, R, S>,
) -> Vec<u8> {
    let mut buf = b"keyeo:op:v1".to_vec();
    buf.extend_from_slice(&(parents.len() as u64).to_le_bytes());
    for p in parents {
        Postcard(p).write_canonical(&mut buf);
    }
    Postcard(author).write_canonical(&mut buf);
    action.write_canonical(&mut buf);
    buf
}

/// Deterministically encode the **signed content** of an epoch artifact: a version tag followed by
/// `(parents, commitment, epoch, wraps)`, through the same [`CanonicalBytes`] seam as ops (G-S5 — no
/// second hand-rolled encoder). Both the author ([`crate::epoch::Epoch::author`]) and the verifier
/// ([`crate::epoch::verify_epoch`]) call this over the epoch's own fields, so a signature binds to
/// exactly this content and can't be transplanted to a different frontier, membership, or wrap set.
pub fn canonical_encode_epoch<OId: OpId, MId: MemberId>(
    parents: &[OId],
    commitment: &[u8; 32],
    epoch: u64,
    wraps: &[DekWrap<MId>],
) -> Vec<u8> {
    let mut buf = b"keyeo:epoch:v1".to_vec();
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
