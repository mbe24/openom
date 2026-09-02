//! A ready-made concrete operation type implementing [`SignedOp`].
//!
//! Most callers can use [`Op`] directly and never implement [`SignedOp`]
//! themselves. Implement the trait on your own type only when you need a custom
//! backing representation — e.g. a foreign op type you are bridging, or an op
//! carrying extra domain fields.
//!
//! Identity, equality, hashing and ordering are defined by the op's `id` alone:
//! two ops with the same `id` are the same op. This is deliberate — it avoids
//! requiring `R: Ord`, so `Op` works with any [`Role`].

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use crate::dag::resolver::{GroupId, MemberId, MembershipAction, OpId, SignedOp};
use crate::roles::Role;
use crate::signature::{Ed25519, SignatureScheme};

/// A concrete, self-contained signed membership operation.
///
/// `OId` is the operation id (a DAG node); `MId` is a member id; `R` the role
/// type; `S` the signature scheme (defaults to [`Ed25519`]). The `signature` is
/// produced over the library's canonical encoding of the op's fields (see
/// [`crate::canonical::canonical_encode`]); the engine recomputes that encoding
/// and verifies the signature against it, so `signature` must come from
/// [`Op::sign`] (or be produced over `canonical_encode(id, parents, author, action)`).
#[derive(Clone, Debug)]
pub struct Op<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme = Ed25519> {
    pub id: OId,
    /// The group this op belongs to (openom: the tree id) — a [`GroupId`] bound into the signed +
    /// content-addressed bytes and enforced by the engine (an op whose `group_id` differs from the group
    /// being resolved is refused). [`GroupId::unscoped`] for single-group / test callers.
    pub group_id: GroupId,
    pub parents: Vec<OId>,
    pub author: MId,
    pub action: MembershipAction<MId, R, S>,
    pub signature: <S as SignatureScheme>::Signature,
    pub author_public_key: <S as SignatureScheme>::PublicKey,
    /// An opaque application payload, signed + content-addressed with the op but never interpreted by
    /// keyeo (openom rides its DEK-epoch / recovery-escrow records here; OPE-273). Empty for ops that
    /// carry none. Set it via [`Op::new`]'s result (the field is public) or the sealing-aware constructors.
    pub sealing: Vec<u8>,
}

impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> Op<OId, MId, R, S> {
    /// Assemble an op from its parts. Fields are public too — this is just the
    /// positional convenience constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: OId,
        group_id: GroupId,
        parents: Vec<OId>,
        author: MId,
        action: MembershipAction<MId, R, S>,
        signature: <S as SignatureScheme>::Signature,
        author_public_key: <S as SignatureScheme>::PublicKey,
    ) -> Self {
        Self {
            id,
            group_id,
            parents,
            author,
            action,
            signature,
            author_public_key,
            sealing: Vec::new(),
        }
    }

    /// Sign this op using an Ed25519 signing key.
    ///
    /// Computes the canonical encoding internally, signs it, and fills in
    /// `signature` and `author_public_key` automatically.
    /// This is the recommended constructor for the common case.
    ///
    /// Requires `S: SignatureScheme<PublicKey = [u8; 32], Signature = [u8; 64]>`
    /// which is true for `Ed25519` (the default scheme) and any compatible
    /// scheme. For exotic schemes, construct the op manually via `Op::new()`.
    pub fn sign(self, signing_key: &ed25519_dalek::SigningKey) -> Self
    where
        OId: std::fmt::Debug,
        MId: std::fmt::Debug,
        R: std::fmt::Debug,
        S: SignatureScheme<PublicKey = [u8; 32], Signature = [u8; 64]>,
    {
        use ed25519_dalek::Signer;
        let canonical = crate::canonical::canonical_encode(
            &self.group_id,
            &self.parents,
            &self.author,
            &self.action,
            &self.sealing,
        );
        let signature = signing_key.sign(&canonical).to_bytes();
        let author_public_key = signing_key.verifying_key().to_bytes();
        Self {
            signature,
            author_public_key,
            ..self
        }
    }
}

// Identity is the op id alone. Manual (not derived) so we don't force `R: Ord`.
impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> PartialEq for Op<OId, MId, R, S> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> Eq for Op<OId, MId, R, S> {}
impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> Hash for Op<OId, MId, R, S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> PartialOrd for Op<OId, MId, R, S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> Ord for Op<OId, MId, R, S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme> SignedOp for Op<OId, MId, R, S> {
    type S = S;
    type OpId = OId;
    type MemberId = MId;
    type R = R;
    fn id(&self) -> OId {
        self.id
    }
    fn parents(&self) -> &[OId] {
        &self.parents
    }
    fn author(&self) -> &MId {
        &self.author
    }
    fn action(&self) -> &MembershipAction<MId, R, S> {
        &self.action
    }
    fn signature(&self) -> &<S as SignatureScheme>::Signature {
        &self.signature
    }
    fn author_public_key(&self) -> &<S as SignatureScheme>::PublicKey {
        &self.author_public_key
    }
    fn sealing(&self) -> &[u8] {
        &self.sealing
    }
    fn group_id(&self) -> &GroupId {
        &self.group_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Ed25519;

    #[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
    struct TRole;
    impl Role for TRole {
        fn grants_at_least(&self, _other: &Self) -> bool {
            true
        }
    }

    #[test]
    fn sign_fills_canonical_signature_and_key() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let action = MembershipAction::<[u8; 32], TRole, Ed25519>::Remove { member: [1u8; 32] };
        let op = Op::new(
            42u64,
            GroupId::unscoped(),
            vec![1u64, 2u64],
            [3u8; 32],
            action,
            [0u8; 64],
            [0u8; 32],
        )
        .sign(&sk);

        // the signature verifies over the library's canonical encoding of the fields
        let canonical = crate::canonical::canonical_encode(
            &op.group_id,
            &op.parents,
            &op.author,
            &op.action,
            &op.sealing,
        );
        assert_eq!(op.author_public_key, sk.verifying_key().to_bytes());
        assert!(<Ed25519 as SignatureScheme>::verify(
            &op.author_public_key,
            &canonical,
            &op.signature
        )
        .is_ok());
        // a different action produces different canonical bytes (binding)
        let other = crate::canonical::canonical_encode(
            &op.group_id,
            &op.parents,
            &op.author,
            &MembershipAction::<[u8; 32], TRole, Ed25519>::Remove { member: [2u8; 32] },
            &op.sealing,
        );
        assert_ne!(canonical, other);
    }
}
