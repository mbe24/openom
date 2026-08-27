//! Content-addressed operation ids (the Git/Automerge/IPFS model).
//!
//! `id = H(canonical(parents, author, action) ‖ signature ‖ author_public_key)` — SHA-256. With this
//! `OpId`, the op-DAG is a **Merkle-DAG**: every parent link is a hash, so the graph is
//! self-verifying and ops dedup for free. The id is deliberately *not* part of the signed bytes
//! (that would be circular — see [`crate::canonical`]); instead the signature is folded into the id,
//! so tampering with the content (or the signature) changes the id.
//!
//! This complements — does not replace — a snapshot's history commitment: content ids secure the op
//! *graph*; the commitment secures the resolved state *at a frontier* so it survives GC.

use sha2::{Digest, Sha256};

use crate::canonical::canonical_encode;
use crate::dag::resolver::{MemberId, MembershipAction, OpId, SignedOp};
use crate::op::Op;
use crate::roles::Role;
use crate::signature::{Ed25519, SignatureScheme};

/// A 32-byte content-addressed operation id (SHA-256 of the op's content).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, serde::Serialize)]
pub struct ContentId(pub [u8; 32]);

impl OpId for ContentId {}

/// Compute the content id from an op's fields: `H(canonical(parents, author, action) ‖ signature ‖
/// author_public_key)`.
pub fn content_id<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme>(
    parents: &[OId],
    author: &MId,
    action: &MembershipAction<MId, R, S>,
    signature: &<S as SignatureScheme>::Signature,
    author_public_key: &<S as SignatureScheme>::PublicKey,
) -> ContentId {
    let mut h = Sha256::new();
    h.update(canonical_encode(parents, author, action));
    h.update(signature.as_ref());
    h.update(author_public_key.as_ref());
    ContentId(h.finalize().into())
}

impl<MId: MemberId, R: Role> Op<ContentId, MId, R, Ed25519> {
    /// Build a signed, content-addressed op: sign `(parents, author, action)`, then set
    /// `id = H(canonical ‖ signature ‖ author_public_key)`. The recommended constructor for a keyring.
    pub fn content_addressed(
        parents: Vec<ContentId>,
        author: MId,
        action: MembershipAction<MId, R, Ed25519>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let canonical = canonical_encode(&parents, &author, &action);
        let signature = signing_key.sign(&canonical).to_bytes();
        let author_public_key = signing_key.verifying_key().to_bytes();
        let id = content_id(&parents, &author, &action, &signature, &author_public_key);
        Op {
            id,
            parents,
            author,
            action,
            signature,
            author_public_key,
        }
    }
}

/// Re-derive the content id from an op's fields and confirm it matches the claimed `id`. This is the
/// content-integrity check: a tampered `parents`/`author`/`action`/`signature` (with the id kept)
/// fails here. Run it at **ingest**, before handing a content-addressed op to the engine (which
/// separately verifies the signature). Together they give: the id names exactly this content, and
/// the content is signed.
pub fn verify_content_id<MId: MemberId, R: Role, S: SignatureScheme>(
    op: &Op<ContentId, MId, R, S>,
) -> bool {
    content_id(
        op.parents(),
        op.author(),
        op.action(),
        op.signature(),
        op.author_public_key(),
    ) == op.id()
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
    fn content_id_verifies_and_detects_tampering() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let action = MembershipAction::<[u8; 32], TRole, Ed25519>::Remove { member: [1u8; 32] };
        let op = Op::content_addressed(vec![], [3u8; 32], action, &sk);

        // The id names this content; re-derivation matches.
        assert!(verify_content_id(&op));

        // Tamper the action but keep the id → content no longer hashes to the claimed id.
        let tampered = Op {
            action: MembershipAction::Remove { member: [2u8; 32] },
            ..op.clone()
        };
        assert!(!verify_content_id(&tampered));

        // Distinct content ⇒ distinct id (Merkle-DAG property).
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let other = Op::content_addressed(
            vec![],
            [3u8; 32],
            MembershipAction::<[u8; 32], TRole, Ed25519>::Remove { member: [1u8; 32] },
            &sk2,
        );
        assert_ne!(
            op.id(),
            other.id(),
            "different signer ⇒ different content id"
        );
    }
}
