//! The DAG keyring's **client facade** (OPE-273) — the secret-adjacent surface the vault (`openom-sealer`'s
//! `dag_vault.rs`) drives, so the vault never touches `keyeo` or this crate's op types directly (a
//! one-line import grep keeps `dag_vault.rs` free of `keyeo`). It mints content-addressed ops carrying an
//! opaque `sealing` payload, packages the trust anchor, and resolves an anchor to a [`MembershipView`] plus
//! the effective ops' sealing payloads for the vault's sealing fold.
//!
//! The anchor is the same trust state the keyless [`crate::verifier`] uses — pinned founding config + the
//! op closure — plus the pinned **genesis op id** (the sealing fold's root: the genesis `Create` is
//! resolver-inert per OPE-271, so it is pinned to always contribute its sealing).

use std::collections::{HashMap, HashSet};

use keyeo::{Keyeo, MembershipAction, StrongRemove};
use openom_keyring_seam::MembershipView;
use serde::{Deserialize, Serialize};

use crate::blob_sync::{decode_op, dto_to_minit, encode_op, minit_to_dto, MemberInitDto};
use crate::verifier::view_of;
use crate::{
    KeyringAccess, KeyringAction, KeyringMemberInit, KeyringOp, KeyringRole, KeyringState,
};

/// Mint an op with `action` + `sealing`, parented on the current frontier and signed by `signing_key`,
/// and append it to the anchor. The shared core of every `append_*` (Add / ReFound / Retarget).
fn append(
    anchor_bytes: &[u8],
    author: &str,
    action: KeyringAction,
    sealing: Vec<u8>,
    signing_key: &openom_sign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let mut anchor: DagAnchor =
        serde_json::from_slice(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let ops: Vec<KeyringOp> = anchor
        .ops
        .iter()
        .map(|b| decode_op(b))
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))?;
    let op = mint(frontier(&ops), author.to_string(), action, sealing, signing_key);
    anchor.ops.push(encode_op(&op));
    Ok(serde_json::to_vec(&anchor).expect("DagAnchor serialization is infallible"))
}

/// Append an **Add** op — an authorized signer (`author`) adds `member_id` at `role`, carrying the
/// joiner's per-epoch DEK wraps in `sealing`. Signed by the author's current key.
#[allow(clippy::too_many_arguments)]
pub fn append_add(
    anchor_bytes: &[u8],
    author: &str,
    member_id: &str,
    role: KeyringRole,
    new_author_public_key: [u8; 32],
    new_hpke_public_key: [u8; 32],
    sealing: Vec<u8>,
    author_signing_key: &openom_sign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::Add {
        member: member_id.to_string(),
        role,
        author_public_key: new_author_public_key,
        hpke_public_key: new_hpke_public_key,
        member_proof: None,
    };
    append(anchor_bytes, author, action, sealing, author_signing_key)
}

/// Append a **Remove** op — an authorized signer (`author`) removes `member_id`, carrying the
/// forward-secret re-epoch (a fresh DEK wrapped only to the remaining members) in `sealing`. Signed by the
/// author's current key.
pub fn append_remove(
    anchor_bytes: &[u8],
    author: &str,
    member_id: &str,
    sealing: Vec<u8>,
    author_signing_key: &openom_sign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::Remove {
        member: member_id.to_string(),
    };
    append(anchor_bytes, author, action, sealing, author_signing_key)
}

/// A client-side failure resolving or minting against the dag keyring.
#[derive(Debug)]
pub enum ClientError {
    /// The anchor bytes / an op blob wouldn't decode.
    Malformed(String),
    /// A stored op was rejected replaying onto a fresh engine (corrupt/tampered anchor, not a new refusal).
    Engine(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Malformed(m) => write!(f, "malformed dag anchor: {m}"),
            ClientError::Engine(m) => write!(f, "dag anchor replay rejected: {m}"),
        }
    }
}
impl std::error::Error for ClientError {}

/// The client trust anchor: the pinned founding config + the pinned genesis op id + the op closure. The
/// vault persists + publishes it opaquely; only this module reads it.
#[derive(Serialize, Deserialize)]
struct DagAnchor {
    genesis: Vec<MemberInitDto>,
    reset_authority: Option<[u8; 32]>,
    genesis_op_id: [u8; 32],
    ops: Vec<Vec<u8>>,
}

/// Mint a signed, content-addressed op carrying an opaque `sealing` payload, using openom's `OpenomSign`
/// scheme (keyeo's `Op::content_addressed` is Ed25519/`ContentId`-specific; openom's `KeyringOp` uses
/// `[u8; 32]` ids + `OpenomSign`, so we derive the content id via the generic `keyeo::content_id`).
fn mint(
    parents: Vec<[u8; 32]>,
    author: String,
    action: KeyringAction,
    sealing: Vec<u8>,
    signing_key: &openom_sign::SigningKey,
) -> KeyringOp {
    let canonical = keyeo::canonical_encode(&parents, &author, &action, &sealing);
    let signature = signing_key.sign(&canonical).to_bytes();
    let author_public_key = signing_key.verifying_key().to_bytes();
    let id = keyeo::content_id(&parents, &author, &action, &sealing, &signature, &author_public_key).0;
    let mut op = KeyringOp::new(id, parents, author, action, signature, author_public_key);
    op.sealing = sealing;
    op
}

/// Create a brand-new dag keyring anchor: a content-addressed genesis `Create` op naming `founder_id` as
/// the sole Owner, carrying the opaque `sealing` payload (the vault's epoch-0 + recovery escrow), with the
/// recovery authority (RVK) pinned. Returns the serialized anchor bytes.
pub fn provision_anchor(
    founder_id: &str,
    author_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    reset_authority: [u8; 32],
    sealing: Vec<u8>,
    signing_key: &openom_sign::SigningKey,
) -> Vec<u8> {
    let founder = KeyringMemberInit {
        id: founder_id.to_string(),
        role: KeyringRole::OWNER,
        author_public_key,
        hpke_public_key,
    };
    let action = MembershipAction::Create {
        initial_members: vec![founder.clone()],
    };
    let op = mint(vec![], founder_id.to_string(), action, sealing, signing_key);
    let anchor = DagAnchor {
        genesis: vec![minit_to_dto(&founder)],
        reset_authority: Some(reset_authority),
        genesis_op_id: op.id,
        ops: vec![encode_op(&op)],
    };
    serde_json::to_vec(&anchor).expect("DagAnchor serialization is infallible")
}

/// A resolved dag keyring: the membership view + the effective ops' `sealing` payloads (genesis-first) for
/// the vault's sealing fold.
pub struct Resolved {
    pub members: MembershipView,
    /// The sealing payloads of the effective ops, in fold order (the pinned genesis op first). The vault
    /// deserializes + folds these into the current epochs + escrow.
    pub sealing: Vec<Vec<u8>>,
}

/// Resolve an anchor: rebuild the engine from the pinned config, replay the op closure, and return the
/// membership view + the effective ops' sealing (in fold order).
///
/// The sealing fold rule (design.dag-vault-anchor.md): the pinned **genesis** op always contributes its
/// sealing (it is resolver-inert per OPE-271 but is the pinned root); every other op contributes iff the
/// engine reports it **effective** ([`Keyeo::effective_ops`]) — not ignored/carve-out-voided, authorized
/// at its causal position, and for a `Commit` its quorum met — folded in resolved topological order.
pub fn resolve(anchor_bytes: &[u8]) -> Result<Resolved, ClientError> {
    let anchor: DagAnchor =
        serde_json::from_slice(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let genesis: Vec<KeyringMemberInit> = anchor
        .genesis
        .iter()
        .map(dto_to_minit)
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))?;
    let base = KeyringState::create(&genesis).with_reset_authority(anchor.reset_authority);
    let mut engine = Keyeo::new(base, KeyringAccess, StrongRemove);
    // Pass 1: decode + replay every op (authorization resolves only once the whole closure is applied).
    let mut ops = Vec::with_capacity(anchor.ops.len());
    for bytes in &anchor.ops {
        let op = decode_op(bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
        ops.push(op.clone());
        engine
            .apply(op)
            .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
    }
    engine
        .flush()
        .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
    let members = view_of(engine.state(), false);
    // Pass 2: fold the sealing of the pinned genesis op (always — it is the resolver-inert root) plus every
    // op the engine reports as EFFECTIVE, in resolved topological order. Using the engine's own
    // `effective_ops` (not a re-derived authorization check) means a carve-out-voided op or an unmet quorum
    // Commit contributes no sealing, and concurrent branches fold in the same order membership resolves.
    let by_id: HashMap<[u8; 32], &KeyringOp> = ops.iter().map(|o| (o.id, o)).collect();
    let genesis_op = by_id.get(&anchor.genesis_op_id).ok_or_else(|| {
        ClientError::Malformed("pinned genesis op not present in the closure".into())
    })?;
    let mut sealing = Vec::new();
    if !genesis_op.sealing.is_empty() {
        sealing.push(genesis_op.sealing.clone());
    }
    for op_id in engine.effective_ops() {
        if op_id == anchor.genesis_op_id {
            continue; // the genesis contributes above; it is inert here anyway
        }
        if let Some(op) = by_id.get(&op_id) {
            if !op.sealing.is_empty() {
                sealing.push(op.sealing.clone());
            }
        }
    }
    Ok(Resolved { members, sealing })
}

/// The DAG frontier: op ids that are no other op's parent (the current tips), sorted for determinism. New
/// ops parent on this; it is also the anti-rollback watermark (OPE-284).
fn frontier(ops: &[KeyringOp]) -> Vec<[u8; 32]> {
    let parents: HashSet<[u8; 32]> = ops.iter().flat_map(|o| o.parents.iter().copied()).collect();
    let mut tips: Vec<[u8; 32]> = ops
        .iter()
        .map(|o| o.id)
        .filter(|id| !parents.contains(id))
        .collect();
    tips.sort_unstable();
    tips
}

/// Append a recovery **ReFound** op — retarget the Owner to new keys, signed by the recovery authority
/// (RVK), carrying the re-escrow in its opaque `sealing` envelope. Parents = the current frontier. Returns
/// the new anchor bytes.
pub fn append_refound(
    anchor_bytes: &[u8],
    owner_id: &str,
    new_author_public_key: [u8; 32],
    new_hpke_public_key: [u8; 32],
    era: u64,
    sealing: Vec<u8>,
    rvk_signing_key: &openom_sign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::ReFound {
        member: owner_id.to_string(),
        new_author_public_key,
        new_hpke_public_key,
        era,
    };
    append(anchor_bytes, owner_id, action, sealing, rvk_signing_key)
}

/// Append a voluntary **Retarget** op — `member` rotates their OWN keys, signed by their CURRENT key
/// (change-passphrase), carrying the re-escrow in its opaque `sealing`. Parents = the current frontier.
/// Returns the new anchor bytes.
pub fn append_retarget(
    anchor_bytes: &[u8],
    member_id: &str,
    new_author_public_key: [u8; 32],
    new_hpke_public_key: [u8; 32],
    sealing: Vec<u8>,
    current_signing_key: &openom_sign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::Retarget {
        member: member_id.to_string(),
        new_author_public_key,
        new_hpke_public_key,
    };
    append(anchor_bytes, member_id, action, sealing, current_signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery;

    fn sk(seed: u8) -> openom_sign::SigningKey {
        openom_sign::SigningKey::from_seed(&[seed; 32])
    }
    fn vk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }
    fn minit(id: &str, role: KeyringRole, seed: u8) -> KeyringMemberInit {
        KeyringMemberInit {
            id: id.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
        }
    }

    /// A privileged op concurrent with a surviving recovery is carve-out-voided — and its SEALING must be
    /// dropped from the fold, not merely its membership effect. Proves resolve() folds over the engine's
    /// `effective_ops` (topo + carve-out + quorum), never mere op presence. (OPE-285.)
    #[test]
    fn a_carve_out_voided_ops_sealing_is_dropped() {
        let founder = minit("founder", KeyringRole::OWNER, 1);
        let bob = minit("bob", KeyringRole::CO_OWNER, 2);
        let rvk = recovery::derive_rvk(&[42u8; 32]);
        let rvk_pub = rvk.verifying_key().to_bytes();

        // Genesis {founder Owner, bob CoOwner}, RVK pinned; carries a genesis sealing.
        let genesis_op = mint(
            vec![],
            "founder".to_string(),
            MembershipAction::Create {
                initial_members: vec![founder.clone(), bob.clone()],
            },
            b"GENESIS-SEALING".to_vec(),
            &sk(1),
        );
        let genesis_id = genesis_op.id;

        // (A) the compromised founder key adds a co-owner (a signer = privileged), concurrent with (B) an
        // RVK-signed recovery ReFound. Both are children of genesis. Each carries a sealing delta.
        let thief = mint(
            vec![genesis_id],
            "founder".to_string(),
            MembershipAction::Add {
                member: "mallory".to_string(),
                role: KeyringRole::CO_OWNER,
                author_public_key: vk(9),
                hpke_public_key: [9; 32],
                member_proof: None,
            },
            b"THIEF-SEALING".to_vec(),
            &sk(1),
        );
        let recovery_op = mint(
            vec![genesis_id],
            "founder".to_string(),
            MembershipAction::ReFound {
                member: "founder".to_string(),
                new_author_public_key: vk(7),
                new_hpke_public_key: [7; 32],
                era: 1,
            },
            b"RECOVERY-SEALING".to_vec(),
            &rvk,
        );

        let anchor = DagAnchor {
            genesis: vec![minit_to_dto(&founder), minit_to_dto(&bob)],
            reset_authority: Some(rvk_pub),
            genesis_op_id: genesis_id,
            ops: vec![
                encode_op(&genesis_op),
                encode_op(&thief),
                encode_op(&recovery_op),
            ],
        };
        let resolved = resolve(&serde_json::to_vec(&anchor).unwrap()).unwrap();

        let has = |needle: &[u8]| resolved.sealing.iter().any(|s| s.as_slice() == needle);
        assert!(has(b"GENESIS-SEALING"), "the pinned genesis op always contributes");
        assert!(has(b"RECOVERY-SEALING"), "the surviving recovery contributes");
        assert!(
            !has(b"THIEF-SEALING"),
            "a carve-out-voided op's sealing is dropped, not folded"
        );
        assert!(
            !resolved.members.members.iter().any(|m| m.member_id == "mallory"),
            "and the voided op has no membership effect either"
        );
    }
}
