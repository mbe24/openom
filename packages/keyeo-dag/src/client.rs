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
use keyeo_api::MembershipView;
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
    signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let mut anchor: DagAnchor =
        serde_json::from_slice(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let ops: Vec<KeyringOp> = anchor
        .ops
        .iter()
        .map(|b| decode_op(b))
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))?;
    let group_id = keyeo::GroupId::new(anchor.group_id.clone());
    let op = mint(&group_id, frontier(&ops), author.to_string(), action, sealing, signing_key);
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
    author_signing_key: &edsign::SigningKey,
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
    author_signing_key: &edsign::SigningKey,
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
    /// The served anchor is behind the caller's anti-rollback watermark: a previously-seen frontier op-id
    /// is absent from its op set, so history was rolled back (a stale or equivocating anchor).
    RolledBack(String),
    /// The opaque `floor` handed to [`check_floor`] isn't a valid watermark encoding (length not a multiple
    /// of 32). Client-local corruption, refused rather than silently dropped (dropping it drops protection).
    BadWatermark(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Malformed(m) => write!(f, "malformed dag anchor: {m}"),
            ClientError::Engine(m) => write!(f, "dag anchor replay rejected: {m}"),
            ClientError::RolledBack(m) => write!(f, "dag anchor rolled back below watermark: {m}"),
            ClientError::BadWatermark(m) => write!(f, "malformed anti-rollback watermark: {m}"),
        }
    }
}
impl std::error::Error for ClientError {}

/// The client trust anchor: the pinned founding config + the pinned genesis op id + the op closure. The
/// vault persists + publishes it opaquely; only this module reads it.
#[derive(Serialize, Deserialize)]
struct DagAnchor {
    /// The group (openom: the tree) id every op in this anchor is bound to, pinned at provision. It is the
    /// value the engine's genesis is scoped to on resolve, and the id every appended op carries — so an op
    /// minted for a different tree is refused (`keyeo::Error::WrongGroup`). A hint the SIGNED ops must
    /// agree with: tampering it makes resolution fail closed, since the signed ops won't match.
    group_id: Vec<u8>,
    genesis: Vec<MemberInitDto>,
    reset_authority: Option<[u8; 32]>,
    genesis_op_id: [u8; 32],
    ops: Vec<Vec<u8>>,
}

/// Mint a signed, content-addressed op carrying an opaque `sealing` payload, using openom's `OpenomSign`
/// scheme (keyeo's `Op::content_addressed` is Ed25519/`ContentId`-specific; openom's `KeyringOp` uses
/// `[u8; 32]` ids + `OpenomSign`, so we derive the content id via the generic `keyeo::content_id`).
fn mint(
    group_id: &keyeo::GroupId,
    parents: Vec<[u8; 32]>,
    author: String,
    action: KeyringAction,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> KeyringOp {
    let canonical = keyeo::canonical_encode(group_id, &parents, &author, &action, &sealing);
    let signature = signing_key.sign(&canonical).to_bytes();
    let author_public_key = signing_key.verifying_key().to_bytes();
    let id =
        keyeo::content_id(group_id, &parents, &author, &action, &sealing, &signature, &author_public_key).0;
    let mut op = KeyringOp::new(id, group_id.clone(), parents, author, action, signature, author_public_key);
    op.sealing = sealing;
    op
}

/// Create a brand-new dag keyring anchor: a content-addressed genesis `Create` op naming `founder_id` as
/// the sole Owner, carrying the opaque `sealing` payload (the vault's epoch-0 + recovery escrow), with the
/// recovery authority (RVK) pinned. Returns the serialized anchor bytes.
#[allow(clippy::too_many_arguments)]
pub fn provision_anchor(
    tree_id: &[u8],
    founder_id: &str,
    author_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    reset_authority: [u8; 32],
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Vec<u8> {
    let group_id = keyeo::GroupId::new(tree_id.to_vec());
    let founder = KeyringMemberInit {
        id: founder_id.to_string(),
        role: KeyringRole::OWNER,
        author_public_key,
        hpke_public_key,
    };
    let action = MembershipAction::Create {
        initial_members: vec![founder.clone()],
    };
    let op = mint(&group_id, vec![], founder_id.to_string(), action, sealing, signing_key);
    let anchor = DagAnchor {
        group_id: tree_id.to_vec(),
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
    /// The sealing payloads of the effective ops, in fold order (the pinned genesis op first), each tagged
    /// with the id of the op that minted it. The vault deserializes + folds these into the current epochs +
    /// escrow, and uses the op-id to break concurrent same-ordinal epoch ties deterministically (OPE-282).
    pub sealing: Vec<SealingEntry>,
}

/// One effective op's opaque `sealing` payload, tagged with the content-addressed id of the op that minted
/// it and the coarse kind of that op. The op-id is the deterministic winner tiebreak for concurrent
/// same-ordinal epochs; it is attached here, at resolve time, because it cannot live inside the sealing —
/// the op-id is a hash *of* the sealing. The origin lets the sealer's fold decide which epochs may win the
/// write epoch WITHOUT keyeo ever interpreting the sealing.
pub struct SealingEntry {
    pub op_id: [u8; 32],
    pub origin: SealingOrigin,
    pub bytes: Vec<u8>,
}

/// The coarse kind of the op that minted a sealing payload. Only Genesis, Remove, and Reseal ops
/// legitimately mint a NEW epoch (Genesis: epoch 0; Remove / Reseal: a forward-secret re-epoch); an epoch
/// carried by any `Other` op (e.g. an Add's joiner wraps, or a Retarget's re-escrow) is anomalous and the
/// sealer's fold refuses to let it win the write epoch. The facade maps the keyeo action to this — keyeo
/// itself never sees the sealing (invariant).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealingOrigin {
    Genesis,
    Remove,
    Reseal,
    Other,
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
    let base = KeyringState::create(keyeo::GroupId::new(anchor.group_id.clone()), &genesis)
        .with_reset_authority(anchor.reset_authority);
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
        sealing.push(SealingEntry {
            op_id: anchor.genesis_op_id,
            origin: SealingOrigin::Genesis,
            bytes: genesis_op.sealing.clone(),
        });
    }
    for op_id in engine.effective_ops() {
        if op_id == anchor.genesis_op_id {
            continue; // the genesis contributes above; it is inert here anyway
        }
        if let Some(op) = by_id.get(&op_id) {
            if !op.sealing.is_empty() {
                sealing.push(SealingEntry {
                    op_id,
                    origin: origin_of(&op.action),
                    bytes: op.sealing.clone(),
                });
            }
        }
    }
    Ok(Resolved { members, sealing })
}

/// Map a keyeo action to the coarse [`SealingOrigin`] the sealer's fold uses to decide epoch eligibility.
/// Only Remove (and, once it lands, Reseal) legitimately mints a forward-secret epoch outside genesis; the
/// genesis Create is tagged [`SealingOrigin::Genesis`] at its own (pinned) call site, so a Create here is an
/// (inert) non-genesis op and counts as `Other`.
fn origin_of(action: &KeyringAction) -> SealingOrigin {
    match action {
        MembershipAction::Remove { .. } => SealingOrigin::Remove,
        MembershipAction::Reseal => SealingOrigin::Reseal,
        _ => SealingOrigin::Other,
    }
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

/// Decode an anchor's op closure (shared by [`watermark`] and [`check_floor`]).
fn anchor_ops(anchor_bytes: &[u8]) -> Result<Vec<KeyringOp>, ClientError> {
    let anchor: DagAnchor =
        serde_json::from_slice(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    anchor
        .ops
        .iter()
        .map(|b| decode_op(b))
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))
}

/// The anchor's opaque anti-rollback **watermark**: its frontier (sorted tip op-ids) concatenated as raw
/// 32-byte ids. Deterministic — equal frontiers give equal bytes — so the caller persists it and passes it
/// back as the `floor` on the next mutating flow. The sealer treats these bytes as opaque (guardrail #1).
pub fn watermark(anchor_bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
    let ops = anchor_ops(anchor_bytes)?;
    Ok(frontier(&ops).into_iter().flatten().collect())
}

/// Enforce the caller's anti-rollback `floor` (a watermark previously emitted by [`watermark`]) against a
/// served anchor: every frontier op-id it names must still be present in the anchor's (append-only,
/// causally-closed) op set. A missing one means the anchor dropped history — [`ClientError::RolledBack`].
/// An empty floor is "no floor" (Ok); a floor whose length isn't a multiple of 32 is a corrupt watermark
/// and is refused ([`ClientError::Malformed`]) rather than silently ignored — dropping it would drop
/// rollback protection.
pub fn check_floor(anchor_bytes: &[u8], floor: &[u8]) -> Result<(), ClientError> {
    if floor.is_empty() {
        return Ok(());
    }
    if floor.len() % 32 != 0 {
        return Err(ClientError::BadWatermark(format!(
            "length {} is not a multiple of 32",
            floor.len()
        )));
    }
    let present: HashSet<[u8; 32]> = anchor_ops(anchor_bytes)?.iter().map(|o| o.id).collect();
    for chunk in floor.chunks_exact(32) {
        let id: [u8; 32] = chunk.try_into().expect("chunks_exact(32) yields 32 bytes");
        if !present.contains(&id) {
            return Err(ClientError::RolledBack(format!(
                "frontier op {} is absent from the served anchor",
                hex32(&id)
            )));
        }
    }
    Ok(())
}

/// First 8 bytes of an op-id, hex, for error messages (full id is 32 bytes).
fn hex32(id: &[u8; 32]) -> String {
    id[..8].iter().map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

/// Merge two anchors of the same tree into their causal union — the op closures unioned, deduplicated by
/// op-id, keeping `a`'s pinned genesis config. Concurrent branches both survive and resolve deterministically
/// (the op-DAG is a set-union CRDT). A direct convenience over the store-based anti-entropy in `blob_sync`.
pub fn merge(anchor_a: &[u8], anchor_b: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut a: DagAnchor =
        serde_json::from_slice(anchor_a).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let b: DagAnchor =
        serde_json::from_slice(anchor_b).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let mut seen: HashSet<[u8; 32]> = anchor_ops(anchor_a)?.iter().map(|o| o.id).collect();
    for (blob, op) in b.ops.iter().zip(anchor_ops(anchor_b)?) {
        if seen.insert(op.id) {
            a.ops.push(blob.clone());
        }
    }
    Ok(serde_json::to_vec(&a).expect("DagAnchor serialization is infallible"))
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
    rvk_signing_key: &edsign::SigningKey,
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
    current_signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::Retarget {
        member: member_id.to_string(),
        new_author_public_key,
        new_hpke_public_key,
    };
    append(anchor_bytes, member_id, action, sealing, current_signing_key)
}

/// Append a **Reseal** op (OPE-282) — a membership-inert forward-secrecy repair authored by active
/// `member_id`, carrying a fresh DEK epoch (wrapped to the resolved membership) in its opaque `sealing`.
/// Parents = the current frontier. Signed by the author's current key. Returns the new anchor bytes.
pub fn append_reseal(
    anchor_bytes: &[u8],
    member_id: &str,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    append(anchor_bytes, member_id, MembershipAction::Reseal, sealing, signing_key)
}

/// Append a **Backfill** op (OPE-288) — a membership-inert HISTORICAL-READ repair authored by `member_id`,
/// carrying ONLY `added_wraps` (the missing member wraps for existing epochs) in its opaque `sealing`, no new
/// epoch. It reuses the inert `Reseal` keyeo action: keyeo sees only an authored, membership-inert op, and
/// what the sealing actually does — add wraps vs mint an epoch — is the sealer's concern, invisible to keyeo
/// (the sealing invariant). Parents = the current frontier. Returns the new anchor bytes.
pub fn append_backfill(
    anchor_bytes: &[u8],
    member_id: &str,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    append(anchor_bytes, member_id, MembershipAction::Reseal, sealing, signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery;

    fn sk(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
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
        let genesis_op = mint(&keyeo::GroupId::unscoped(),
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
        let thief = mint(&keyeo::GroupId::unscoped(),
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
        let recovery_op = mint(&keyeo::GroupId::unscoped(),
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
            group_id: Vec::new(),
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

        let has = |needle: &[u8]| resolved.sealing.iter().any(|s| s.bytes.as_slice() == needle);
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

    /// The watermark is the frontier op-id set, and check_floor is causal-descendant containment: an
    /// advanced anchor still satisfies an older floor (the old tip remains an ancestor), while a stale
    /// anchor fails a newer floor (the advanced tip is absent). Empty = no floor; a non-32-multiple = bad.
    #[test]
    fn watermark_advances_and_check_floor_catches_rollback() {
        let a0 = provision_anchor(b"tree-1", "founder", vk(1), [1; 32], vk(3), b"seal".to_vec(), &sk(1));
        let w0 = watermark(&a0).unwrap();
        assert_eq!(w0.len(), 32, "a single tip (the genesis op) encodes to 32 bytes");
        assert!(check_floor(&a0, &w0).is_ok(), "the current frontier satisfies its own floor");
        assert!(check_floor(&a0, &[]).is_ok(), "an empty floor is no floor");
        assert!(
            matches!(check_floor(&a0, &[1, 2, 3]), Err(ClientError::BadWatermark(_))),
            "a floor whose length isn't a multiple of 32 is refused"
        );

        // Append an Add — an authorized owner adds a co-owner; the frontier moves to the new op.
        let a1 = append_add(
            &a0, "founder", "bob", KeyringRole::CO_OWNER, vk(2), [2; 32], b"wrap".to_vec(), &sk(1),
        )
        .unwrap();
        let w1 = watermark(&a1).unwrap();
        assert_ne!(w1, w0, "the watermark advances when the frontier moves");
        assert!(
            check_floor(&a1, &w0).is_ok(),
            "the old tip is still an ancestor in the advanced anchor"
        );
        assert!(
            matches!(check_floor(&a0, &w1), Err(ClientError::RolledBack(_))),
            "the advanced tip is absent from the stale anchor — a rollback"
        );
    }
}
