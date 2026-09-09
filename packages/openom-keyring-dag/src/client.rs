//! The DAG keyring's **client facade** (OPE-273).
//!
//! the secret-adjacent surface the vault (`openom-sealer`'s
//! `dag_vault.rs`) drives, so the vault never touches `keyeo` or this crate's op types directly (a
//! one-line import grep keeps `dag_vault.rs` free of `keyeo`).
//!
//! It mints content-addressed ops carrying an
//! opaque `sealing` payload, packages the trust anchor, and resolves an anchor to a [`MembershipView`] plus
//! the effective ops' sealing payloads for the vault's sealing fold.
//!
//! The anchor is the same trust state the keyless [`crate::verifier`] uses — pinned founding config + the
//! op closure — plus the pinned **genesis op id** (the sealing fold's root: the genesis `Create` is
//! resolver-inert per OPE-271, so it is pinned to always contribute its sealing).

use std::collections::{HashMap, HashSet};

use keyeo_dag::{
    Compacted, Compaction, Ed25519, Frontier, Keyeo, MembershipAction, Retained, RetentionPlan,
    StrongRemove,
};
use openom_keyring_api::MembershipView;
use serde::{Deserialize, Serialize};

use crate::blob_sync::{decode_op, dto_to_minit, encode_op, minit_to_dto, MemberInitDto};
use crate::verifier::view_of;
use crate::{
    KeyringAccess, KeyringAction, KeyringMemberInit, KeyringOp, KeyringRole, KeyringState,
};

/// Mint an op with `action` + `sealing`, parented on the current frontier and signed by `signing_key`,
/// and append it to the anchor. The shared core of every `append_*` (Add / `ReFound` / Retarget).
fn append(
    anchor_bytes: &[u8],
    author: &str,
    action: KeyringAction,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let mut anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let ops: Vec<KeyringOp> = anchor
        .ops
        .iter()
        .map(|b| decode_op(b))
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))?;
    let group_id = keyeo_dag::GroupId::new(anchor.group_id.clone());
    let op = mint(
        &group_id,
        frontier(&ops),
        author.to_string(),
        action,
        sealing,
        signing_key,
    );
    anchor.ops.push(encode_op(&op));
    Ok(postcard::to_allocvec(&anchor).expect("DagAnchor serialization is infallible"))
}

/// Append an **Add** op — an authorized signer (`author`) adds `member` (id + role + carried signing/HPKE
/// keys) carrying the joiner's per-epoch DEK wraps in `sealing`.
///
/// Signed by the author's current key.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn append_add(
    anchor_bytes: &[u8],
    author: &str,
    member: &KeyringMemberInit,
    sealing: Vec<u8>,
    author_signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::Add {
        member: member.id.clone(),
        role: member.role,
        author_public_key: member.author_public_key,
        hpke_public_key: member.hpke_public_key,
        member_proof: None,
    };
    append(anchor_bytes, author, action, sealing, author_signing_key)
}

/// Append a **Remove** op — an authorized signer (`author`) removes `member_id`, carrying the
/// forward-secret re-epoch (a fresh DEK wrapped only to the remaining members) in `sealing`.
///
/// Signed by the
/// author's current key.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
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
            Self::Malformed(m) => write!(f, "malformed dag anchor: {m}"),
            Self::Engine(m) => write!(f, "dag anchor replay rejected: {m}"),
            Self::RolledBack(m) => write!(f, "dag anchor rolled back below watermark: {m}"),
            Self::BadWatermark(m) => write!(f, "malformed anti-rollback watermark: {m}"),
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
    /// minted for a different tree is refused (`keyeo_dag::Error::WrongGroup`). A hint the SIGNED ops must
    /// agree with: tampering it makes resolution fail closed, since the signed ops won't match.
    group_id: Vec<u8>,
    genesis: Vec<MemberInitDto>,
    reset_authority: Option<[u8; 32]>,
    genesis_op_id: [u8; 32],
    ops: Vec<Vec<u8>>,
    /// A compaction checkpoint (OPE-348 step 2a): when present, the ops below its frontier are pruned and this
    /// signed checkpoint stands in for them — `resolve()` adopts its membership base + resumes the sealing fold
    /// from its preserved epochs instead of walking the pinned genesis. `None` for an un-compacted anchor.
    #[serde(default)]
    checkpoint: Option<crate::checkpoint::SignedCheckpoint>,
}

/// Mint a signed, content-addressed op carrying an opaque `sealing` payload, using keyeo's unified
/// `Ed25519` scheme (keyeo's `Op::content_addressed` is `ContentId`-specific; openom's `KeyringOp` uses
/// `[u8; 32]` ids + `Ed25519`, so we derive the content id via the generic `keyeo_dag::content_id`).
fn mint(
    group_id: &keyeo_dag::GroupId,
    parents: Vec<[u8; 32]>,
    author: String,
    action: KeyringAction,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> KeyringOp {
    let canonical = keyeo_dag::canonical_encode(group_id, &parents, &author, &action, &sealing);
    let signature = signing_key.sign(&canonical).to_bytes();
    let author_public_key = signing_key.verifying_key().to_bytes();
    let id = keyeo_dag::content_id(
        group_id,
        &parents,
        &author,
        &action,
        &sealing,
        &signature,
        &author_public_key,
    )
    .0;
    let mut op = KeyringOp::new(
        id,
        group_id.clone(),
        parents,
        author,
        action,
        signature,
        author_public_key,
    );
    op.sealing = sealing;
    op
}

/// Create a brand-new dag keyring anchor.
///
/// a content-addressed genesis `Create` op naming `founder_id` as
/// the sole Owner, carrying the opaque `sealing` payload (the vault's epoch-0 + recovery escrow), with the
/// recovery authority (RVK) pinned.
///
/// Returns the serialized anchor bytes.
///
/// # Panics
/// Never in practice: a freshly-built `DagAnchor` always serializes.
#[must_use]
pub fn provision_anchor(
    tree_id: &[u8],
    founder_id: &str,
    author_public_key: edsign::VerifyingKey,
    hpke_public_key: keyeo_wrap::X25519PublicKey,
    reset_authority: [u8; 32],
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Vec<u8> {
    let group_id = keyeo_dag::GroupId::new(tree_id.to_vec());
    let founder = KeyringMemberInit {
        id: founder_id.to_string(),
        role: KeyringRole::OWNER,
        // Both keys are typed and DISTINCT (`VerifyingKey` / `X25519PublicKey`), so a transposition is a
        // compile error; each is narrowed to keyeo's raw `[u8; 32]` here at the engine boundary.
        author_public_key: author_public_key.to_bytes(),
        hpke_public_key: hpke_public_key.to_bytes(),
    };
    let action = MembershipAction::Create {
        initial_members: vec![founder.clone()],
    };
    let op = mint(
        &group_id,
        vec![],
        founder_id.to_string(),
        action,
        sealing,
        signing_key,
    );
    let anchor = DagAnchor {
        group_id: tree_id.to_vec(),
        genesis: vec![minit_to_dto(&founder)],
        reset_authority: Some(reset_authority),
        genesis_op_id: op.id,
        ops: vec![encode_op(&op)],
        checkpoint: None,
    };
    postcard::to_allocvec(&anchor).expect("DagAnchor serialization is infallible")
}

/// A resolved dag keyring: the membership view + the effective ops' `sealing` payloads (genesis-first) for
/// the vault's sealing fold.
pub struct Resolved {
    pub members: MembershipView,
    /// The sealing payloads of the effective ops, in fold order (the pinned genesis op first), each tagged
    /// with the id of the op that minted it. The vault deserializes + folds these into the current epochs +
    /// escrow, and uses the op-id to break concurrent same-ordinal epoch ties deterministically (OPE-282).
    pub sealing: Vec<SealingEntry>,
    /// Whether this tree HAS EVER been shared (any effective Add) — the dag's monotonic attributed-writes
    /// gate, the analog of the chain's `first_shared_revision != 0`. Never regresses after an un-share.
    pub has_been_shared: bool,
    /// On a CHECKPOINT anchor: the checkpoint's preserved sealing entries (retained epochs + escrow), folded
    /// BEFORE `sealing` and WITHOUT counting their mints (already in `minting_ops_baseline`). `None` on an
    /// un-compacted anchor. The vault picks `fold_from_checkpoint` vs `fold_sealing` on this.
    pub checkpoint_sealing: Option<Vec<SealingEntry>>,
    /// The checkpoint's minting-op baseline (0 on an un-compacted anchor) — seeds the OPE-289 count.
    pub minting_ops_baseline: u32,
    /// The members EVER legitimately admitted (id → their author public key) — the genesis founder plus every
    /// member whose `Add` op is EFFECTIVE (authorized at its causal position), INCLUDING members later removed
    /// (a `Remove` is a separate op; it doesn't un-effect the `Add`). It EXCLUDES a carve-out-voided `Add` (a
    /// key-thief neutralized by a `ReFound` recovery — that Add is not effective). The self-heal (OPE-382)
    /// uses this two ways: the READER (pin P6) covered-accepts a data entry only if its author is here, so a
    /// voided thief's entries are never blessed; the WRITER binds the author's key into the cover it mints.
    pub ever_members: std::collections::BTreeMap<String, Vec<u8>>,
}

/// One effective op's opaque `sealing` payload, tagged with the content-addressed id of the op that minted
/// it and the coarse kind of that op.
///
/// The op-id is the deterministic winner tiebreak for concurrent
/// same-ordinal epochs; it is attached here, at resolve time, because it cannot live inside the sealing —
/// the op-id is a hash *of* the sealing. The origin lets the sealer's fold decide which epochs may win the
/// write epoch WITHOUT keyeo ever interpreting the sealing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealingEntry {
    pub op_id: [u8; 32],
    pub origin: SealingOrigin,
    pub bytes: Vec<u8>,
}

/// The coarse kind of the op that minted a sealing payload.
///
/// Only Genesis, Remove, and Reseal ops
/// legitimately mint a NEW epoch (Genesis: epoch 0; Remove / Reseal: a forward-secret re-epoch); an epoch
/// carried by any `Other` op (e.g. an Add's joiner wraps, or a Retarget's re-escrow) is anomalous and the
/// sealer's fold refuses to let it win the write epoch. The facade maps the keyeo action to this — keyeo
/// itself never sees the sealing (invariant).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
///
/// # Errors
/// Returns [`ClientError`] if the anchor is malformed, a stored op is rejected on replay, or history
/// rolled back below the caller's watermark.
pub fn resolve(anchor_bytes: &[u8]) -> Result<Resolved, ClientError> {
    let anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    // Build the engine: from an adopted CHECKPOINT base (its pre-frontier history pruned), or from the pinned
    // genesis. Both arms produce the same engine type (Individual governance).
    let (mut engine, checkpoint_sealing, minting_ops_baseline) = if let Some(signed_cp) =
        &anchor.checkpoint
    {
        let cp = signed_cp
            .verify()
            .ok_or_else(|| ClientError::Malformed("checkpoint signature does not verify".into()))?;
        let base = cp.state.clone().into_state(
            keyeo_dag::GroupId::new(anchor.group_id.clone()),
            anchor.reset_authority,
        );
        let base_frontier_depths: HashMap<[u8; 32], usize> = cp
            .frontier_depths
            .iter()
            // A depth past usize::MAX (only reachable on a 32-bit target) saturates — it stays an upper bound.
            .map(|(id, d)| (*id, usize::try_from(*d).unwrap_or(usize::MAX)))
            .collect();
        let engine = Keyeo::adopt(
            base,
            base_frontier_depths,
            cp.has_been_shared,
            KeyringAccess,
            StrongRemove,
            keyeo_dag::Individual,
        );
        (engine, Some(cp.sealing.clone()), cp.minting_ops_baseline)
    } else {
        let genesis: Vec<KeyringMemberInit> = anchor.genesis.iter().map(dto_to_minit).collect();
        let base = KeyringState::create(keyeo_dag::GroupId::new(anchor.group_id.clone()), &genesis)
            .with_reset_authority(anchor.reset_authority);
        (Keyeo::new(base, KeyringAccess, StrongRemove), None, 0)
    };
    // Pass 1: decode + replay every op (authorization resolves only once the whole closure is applied).
    let mut ops = Vec::with_capacity(anchor.ops.len());
    for bytes in &anchor.ops {
        let op = decode_op(bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
        // Content-integrity (H2): the op's id MUST be the content-address of its fields. keyeo's `apply`
        // authenticates the signature but keys the DAG by the SELF-DECLARED id and never checks it — so a
        // validly-signed op could be relabeled, forging the Merkle identity the genesis-op pin + the
        // watermark/`check_floor` anti-rollback rest on. Enforce it here, fail-closed, so any anchor that
        // resolves has content-addressed ids.
        if !crate::blob_sync::content_id_matches(&op) {
            return Err(ClientError::Malformed("op id does not match its content (relabeled op)".into()));
        }
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
    let mut sealing = Vec::new();
    // The pinned genesis op contributes its sealing ONLY on an un-compacted anchor. On a checkpoint anchor the
    // genesis is pruned and its epoch-0 + escrow ride the checkpoint segment (`checkpoint_sealing`) instead —
    // so both the genesis-presence check and the genesis fold are suppressed here.
    if anchor.checkpoint.is_none() {
        let genesis_op = by_id.get(&anchor.genesis_op_id).ok_or_else(|| {
            ClientError::Malformed("pinned genesis op not present in the closure".into())
        })?;
        if !genesis_op.sealing.is_empty() {
            sealing.push(SealingEntry {
                op_id: anchor.genesis_op_id,
                origin: SealingOrigin::Genesis,
                bytes: genesis_op.sealing.clone(),
            });
        }
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
    let has_been_shared = engine.has_been_shared();
    // The ever-legitimately-a-member set (pin P6): the current members (founder + non-removed) plus every
    // member whose Add is effective — which INCLUDES removed members (an effective Add survives a Remove) but
    // NOT carve-out-voided Adds (they aren't effective). So a legitimately-removed member's history can be
    // covered-accepted, while a voided thief's cannot.
    let ever_members = collect_ever_members(&members, engine.effective_ops(), &by_id);
    Ok(Resolved {
        members,
        sealing,
        has_been_shared,
        checkpoint_sealing,
        minting_ops_baseline,
        ever_members,
    })
}

/// The OOB trust pin a joining dag member binds to (the dag analog of the chain invite `(revision, hash)`):
/// the content-addressed **genesis op id** (authenticates the founder + genesis config — see H1/H2 below),
/// the pinned **recovery authority**, and an invite-time **frontier watermark** (the freshness floor — H4).
/// The owner mints it at invite time via [`anchor_pin`]; the joiner hands it to [`verify_anchor`]. All three
/// travel out-of-band; a compromised server cannot forge any of them.
#[derive(Clone, Serialize, Deserialize)]
pub struct DagPin {
    /// The content-address of the genesis `Create` op — a collision-resistant hash over the founder key +
    /// genesis members + signature. Invariant across every later membership change.
    pub genesis_op_id: [u8; 32],
    /// The pinned recovery authority (RVK). NOT covered by `genesis_op_id` (the signed `Create` carries no
    /// RVK), so it must be pinned + checked separately (H1).
    pub reset_authority: Option<[u8; 32]>,
    /// The frontier watermark at invite time — the freshness floor the join enforces so a server can't serve
    /// an older valid subset (e.g. omit a `Remove` so a removed member reads as active) (H4).
    pub watermark: Vec<u8>,
}

impl DagPin {
    /// Serialize the pin for the out-of-band channel (opaque to the caller).
    ///
    /// # Panics
    /// Never in practice: a `DagPin` (two fixed arrays + a byte vec) always serializes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("DagPin serialization is infallible")
    }

    /// Parse an out-of-band pin.
    ///
    /// # Errors
    /// Returns [`ClientError::Malformed`] if the bytes are not a valid encoded pin.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        postcard::from_bytes(bytes).map_err(|e| ClientError::Malformed(e.to_string()))
    }
}

/// Mint the OOB [`DagPin`] for the CURRENT anchor (the owner does this at invite time).
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn anchor_pin(anchor_bytes: &[u8]) -> Result<DagPin, ClientError> {
    let anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    Ok(DagPin {
        genesis_op_id: anchor.genesis_op_id,
        reset_authority: anchor.reset_authority,
        watermark: watermark(anchor_bytes)?,
    })
}

/// Verify an anchor served by an UNTRUSTED network against an OOB [`DagPin`] — the dag analog of the chain
/// genesis-walk (design.dag-distribution.md). Establishes first-sight trust: the served anchor genuinely
/// descends from the pinned founder and is no older than invite time. Fail-closed; the caller unlocks (its
/// own-key anti-substitution) only on `Ok`. Returns the validated [`Resolved`] membership.
///
/// The checks, in order:
/// - **H3** reject a checkpoint anchor (its base is only self-signed, not authority-verified).
/// - group id, pinned genesis op id, and pinned recovery authority all match the pin.
/// - `resolve` — every op's signature + content-id (H2) + group is validated and membership folded; this
///   also confirms the genesis op is present at `genesis_op_id` and content-addresses to it.
/// - **H1** the membership `resolve` actually trusts (the separate `anchor.genesis` DTO, since the in-DAG
///   genesis `Create` is resolver-inert) must EXACTLY equal the pinned genesis op's `Create.initial_members`
///   — else a server pins the real founder op yet seeds a substituted owner via the DTO.
/// - **H4** `check_floor` against the pin's invite-time watermark — no rollback below invite-time state.
///
/// # Errors
/// Returns [`ClientError`] on any failed check (malformed, checkpoint, pin mismatch, DTO mismatch, rollback).
pub fn verify_anchor(anchor_bytes: &[u8], group_id: &[u8], pin: &DagPin) -> Result<Resolved, ClientError> {
    let anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    if anchor.checkpoint.is_some() {
        return Err(ClientError::Malformed(
            "a compacted (checkpoint) anchor is not accepted on an untrusted join/adopt".into(),
        ));
    }
    if anchor.group_id.as_slice() != group_id {
        return Err(ClientError::Malformed("anchor group id does not match the tree".into()));
    }
    if anchor.genesis_op_id != pin.genesis_op_id {
        return Err(ClientError::Malformed("anchor genesis op id does not match the pin".into()));
    }
    if anchor.reset_authority != pin.reset_authority {
        return Err(ClientError::Malformed("anchor recovery authority does not match the pin".into()));
    }
    let resolved = resolve(anchor_bytes)?;
    // H1: bind the DTO membership resolve trusts to the pinned genesis op's own `initial_members`.
    let genesis_op = anchor_ops(anchor_bytes)?
        .into_iter()
        .find(|o| o.id == anchor.genesis_op_id)
        .ok_or_else(|| ClientError::Malformed("pinned genesis op absent from the closure".into()))?;
    let MembershipAction::Create { initial_members } = &genesis_op.action else {
        return Err(ClientError::Malformed("pinned genesis op is not a Create".into()));
    };
    let init_dtos: Vec<_> = initial_members.iter().map(minit_to_dto).collect();
    if anchor.genesis != init_dtos {
        return Err(ClientError::Malformed(
            "anchor genesis membership does not match the pinned genesis op".into(),
        ));
    }
    check_floor(anchor_bytes, &pin.watermark)?;
    Ok(resolved)
}

/// Adopt a newer anchor pulled from an UNTRUSTED network onto a member's local anchor (the sync/adopt path).
/// Re-verifies the remote against the persisted `pin` (founder + recovery authority + group + no checkpoint +
/// H1 DTO binding) with the member's PERSISTED `floor` as the freshness watermark (H4-on-sync), then
/// set-union-`merge`s it onto the local anchor. `merge` keeps the local pinned genesis and never drops a
/// local op, so a server that omitted the member's `Remove` can't re-add a removed member (and `check_floor`
/// rejects the omission outright). Returns the merged anchor bytes; the caller re-`watermark`s + persists.
///
/// # Errors
/// Returns [`ClientError`] on a failed verify (pin mismatch, checkpoint, rollback below `floor`) or a
/// malformed anchor.
pub fn accept_remote_anchor(
    local_bytes: &[u8],
    remote_bytes: &[u8],
    group_id: &[u8],
    pin: &DagPin,
    floor: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let sync_pin = DagPin {
        genesis_op_id: pin.genesis_op_id,
        reset_authority: pin.reset_authority,
        watermark: floor.to_vec(),
    };
    verify_anchor(remote_bytes, group_id, &sync_pin)?;
    merge(local_bytes, remote_bytes)
}

/// The ever-legitimately-a-member set (id → author key): the current members plus every member whose Add is
/// EFFECTIVE (which includes removed members but excludes carve-out-voided Adds). See [`Resolved::ever_members`].
fn collect_ever_members(
    members: &MembershipView,
    effective: Vec<[u8; 32]>,
    by_id: &HashMap<[u8; 32], &KeyringOp>,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut ever: std::collections::BTreeMap<String, Vec<u8>> = members
        .members
        .iter()
        .map(|m| (m.member_id.clone(), m.author_public_key.clone()))
        .collect();
    for op_id in effective {
        let Some(op) = by_id.get(&op_id) else { continue };
        match &op.action {
            MembershipAction::Add { member, author_public_key, .. } => {
                ever.entry(member.clone()).or_insert_with(|| author_public_key.to_vec());
            }
            MembershipAction::Create { initial_members } => {
                for m in initial_members {
                    ever.entry(m.id.clone()).or_insert_with(|| m.author_public_key.to_vec());
                }
            }
            _ => {}
        }
    }
    ever
}

/// The dag's compaction DECISION for a concrete openom keyring: the checkpoint to author + the ops that may be
/// dropped. See [`keyeo_dag::Compacted`].
pub type KeyringCompacted = Compacted<[u8; 32], String, KeyringRole, Ed25519>;

/// Compute a compaction DECISION for `anchor_bytes`.
///
/// rebuild the engine (exactly as [`resolve`] does), then ask
/// keyeo-dag which checkpoint to author and which ops may be pruned, given the host's `stable` frontier + the
/// retention `plan`.
///
/// This is the DECISION ONLY — no signing, no anchor mutation: the caller (the vault) authors
/// the signed `Snapshot` from the returned resolved state and applies the prune to its stored anchor.
///
/// `stable` is the frontier every peer has synced past — the data-loss guard `compact` never prunes above.
/// Until the sync layer supplies a real one, callers pass a conservative frontier. `None` = `KeepAll` / nothing to
/// drop.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed or a stored op is rejected on replay.
pub fn compact(
    anchor_bytes: &[u8],
    stable: &Frontier<[u8; 32]>,
    plan: RetentionPlan,
) -> Result<Option<KeyringCompacted>, ClientError> {
    let anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let genesis: Vec<KeyringMemberInit> = anchor.genesis.iter().map(dto_to_minit).collect();
    let base = KeyringState::create(keyeo_dag::GroupId::new(anchor.group_id.clone()), &genesis)
        .with_reset_authority(anchor.reset_authority);
    let mut engine = Keyeo::new(base, KeyringAccess, StrongRemove);
    for bytes in &anchor.ops {
        let op = decode_op(bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
        engine
            .apply(op)
            .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
    }
    engine
        .flush()
        .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
    <Retained<'_, KeyringOp> as Compaction>::compact(&engine.retained(), stable, plan)
        .map_err(|e| ClientError::Engine(e.to_string()))
}

/// Map a keyeo action to the coarse [`SealingOrigin`] the sealer's fold uses to decide epoch eligibility.
/// Only Remove (and, once it lands, Reseal) legitimately mints a forward-secret epoch outside genesis; the
/// genesis Create is tagged [`SealingOrigin::Genesis`] at its own (pinned) call site, so a Create here is an
/// (inert) non-genesis op and counts as `Other`.
const fn origin_of(action: &KeyringAction) -> SealingOrigin {
    match action {
        MembershipAction::Remove { .. } => SealingOrigin::Remove,
        MembershipAction::Reseal => SealingOrigin::Reseal,
        _ => SealingOrigin::Other,
    }
}

/// Author a CHECKPOINT-ROOTED anchor (OPE-348 step 2a).
///
/// given a supplied DOMINATING `frontier`, prune the ops
/// at/below it and replace them with a signed [`Checkpoint`](crate::checkpoint::Checkpoint) carrying the
/// resolved membership at the cut, the frontier depths, and the preserved sealing.
///
/// The sealing preservation
/// rides in as the `author_sealing` callback — the vault supplies it, so keyring-dag never interprets sealing.
/// Un-compacted base only for now (chained checkpointing is a follow-up).
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed, already a checkpoint anchor, a stored op is
/// rejected on replay, or the `author_sealing` callback fails.
///
/// # Panics
/// Never in practice: the rebuilt `DagAnchor` always serializes.
pub fn compact_to_checkpoint(
    anchor_bytes: &[u8],
    frontier: &[[u8; 32]],
    prev_snapshot: Option<[u8; 32]>,
    author: String,
    signing_key: &edsign::SigningKey,
    author_sealing: impl FnOnce(&[SealingEntry]) -> Result<(Vec<SealingEntry>, u32), String>,
) -> Result<Vec<u8>, ClientError> {
    let anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    if anchor.checkpoint.is_some() {
        return Err(ClientError::Malformed(
            "re-compacting a checkpoint anchor is not yet supported".into(),
        ));
    }
    let ops: Vec<KeyringOp> = anchor
        .ops
        .iter()
        .map(|b| decode_op(b))
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))?;
    let by_id: HashMap<[u8; 32], &KeyringOp> = ops.iter().map(|o| (o.id, o)).collect();

    // pre-cut = the frontier tips + all their ancestors (walk parents); everything else is retained above the cut.
    let mut pre_cut: HashSet<[u8; 32]> = frontier.iter().copied().collect();
    let mut stack: Vec<[u8; 32]> = frontier.to_vec();
    while let Some(id) = stack.pop() {
        if let Some(op) = by_id.get(&id) {
            for p in &op.parents {
                if pre_cut.insert(*p) {
                    stack.push(*p);
                }
            }
        }
    }

    // Resolve the pre-cut sub-DAG → the cut state (membership), its op depths, and its sealing.
    let genesis: Vec<KeyringMemberInit> = anchor.genesis.iter().map(dto_to_minit).collect();
    let base = KeyringState::create(keyeo_dag::GroupId::new(anchor.group_id.clone()), &genesis)
        .with_reset_authority(anchor.reset_authority);
    let mut engine = Keyeo::new(base, KeyringAccess, StrongRemove);
    for op in &ops {
        if pre_cut.contains(&op.id) {
            engine
                .apply(op.clone())
                .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
        }
    }
    engine
        .flush()
        .map_err(|e| ClientError::Engine(format!("{e:?}")))?;

    // Pre-cut sealing (genesis first, then effective pre-cut ops) — the input to the segment authoring.
    let mut pre_sealing = Vec::new();
    if let Some(g) = by_id.get(&anchor.genesis_op_id) {
        if !g.sealing.is_empty() {
            pre_sealing.push(SealingEntry {
                op_id: anchor.genesis_op_id,
                origin: SealingOrigin::Genesis,
                bytes: g.sealing.clone(),
            });
        }
    }
    for op_id in engine.effective_ops() {
        if op_id == anchor.genesis_op_id {
            continue;
        }
        if let Some(op) = by_id.get(&op_id) {
            if !op.sealing.is_empty() {
                pre_sealing.push(SealingEntry {
                    op_id,
                    origin: origin_of(&op.action),
                    bytes: op.sealing.clone(),
                });
            }
        }
    }

    let (segment, baseline) = author_sealing(&pre_sealing).map_err(ClientError::Malformed)?;

    let depths = engine.op_depths();
    let frontier_depths: Vec<([u8; 32], u64)> = frontier
        .iter()
        .map(|t| (*t, *depths.get(t).unwrap_or(&0) as u64))
        .collect();

    let checkpoint = crate::checkpoint::Checkpoint {
        frontier_depths,
        state: crate::checkpoint::GroupStateView::of(engine.state()),
        prev_snapshot,
        has_been_shared: engine.has_been_shared(),
        sealing: segment,
        minting_ops_baseline: baseline,
        author,
    };
    let signed: crate::checkpoint::SignedCheckpoint =
        keyeo_dag::Signed::sign(checkpoint, signing_key);

    let retained: Vec<Vec<u8>> = ops
        .iter()
        .filter(|o| !pre_cut.contains(&o.id))
        .map(encode_op)
        .collect();

    let new_anchor = DagAnchor {
        group_id: anchor.group_id,
        genesis: anchor.genesis,
        reset_authority: anchor.reset_authority,
        genesis_op_id: anchor.genesis_op_id,
        ops: retained,
        checkpoint: Some(signed),
    };
    Ok(postcard::to_allocvec(&new_anchor).expect("DagAnchor serialization is infallible"))
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
///
/// NOTE: this decodes ops WITHOUT the [`content_id_matches`](crate::blob_sync::content_id_matches) integrity
/// check — that lives in [`resolve`], the trust chokepoint. The anti-rollback machinery built on this
/// ([`watermark`]/[`check_floor`]) keys off op ids, which are only trustworthy AFTER `resolve` has run. On the
/// untrusted-ingest path [`verify_anchor`] runs `resolve` FIRST, so the floor check sees authenticated ids; a
/// future caller must preserve that ordering (resolve-then-floor) rather than run the floor on raw bytes.
fn anchor_ops(anchor_bytes: &[u8]) -> Result<Vec<KeyringOp>, ClientError> {
    let anchor: DagAnchor =
        postcard::from_bytes(anchor_bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
    anchor
        .ops
        .iter()
        .map(|b| decode_op(b))
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::Malformed(e.to_string()))
}

/// The anchor's opaque anti-rollback **watermark**: its frontier (sorted tip op-ids) concatenated as raw
/// 32-byte ids.
///
/// Deterministic — equal frontiers give equal bytes — so the caller persists it and passes it
/// back as the `floor` on the next mutating flow. The sealer treats these bytes as opaque (guardrail #1).
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn watermark(anchor_bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
    let ops = anchor_ops(anchor_bytes)?;
    Ok(frontier(&ops).into_iter().flatten().collect())
}

/// Enforce the caller's anti-rollback `floor` (a watermark previously emitted by [`watermark`]) against a
/// served anchor.
///
/// every frontier op-id it names must still be present in the anchor's (append-only,
/// causally-closed) op set.
///
/// A missing one means the anchor dropped history — [`ClientError::RolledBack`].
/// An empty floor is "no floor" (Ok); a floor whose length isn't a multiple of 32 is a corrupt watermark
/// and is refused ([`ClientError::Malformed`]) rather than silently ignored — dropping it would drop
/// rollback protection.
///
/// # Errors
/// Returns [`ClientError::BadWatermark`] if `floor`'s length isn't a multiple of 32,
/// [`ClientError::RolledBack`] if a floor op-id is absent from the anchor, or [`ClientError::Malformed`]
/// if the anchor doesn't decode.
///
/// # Panics
/// Never in practice: each 32-byte chunk always converts to `[u8; 32]`.
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
    use std::fmt::Write;
    let mut s = String::with_capacity(17);
    for b in &id[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s.push('…');
    s
}

/// Merge two anchors of the same tree into their causal union — the op closures unioned, deduplicated by
/// op-id, keeping `a`'s pinned genesis config.
///
/// Concurrent branches both survive and resolve deterministically
/// (the op-DAG is a set-union CRDT). A direct convenience over the store-based anti-entropy in `blob_sync`.
///
/// # Errors
/// Returns [`ClientError`] if either anchor is malformed.
///
/// # Panics
/// Never in practice: the merged `DagAnchor` always serializes.
pub fn merge(anchor_a: &[u8], anchor_b: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut a: DagAnchor =
        postcard::from_bytes(anchor_a).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let b: DagAnchor =
        postcard::from_bytes(anchor_b).map_err(|e| ClientError::Malformed(e.to_string()))?;
    let mut seen: HashSet<[u8; 32]> = anchor_ops(anchor_a)?.iter().map(|o| o.id).collect();
    for (blob, op) in b.ops.iter().zip(anchor_ops(anchor_b)?) {
        // Never union a content-id-relabeled op (H2) from the other anchor: `apply` doesn't bind id↔content,
        // so a relabeled op that reached us would be PERSISTED here and then fail every later `resolve()`
        // (`Malformed`) — a peer-triggered denial of service on the local keyring. `resolve` re-checks anyway,
        // but dropping it at the merge chokepoint keeps a poisoned op from ever entering the stored anchor.
        // (The guarded `accept_remote_anchor` path has already content-validated `b` via `resolve`, so this is
        // a no-op there; it hardens any UNguarded caller of `merge`.)
        if !crate::blob_sync::content_id_matches(&op) {
            continue;
        }
        if seen.insert(op.id) {
            a.ops.push(blob.clone());
        }
    }
    Ok(postcard::to_allocvec(&a).expect("DagAnchor serialization is infallible"))
}

/// Append a recovery **`ReFound`** op — retarget the Owner to new keys, signed by the recovery authority
/// (RVK), carrying the re-escrow in its opaque `sealing` envelope.
///
/// Parents = the current frontier. Returns
/// the new anchor bytes.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn append_refound(
    anchor_bytes: &[u8],
    owner_id: &str,
    new_author_public_key: edsign::VerifyingKey,
    new_hpke_public_key: keyeo_wrap::X25519PublicKey,
    era: u64,
    sealing: Vec<u8>,
    rvk_signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::ReFound {
        member: owner_id.to_string(),
        new_author_public_key: new_author_public_key.to_bytes(),
        new_hpke_public_key: new_hpke_public_key.to_bytes(),
        era,
    };
    append(anchor_bytes, owner_id, action, sealing, rvk_signing_key)
}

/// Append a voluntary **Retarget** op — `member` rotates their OWN keys, signed by their CURRENT key
/// (change-passphrase), carrying the re-escrow in its opaque `sealing`.
///
/// Parents = the current frontier.
/// Returns the new anchor bytes.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn append_retarget(
    anchor_bytes: &[u8],
    member_id: &str,
    new_author_public_key: edsign::VerifyingKey,
    new_hpke_public_key: keyeo_wrap::X25519PublicKey,
    sealing: Vec<u8>,
    current_signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    let action = MembershipAction::Retarget {
        member: member_id.to_string(),
        new_author_public_key: new_author_public_key.to_bytes(),
        new_hpke_public_key: new_hpke_public_key.to_bytes(),
    };
    append(
        anchor_bytes,
        member_id,
        action,
        sealing,
        current_signing_key,
    )
}

/// Append a **Reseal** op (OPE-282) — a membership-inert forward-secrecy repair authored by active
/// `member_id`, carrying a fresh DEK epoch (wrapped to the resolved membership) in its opaque `sealing`.
///
/// Parents = the current frontier. Signed by the author's current key. Returns the new anchor bytes.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn append_reseal(
    anchor_bytes: &[u8],
    member_id: &str,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    append(
        anchor_bytes,
        member_id,
        MembershipAction::Reseal,
        sealing,
        signing_key,
    )
}

/// Append a **Backfill** op (OPE-288).
///
/// a membership-inert HISTORICAL-READ repair authored by `member_id`,
/// carrying ONLY `added_wraps` (the missing member wraps for existing epochs) in its opaque `sealing`, no new
/// epoch.
///
/// It reuses the inert `Reseal` keyeo action: keyeo sees only an authored, membership-inert op, and
/// what the sealing actually does — add wraps vs mint an epoch — is the sealer's concern, invisible to keyeo
/// (the sealing invariant). Parents = the current frontier. Returns the new anchor bytes.
///
/// # Errors
/// Returns [`ClientError`] if `anchor_bytes` is malformed.
pub fn append_backfill(
    anchor_bytes: &[u8],
    member_id: &str,
    sealing: Vec<u8>,
    signing_key: &edsign::SigningKey,
) -> Result<Vec<u8>, ClientError> {
    append(
        anchor_bytes,
        member_id,
        MembershipAction::Reseal,
        sealing,
        signing_key,
    )
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
    fn vpk(seed: u8) -> edsign::VerifyingKey {
        sk(seed).verifying_key()
    }
    fn xpk(seed: u8) -> keyeo_wrap::X25519PublicKey {
        keyeo_wrap::X25519PublicKey::from_bytes([seed; 32])
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
            &keyeo_dag::GroupId::unscoped(),
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
            &keyeo_dag::GroupId::unscoped(),
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
            &keyeo_dag::GroupId::unscoped(),
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
            checkpoint: None,
        };
        let resolved = resolve(&postcard::to_allocvec(&anchor).unwrap()).unwrap();

        let has = |needle: &[u8]| {
            resolved
                .sealing
                .iter()
                .any(|s| s.bytes.as_slice() == needle)
        };
        assert!(
            has(b"GENESIS-SEALING"),
            "the pinned genesis op always contributes"
        );
        assert!(
            has(b"RECOVERY-SEALING"),
            "the surviving recovery contributes"
        );
        assert!(
            !has(b"THIEF-SEALING"),
            "a carve-out-voided op's sealing is dropped, not folded"
        );
        assert!(
            !resolved
                .members
                .members
                .iter()
                .any(|m| m.member_id == "mallory"),
            "and the voided op has no membership effect either"
        );
    }

    /// The watermark is the frontier op-id set, and check_floor is causal-descendant containment: an
    /// advanced anchor still satisfies an older floor (the old tip remains an ancestor), while a stale
    /// anchor fails a newer floor (the advanced tip is absent). Empty = no floor; a non-32-multiple = bad.
    #[test]
    fn watermark_advances_and_check_floor_catches_rollback() {
        let a0 = provision_anchor(
            b"tree-1",
            "founder",
            vpk(1),
            xpk(1),
            vk(3),
            b"seal".to_vec(),
            &sk(1),
        );
        let w0 = watermark(&a0).unwrap();
        assert_eq!(
            w0.len(),
            32,
            "a single tip (the genesis op) encodes to 32 bytes"
        );
        assert!(
            check_floor(&a0, &w0).is_ok(),
            "the current frontier satisfies its own floor"
        );
        assert!(check_floor(&a0, &[]).is_ok(), "an empty floor is no floor");
        assert!(
            matches!(
                check_floor(&a0, &[1, 2, 3]),
                Err(ClientError::BadWatermark(_))
            ),
            "a floor whose length isn't a multiple of 32 is refused"
        );

        // Append an Add — an authorized owner adds a co-owner; the frontier moves to the new op.
        let a1 = append_add(
            &a0,
            "founder",
            &minit("bob", KeyringRole::CO_OWNER, 2),
            b"wrap".to_vec(),
            &sk(1),
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

    /// A shared anchor (owner + an added member) with its OOB pin — the join fixture.
    fn shared_anchor_and_pin() -> (Vec<u8>, DagPin) {
        let a0 = provision_anchor(b"tree-vd", "founder", vpk(1), xpk(1), vk(3), b"seal".to_vec(), &sk(1));
        let a1 = append_add(&a0, "founder", &minit("bob", KeyringRole::MAINTAINER, 2), b"wrap".to_vec(), &sk(1))
            .unwrap();
        let pin = anchor_pin(&a1).unwrap();
        (a1, pin)
    }

    #[test]
    fn verify_anchor_accepts_a_legit_anchor_at_the_right_pin() {
        let (anchor, pin) = shared_anchor_and_pin();
        let resolved = verify_anchor(&anchor, b"tree-vd", &pin).unwrap();
        assert!(resolved.has_been_shared, "a shared tree resolves as shared");
        assert!(resolved.members.members.iter().any(|m| m.member_id == "bob"), "bob is a resolved member");
    }

    #[test]
    fn verify_anchor_rejects_a_wrong_tree_or_wrong_pin() {
        let (anchor, pin) = shared_anchor_and_pin();
        assert!(verify_anchor(&anchor, b"other-tree", &pin).is_err(), "a wrong tree id is refused");
        let mut bad = pin.clone();
        bad.genesis_op_id[0] ^= 0xff;
        assert!(verify_anchor(&anchor, b"tree-vd", &bad).is_err(), "a wrong genesis-op pin is refused");
        let mut bad_rvk = pin.clone();
        bad_rvk.reset_authority = Some([9u8; 32]);
        assert!(verify_anchor(&anchor, b"tree-vd", &bad_rvk).is_err(), "a wrong recovery-authority pin is refused");
    }

    #[test]
    fn verify_anchor_rejects_a_founder_substituted_anchor() {
        // H1: keep the REAL genesis op (so the genesis_op_id pin matches) but tamper the SEPARATE `anchor.genesis`
        // DTO that `resolve` actually builds membership from — seed a substituted owner key under the founder id.
        // Without the DTO<->genesis-op binding, resolve would trust the attacker's key; the H1 check refuses it.
        let (anchor, pin) = shared_anchor_and_pin();
        let mut tampered: DagAnchor = postcard::from_bytes(&anchor).unwrap();
        tampered.genesis = vec![crate::blob_sync::minit_to_dto(&minit("founder", KeyringRole::OWNER, 99))];
        let bytes = postcard::to_allocvec(&tampered).unwrap();
        assert!(
            verify_anchor(&bytes, b"tree-vd", &pin).is_err(),
            "an anchor whose genesis DTO diverges from the pinned genesis op is refused (founder substitution)"
        );
    }

    #[test]
    fn verify_anchor_rejects_a_rolled_back_anchor() {
        // H4: pin at the CURRENT (post-add) frontier, then serve the older pre-add anchor. The invite-time
        // freshness floor must reject it — else a server could serve a stale subset (e.g. before a Remove).
        let a0 = provision_anchor(b"tree-rb", "founder", vpk(1), xpk(1), vk(3), b"seal".to_vec(), &sk(1));
        let a1 = append_add(&a0, "founder", &minit("bob", KeyringRole::MAINTAINER, 2), b"wrap".to_vec(), &sk(1))
            .unwrap();
        let pin = anchor_pin(&a1).unwrap(); // watermark = the post-add frontier
        assert!(verify_anchor(&a1, b"tree-rb", &pin).is_ok(), "the current anchor satisfies its own floor");
        assert!(
            matches!(verify_anchor(&a0, b"tree-rb", &pin), Err(ClientError::RolledBack(_))),
            "an anchor rolled back below the invite-time frontier is refused"
        );
    }

    #[test]
    fn accept_remote_anchor_adopts_forward_and_refuses_rollback() {
        // The sync/adopt path: a member on a0 adopts the owner's advanced a1 (forward — ok), but refuses to
        // "adopt" the stale a0 when its floor is already at a1 (a rollback).
        let a0 = provision_anchor(b"tree-ad", "founder", vpk(1), xpk(1), vk(3), b"seal".to_vec(), &sk(1));
        let a1 = append_add(&a0, "founder", &minit("bob", KeyringRole::MAINTAINER, 2), b"wrap".to_vec(), &sk(1))
            .unwrap();
        let pin = anchor_pin(&a0).unwrap();
        let floor0 = watermark(&a0).unwrap();
        let merged = accept_remote_anchor(&a0, &a1, b"tree-ad", &pin, &floor0).unwrap();
        assert!(resolve(&merged).unwrap().members.members.iter().any(|m| m.member_id == "bob"), "adopts a1");
        let floor1 = watermark(&a1).unwrap();
        assert!(
            accept_remote_anchor(&a1, &a0, b"tree-ad", &pin, &floor1).is_err(),
            "refuses to adopt an anchor rolled back below the member's persisted floor"
        );
    }

    #[test]
    fn merge_drops_a_content_id_relabeled_op() {
        // Defense in depth (review observation): `merge` must never union a content-id-relabeled op from the
        // other anchor — else an UNguarded caller would PERSIST a poisoned op that fails every later resolve().
        let a0 = provision_anchor(b"tree-mg", "founder", vpk(1), xpk(1), vk(3), b"seal".to_vec(), &sk(1));
        let genesis_id = {
            let a: DagAnchor = postcard::from_bytes(&a0).unwrap();
            a.genesis_op_id
        };
        // Mint a valid Add op, then RELABEL its id so it is no longer its own content-address.
        let mut relabeled = mint(
            &keyeo_dag::GroupId::new(b"tree-mg".to_vec()),
            vec![genesis_id],
            "founder".to_string(),
            MembershipAction::Add {
                member: "mallory".to_string(),
                role: KeyringRole::CO_OWNER,
                author_public_key: vk(9),
                hpke_public_key: [9; 32],
                member_proof: None,
            },
            b"wrap".to_vec(),
            &sk(1),
        );
        relabeled.id = [0xAA; 32];
        let mut b: DagAnchor = postcard::from_bytes(&a0).unwrap();
        b.ops.push(crate::blob_sync::encode_op(&relabeled));
        let merged = merge(&a0, &postcard::to_allocvec(&b).unwrap()).unwrap();
        // The relabeled op was dropped at the merge chokepoint: the merged anchor still resolves cleanly and
        // mallory (carried only by the relabeled Add) is not a member.
        let resolved = resolve(&merged).expect("a merge that dropped the relabeled op still resolves");
        assert!(!resolved.members.members.iter().any(|m| m.member_id == "mallory"));
    }

    #[test]
    fn has_been_shared_is_monotonic_true_after_an_add_even_once_removed() {
        // Solo genesis: never shared.
        let a0 = provision_anchor(
            b"tree-es",
            "founder",
            vpk(1),
            xpk(1),
            vk(3),
            b"seal".to_vec(),
            &sk(1),
        );
        assert!(
            !resolve(&a0).unwrap().has_been_shared,
            "a solo tree has never been shared"
        );

        // Admit a member → shared.
        let a1 = append_add(
            &a0,
            "founder",
            &minit("bob", KeyringRole::CO_OWNER, 2),
            b"wrap".to_vec(),
            &sk(1),
        )
        .unwrap();
        assert!(
            resolve(&a1).unwrap().has_been_shared,
            "admitting a member makes the tree shared"
        );

        // Remove the member → solo membership again, but has_been_shared stays TRUE (the effective Add persists).
        let a2 = append_remove(&a1, "founder", "bob", b"reseal".to_vec(), &sk(1)).unwrap();
        assert!(
            resolve(&a2).unwrap().has_been_shared,
            "an un-shared-back-to-solo dag still reports has_been_shared (monotonic)"
        );
    }

    #[test]
    fn compact_computes_a_decision_over_the_rebuilt_engine() {
        let a0 = provision_anchor(
            b"tree-cp",
            "founder",
            vpk(1),
            xpk(1),
            vk(3),
            b"g".to_vec(),
            &sk(1),
        );
        let a1 = append_add(
            &a0,
            "founder",
            &minit("bob", KeyringRole::CO_OWNER, 2),
            b"w".to_vec(),
            &sk(1),
        )
        .unwrap();

        // KeepAll → the engine builds, but there's nothing to compact.
        assert!(
            compact(&a1, &Frontier { ops: vec![] }, RetentionPlan::KeepAll)
                .unwrap()
                .is_none()
        );

        // With the current head as the stable frontier, the decision carries the resolved state (has_been_shared
        // for this now-shared tree) and marks the subsumed history below the head as prunable.
        let wm = watermark(&a1).unwrap();
        let tips: Vec<[u8; 32]> = wm.chunks(32).map(|c| c.try_into().unwrap()).collect();
        let out = compact(
            &a1,
            &Frontier { ops: tips },
            RetentionPlan::Snapshot { keep_last: 0 },
        )
        .unwrap()
        .expect("a shared tree with history below the head has a compaction decision");
        assert!(
            out.has_been_shared,
            "the checkpoint records the shared marker"
        );
        assert!(
            !out.prune.is_empty(),
            "history below the head frontier is prunable"
        );
    }
}
