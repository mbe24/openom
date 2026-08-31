//! The DAG keyring's **client facade** (OPE-273) — the secret-adjacent surface the vault (`openom-sealer`'s
//! `dag_vault.rs`) drives, so the vault never touches `keyeo` or this crate's op types directly (a
//! one-line import grep keeps `dag_vault.rs` free of `keyeo`). It mints content-addressed ops carrying an
//! opaque `sealing` payload, packages the trust anchor, and resolves an anchor to a [`MembershipView`] plus
//! the effective ops' sealing payloads for the vault's sealing fold.
//!
//! The anchor is the same trust state the keyless [`crate::verifier`] uses — pinned founding config + the
//! op closure — plus the pinned **genesis op id** (the sealing fold's root: the genesis `Create` is
//! resolver-inert per OPE-271, so it is pinned to always contribute its sealing).

use keyeo::{Keyeo, MembershipAction, StrongRemove};
use openom_keyring_seam::MembershipView;
use serde::{Deserialize, Serialize};

use crate::blob_sync::{decode_op, dto_to_minit, encode_op, minit_to_dto, MemberInitDto};
use crate::verifier::view_of;
use crate::{
    KeyringAccess, KeyringAction, KeyringMemberInit, KeyringOp, KeyringRole, KeyringState,
};

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
/// membership view + the effective ops' sealing.
///
/// TODO(OPE-273 multi-op fold): today this contributes only the pinned genesis op's sealing (the
/// single-owner path — the only ops are the genesis). Once membership authoring lands, non-genesis ops
/// contribute their sealing iff effective, via the engine's `effective_ops` accessor (design.dag-vault-
/// anchor.md); the genesis op always contributes (it is resolver-inert per OPE-271 but pinned as the root).
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
    let mut genesis_sealing: Option<Vec<u8>> = None;
    for bytes in &anchor.ops {
        let op = decode_op(bytes).map_err(|e| ClientError::Malformed(e.to_string()))?;
        if op.id == anchor.genesis_op_id {
            genesis_sealing = Some(op.sealing.clone());
        }
        engine
            .apply(op)
            .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
    }
    engine
        .flush()
        .map_err(|e| ClientError::Engine(format!("{e:?}")))?;
    let members = view_of(engine.state(), false);
    let sealing = genesis_sealing
        .map(|s| vec![s])
        .ok_or_else(|| ClientError::Malformed("pinned genesis op not present in the closure".into()))?;
    Ok(Resolved { members, sealing })
}
