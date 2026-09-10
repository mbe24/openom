//! Engine-neutral keyring/membership **orchestration glue** — the marshalling + walk / wrap / summary logic
//! that sits ABOVE the pure crypto (`verify_walk` / `verify_reset` / `dag_client`) and BELOW the veneers.
//!
//! Lifted out of the vault's `wasm.rs` (OPE-382 Half B) so BOTH that wasm veneer AND `openom-app-core`'s
//! worker veneer call ONE implementation. Everything here is pure Rust returning `Result<_, VaultError>`;
//! a veneer adds only the JS marshalling (`&str` engine tag → [`EngineKind`], byte arrays) and the
//! `VaultError → JsError` mapping. Behaviour is identical to the pre-lift `wasm.rs` functions — the error
//! strings are preserved verbatim through [`VaultError::Sharing`].

use openom_crypto::Passphrase;
use openom_keyring_api::{EngineKind, MembershipEnvelope};
use openom_keyring_chain::wire::{Keyring, MEMBER_OWNER};
use openom_keyring_chain::{
    bootstrap_from_genesis, encode_governing_ref, keyring_hash, verify_reset, verify_walk,
    KeyringAnchor, VerifyingKey,
};
use openom_keyring_dag::client as dag_client;
use openom_keyring_dag::KeyringRole;
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_protocol::v1::{KeyringUpdate, MemberRole};
use openom_protocol::Message;
use openom_sealer::SealerSet;

use crate::dag_vault::DagVault;
use crate::lifecycle::VaultContext;
use crate::{vault, VaultError};

/// An orchestration diagnostic → [`VaultError::Sharing`] (verbatim message, no prefix).
fn err(msg: impl Into<String>) -> VaultError {
    VaultError::Sharing(msg.into())
}

// --- result shapes (plain Rust; a veneer wraps these in its wasm-bindgen struct) -------------------

/// The accepted head of a walked / reset keyring run: the RAW head `Keyring` body to store + the opaque
/// anti-rollback watermark to persist. (No sealer — keyring state only; re-unlock to read a rotated epoch.)
pub struct AcceptedKeyring {
    /// The RAW chain `Keyring` body bytes to store as the new head (empty on a no-op accept).
    pub keyring: Vec<u8>,
    /// The engine-opaque anti-rollback cursor to persist and pass back as the floor.
    pub watermark: Vec<u8>,
}

/// A joining member's verified view of a tree's WHOLE keyring history (the `verify_keyring_walk` output).
pub struct WalkedHistory {
    /// The verified head revision (>= the invite's pinned revision).
    pub revision: u32,
    /// The RAW head `Keyring` body — stored as the head and fed to `unlock_as_member`.
    pub head_keyring: Vec<u8>,
    /// The head's authorized signers as JSON `[{"memberId","authorPublicKey"(hex)}]` — the caller computes
    /// the canonical fingerprint over these and cross-checks the invite's `fp`.
    pub signers_json: String,
    /// Every RAW per-revision body 1..=head, ascending, length-prefix framed (`[u32-be len][bytes]…`) so the
    /// caller unframes + retains each for pre-join attributed-entry verification.
    pub bodies_framed: Vec<u8>,
}

// --- small helpers (moved verbatim) ----------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// A dag frontier (concatenated 32-byte op-ids) → `["op:<hex>", ...]`.
fn dag_basis_tokens(anchor: &[u8]) -> Result<Vec<String>, VaultError> {
    let wm = dag_client::watermark(anchor).map_err(|e| err(e.to_string()))?;
    if wm.len() % 32 != 0 {
        return Err(err("dag watermark is not a whole number of op-ids"));
    }
    Ok(wm.chunks_exact(32).map(|c| format!("op:{}", hex(c))).collect())
}

/// Decode `["op:<hex>", ...]` back to the concatenated 32-byte floor for `check_floor`. `None` if any token
/// is malformed (→ treated as "not covered", the safe default that triggers a refresh).
fn dag_floor_from_tokens(tokens: &[String]) -> Option<Vec<u8>> {
    let mut floor = Vec::with_capacity(tokens.len() * 32);
    for t in tokens {
        let h = t.strip_prefix("op:")?;
        if h.len() != 64 {
            return None;
        }
        for i in 0..32 {
            floor.push(u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?);
        }
    }
    Some(floor)
}

/// Concatenate byte runs as `[u32-be length][bytes]…` — the framing that keeps a list of variable-length
/// keyrings marshallable over the plain byte boundary (no serde), the inverse of [`split_length_prefixed`].
fn frame_length_prefixed(runs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(runs.iter().map(|r| r.len() + 4).sum());
    for r in runs {
        out.extend_from_slice(&u32::try_from(r.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(r);
    }
    out
}

/// Split a buffer of `[u32-be length][bytes]…` frames into slices.
fn split_length_prefixed(buf: &[u8]) -> Result<Vec<&[u8]>, VaultError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        if i + 4 > buf.len() {
            return Err(err("truncated length prefix in hops buffer"));
        }
        let len = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        let end = i.checked_add(len).ok_or_else(|| err("length prefix overflow"))?;
        if end > buf.len() {
            return Err(err("length prefix overruns hops buffer"));
        }
        out.push(&buf[i..end]);
        i = end;
    }
    Ok(out)
}

/// Build a chain watermark that pins the write epoch: `revision(4) ‖ write_key_id(16) ‖ H(DEK)(32)`, the
/// commitment recover authenticates the write epoch against (OPE-286 phase 2). Membership ops that open the
/// write epoch (add/remove member) emit the full pin rather than a bare revision that would erase a prior
/// recover pin. Falls back to revision-only if the pin isn't sized right.
#[must_use]
pub fn chain_wm_pinned(revision: u32, write_key_id: &[u8], write_dek_hash: &[u8]) -> Vec<u8> {
    let mut wm = revision.to_be_bytes().to_vec();
    if write_key_id.len() == 16 && write_dek_hash.len() == 32 {
        wm.extend_from_slice(write_key_id);
        wm.extend_from_slice(write_dek_hash);
    }
    wm
}

// --- summary DTOs (serde) --------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct KeyringSummaryDto {
    members: Vec<SummaryMemberDto>,
    basis: Vec<String>,
}

#[derive(serde::Serialize)]
struct SummaryMemberDto {
    #[serde(rename = "memberId")]
    member_id: String,
    role: i16,
}

#[derive(serde::Serialize)]
struct WalkSignerDto {
    #[serde(rename = "memberId")]
    member_id: String,
    #[serde(rename = "authorPublicKey")]
    author_public: String,
}

// --- the lifted orchestration functions ------------------------------------------------------------

/// The resolved advisory membership + the engine-opaque basis for a keyring anchor, as a JSON string
/// `{"members":[{"memberId","role"}],"basis":[...]}` — what the client asserts to the server's /access.
///
/// # Errors
/// Returns [`VaultError`] on a malformed keyring/anchor or a failed dag resolve.
pub fn keyring_summary(engine: EngineKind, keyring: &[u8]) -> Result<String, VaultError> {
    let dto = match engine {
        EngineKind::Dag => {
            let resolved = dag_client::resolve(keyring).map_err(|e| err(e.to_string()))?;
            KeyringSummaryDto {
                members: resolved
                    .members
                    .members
                    .iter()
                    .map(|m| SummaryMemberDto {
                        member_id: m.member_id.clone(),
                        role: m.role,
                    })
                    .collect(),
                basis: dag_basis_tokens(keyring)?,
            }
        }
        EngineKind::Chain => {
            let k = Keyring::decode(keyring).map_err(|e| err(format!("bad keyring: {e}")))?;
            KeyringSummaryDto {
                members: k
                    .members
                    .iter()
                    .map(|m| SummaryMemberDto {
                        member_id: m.member_id.clone(),
                        role: i16::try_from(m.role).unwrap_or(i16::MAX),
                    })
                    .collect(),
                basis: vec![format!("rev:{}:{}", k.revision, hex(keyring_hash(&k).as_slice()))],
            }
        }
    };
    serde_json::to_string(&dto).map_err(|e| err(e.to_string()))
}

/// Whether this keyring's trust state COVERS `stored_basis` (the frontier a prior /access push was computed
/// from) — the client's pre-push staleness guard. dag: every stored tip op-id is in our op closure
/// (`check_floor`); chain: our revision ≥ the stored revision. An empty basis is trivially covered; a
/// malformed stored basis is treated as NOT covered (safe default — the caller then refreshes).
///
/// # Errors
/// Returns [`VaultError`] on a malformed chain keyring.
pub fn keyring_covers(
    engine: EngineKind,
    keyring: &[u8],
    stored_basis: &[String],
) -> Result<bool, VaultError> {
    if stored_basis.is_empty() {
        return Ok(true);
    }
    Ok(match engine {
        EngineKind::Dag => dag_floor_from_tokens(stored_basis)
            .is_some_and(|floor| dag_client::check_floor(keyring, &floor).is_ok()),
        EngineKind::Chain => {
            let k = Keyring::decode(keyring).map_err(|e| err(format!("bad keyring: {e}")))?;
            match stored_basis
                .first()
                .and_then(|t| t.strip_prefix("rev:"))
                .and_then(|s| s.split(':').next())
                .and_then(|n| n.parse::<u32>().ok())
            {
                Some(stored_rev) => k.revision >= stored_rev,
                None => false,
            }
        }
    })
}

/// Unwrap a served [`MembershipEnvelope`] to its RAW chain `Keyring` body bytes — the format the client
/// retains per revision and feeds §B3 verify. Refuses a non-chain envelope.
///
/// # Errors
/// Returns [`VaultError`] if the bytes aren't a chain-tagged membership envelope.
pub fn unwrap_chain_keyring(bytes: &[u8]) -> Result<Vec<u8>, VaultError> {
    let env = MembershipEnvelope::decode(bytes)
        .map_err(|_| err("served keyring is not a valid membership envelope"))?;
    if env.engine_kind() != Ok(EngineKind::Chain) {
        return Err(err("served keyring envelope is not a chain keyring"));
    }
    Ok(env.body)
}

/// Accept a keyring run pulled from the **untrusted network** — the chain-walk read-side. `anchor` is the
/// caller's currently-trusted head; `hops` is `[u32-be len][MembershipEnvelope bytes]…` for the successor
/// revisions, ascending, no gaps. Each is validated as a legitimate successor of the last ([`verify_walk`]);
/// a fork / rollback / withheld hop / rogue-signer injection fails closed. An empty run is a no-op at the
/// current head.
///
/// # Errors
/// Returns [`VaultError`] on a malformed anchor/hop, a tree mismatch, or a rejected transition.
///
/// # Panics
/// Never in practice: the hop run is validated non-empty before its last element is taken.
pub fn accept_remote_keyring(
    anchor: &[u8],
    tree_id: &[u8],
    hops: &[u8],
) -> Result<AcceptedKeyring, VaultError> {
    let anchor_keyring =
        Keyring::decode(anchor).map_err(|e| err(format!("bad anchor keyring: {e}")))?;
    if anchor_keyring.tree_id != tree_id {
        return Err(err("anchor keyring is for a different tree"));
    }
    let raw = split_length_prefixed(hops)?;
    if raw.is_empty() {
        // No-op / accept opens no epoch — the caller carries the stored write-epoch pin forward onto this
        // revision rather than let a bare-revision watermark erase a recover pin (OPE-286 phase 2).
        return Ok(AcceptedKeyring {
            keyring: Vec::new(),
            watermark: anchor_keyring.revision.to_be_bytes().to_vec(),
        });
    }
    // Each served hop is a MembershipEnvelope (the server's opaque stored payload); unwrap to the chain's
    // Keyring body once here so the rest of the client keeps working on raw Keyring bytes.
    let bodies = raw
        .iter()
        .map(|b| unwrap_chain_keyring(b))
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    let decoded = bodies
        .iter()
        .map(|b| Keyring::decode(b.as_slice()).map_err(|e| err(format!("bad served keyring: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let new_anchor = verify_walk(&KeyringAnchor::from_keyring(&anchor_keyring), &decoded)
        .map_err(|e| err(e.to_string()))?;
    Ok(AcceptedKeyring {
        keyring: bodies.last().expect("non-empty run").clone(),
        watermark: new_anchor.revision.to_be_bytes().to_vec(),
    })
}

/// Verify a tree's WHOLE keyring history from GENESIS — a joining member's read-side bootstrap. Trusts the
/// genesis founder on first use (TOFU: the sole owner-role member's author key), walks forward, then PINS the
/// verified history to the `(revision, keyring_hash)` the owner published out-of-band in the invite. Fails
/// closed (the caller persists nothing) on an empty/truncated history, a first revision that isn't a genesis
/// (revision 1) or lacks exactly one owner, any invalid transition, a wrong tree, or a pinned revision
/// outside the history / whose hash doesn't match.
///
/// `hops` is `[u32-be len][MembershipEnvelope bytes]…` for revisions 1..=head, ascending, no gaps.
///
/// # Errors
/// Returns [`VaultError`] on any of the fail-closed conditions above.
///
/// # Panics
/// Never in practice: the hop run is validated non-empty before its last element is taken.
pub fn verify_keyring_walk(
    tree_id: &[u8],
    hops: &[u8],
    pinned_revision: u32,
    pinned_hash: &[u8],
) -> Result<WalkedHistory, VaultError> {
    if pinned_hash.len() != 32 {
        return Err(err("pinned keyring hash must be 32 bytes"));
    }
    let raw = split_length_prefixed(hops)?;
    if raw.is_empty() {
        return Err(err("empty keyring history (need at least the genesis)"));
    }
    let bodies = raw
        .iter()
        .map(|b| unwrap_chain_keyring(b))
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    let decoded = bodies
        .iter()
        .map(|b| Keyring::decode(b.as_slice()).map_err(|e| err(format!("bad served keyring: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let genesis = &decoded[0];
    if genesis.revision != 1 {
        return Err(err("first keyring in the history is not the genesis (revision 1)"));
    }
    // TOFU the genesis founder: the sole role==MEMBER_OWNER member's author key.
    let owners: Vec<_> = genesis.members.iter().filter(|m| m.role == MEMBER_OWNER).collect();
    let founder = match owners.as_slice() {
        [only] => *only,
        [] => return Err(err("genesis keyring declares no owner")),
        _ => return Err(err("genesis keyring declares more than one owner")),
    };
    let founder_arr: [u8; 32] = founder
        .author_public_key
        .as_slice()
        .try_into()
        .map_err(|_| err("genesis owner author key is not 32 bytes"))?;
    let founder_key = VerifyingKey::from_bytes(&founder_arr)
        .map_err(|_| err("genesis owner has an invalid author public key"))?;
    let genesis_anchor =
        bootstrap_from_genesis(genesis, &founder_key).map_err(|e| err(e.to_string()))?;
    let head = verify_walk(&genesis_anchor, &decoded[1..]).map_err(|e| err(e.to_string()))?;
    if head.tree_id != tree_id {
        return Err(err("keyring history is for a different tree"));
    }
    // Bind the verified history to the invite's out-of-band pin — a PREFIX: the pinned revision must appear
    // in the verified history with the pinned hash, while the head may be >= it.
    if pinned_revision < 1 || pinned_revision > head.revision {
        return Err(err("invite-pinned revision is outside the verified keyring history"));
    }
    // genesis == revision 1 + verify_walk enforces contiguous ascending, so revision r is at index r-1.
    let pinned_body = &decoded[(pinned_revision - 1) as usize];
    if keyring_hash(pinned_body).as_slice() != pinned_hash {
        return Err(err("keyring at the invite-pinned revision does not match the pin"));
    }
    let signers = head
        .trusted_signers
        .iter()
        .map(|s| WalkSignerDto {
            member_id: s.member_id.clone(),
            author_public: hex(&s.public_key),
        })
        .collect::<Vec<_>>();
    let signers_json = serde_json::to_string(&signers).map_err(|e| err(e.to_string()))?;
    Ok(WalkedHistory {
        revision: head.revision,
        head_keyring: bodies.last().expect("non-empty run").clone(),
        signers_json,
        bodies_framed: frame_length_prefixed(&bodies),
    })
}

/// Frame a raw signed chain `Keyring` revision as the wire `KeyringUpdate` the server's `PUT
/// /trees/{id}/keyring` accepts — the OUTBOUND mirror of [`accept_remote_keyring`]'s unwrap. `version` = the
/// server's `KEYRING_UPDATE_VERSION` (1); `tree_id` + `update_ref` are routing hints the server cross-checks
/// against the signed body; `engine` = `"chain"`; `payload` = the [`MembershipEnvelope`]-wrapped bytes.
///
/// # Errors
/// Returns [`VaultError`] if `keyring` isn't a decodable chain `Keyring`.
pub fn wrap_chain_keyring_update(keyring: &[u8]) -> Result<Vec<u8>, VaultError> {
    // The server checks `update.version != KEYRING_UPDATE_VERSION` (openom/src/keyring.rs); no shared const
    // yet, so this literal tracks that value.
    const KEYRING_UPDATE_VERSION: u32 = 1;
    let kr = Keyring::decode(keyring).map_err(|e| err(format!("not a decodable chain keyring: {e}")))?;
    let update = KeyringUpdate {
        version: KEYRING_UPDATE_VERSION,
        tree_id: kr.tree_id.clone(),
        engine: EngineKind::Chain.as_tag().to_string(),
        update_ref: encode_governing_ref(kr.revision),
        payload: MembershipEnvelope::wrap(EngineKind::Chain, keyring.to_vec()).encode(),
    };
    Ok(update.encode_to_vec())
}

// --- dag keyring distribution (OPE-392) — the thin marshallers over `openom_keyring_dag::client`'s trust
//     primitives; the dag counterparts of the chain walk/wrap/hash above. ------------------------------------

/// Mint the OOB trust pin for a dag tree's CURRENT anchor (owner, at invite time): the genesis-op id +
/// recovery authority + invite-time frontier a joiner binds to. Opaque bytes; the joiner hands them back to
/// [`verify_dag_anchor`]. The dag analog of [`chain_keyring_hash`].
///
/// # Errors
/// Returns [`VaultError`] if the anchor is malformed.
pub fn dag_anchor_pin(anchor: &[u8]) -> Result<Vec<u8>, VaultError> {
    Ok(dag_client::anchor_pin(anchor)
        .map_err(|e| err(e.to_string()))?
        .encode())
}

/// Verify a dag anchor served by the UNTRUSTED network against an OOB pin — a member's first-sight JOIN, the
/// dag analog of [`verify_keyring_walk`]. Returns the validated anchor + its watermark to persist.
///
/// # Errors
/// Returns [`VaultError`] on a malformed anchor/pin or any failed trust check (founder substitution, rollback,
/// wrong tree, checkpoint).
pub fn verify_dag_anchor(anchor: &[u8], tree_id: &[u8], pin: &[u8]) -> Result<AcceptedKeyring, VaultError> {
    let pin = dag_client::DagPin::decode(pin).map_err(|e| err(e.to_string()))?;
    dag_client::verify_anchor(anchor, tree_id, &pin).map_err(|e| err(e.to_string()))?;
    let watermark = dag_client::watermark(anchor).map_err(|e| err(e.to_string()))?;
    Ok(AcceptedKeyring {
        keyring: anchor.to_vec(),
        watermark,
    })
}

/// Adopt a newer dag anchor pulled from the UNTRUSTED network onto the caller's local anchor — a member's
/// SYNC, enforcing the persisted pin + anti-rollback floor. Returns the merged anchor + its new watermark.
///
/// # Errors
/// Returns [`VaultError`] on a malformed input or a failed verify / rollback check.
pub fn accept_remote_dag_anchor(
    local: &[u8],
    remote: &[u8],
    tree_id: &[u8],
    pin: &[u8],
    floor: &[u8],
) -> Result<AcceptedKeyring, VaultError> {
    let pin = dag_client::DagPin::decode(pin).map_err(|e| err(e.to_string()))?;
    let merged = dag_client::accept_remote_anchor(local, remote, tree_id, &pin, floor)
        .map_err(|e| err(e.to_string()))?;
    let watermark = dag_client::watermark(&merged).map_err(|e| err(e.to_string()))?;
    Ok(AcceptedKeyring {
        keyring: merged,
        watermark,
    })
}

/// Frame a full dag anchor as the wire `KeyringUpdate` the server's keyring channel accepts — the dag mirror
/// of [`wrap_chain_keyring_update`]. A dag anchor carries no revision of its own, so the caller supplies the
/// target server slot (`revision` = server-head + 1) and the `tree_id` as routing hints.
///
/// # Errors
/// Never fails today (the anchor is passed through opaquely); returns [`VaultError`] for signature symmetry
/// with the chain wrap.
#[allow(clippy::unnecessary_wraps)]
pub fn wrap_dag_keyring_update(anchor: &[u8], tree_id: &[u8], revision: u32) -> Result<Vec<u8>, VaultError> {
    const KEYRING_UPDATE_VERSION: u32 = 1;
    let update = KeyringUpdate {
        version: KEYRING_UPDATE_VERSION,
        tree_id: tree_id.to_vec(),
        engine: EngineKind::Dag.as_tag().to_string(),
        update_ref: encode_governing_ref(revision),
        payload: MembershipEnvelope::wrap(EngineKind::Dag, anchor.to_vec()).encode(),
    };
    Ok(update.encode_to_vec())
}

/// Unwrap a served dag `MembershipEnvelope` payload to the raw anchor bytes — the dag mirror of
/// [`unwrap_chain_keyring`].
///
/// # Errors
/// Returns [`VaultError`] if the bytes aren't a dag-tagged membership envelope.
pub fn unwrap_dag_keyring(bytes: &[u8]) -> Result<Vec<u8>, VaultError> {
    let env = MembershipEnvelope::decode(bytes)
        .map_err(|_| err("served keyring is not a valid membership envelope"))?;
    if env.engine_kind() != Ok(EngineKind::Dag) {
        return Err(err("served keyring envelope is not a dag anchor"));
    }
    Ok(env.body)
}

/// Validate a **recovery/succession reset** keyring against the caller's trusted `anchor` (§B3 slice 4). A
/// reset changes the signer set WITHOUT the old set's endorsement, so `verify_walk` rejects it; this accepts
/// it, but ONLY if it can't roll back or fork: a structurally valid, self-signed, wrap-complete keyring
/// ([`verify_reset`]) chaining onto the anchor by hash at exactly `anchor.revision + 1`, pinning the SAME
/// recovery authority. Trust in the NEW signer set is the CALLER's responsibility (out-of-band re-verify +
/// user confirm BEFORE calling — this is the commit step).
///
/// # Errors
/// Returns [`VaultError`] on a malformed keyring, a tree mismatch, a non-next revision, a broken hash chain,
/// or a rejected reset.
pub fn accept_reset_keyring(
    anchor: &[u8],
    tree_id: &[u8],
    candidate: &[u8],
) -> Result<AcceptedKeyring, VaultError> {
    let anchor_kr = Keyring::decode(anchor).map_err(|e| err(format!("bad anchor keyring: {e}")))?;
    let cand = Keyring::decode(candidate).map_err(|e| err(format!("bad candidate keyring: {e}")))?;
    if anchor_kr.tree_id != tree_id || cand.tree_id != tree_id {
        return Err(err("keyring is for a different tree"));
    }
    // Must supersede our trusted head — never roll back or fork.
    if cand.revision != anchor_kr.revision + 1 {
        return Err(err("a reset must be exactly the next revision after the trusted head"));
    }
    if cand.prev_keyring_hash.as_slice() != keyring_hash(&anchor_kr) {
        return Err(err("reset does not chain onto the trusted head"));
    }
    // Reader-side RVK continuity gate: the candidate must pin the SAME recovery authority the trusted head
    // pinned (and be signed by it). The prior authority is the trusted anchor's own RVK (empty ⇒ inert).
    let prior_rvk = KeyringAnchor::from_keyring(&anchor_kr).recovery_verifying_key;
    let new_anchor = verify_reset((!prior_rvk.is_empty()).then_some(prior_rvk.as_slice()), &cand)
        .map_err(|e| err(e.to_string()))?;
    Ok(AcceptedKeyring {
        keyring: candidate.to_vec(),
        watermark: new_anchor.revision.to_be_bytes().to_vec(),
    })
}

/// Whether this tree HAS BEEN SHARED — a non-founder member was ever admitted — the MONOTONIC signal that
/// gates attributed writes (§B3 slice 2). Chain: `first_shared_revision != 0`. Dag: the resolved anchor's
/// `has_been_shared` (a monotonic effective-`Add` scan). Read from the VERIFIED keyring the caller supplies.
///
/// # Errors
/// Returns [`VaultError`] on a malformed chain keyring or a failed dag resolve.
pub fn keyring_has_been_shared(engine: EngineKind, keyring: &[u8]) -> Result<bool, VaultError> {
    match engine {
        EngineKind::Chain => {
            let kr = Keyring::decode(keyring).map_err(|e| err(format!("bad keyring: {e}")))?;
            Ok(crate::has_been_shared(&kr))
        }
        EngineKind::Dag => {
            let resolved = dag_client::resolve(keyring).map_err(|e| err(e.to_string()))?;
            Ok(resolved.has_been_shared)
        }
    }
}

/// The content hash of a chain keyring revision — what an invite pins so a joiner's genesis-walk can bind the
/// verified history to the exact revision the owner published out-of-band. `keyring` is the RAW chain
/// `Keyring` body.
///
/// # Errors
/// Returns [`VaultError`] if the bytes aren't a decodable chain keyring.
pub fn chain_keyring_hash(keyring: &[u8]) -> Result<Vec<u8>, VaultError> {
    let kr = Keyring::decode(keyring).map_err(|e| err(format!("bad keyring: {e}")))?;
    Ok(keyring_hash(&kr).as_slice().to_vec())
}

/// A joining member's minted account (from [`provision_member`]): the KDF params (already `codec`-encoded,
/// ready to persist) + the two OOB-shareable public keys.
pub struct MemberAccount {
    /// The account's KDF params, `codec`-encoded — persist locally, replay on member unlock.
    pub kdf_params: Vec<u8>,
    /// The Ed25519 author public key — hand to the owner for `add_member`.
    pub author_public_key: Vec<u8>,
    /// The X25519 HPKE public key — hand to the owner for `add_member`.
    pub hpke_public_key: Vec<u8>,
}

/// Mint a joining member's account from their passphrase — the first step of the member flow, before the
/// owner admits them.
///
/// # Errors
/// Returns [`VaultError`] if the member secret derivation fails.
pub fn provision_member(passphrase: &Passphrase) -> Result<MemberAccount, VaultError> {
    let m = vault::provision_member(passphrase)?;
    Ok(MemberAccount {
        kdf_params: keyeo_crypto::codec::encode_kdf_params(&m.kdf_params),
        author_public_key: m.author_public_key,
        hpke_public_key: m.hpke_public_key,
    })
}

/// The moderator `did:key`s (members at Maintainer+) resolved from a keyring — the set the claim engine's
/// fold treats as authorized to remove/supersede/revoke any claim. The worker feeds these to
/// `AppCore::set_moderators` on unlock + every keyring change. Engine-neutral over the resolved membership.
///
/// # Errors
/// Returns [`VaultError`] on a malformed chain keyring or a failed dag resolve.
pub fn moderators_from_keyring(engine: EngineKind, keyring: &[u8]) -> Result<Vec<String>, VaultError> {
    let view = match engine {
        EngineKind::Chain => {
            let kr = Keyring::decode(keyring).map_err(|e| err(format!("bad keyring: {e}")))?;
            openom_keyring_chain::membership_view(&kr)
        }
        EngineKind::Dag => dag_client::resolve(keyring).map_err(|e| err(e.to_string()))?.members,
    };
    Ok(crate::membership::moderators(&view).into_iter().collect())
}

/// A non-owner member's unlock result: the DEK sealer to install in the running core, the member's author
/// `did:key`, the anti-rollback watermark to persist, and the retained epoch-adopt secret.
pub struct MemberUnlock {
    /// The per-epoch DEK sealer (a member is on a shared tree by definition, so it signs entries).
    pub sealer: SealerSet,
    /// The member's author `did:key` (the claim `createdBy`).
    pub did_key: String,
    /// The engine-opaque anti-rollback cursor to persist.
    pub watermark: Vec<u8>,
    /// The member's retained epoch-adopt capability (OPE-393). A member unlock ALWAYS has one (a member is on
    /// a shared tree by definition), so it is non-optional — the running core holds it to splice a later
    /// (post-removal) epoch into its sealer on sync without a passphrase.
    pub epoch_secret: MemberEpochSecret,
    /// Advisory: this member's own DEK bag didn't reach the current write epoch — a locally-derived lockout
    /// signal, immune to the unauthenticated coverage hint a malicious wrap can forge. The running core
    /// responds with a forced `reseal_as_member` (dag only; chain always `false`) (OPE-299).
    pub write_epoch_unreachable: bool,
}

/// A member's retained epoch-adopt capability (OPE-393): the HPKE secret plus the context
/// [`vault_core::member_epoch_deks`](crate) needs to unwrap a LATER epoch's DEK from a synced keyring/anchor
/// WITHOUT the passphrase. The running member core holds this (never exposed to JS) and calls [`adopt`] after
/// a keyring sync that rotated the write epoch (a removal), so it can then OPEN content sealed under the new
/// epoch — the self-heal cover included — and SEAL new entries under it. The counterpart to the owner's
/// passphrase re-unlock, which a member's background sync can't do (no passphrase in scope).
///
/// [`adopt`]: MemberEpochSecret::adopt
pub struct MemberEpochSecret {
    engine: EngineKind,
    hpke_secret: openom_crypto::HpkePrivate,
    tree_id: Vec<u8>,
    member_id: String,
}

/// The epochs a [`MemberEpochSecret::adopt`] recovered from a synced keyring — to splice into the running
/// sealer via [`openom_sealer::SealerSet::adopt_epochs`].
pub struct AdoptedEpochs {
    /// The reachable epoch DEKs `(key_id, dek)`; the sealer skips epochs it already holds (idempotent).
    pub epochs: Vec<(Vec<u8>, openom_crypto::Key32)>,
    /// The new write epoch's `key_id` — the highest-ordinal epoch the member can actually reach.
    pub write_key_id: Vec<u8>,
    /// The refreshed `governing_ref` for the new write epoch, so the member's attributed writes stamp the
    /// current head (empty on a never-shared tree, where writes are unattributed).
    pub governing_ref: Vec<u8>,
}

impl MemberEpochSecret {
    /// Re-derive the reachable epoch DEKs from a freshly-synced keyring/anchor — a member's counterpart to the
    /// owner re-unlock, needing no passphrase. The caller splices the result into the running sealer.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the keyring/anchor is malformed or the member now reaches NO epoch (a removed
    /// member — the caller treats that as "nothing to adopt", not a hard failure).
    pub fn adopt(&self, keyring: &[u8]) -> Result<AdoptedEpochs, VaultError> {
        match self.engine {
            EngineKind::Chain => {
                vault::adopt_member_epochs(keyring, &self.hpke_secret, &self.tree_id, &self.member_id)
            }
            EngineKind::Dag => {
                DagVault.adopt_member_epochs(keyring, &self.hpke_secret, &self.tree_id, &self.member_id)
            }
        }
    }
}

/// Parse a role tag into the chain engine's [`MemberRole`]. Accepts the canonical `"maintainer"` (the app's
/// role vocabulary) as well as the chain's own `"admin"` tag for it, so ONE role string from the JS caller
/// resolves on either engine (the dag's `parse_keyring_role` speaks `"maintainer"`).
fn parse_member_role(s: &str) -> Result<MemberRole, VaultError> {
    match s {
        "owner" => Ok(MemberRole::Owner),
        "co-owner" => Ok(MemberRole::CoOwner),
        "maintainer" | "admin" => Ok(MemberRole::Admin),
        "editor" => Ok(MemberRole::Editor),
        "viewer" => Ok(MemberRole::Viewer),
        other => Err(err(format!("unknown role: {other}"))),
    }
}

/// Parse a role tag into the dag engine's [`KeyringRole`].
fn parse_keyring_role(s: &str) -> Result<KeyringRole, VaultError> {
    match s {
        "owner" => Ok(KeyringRole::OWNER),
        "co-owner" => Ok(KeyringRole::CO_OWNER),
        "maintainer" => Ok(KeyringRole::MAINTAINER),
        "editor" => Ok(KeyringRole::EDITOR),
        "viewer" => Ok(KeyringRole::VIEWER),
        other => Err(err(format!("unknown role: {other}"))),
    }
}

/// Split a flat buffer of concatenated 32-byte Ed25519 verify-keys into pinned signer keys. At least one is
/// required and the length must be a whole multiple of 32.
fn parse_trusted_signers(bytes: &[u8]) -> Result<Vec<VerifyingKey>, VaultError> {
    if bytes.is_empty() || bytes.len() % 32 != 0 {
        return Err(err("trustedSigners must be one or more concatenated 32-byte keys"));
    }
    bytes
        .chunks_exact(32)
        .map(|c| {
            let arr: [u8; 32] = c.try_into().expect("chunks_exact(32) yields 32 bytes");
            VerifyingKey::from_bytes(&arr).map_err(|_| err("invalid trusted signer key"))
        })
        .collect()
}

/// Add a member (owner action) — HPKE-wrap the tree DEK to the OOB-verified joiner keys + record them in a
/// new signed keyring revision (chain) / `Add` op (dag). Returns the new keyring/anchor + its watermark to
/// persist; the owner's own session is unchanged (an add mints no new epoch), so it just re-reads membership.
///
/// # Errors
/// Returns [`VaultError`] on a malformed keyring, a wrong owner passphrase, a bad joiner key, or an
/// unauthorized add.
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    engine: EngineKind,
    keyring: &[u8],
    owner_passphrase: &Passphrase,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
    new_member_id: &str,
    role: &str,
    member_author_public: &[u8],
    member_hpke_public: &[u8],
) -> Result<AcceptedKeyring, VaultError> {
    let joiner_id = MemberId::new(new_member_id);
    match engine {
        EngineKind::Chain => {
            let added = vault::add_member(
                keyring,
                owner_passphrase,
                &TreeId::new(tree_id),
                &MemberId::new(owner_member_id),
                min_revision,
                &vault::Joiner::from_bytes(
                    &joiner_id,
                    parse_member_role(role)?,
                    member_author_public,
                    member_hpke_public,
                )?,
            )?;
            Ok(AcceptedKeyring {
                keyring: added.keyring,
                watermark: chain_wm_pinned(
                    added.revision,
                    &added.write_key_id,
                    &added.write_dek_hash,
                ),
            })
        }
        EngineKind::Dag => {
            let (tree, owner, replica) = (
                TreeId::new(tree_id),
                MemberId::new(owner_member_id),
                ReplicaId::new(replica_id),
            );
            let ctx = VaultContext {
                tree_id: &tree,
                member_id: &owner,
                replica_id: &replica,
            };
            let joiner = vault::Joiner::from_bytes(
                &joiner_id,
                parse_keyring_role(role)?,
                member_author_public,
                member_hpke_public,
            )?;
            let anchor = DagVault.add_member(&ctx, keyring, owner_passphrase, &joiner)?;
            let watermark = DagVault.watermark(&anchor)?;
            Ok(AcceptedKeyring {
                keyring: anchor,
                watermark,
            })
        }
    }
}

/// Remove a member (owner action) with **forward-secure revocation** — mint a fresh DEK under a new epoch,
/// wrap it only for those who remain, and record the removal in a new signed keyring revision (chain) /
/// `Remove` op (dag). Returns the new keyring/anchor + its watermark to persist. Unlike an add, a removal
/// ROTATES the write epoch, so the owner's running sealer is now stale — the caller must re-unlock on the new
/// keyring to obtain a signing sealer under the fresh epoch (the worker does this, then authors a self-heal
/// cover so the removed member's prior history stays verifiable — dag only).
///
/// # Errors
/// Returns [`VaultError`] on a malformed keyring, a wrong owner passphrase, an attempt to remove the owner, an
/// unknown member, or an unauthorized removal.
#[allow(clippy::too_many_arguments)]
pub fn remove_member(
    engine: EngineKind,
    keyring: &[u8],
    owner_passphrase: &Passphrase,
    tree_id: &[u8],
    owner_member_id: &str,
    replica_id: &[u8],
    min_revision: u32,
    remove_member_id: &str,
) -> Result<AcceptedKeyring, VaultError> {
    match engine {
        EngineKind::Chain => {
            let removed = vault::remove_member(
                keyring,
                owner_passphrase,
                &TreeId::new(tree_id),
                &MemberId::new(owner_member_id),
                min_revision,
                &MemberId::new(remove_member_id),
                &ReplicaId::new(replica_id),
            )?;
            Ok(AcceptedKeyring {
                keyring: removed.keyring,
                watermark: chain_wm_pinned(
                    removed.revision,
                    &removed.write_key_id,
                    &removed.write_dek_hash,
                ),
            })
        }
        EngineKind::Dag => {
            let (tree, owner, replica) = (
                TreeId::new(tree_id),
                MemberId::new(owner_member_id),
                ReplicaId::new(replica_id),
            );
            let ctx = VaultContext {
                tree_id: &tree,
                member_id: &owner,
                replica_id: &replica,
            };
            let anchor = DagVault.remove_member(&ctx, keyring, owner_passphrase, remove_member_id)?;
            let watermark = DagVault.watermark(&anchor)?;
            Ok(AcceptedKeyring {
                keyring: anchor,
                watermark,
            })
        }
    }
}

/// Unlock a shared tree as a non-owner member — verify against the pinned `trusted_signers` (chain) / resolve
/// the anchor (dag), then HPKE-unwrap the member's DEKs with their passphrase + account KDF. Returns a sealer
/// to install in the core. `trusted_signers` is ignored by the dag (it resolves admission from the anchor).
///
/// # Errors
/// Returns [`VaultError`] on a malformed keyring, a wrong passphrase, an unpinned signer, or a removed member.
#[allow(clippy::too_many_arguments)]
pub fn unlock_as_member(
    engine: EngineKind,
    keyring: &[u8],
    passphrase: &Passphrase,
    member_kdf_params: &[u8],
    tree_id: &[u8],
    member_id: &str,
    trusted_signers: &[u8],
    replica_id: &[u8],
    min_revision: u32,
) -> Result<MemberUnlock, VaultError> {
    let kdf =
        keyeo_crypto::codec::decode_kdf_params(member_kdf_params).map_err(|_| err("bad kdf params"))?;
    let member = MemberId::new(member_id);
    let epoch_secret = |engine, hpke_secret| MemberEpochSecret {
        engine,
        hpke_secret,
        tree_id: tree_id.to_vec(),
        member_id: member_id.to_string(),
    };
    match engine {
        EngineKind::Chain => {
            let trusted = parse_trusted_signers(trusted_signers)?;
            let (u, hpke_secret) = vault::unlock_as_member(
                keyring,
                &vault::MemberAuth {
                    passphrase,
                    kdf: &kdf,
                    member_id: &member,
                    trusted_signers: &trusted,
                },
                &TreeId::new(tree_id),
                &ReplicaId::new(replica_id),
                min_revision,
            )?;
            Ok(MemberUnlock {
                sealer: u.sealer,
                did_key: u.did_key.into_string(),
                watermark: chain_wm_pinned(u.revision, &u.write_key_id, &u.write_dek_hash),
                epoch_secret: epoch_secret(EngineKind::Chain, hpke_secret),
                write_epoch_unreachable: false, // a linear chain always reaches its own write epoch (OPE-299)
            })
        }
        EngineKind::Dag => {
            let (tree, replica) = (TreeId::new(tree_id), ReplicaId::new(replica_id));
            let ctx = VaultContext {
                tree_id: &tree,
                member_id: &member,
                replica_id: &replica,
            };
            let (u, hpke_secret) = DagVault.unlock_as_member(&ctx, keyring, passphrase, &kdf)?;
            Ok(MemberUnlock {
                sealer: u.sealer,
                did_key: u.did_key.into_string(),
                watermark: u.watermark,
                epoch_secret: epoch_secret(EngineKind::Dag, hpke_secret),
                write_epoch_unreachable: u.write_epoch_unreachable,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        chain_wm_pinned, frame_length_prefixed, split_length_prefixed, unwrap_chain_keyring,
    };
    use openom_keyring_api::{EngineKind, MembershipEnvelope};
    use openom_protocol::Message;

    #[test]
    fn frame_and_split_round_trip() {
        let runs = vec![vec![1u8, 2, 3], Vec::new(), vec![9u8; 100]];
        let framed = frame_length_prefixed(&runs);
        let split = split_length_prefixed(&framed).unwrap();
        assert_eq!(split.len(), 3);
        assert_eq!(split[0], [1, 2, 3]);
        assert!(split[1].is_empty());
        assert_eq!(split[2], vec![9u8; 100].as_slice());
    }

    #[test]
    fn split_rejects_a_frame_that_overruns_its_length() {
        // Claims 5 bytes but only 2 follow.
        assert!(split_length_prefixed(&[0, 0, 0, 5, 1, 2]).is_err());
        // A dangling partial length prefix.
        assert!(split_length_prefixed(&[0, 0]).is_err());
    }

    #[test]
    fn unwrap_chain_keyring_round_trips_and_refuses_non_chain() {
        let body = b"raw-chain-keyring-bytes".to_vec();
        let chain = MembershipEnvelope::wrap(EngineKind::Chain, body.clone()).encode();
        assert_eq!(unwrap_chain_keyring(&chain).unwrap(), body);

        let dag = MembershipEnvelope::wrap(EngineKind::Dag, body).encode();
        assert!(unwrap_chain_keyring(&dag).is_err(), "a dag envelope is refused");
        assert!(unwrap_chain_keyring(b"not an envelope").is_err());
    }

    #[test]
    fn chain_wm_pinned_emits_the_full_pin_or_falls_back_to_revision() {
        let full = chain_wm_pinned(7, &[1u8; 16], &[2u8; 32]);
        assert_eq!(full.len(), 4 + 16 + 32);
        assert_eq!(&full[..4], 7u32.to_be_bytes());
        // A wrongly-sized key id / dek hash falls back to a bare revision.
        assert_eq!(chain_wm_pinned(7, &[1u8; 8], &[2u8; 32]), 7u32.to_be_bytes().to_vec());
    }

    /// SPIKE (OPE-388 de-risk): drive the CHAIN genesis-walk member-join end-to-end at the rlib level, to
    /// validate the exact data flow the worker JS must marshal — wrap each revision as the server's
    /// `MembershipEnvelope`, frame the hops, `verify_keyring_walk` from the genesis pin, then `unlock_as_member`
    /// at the verified head. If this passes, the worker join is just marshalling these calls.
    #[test]
    fn chain_genesis_walk_join_end_to_end() {
        use crate::vault;
        use openom_crypto::Passphrase;
        use openom_keyring_chain::{keyring_hash, wire::Keyring};
        use openom_protocol::ids::{MemberId, ReplicaId, TreeId};

        let tree = TreeId::new(b"tree-uuid-16byte".to_vec());
        let owner = MemberId::new("acct-owner");
        let owner_pass = Passphrase::new(b"owner passphrase".to_vec());

        // Owner provisions the genesis (rev 1); bob mints his member account; owner admits bob (rev 2).
        let prov = vault::provision(&owner_pass, &tree, &owner, &ReplicaId::new(b"ro".to_vec())).unwrap();
        let owner_key = prov.did_key.to_public_key(); // the signer bob pins
        let bob_pass = Passphrase::new(b"bob passphrase".to_vec());
        let bob = vault::provision_member(&bob_pass).unwrap();
        let shared = super::add_member(
            EngineKind::Chain, &prov.keyring, &owner_pass, b"tree-uuid-16byte", "acct-owner", b"ro", 1,
            "acct-bob", "editor", &bob.author_public_key, &bob.hpke_public_key,
        )
        .unwrap()
        .keyring;

        // The server stores each revision as a MembershipEnvelope; the joiner pulls them framed as hops.
        let hops = frame_length_prefixed(&[
            MembershipEnvelope::wrap(EngineKind::Chain, prov.keyring.clone()).encode(),
            MembershipEnvelope::wrap(EngineKind::Chain, shared.clone()).encode(),
        ]);
        let pin_hash = keyring_hash(&Keyring::decode(prov.keyring.as_slice()).unwrap())
            .as_slice()
            .to_vec();

        // Genesis-walk + invite-pin (pin the genesis rev 1).
        let walk = super::verify_keyring_walk(b"tree-uuid-16byte", &hops, 1, &pin_hash).unwrap();
        assert_eq!(walk.revision, 2, "walks to the shared head");
        assert_eq!(walk.head_keyring, shared, "head body is the rev-2 keyring");
        assert_eq!(split_length_prefixed(&walk.bodies_framed).unwrap().len(), 2, "retains both revisions");

        // Bob joins at the verified head, pinning the owner as the trusted signer.
        let unlocked = super::unlock_as_member(
            EngineKind::Chain, &walk.head_keyring, &bob_pass,
            &keyeo_crypto::codec::encode_kdf_params(&bob.kdf_params),
            b"tree-uuid-16byte", "acct-bob", &owner_key, b"rb", walk.revision,
        )
        .unwrap();
        assert!(!unlocked.did_key.is_empty(), "bob unlocks as a member and gets his author did:key");
        assert_eq!(unlocked.watermark.len(), 4 + 16 + 32, "the head watermark is the OPE-286 pinned form");
    }
}
