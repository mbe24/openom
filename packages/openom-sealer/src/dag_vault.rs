//! The DAG keyring's vault (OPE-273) — the dag-engine counterpart to [`crate::vault`], producing the same
//! [`SealerSet`] through the shared sealing core ([`crate::vault_core`]) while resolving membership +
//! recovery authority through the DAG keyring's client facade (`openom_keyring_dag::client`).
//!
//! The trust anchor is engine-opaque bytes: the dag's pinned genesis config + op closure, with the DEK
//! epochs + recovery escrow riding the ops' `sealing` payloads (the design pass converged on this — one
//! signed channel, folded alongside membership). `dag_vault.rs` never touches `keyeo` directly (a one-line
//! import grep enforces it); it drives the facade.
//!
//! STATUS: all four [`KeyringLifecycle`] flows are built — provision, unlock, recover (RVK-authorized
//! ReFound), change_passphrase (current-key Retarget) — with membership authoring (add/remove with
//! member-unlock), the effective-op sealing fold (reset-merge carve-out / quorum-Commit), and the
//! anti-rollback watermark (the anchor's frontier op-id set; enforced as a floor on recover +
//! change_passphrase). DagVault is interchangeable with ChainVault behind the trait.

use openom_crypto::{
    derive_kek, derive_root, derive_rvk, generate_dek, generate_hpke_keypair, generate_salt,
    parse_recovery_code, unwrap_rrk_secret, CryptoError, HpkeKeypair, Passphrase, RecoveryCode,
    RrkSecret,
};
use openom_did::DidKey;
use openom_keyring_dag::{client as dag_client, KeyringRole};
use openom_protocol::v1::KdfParams;
use serde::{Deserialize, Serialize};

use crate::lifecycle::{
    KeyringLifecycle, Provisioned, Recovered, Rekeyed, Unlocked, VaultContext,
};
use crate::vault_core::{
    build_recovery_escrow, epoch_deks, member_epoch_deks, member_wrap_epoch, new_owner_secrets,
    rrk_wrap_epoch, sealer_set_from_deks, validate_kdf, CoreKdf, CoreWrap, RecoveryEscrow,
    SealedEpoch, HPKE, PASSPHRASE, RECOVERY, RRK_HPKE,
};
use openom_keyring_seam::MembershipView;
use crate::SealerError;

/// The opaque **delta** an op carries in its `sealing` field. The vault folds these (in effective-op
/// order) into the current sealing state: `new_epochs` are inserted (genesis's epoch-0; a member removal's
/// forward-secret epoch), `added_wraps` are appended to existing epochs (an add-member's per-epoch wraps
/// for the joiner), and `escrow` sets the recovery escrow (`None` = unchanged). Deltas — not snapshots —
/// so it stays CRDT-clean (concurrent additions both survive) and compact. (JSON today, matching the dag
/// op codec; a compact/binary form is a later perf task.)
#[derive(Serialize, Deserialize)]
pub(crate) struct SealingPayload {
    new_epochs: Vec<SealedEpoch>,
    added_wraps: Vec<AddedWrap>,
    escrow: Option<RecoveryEscrow>,
}

/// A wrap added to an EXISTING epoch (identified by `key_id`) — how an add-member gives the joiner access
/// to an epoch without minting a new one.
#[derive(Serialize, Deserialize)]
pub(crate) struct AddedWrap {
    key_id: Vec<u8>,
    wrap: CoreWrap,
}

impl SealingPayload {
    /// A payload that only sets/re-sets the escrow (provision's is built inline; recover / change_passphrase
    /// re-escrow with no epoch change).
    fn escrow_only(escrow: RecoveryEscrow) -> Self {
        SealingPayload {
            new_epochs: vec![],
            added_wraps: vec![],
            escrow: Some(escrow),
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SealingPayload serialization is infallible")
    }
}

/// Fold the effective ops' sealing deltas into the current epochs + escrow + the deterministic write epoch
/// + whether it needs a reseal. `new_epochs` are retained only from Genesis/Remove/Reseal ops (an epoch
/// from any other op is anomalous — a smuggled self-only epoch — and dropped); `added_wraps` attach to the
/// matching existing epoch (an unknown-epoch wrap is skipped); the latest escrow wins. The write epoch is
/// the greatest `(ordinal, op-id)` among ELIGIBLE epochs (genesis/remove always, reseal iff it covers the
/// resolved membership), so a concurrent same-ordinal tie resolves identically on every replica and a
/// wrong-set reseal can never win. Errors if no escrow / no eligible epoch was ever set.
fn fold_sealing(
    sealing: &[dag_client::SealingEntry],
    members: &MembershipView,
) -> Result<FoldedSealing, SealerError> {
    use dag_client::SealingOrigin;
    // Each retained epoch tagged with (origin, minting op-id). Only Genesis/Remove/Reseal ops may MINT an
    // epoch — a new_epoch from any Other op is anomalous (a self-Retarget/self-Remove smuggling a self-only
    // epoch) and is dropped: no legitimate write is ever sealed under it, so it never needs retaining.
    let mut tagged: Vec<(SealedEpoch, SealingOrigin, [u8; 32])> = Vec::new();
    let mut escrow: Option<RecoveryEscrow> = None;
    for entry in sealing {
        let payload: SealingPayload = serde_json::from_slice(&entry.bytes)
            .map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        for e in payload.new_epochs {
            match entry.origin {
                SealingOrigin::Genesis | SealingOrigin::Remove | SealingOrigin::Reseal => {
                    tagged.push((e, entry.origin, entry.op_id));
                }
                SealingOrigin::Other => {}
            }
        }
        // added_wraps attach a member's wrap to an EXISTING epoch (an add-member's joiner wraps ride an
        // Other-origin Add op — legitimate, unlike minting) — applied post-fold so coverage sees them.
        for aw in payload.added_wraps {
            if let Some((ep, _, _)) = tagged.iter_mut().find(|(e, _, _)| e.key_id == aw.key_id) {
                ep.wraps.push(aw.wrap);
            }
        }
        if payload.escrow.is_some() {
            escrow = payload.escrow;
        }
    }
    let escrow =
        escrow.ok_or_else(|| SealerError::BadKeyring("dag keyring has no recovery escrow".into()))?;

    // The write epoch is the deterministic winner among ELIGIBLE epochs — genesis/remove are always
    // eligible (the legitimate baseline), a reseal only if it COVERS the resolved membership, so a
    // self-only or wrong-set reseal can never win regardless of ordinal grinding. Among eligible, the
    // greatest (ordinal, op-id). `needs_reseal` = the winner's wrap set is stale vs the resolved membership.
    let mut winner: Option<(u32, [u8; 32], Vec<u8>, bool)> = None;
    for (ep, origin, op_id) in &tagged {
        let covers = epoch_covers(ep, members);
        let eligible = match origin {
            SealingOrigin::Genesis | SealingOrigin::Remove => true,
            SealingOrigin::Reseal => covers,
            SealingOrigin::Other => false,
        };
        if eligible
            && winner
                .as_ref()
                .is_none_or(|(we, wid, _, _)| (ep.epoch, *op_id) > (*we, *wid))
        {
            winner = Some((ep.epoch, *op_id, ep.key_id.clone(), covers));
        }
    }
    let (_, _, write_key_id, winner_covers) = winner.ok_or(SealerError::MissingWrap)?;

    Ok(FoldedSealing {
        epochs: tagged.into_iter().map(|(e, _, _)| e).collect(),
        escrow,
        write_key_id,
        needs_reseal: !winner_covers,
    })
}

/// The result of folding the sealing deltas: the retained epochs (for reads), the recovery escrow, the
/// deterministic write-epoch `key_id` (the winner), and whether the winner is stale vs the resolved
/// membership (`needs_reseal`).
struct FoldedSealing {
    epochs: Vec<SealedEpoch>,
    escrow: RecoveryEscrow,
    write_key_id: Vec<u8>,
    needs_reseal: bool,
}

/// The result of [`DagVault::reseal`]: the (possibly unchanged) anchor to publish + its watermark, and
/// whether a repair was actually appended (`false` = nothing was stale, a no-op).
pub struct Resealed {
    pub anchor: Vec<u8>,
    pub watermark: Vec<u8>,
    pub resealed: bool,
}

/// Whether `epoch`'s wraps exactly serve the resolved membership: an RRK wrap for the owner, plus an HPKE
/// member wrap for each — and ONLY each — resolved non-owner member. A mismatch means the epoch is stale vs
/// the merged membership — a concurrently-removed member still wrapped (a leak) or a concurrently-added
/// member missing (a lockout) — so a reseal is needed. Member-id level for now; binding the recipient's
/// HPKE key is a later precision refinement (a wrong-key wrap is safe meanwhile — it fails at decrypt and
/// self-heals via a corrective reseal).
fn epoch_covers(epoch: &SealedEpoch, members: &MembershipView) -> bool {
    use std::collections::HashSet;
    let has_rrk = epoch.wraps.iter().any(|w| w.wrap_method == RRK_HPKE);
    let wrapped: HashSet<&str> = epoch
        .wraps
        .iter()
        .filter(|w| w.wrap_method == HPKE)
        .map(|w| w.member_id.as_str())
        .collect();
    let resolved: HashSet<&str> = members
        .members
        .iter()
        .filter(|m| !m.is_owner())
        .map(|m| m.member_id.as_str())
        .collect();
    has_rrk && wrapped == resolved
}

/// Map a facade anti-rollback failure onto the sealer's error vocabulary: a rolled-back anchor and a
/// corrupt floor stay distinct (mirroring the chain's `RevisionRollback` / `MalformedWatermark`); anything
/// else (a bad anchor) is a `BadKeyring`.
fn map_floor_err(e: dag_client::ClientError) -> SealerError {
    match e {
        dag_client::ClientError::RolledBack(detail) => SealerError::WatermarkRollback { detail },
        dag_client::ClientError::BadWatermark(_) => SealerError::MalformedWatermark,
        other => SealerError::BadKeyring(other.to_string()),
    }
}

/// The DAG engine's vault — a zero-sized selector, like [`crate::lifecycle::ChainVault`]. Its anchor is the
/// dag keyring's pinned-config + op-closure bytes; each flow resolves membership through the facade and DEK
/// material through the shared core.
pub struct DagVault;

impl KeyringLifecycle for DagVault {
    /// Create a brand-new dag-backed tree: mint a fresh DEK (epoch 0), a recovery root key escrowing it,
    /// and a content-addressed genesis op naming the founder as Owner + carrying epoch-0 and the escrow in
    /// its `sealing` payload, with the derived RVK pinned as the recovery authority.
    fn provision(
        &self,
        ctx: &VaultContext,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        let dek = generate_dek()?;
        let key_id = generate_salt()?.to_vec();
        let HpkeKeypair {
            secret,
            public: rrk_public,
        } = generate_hpke_keypair()?;
        let rrk_secret = RrkSecret::from(secret);
        let secrets = new_owner_secrets(passphrase.expose())?;

        // Epoch 0: the founder reaches the DEK via the RRK wrap (as on the chain).
        let rrk_wrap = rrk_wrap_epoch(&rrk_public, &dek, tree_id, member_id, &key_id)?;
        let epoch0 = SealedEpoch {
            key_id: key_id.clone(),
            epoch: 0,
            wraps: vec![rrk_wrap],
        };
        let escrow = build_recovery_escrow(&rrk_secret, &rrk_public, tree_id, member_id, &secrets)?;

        let author_public = secrets.root.identity.verifying_key().to_bytes();
        let did_key = DidKey::from_public_key(&author_public);
        let rvk_public = derive_rvk(rrk_secret.expose()).verifying_key().to_bytes();

        let sealing = SealingPayload {
            new_epochs: vec![epoch0],
            added_wraps: vec![],
            escrow: Some(escrow),
        }
        .to_bytes();
        let anchor = dag_client::provision_anchor(
            member_id,
            author_public,
            secrets.root.hpke_public,
            rvk_public,
            sealing,
            &secrets.root.identity,
        );

        let sealer = sealer_set_from_deks(tree_id, replica_id, vec![(key_id.clone(), 0, dek)], key_id)?;
        let watermark = dag_client::watermark(&anchor).map_err(map_floor_err)?;
        Ok(Provisioned {
            anchor,
            recovery_code: secrets.recovery_code,
            sealer,
            did_key,
            watermark,
        })
    }

    /// Re-open a dag-backed tree from its anchor + passphrase: resolve the membership, fold the sealing
    /// state, derive the KEK from the passphrase, unwrap the RRK, and open every epoch's DEK into a sealer.
    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
    ) -> Result<Unlocked, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| SealerError::BadKeyring("no owner in the resolved dag keyring".into()))?;

        let FoldedSealing { epochs, escrow, write_key_id, needs_reseal } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // The RRK is wrapped under the passphrase KEK: derive it via that wrap's KDF.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(SealerError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| SealerError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
        validate_kdf(kdf)?;
        let root = derive_root(passphrase.expose(), &KdfParams::from(kdf))?;

        // Anti-substitution: the passphrase-derived identity must be the RESOLVED Owner's key (not the
        // pinned genesis — a Retarget/ReFound legitimately retargets it), so a wrong passphrase — or a
        // swapped owner — fails here, before any unwrap.
        if root.identity.verifying_key().to_bytes().as_slice() != founder.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        let rrk_secret = unwrap_rrk_secret(
            &root.kek,
            &pass_wrap.nonce,
            &pass_wrap.wrapped_dek,
            tree_id,
            member_id,
            PASSPHRASE,
        )?;
        let deks = epoch_deks(&epochs, tree_id, member_id, &rrk_secret)?;
        let sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id)?;

        let owner_key: [u8; 32] = founder
            .author_public_key
            .as_slice()
            .try_into()
            .map_err(|_| SealerError::BadKeyring("owner key is not 32 bytes".into()))?;
        Ok(Unlocked {
            sealer,
            // The anti-rollback watermark is the anchor's frontier (opaque to us). unlock takes no floor —
            // it reports the cursor the caller persists and passes back as the floor on the next mutation.
            watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
            did_key: DidKey::from_public_key(&owner_key),
            needs_reseal,
        })
    }

    /// Recover with the recovery code: unwrap the RRK via the code, re-establish owner access under
    /// `new_passphrase` (fresh identity + recovery code), and append an RVK-signed `ReFound` retargeting the
    /// Owner + carrying the re-escrow. The RRK — and every DEK it reaches — is UNCHANGED (re-wrap, not
    /// rotate), so the RVK is the same and the ReFound is authorized by the pinned recovery authority, and
    /// the returned sealer opens exactly the same data.
    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        // Anti-rollback: the served anchor is untrusted on recovery, so refuse one that dropped a frontier
        // op below the caller's floor before doing any work.
        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        // Resolve the current sealing → the escrow, and unwrap the RRK via the recovery code.
        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let FoldedSealing { epochs, escrow, write_key_id, needs_reseal } = fold_sealing(&resolved.sealing, &resolved.members)?;
        let rec_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == RECOVERY)
            .ok_or(SealerError::MissingWrap)?;
        let rec_kdf = rec_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| SealerError::BadKeyring("escrow recovery wrap missing kdf".into()))?;
        validate_kdf(rec_kdf)?;
        let entropy = parse_recovery_code(recovery_code)?;
        let rec_kek = derive_kek(entropy.as_slice(), &KdfParams::from(rec_kdf))?;
        let rrk_secret = unwrap_rrk_secret(
            &rec_kek,
            &rec_wrap.nonce,
            &rec_wrap.wrapped_dek,
            tree_id,
            member_id,
            RECOVERY,
        )?;

        // Re-establish owner access under the new passphrase, re-wrapping the SAME RRK.
        let secrets = new_owner_secrets(new_passphrase.expose())?;
        let new_escrow =
            build_recovery_escrow(&rrk_secret, &escrow.public_key, tree_id, member_id, &secrets)?;
        let new_author = secrets.root.identity.verifying_key().to_bytes();
        let did_key = DidKey::from_public_key(&new_author);

        // Mint the RVK-signed ReFound retargeting the Owner, carrying the new escrow in its sealing.
        let rvk = derive_rvk(rrk_secret.expose());
        let sealing = SealingPayload::escrow_only(new_escrow).to_bytes();
        let new_anchor = dag_client::append_refound(
            anchor,
            member_id,
            new_author,
            secrets.root.hpke_public,
            // era is a UX/rate-limit scalar only; a monotone counter is a later refinement (single recover).
            1,
            sealing,
            &rvk,
        )
        .map_err(|e| SealerError::BadKeyring(e.to_string()))?;

        // The DEK is unchanged, so the sealer opens the same epochs via the RRK.
        let deks = epoch_deks(&epochs, tree_id, member_id, &rrk_secret)?;
        let sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id)?;

        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Recovered {
            anchor: new_anchor,
            recovery_code: secrets.recovery_code,
            sealer,
            watermark,
            did_key,
            needs_reseal,
        })
    }

    /// Change the passphrase: unwrap the RRK via the OLD passphrase, re-establish owner access under
    /// `new_passphrase` (fresh identity + recovery code) by re-wrapping the SAME RRK, and append an ordinary
    /// (current-key-signed) `Retarget` op retargeting the Owner to the new identity + carrying the new
    /// escrow in its sealing. The DEK is unchanged, so any running sealer keeps working — no re-seal, and no
    /// sealer is returned.
    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| SealerError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing { escrow, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // Unwrap the RRK via the OLD passphrase, checking the derived identity is the resolved Owner.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(SealerError::MissingWrap)?;
        let old_kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| SealerError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
        validate_kdf(old_kdf)?;
        let old_root = derive_root(old_passphrase.expose(), &KdfParams::from(old_kdf))?;
        if old_root.identity.verifying_key().to_bytes().as_slice() != founder.author_public_key.as_slice()
        {
            return Err(CryptoError::Signature.into());
        }
        let rrk_secret = unwrap_rrk_secret(
            &old_root.kek,
            &pass_wrap.nonce,
            &pass_wrap.wrapped_dek,
            tree_id,
            member_id,
            PASSPHRASE,
        )?;

        // Re-establish under the new passphrase, re-wrapping the SAME RRK (re-wrap, not rotate).
        let secrets = new_owner_secrets(new_passphrase.expose())?;
        let new_escrow =
            build_recovery_escrow(&rrk_secret, &escrow.public_key, tree_id, member_id, &secrets)?;
        let new_author = secrets.root.identity.verifying_key().to_bytes();

        // Mint the Retarget signed by the OLD (current) owner key, retargeting to the new identity.
        let sealing = SealingPayload::escrow_only(new_escrow).to_bytes();
        let new_anchor = dag_client::append_retarget(
            anchor,
            member_id,
            new_author,
            secrets.root.hpke_public,
            sealing,
            &old_root.identity,
        )
        .map_err(|e| SealerError::BadKeyring(e.to_string()))?;

        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Rekeyed {
            anchor: new_anchor,
            recovery_code: secrets.recovery_code,
            watermark,
        })
    }
}

impl DagVault {
    /// Merge a remote anchor of the SAME tree into the local one — the causal set-union of their op closures
    /// (the op-DAG is a set-union CRDT), so concurrent membership branches both survive and resolve
    /// deterministically. The host calls this to fold in a peer's anchor before persisting + re-watermarking;
    /// a following `unlock` reports `needs_reseal` if the merged write epoch is stale (see [`Self::reseal`]).
    pub fn merge(&self, local: &[u8], remote: &[u8]) -> Result<Vec<u8>, SealerError> {
        dag_client::merge(local, remote).map_err(|e| SealerError::BadKeyring(e.to_string()))
    }

    /// The anchor's opaque anti-rollback watermark (its frontier op-id set) — the cursor the host persists
    /// alongside the anchor and passes back as the floor on the next mutation. Opaque bytes to every caller.
    pub fn watermark(&self, anchor: &[u8]) -> Result<Vec<u8>, SealerError> {
        dag_client::watermark(anchor).map_err(map_floor_err)
    }

    /// Add `new_member_id` (at `role`, with their OOB-verified keys) to a dag tree. The owner unwraps the
    /// RRK via their passphrase, reaches every epoch's DEK, wraps each to the new member's HPKE key, and
    /// appends an `Add` op carrying those per-epoch wraps in its sealing. Returns the new anchor. Inherent,
    /// not a [`KeyringLifecycle`] flow — membership authoring stays engine-specific (OPE-277 gate, Q2=B).
    #[allow(clippy::too_many_arguments)]
    pub fn add_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        owner_passphrase: &Passphrase,
        new_member_id: &str,
        role: KeyringRole,
        new_member_author_public: [u8; 32],
        new_member_hpke_public: [u8; 32],
    ) -> Result<Vec<u8>, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let owner_id = ctx.member_id.as_str();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| SealerError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing { epochs, escrow, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // The owner unwraps the RRK via their passphrase (anti-substitution vs the resolved Owner key).
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(SealerError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| SealerError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
        validate_kdf(kdf)?;
        let root = derive_root(owner_passphrase.expose(), &KdfParams::from(kdf))?;
        if root.identity.verifying_key().to_bytes().as_slice() != founder.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }
        let rrk_secret = unwrap_rrk_secret(
            &root.kek,
            &pass_wrap.nonce,
            &pass_wrap.wrapped_dek,
            tree_id,
            owner_id,
            PASSPHRASE,
        )?;

        // Reach every epoch's DEK and wrap each to the new member's HPKE key.
        let deks = epoch_deks(&epochs, tree_id, owner_id, &rrk_secret)?;
        let added_wraps: Vec<AddedWrap> = deks
            .iter()
            .map(|(key_id, _epoch, dek)| {
                member_wrap_epoch(&new_member_hpke_public, dek, tree_id, new_member_id, key_id)
                    .map(|wrap| AddedWrap {
                        key_id: key_id.clone(),
                        wrap,
                    })
            })
            .collect::<Result<_, _>>()?;

        let sealing = SealingPayload {
            new_epochs: vec![],
            added_wraps,
            escrow: None,
        }
        .to_bytes();
        dag_client::append_add(
            anchor,
            owner_id,
            new_member_id,
            role,
            new_member_author_public,
            new_member_hpke_public,
            sealing,
            &root.identity,
        )
        .map_err(|e| SealerError::BadKeyring(e.to_string()))
    }

    /// Unlock as an ORDINARY member (not the owner): resolve the keyring, find `ctx.member_id`, derive their
    /// identity from their passphrase + their account `member_kdf`, check it against their resolved key
    /// (anti-substitution), and reach the DEKs via their OWN per-epoch HPKE wraps (join-epoch-onward) — not
    /// the RRK, which only the owner holds. Inherent (the trait `unlock` is the owner/RRK path).
    pub fn unlock_as_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
        member_kdf: &KdfParams,
    ) -> Result<Unlocked, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let me = resolved
            .members
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| SealerError::BadKeyring("not a member of this tree".into()))?;
        let FoldedSealing { epochs, write_key_id, needs_reseal, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        validate_kdf(&CoreKdf::from(member_kdf))?;
        let root = derive_root(passphrase.expose(), member_kdf)?;
        if root.identity.verifying_key().to_bytes().as_slice() != me.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        let deks = member_epoch_deks(&epochs, tree_id, member_id, &root.hpke_secret)?;
        let sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id)?;
        let my_key: [u8; 32] = me
            .author_public_key
            .as_slice()
            .try_into()
            .map_err(|_| SealerError::BadKeyring("member key is not 32 bytes".into()))?;
        Ok(Unlocked {
            sealer,
            // A member unlock reports the same frontier watermark as the owner path (anti-rollback is not
            // owner-specific): the member persists it and passes it back as their floor.
            watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
            did_key: DidKey::from_public_key(&my_key),
            needs_reseal,
        })
    }

    /// Remove `remove_member_id` from a dag tree with forward secrecy: the owner mints a FRESH DEK the
    /// removed member can't reach, wraps it to the RRK (owner) + each REMAINING ordinary member's HPKE key,
    /// and appends a `Remove` op carrying that new epoch in its sealing. Future entries seal under the new
    /// epoch, so the removed member — who has no wrap for it — can't read them. Returns the new anchor.
    pub fn remove_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        owner_passphrase: &Passphrase,
        remove_member_id: &str,
    ) -> Result<Vec<u8>, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let owner_id = ctx.member_id.as_str();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| SealerError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing { epochs, escrow, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // The owner authorizes via their passphrase-derived signing identity (anti-substitution). Removing
        // needs no RRK secret — the new DEK is wrapped to the RRK PUBLIC.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(SealerError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| SealerError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
        validate_kdf(kdf)?;
        let root = derive_root(owner_passphrase.expose(), &KdfParams::from(kdf))?;
        if root.identity.verifying_key().to_bytes().as_slice() != founder.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        // Forward-secret re-epoch: a fresh DEK wrapped to the RRK (owner) + each REMAINING ordinary member.
        let new_dek = generate_dek()?;
        let new_key_id = generate_salt()?.to_vec();
        let new_epoch = epochs
            .iter()
            .map(|e| e.epoch)
            .max()
            .map_or(Ok(0), |m| m.checked_add(1).ok_or(SealerError::RevisionOverflow))?;
        let mut wraps = vec![rrk_wrap_epoch(
            &escrow.public_key,
            &new_dek,
            tree_id,
            owner_id,
            &new_key_id,
        )?];
        for m in &resolved.members.members {
            if m.member_id == remove_member_id || m.member_id == owner_id {
                continue; // the removed member gets no wrap; the owner reaches it via the RRK
            }
            wraps.push(member_wrap_epoch(
                &m.hpke_public_key,
                &new_dek,
                tree_id,
                &m.member_id,
                &new_key_id,
            )?);
        }
        let sealing = SealingPayload {
            new_epochs: vec![SealedEpoch {
                key_id: new_key_id,
                epoch: new_epoch,
                wraps,
            }],
            added_wraps: vec![],
            escrow: None,
        }
        .to_bytes();
        dag_client::append_remove(anchor, owner_id, remove_member_id, sealing, &root.identity)
            .map_err(|e| SealerError::BadKeyring(e.to_string()))
    }

    /// Repair a stale write epoch (OPE-282): if the resolved keyring `needs_reseal` — a concurrent
    /// membership merge left the write epoch wrapping a removed member (a leak) or missing an added one (a
    /// lockout) — mint a FRESH DEK wrapped to the RRK (owner) + each resolved ordinary member and append a
    /// membership-inert `Reseal` op. Idempotent: a no-op (anchor unchanged, `resealed = false`) when nothing
    /// is stale, so racing devices converge (a covering reseal makes `needs_reseal` false everywhere).
    /// Owner-authored via passphrase (a locked-out member's self-heal via `member_kdf` is a follow-up).
    /// Enforces the anti-rollback `floor`; returns the new anchor + watermark.
    pub fn reseal(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        owner_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Resealed, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let owner_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| SealerError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing {
            epochs,
            escrow,
            needs_reseal,
            ..
        } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // Idempotent: nothing stale → return the anchor unchanged, no op appended.
        if !needs_reseal {
            return Ok(Resealed {
                watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
                anchor: anchor.to_vec(),
                resealed: false,
            });
        }

        // The owner authorizes via their passphrase-derived identity (anti-substitution); the fresh DEK is
        // wrapped to the RRK PUBLIC, so no RRK secret is needed to reseal.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(SealerError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| SealerError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
        validate_kdf(kdf)?;
        let root = derive_root(owner_passphrase.expose(), &KdfParams::from(kdf))?;
        if root.identity.verifying_key().to_bytes().as_slice() != founder.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        // A fresh DEK wrapped to the RRK (owner) + EVERY resolved ordinary member — exactly the resolved
        // membership, so the new epoch COVERS and future writes exclude any concurrently-removed member.
        let new_dek = generate_dek()?;
        let new_key_id = generate_salt()?.to_vec();
        let new_epoch = epochs
            .iter()
            .map(|e| e.epoch)
            .max()
            .map_or(Ok(0), |m| m.checked_add(1).ok_or(SealerError::RevisionOverflow))?;
        let mut wraps = vec![rrk_wrap_epoch(
            &escrow.public_key,
            &new_dek,
            tree_id,
            owner_id,
            &new_key_id,
        )?];
        for m in &resolved.members.members {
            if m.is_owner() {
                continue; // the owner reaches the DEK via the RRK wrap
            }
            wraps.push(member_wrap_epoch(
                &m.hpke_public_key,
                &new_dek,
                tree_id,
                &m.member_id,
                &new_key_id,
            )?);
        }
        let sealing = SealingPayload {
            new_epochs: vec![SealedEpoch {
                key_id: new_key_id,
                epoch: new_epoch,
                wraps,
            }],
            added_wraps: vec![],
            escrow: None,
        }
        .to_bytes();
        let new_anchor = dag_client::append_reseal(anchor, owner_id, sealing, &root.identity)
            .map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Resealed {
            anchor: new_anchor,
            watermark,
            resealed: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, SealContext};
    use openom_keyring_seam::MemberView;
    use openom_protocol::ids::{MemberId, ReplicaId, TreeId};

    const TREE: &[u8] = b"tree-uuid-16byte";
    const MEMBER: &str = "acct-1";

    fn ctx<'a>(tree: &'a TreeId, member: &'a MemberId, replica: &'a ReplicaId) -> VaultContext<'a> {
        VaultContext {
            tree_id: tree,
            member_id: member,
            replica_id: replica,
        }
    }

    /// A resolved membership: `owner` (role 1) plus each of `members` as an Editor (role 4).
    fn membership(owner: &str, members: &[&str]) -> MembershipView {
        let mv = |id: &str, role: i16| MemberView {
            member_id: id.to_string(),
            role,
            author_public_key: vec![],
            hpke_public_key: vec![],
        };
        let mut v = vec![mv(owner, 1)];
        v.extend(members.iter().map(|m| mv(m, 4)));
        MembershipView::new(v, false)
    }

    fn member_wrap(member: &str) -> CoreWrap {
        CoreWrap {
            member_id: member.to_string(),
            wrap_method: HPKE,
            nonce: vec![],
            wrapped_dek: vec![],
            kdf: None,
            ephemeral_public_key: vec![],
        }
    }
    fn rrk_wrap() -> CoreWrap {
        CoreWrap {
            wrap_method: RRK_HPKE,
            ..member_wrap("owner")
        }
    }
    fn sealing_entry(
        op_id: u8,
        key_id: &[u8],
        ordinal: u32,
        origin: dag_client::SealingOrigin,
        wraps: Vec<CoreWrap>,
        escrow: Option<RecoveryEscrow>,
    ) -> dag_client::SealingEntry {
        let payload = SealingPayload {
            new_epochs: vec![SealedEpoch {
                key_id: key_id.to_vec(),
                epoch: ordinal,
                wraps,
            }],
            added_wraps: vec![],
            escrow,
        };
        dag_client::SealingEntry {
            op_id: [op_id; 32],
            origin,
            bytes: payload.to_bytes(),
        }
    }
    fn escrow() -> RecoveryEscrow {
        RecoveryEscrow {
            public_key: vec![1],
            member_id: "owner".into(),
            wraps: vec![],
            recovery_verifying_key: vec![2],
        }
    }

    /// The write epoch is the deterministic `(ordinal, minting op-id)` winner: among concurrent same-ordinal
    /// epochs the greater op-id wins, and the choice is independent of fold order — so every replica agrees
    /// without coordination (OPE-282). Fable's flagged `max_by_key` last-on-tie fragility is now explicit.
    #[test]
    fn fold_sealing_picks_the_ordinal_then_op_id_winner() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &[]);
        // Genesis epoch 0 (carries escrow) + two CONCURRENT Remove epoch-1 ops contend for the winner.
        let entries = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![], Some(escrow())),
            sealing_entry(5, b"kA", 1, Remove, vec![], None),
            sealing_entry(9, b"kB", 1, Remove, vec![], None),
        ];
        let wk = fold_sealing(&entries, &members).unwrap().write_key_id;
        assert_eq!(wk, b"kB".to_vec(), "the greater op-id wins the same-ordinal tie");

        // Order-independent: reorder the input, same winner.
        let reordered = vec![
            sealing_entry(9, b"kB", 1, Remove, vec![], None),
            sealing_entry(0, b"k0", 0, Genesis, vec![], Some(escrow())),
            sealing_entry(5, b"kA", 1, Remove, vec![], None),
        ];
        let wk2 = fold_sealing(&reordered, &members).unwrap().write_key_id;
        assert_eq!(wk2, b"kB".to_vec(), "the winner is independent of fold order");
    }

    /// Coverage drives `needs_reseal`, and origin gates eligibility: a winner that still wraps a removed
    /// member is flagged stale; an exactly-covering winner is clean; and an epoch smuggled through an
    /// `Other`-origin op (a self-Retarget/self-Remove carrying a self-only epoch) can never win, no matter
    /// how high its ordinal. (OPE-282.)
    #[test]
    fn coverage_flags_stale_winner_and_origin_blocks_smuggling() {
        use dag_client::SealingOrigin::{Genesis, Other};
        // Resolved membership = owner + bob; carol was removed.
        let members = membership("owner", &["bob"]);

        // A winner still wrapping the removed carol (a concurrent-merge leak) → stale.
        let stale = vec![sealing_entry(
            0,
            b"k0",
            0,
            Genesis,
            vec![rrk_wrap(), member_wrap("bob"), member_wrap("carol")],
            Some(escrow()),
        )];
        assert!(
            fold_sealing(&stale, &members).unwrap().needs_reseal,
            "a winner wrapping a removed member is stale"
        );

        // A winner wrapping exactly {RRK, bob} → clean.
        let clean = vec![sealing_entry(
            0,
            b"k0",
            0,
            Genesis,
            vec![rrk_wrap(), member_wrap("bob")],
            Some(escrow()),
        )];
        assert!(
            !fold_sealing(&clean, &members).unwrap().needs_reseal,
            "an exactly-covering winner is clean"
        );

        // Smuggling: an Other-origin op carries a self-only epoch at a huge ordinal — dropped, cannot win.
        let smuggle = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![rrk_wrap(), member_wrap("bob")], Some(escrow())),
            sealing_entry(9, b"evil", 999, Other, vec![member_wrap("attacker")], None),
        ];
        let folded = fold_sealing(&smuggle, &members).unwrap();
        assert_eq!(
            folded.write_key_id,
            b"k0".to_vec(),
            "a smuggled Other-origin epoch cannot win the write epoch"
        );
        assert!(!folded.needs_reseal, "the covering genesis epoch is the clean winner");
    }

    /// OPE-287: a garbage epoch (a malicious member could append one) whose RRK wrap won't open is SKIPPED
    /// by `epoch_deks`, not fatal — so one junk epoch can't brick unlock for the owner, who still reaches
    /// every legitimate epoch.
    #[test]
    fn epoch_deks_skips_an_unopenable_epoch_instead_of_bricking() {
        let tree: &[u8] = b"tree-uuid-16byte";
        let HpkeKeypair { secret, public } = generate_hpke_keypair().unwrap();
        let rrk_secret = RrkSecret::from(secret);
        let dek = generate_dek().unwrap();
        let good = SealedEpoch {
            key_id: b"good".to_vec(),
            epoch: 0,
            wraps: vec![rrk_wrap_epoch(&public, &dek, tree, "owner", b"good").unwrap()],
        };
        // A garbage epoch: an RRK-method wrap the owner's RRK secret cannot open.
        let garbage = SealedEpoch {
            key_id: b"evil".to_vec(),
            epoch: 1,
            wraps: vec![CoreWrap {
                member_id: "owner".into(),
                wrap_method: RRK_HPKE,
                nonce: vec![],
                wrapped_dek: vec![9u8; 48],
                kdf: None,
                ephemeral_public_key: vec![9u8; 32],
            }],
        };
        let deks = epoch_deks(&[good, garbage], tree, "owner", &rrk_secret).unwrap();
        assert_eq!(deks.len(), 1, "the un-openable garbage epoch is skipped, not fatal");
        assert_eq!(deks[0].0, b"good".to_vec(), "the legitimate epoch still opens");
    }

    /// Provision on device A, seal data, then unlock from the anchor alone on device B and open it —
    /// the dag vault produces a working SealerSet through the shared core, end to end.
    #[test]
    fn dag_provision_then_unlock_opens_the_same_data() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"correct horse");

        let p = DagVault
            .provision(&ctx(&tree, &member, &ReplicaId::new(b"replica-A")), &pass)
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"the family tree")
            .unwrap()
            .envelope;

        // Device B: unlock from the anchor bytes alone, a fresh replica.
        let u = DagVault
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"replica-B")),
                &p.anchor,
                &pass,
            )
            .unwrap();
        assert_eq!(u.did_key, p.did_key, "same owner identity across provision + unlock");
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"the family tree",
            "device B opens what device A sealed"
        );
    }

    /// Recover under a new passphrase, then unlock the recovered anchor with it and open pre-recovery
    /// data — exercises the ReFound op + the multi-op sealing fold (genesis escrow then the ReFound's
    /// re-escrow, latest wins) + the anti-substitution check against the retargeted Owner.
    #[test]
    fn dag_recover_then_unlock_with_the_new_passphrase_opens_the_same_data() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let old_pass = Passphrase::new(b"correct horse");
        let new_pass = Passphrase::new(b"a whole new passphrase");

        let p = DagVault
            .provision(&ctx(&tree, &member, &ReplicaId::new(b"r1")), &old_pass)
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"heirloom")
            .unwrap()
            .envelope;

        let r = DagVault
            .recover(
                &ctx(&tree, &member, &ReplicaId::new(b"r2")),
                &p.anchor,
                &p.recovery_code,
                &new_pass,
                &[],
            )
            .unwrap();
        assert_ne!(r.did_key, p.did_key, "recovery mints a fresh owner identity");
        assert_eq!(
            r.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"heirloom",
            "the recovered sealer opens pre-recovery data (the DEK is unchanged)"
        );

        // Unlock the recovered anchor with the NEW passphrase on a fresh device.
        let u = DagVault
            .unlock(&ctx(&tree, &member, &ReplicaId::new(b"r3")), &r.anchor, &new_pass)
            .unwrap();
        assert_eq!(u.did_key, r.did_key, "unlock resolves the recovered owner identity");
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"heirloom"
        );

        // The OLD passphrase no longer opens the recovered anchor (the owner key was retargeted).
        assert!(
            DagVault
                .unlock(&ctx(&tree, &member, &ReplicaId::new(b"r4")), &r.anchor, &old_pass)
                .is_err(),
            "the pre-recovery passphrase is retired"
        );
    }

    /// Change the passphrase (a current-key-signed Retarget), then unlock with the new passphrase and open
    /// pre-change data; the old passphrase is retired; and recovery still works via the rotated code — the
    /// three-op fold (genesis → retarget → refound) resolves the current escrow correctly.
    #[test]
    fn dag_change_passphrase_then_unlock_and_still_recover() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let old_pass = Passphrase::new(b"correct horse");
        let new_pass = Passphrase::new(b"battery staple unicorn");

        let p = DagVault
            .provision(&ctx(&tree, &member, &ReplicaId::new(b"r1")), &old_pass)
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"keepsake")
            .unwrap()
            .envelope;

        let re = DagVault
            .change_passphrase(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &p.anchor,
                &old_pass,
                &new_pass,
                &[],
            )
            .unwrap();

        // The NEW passphrase opens the rekeyed anchor (DEK unchanged); the OLD one no longer does.
        let u = DagVault
            .unlock(&ctx(&tree, &member, &ReplicaId::new(b"r2")), &re.anchor, &new_pass)
            .unwrap();
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"keepsake"
        );
        assert!(
            DagVault
                .unlock(&ctx(&tree, &member, &ReplicaId::new(b"r3")), &re.anchor, &old_pass)
                .is_err(),
            "the pre-change passphrase is retired"
        );

        // Recovery still works, via the recovery code the passphrase change rotated.
        let r = DagVault
            .recover(
                &ctx(&tree, &member, &ReplicaId::new(b"r4")),
                &re.anchor,
                &re.recovery_code,
                &Passphrase::new(b"a third passphrase"),
                &[],
            )
            .unwrap();
        assert_eq!(
            r.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"keepsake"
        );
    }

    /// The anti-rollback watermark is wired (OPE-284): unlock reports the anchor's frontier, a mutation past
    /// that floor advances the watermark, and serving the now-stale original anchor — whose op set is behind
    /// the advanced floor — is refused as a rollback.
    #[test]
    fn dag_watermark_advances_and_a_stale_anchor_is_refused() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let old_pass = Passphrase::new(b"correct horse");
        let new_pass = Passphrase::new(b"battery staple unicorn");

        let p = DagVault
            .provision(&ctx(&tree, &member, &ReplicaId::new(b"r1")), &old_pass)
            .unwrap();
        let u = DagVault
            .unlock(&ctx(&tree, &member, &ReplicaId::new(b"r1")), &p.anchor, &old_pass)
            .unwrap();
        assert!(!u.watermark.is_empty(), "unlock reports the frontier watermark, not a stub");

        // A passphrase change, gated on the unlock floor, advances the watermark.
        let re = DagVault
            .change_passphrase(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &p.anchor,
                &old_pass,
                &new_pass,
                &u.watermark,
            )
            .unwrap();
        assert_ne!(re.watermark, u.watermark, "a keyring change advances the watermark");

        // Serving the ORIGINAL anchor now — its op set is behind the advanced floor — is a rollback.
        let rolled_back = DagVault.change_passphrase(
            &ctx(&tree, &member, &ReplicaId::new(b"r1")),
            &p.anchor,
            &old_pass,
            &new_pass,
            &re.watermark,
        );
        assert!(
            matches!(rolled_back, Err(SealerError::WatermarkRollback { .. })),
            "a stale anchor below the floor is refused"
        );

        // A corrupt floor (not a multiple of 32 bytes) is refused, not silently ignored.
        let bad_floor = DagVault.change_passphrase(
            &ctx(&tree, &member, &ReplicaId::new(b"r1")),
            &re.anchor,
            &new_pass,
            &Passphrase::new(b"third one"),
            &[1, 2, 3],
        );
        assert!(
            matches!(bad_floor, Err(SealerError::MalformedWatermark)),
            "a corrupt floor is refused"
        );
    }

    /// The owner adds a member: the joiner appears in the resolved keyring, their per-epoch wrap is minted,
    /// and the owner's own access is unaffected (they still unlock + open the data).
    #[test]
    fn dag_add_member_wraps_the_dek_and_the_owner_still_unlocks() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"correct horse");

        let p = DagVault
            .provision(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &pass)
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"shared secret")
            .unwrap()
            .envelope;

        // bob's OOB-verified keys (a real HPKE public key so the wrap succeeds).
        let bob_id = "acct-bob";
        let HpkeKeypair { public: bob_hpke, .. } = generate_hpke_keypair().unwrap();

        let new_anchor = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &p.anchor,
                &pass,
                bob_id,
                KeyringRole::EDITOR,
                [9u8; 32],
                bob_hpke,
            )
            .unwrap();

        // bob is now a member of the resolved keyring.
        let resolved = dag_client::resolve(&new_anchor).unwrap();
        assert!(
            resolved.members.members.iter().any(|m| m.member_id == bob_id),
            "the added member appears in the resolved keyring"
        );

        // The owner's own access is unaffected: they still unlock the new anchor and open the data.
        let u = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &new_anchor, &pass)
            .unwrap();
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"shared secret"
        );
    }

    /// The full shared-tree cycle: the owner adds bob, and bob unlocks with HIS OWN passphrase + account
    /// KDF (reaching the DEK through his member HPKE wrap, not the RRK) and reads the shared data.
    #[test]
    fn dag_added_member_unlocks_with_their_own_account_and_reads() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");

        let p = DagVault
            .provision(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &owner_pass)
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"family data")
            .unwrap()
            .envelope;

        // bob's account: identity + HPKE + KDF derived from his own passphrase.
        let bob_pass = Passphrase::new(b"bobs own passphrase");
        let bob = new_owner_secrets(bob_pass.expose()).unwrap();
        let bob_author = bob.root.identity.verifying_key().to_bytes();

        let new_anchor = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &p.anchor,
                &owner_pass,
                "acct-bob",
                KeyringRole::EDITOR,
                bob_author,
                bob.root.hpke_public,
            )
            .unwrap();

        // bob unlocks with his own passphrase + account KDF and reads the shared data.
        let bob_id = MemberId::new("acct-bob");
        let u = DagVault
            .unlock_as_member(
                &ctx(&tree, &bob_id, &ReplicaId::new(b"r-bob")),
                &new_anchor,
                &bob_pass,
                &KdfParams::from(&bob.pass_kdf),
            )
            .unwrap();
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"family data"
        );
        assert_eq!(u.did_key, DidKey::from_public_key(&bob_author));
        assert!(!u.watermark.is_empty(), "a member unlock reports the frontier watermark too");

        // A wrong passphrase for bob is rejected (anti-substitution against his resolved key).
        assert!(
            DagVault
                .unlock_as_member(
                    &ctx(&tree, &bob_id, &ReplicaId::new(b"r-bob")),
                    &new_anchor,
                    &Passphrase::new(b"not bobs passphrase"),
                    &KdfParams::from(&bob.pass_kdf),
                )
                .is_err()
        );
    }

    /// Removing a member mints a forward-secret epoch: the removed member can no longer unlock, and the
    /// owner reads post-removal data sealed under the new epoch.
    #[test]
    fn dag_remove_member_forward_secret_epoch_locks_them_out() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");
        let p = DagVault
            .provision(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &owner_pass)
            .unwrap();

        let bob_pass = Passphrase::new(b"bobs passphrase");
        let bob = new_owner_secrets(bob_pass.expose()).unwrap();
        let bob_author = bob.root.identity.verifying_key().to_bytes();
        let bob_id = MemberId::new("acct-bob");
        let a1 = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &p.anchor,
                &owner_pass,
                "acct-bob",
                KeyringRole::EDITOR,
                bob_author,
                bob.root.hpke_public,
            )
            .unwrap();
        assert!(
            DagVault
                .unlock_as_member(&ctx(&tree, &bob_id, &ReplicaId::new(b"rb")), &a1, &bob_pass, &KdfParams::from(&bob.pass_kdf))
                .is_ok(),
            "bob can read before removal"
        );

        let a2 = DagVault
            .remove_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &a1,
                &owner_pass,
                "acct-bob",
            )
            .unwrap();

        assert!(
            DagVault
                .unlock_as_member(&ctx(&tree, &bob_id, &ReplicaId::new(b"rb")), &a2, &bob_pass, &KdfParams::from(&bob.pass_kdf))
                .is_err(),
            "a removed member can no longer unlock"
        );

        // The owner unlocks the new anchor and reads post-removal data sealed under the forward-secret epoch.
        let u = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &a2, &owner_pass)
            .unwrap();
        let post = u
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"post-removal")
            .unwrap()
            .envelope;
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &post).unwrap(),
            b"post-removal"
        );
    }

    /// End-to-end OPE-282: two CONCURRENT removals leave the merged write epoch stale (it still wraps the
    /// member the losing branch removed); unlock flags `needs_reseal`; `reseal` mints a covering fresh epoch
    /// so the flag clears and the owner keeps working; and a second reseal is an idempotent no-op.
    #[test]
    fn reseal_repairs_a_stale_write_epoch_after_concurrent_removals() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");
        let p = DagVault
            .provision(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &owner_pass)
            .unwrap();

        // Add bob + carol as editors.
        let bob = new_owner_secrets(Passphrase::new(b"bob pass").expose()).unwrap();
        let carol = new_owner_secrets(Passphrase::new(b"carol pass").expose()).unwrap();
        let a1 = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &p.anchor,
                &owner_pass,
                "acct-bob",
                KeyringRole::EDITOR,
                bob.root.identity.verifying_key().to_bytes(),
                bob.root.hpke_public,
            )
            .unwrap();
        let a2 = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &a1,
                &owner_pass,
                "acct-carol",
                KeyringRole::EDITOR,
                carol.root.identity.verifying_key().to_bytes(),
                carol.root.hpke_public,
            )
            .unwrap();

        // Two CONCURRENT removals from a2 (both parent on the same frontier): A removes bob, B removes carol.
        let branch_a = DagVault
            .remove_member(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &a2, &owner_pass, "acct-bob")
            .unwrap();
        let branch_b = DagVault
            .remove_member(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &a2, &owner_pass, "acct-carol")
            .unwrap();
        let merged = dag_client::merge(&branch_a, &branch_b).unwrap();

        // The merged write epoch is stale — it still wraps whichever member the losing branch removed.
        let u = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &merged, &owner_pass)
            .unwrap();
        assert!(u.needs_reseal, "concurrent removals leave the write epoch stale");

        // Reseal mints a covering fresh epoch; the flag clears and the owner writes + reads under it.
        let r = DagVault
            .reseal(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &merged, &owner_pass, &[])
            .unwrap();
        assert!(r.resealed, "a stale write epoch is repaired");
        let u2 = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &r.anchor, &owner_pass)
            .unwrap();
        assert!(!u2.needs_reseal, "after reseal the write epoch covers the resolved membership");
        let sealed = u2
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"after reseal")
            .unwrap()
            .envelope;
        assert_eq!(
            u2.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"after reseal"
        );

        // Idempotent: a second reseal finds nothing stale and is a no-op.
        let r2 = DagVault
            .reseal(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &r.anchor, &owner_pass, &[])
            .unwrap();
        assert!(!r2.resealed, "nothing stale -> reseal is a no-op");
    }

    #[test]
    fn dag_unlock_rejects_a_wrong_passphrase() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let p = DagVault
            .provision(
                &ctx(&tree, &member, &ReplicaId::new(b"r")),
                &Passphrase::new(b"correct horse"),
            )
            .unwrap();
        assert!(
            DagVault
                .unlock(
                    &ctx(&tree, &member, &ReplicaId::new(b"r")),
                    &p.anchor,
                    &Passphrase::new(b"wrong"),
                )
                .is_err(),
            "a wrong passphrase does not open the dag vault"
        );
    }
}
