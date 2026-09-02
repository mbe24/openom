//! The DAG keyring's vault (OPE-273) — the dag-engine counterpart to [`crate::vault`], producing the same
//! [`SealerSet`] through the shared sealing core ([`crate::vault_core`]) while resolving membership +
//! recovery authority through the DAG keyring's client facade (`keyeo_dag::client`).
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
use keyeo_dag::{client as dag_client, KeyringRole};
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
use keyeo_api::MembershipView;
use crate::VaultError;

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
) -> Result<FoldedSealing, VaultError> {
    use dag_client::SealingOrigin;
    // Each retained epoch tagged with (origin, minting op-id). Only Genesis/Remove/Reseal ops may MINT an
    // epoch — a new_epoch from any Other op is anomalous (a self-Retarget/self-Remove smuggling a self-only
    // epoch) and is dropped: no legitimate write is ever sealed under it, so it never needs retaining.
    let mut tagged: Vec<(SealedEpoch, SealingOrigin, [u8; 32])> = Vec::new();
    let mut escrow: Option<RecoveryEscrow> = None;
    // Count epoch-minting OPS (Genesis/Remove/Reseal) — the plausibility bound on epoch ordinals below
    // (OPE-289). Counting ops not epochs means one op stuffing many epochs can't inflate the bound.
    let mut minting_ops: u32 = 0;
    for entry in sealing {
        let payload: SealingPayload = serde_json::from_slice(&entry.bytes)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        if matches!(
            entry.origin,
            SealingOrigin::Genesis | SealingOrigin::Remove | SealingOrigin::Reseal
        ) {
            minting_ops = minting_ops.saturating_add(1);
        }
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
        escrow.ok_or_else(|| VaultError::BadKeyring("dag keyring has no recovery escrow".into()))?;

    // Sanitize epoch ordinals (OPE-289). A legitimately-minted ordinal is `max(existing)+1`, so after M
    // epoch-minting ops the greatest possible ordinal is M-1; drop any epoch whose ordinal is >= M. A
    // member-authored Remove/Reseal grinding a huge ordinal (e.g. u32::MAX) would otherwise (a) BRICK every
    // future `max()+1` re-epoch with RevisionOverflow, a permanent DoS, and (b) permanently win the
    // write-epoch race. The bound never drops an honest epoch (its ordinal is always < M) and caps a hostile
    // one at M-1, so `checked_add` can only overflow after ~4e9 real ops.
    tagged.retain(|(e, _, _)| e.epoch < minting_ops);

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
    let (_, _, write_key_id, winner_covers) = winner.ok_or(VaultError::MissingWrap)?;

    let epochs: Vec<SealedEpoch> = tagged.into_iter().map(|(e, _, _)| e).collect();
    let needs_backfill = any_epoch_missing_a_member(&epochs, members);
    Ok(FoldedSealing {
        epochs,
        escrow,
        write_key_id,
        needs_reseal: !winner_covers,
        needs_backfill,
    })
}

/// Build the sealing payload for a covering reseal: a fresh DEK as a single new epoch, wrapped to the RRK
/// (owner) + every resolved ordinary member. Minting needs only PUBLIC keys — the RRK public in the escrow
/// + each member's HPKE key — so both the owner (passphrase) and any active member (member_kdf) can produce
/// it; the caller appends it under their OWN identity (OPE-290). The RRK wrap's AAD is keyed to `owner_id`
/// (the RRK belongs to the owner) whoever authors the op.
fn covering_reseal_sealing(
    tree_id: &[u8],
    owner_id: &str,
    escrow: &RecoveryEscrow,
    members: &MembershipView,
    epochs: &[SealedEpoch],
) -> Result<Vec<u8>, VaultError> {
    let new_dek = generate_dek()?;
    let new_key_id = generate_salt()?.to_vec();
    let new_epoch = epochs
        .iter()
        .map(|e| e.epoch)
        .max()
        .map_or(Ok(0), |m| m.checked_add(1).ok_or(VaultError::RevisionOverflow))?;
    let mut wraps = vec![rrk_wrap_epoch(&escrow.public_key, &new_dek, tree_id, owner_id, &new_key_id)?];
    for m in &members.members {
        // The owner reaches the DEK via the RRK wrap; a member with an empty/malformed key can't be wrapped
        // (excluded from coverage too, so this doesn't leave a permanent needs_reseal — OPE-290).
        if m.is_owner() || m.hpke_public_key.is_empty() {
            continue;
        }
        wraps.push(member_wrap_epoch(&m.hpke_public_key, &new_dek, tree_id, &m.member_id, &new_key_id)?);
    }
    Ok(SealingPayload {
        new_epochs: vec![SealedEpoch {
            key_id: new_key_id,
            epoch: new_epoch,
            wraps,
        }],
        added_wraps: vec![],
        escrow: None,
    }
    .to_bytes())
}

/// Whether some RETAINED epoch lacks an HPKE wrap for a resolved non-owner member (OPE-288) — that member
/// can't READ history sealed under that epoch, the symptom of a concurrent add on a branch that never saw a
/// sibling branch's epochs. Unlike `needs_reseal` (the WRITE epoch must wrap EXACTLY the resolved set — both
/// leaks and lockouts), this is a MISSING-only, ALL-epochs check: an extra (now-removed) member still wrapped
/// in an old epoch is fine — historical read was already granted and removal is forward-only. The owner
/// reaches every DEK via the RRK, so it needs no per-epoch owner wrap.
fn any_epoch_missing_a_member(epochs: &[SealedEpoch], members: &MembershipView) -> bool {
    // Key-bound, MISSING-only (OPE-290): a member is "covered" in an epoch iff it has a wrap addressed to
    // their CURRENT key. A wrap on their stale key (after a rekey race) counts as missing, so backfill
    // re-wraps them. Missing-only (not set equality) because backfill only APPENDS — a leftover stale-key
    // wrap is fine and must not read as an extra. Empty-key members are skipped (can't be wrapped/matched).
    let need: Vec<(&str, &[u8])> = members
        .members
        .iter()
        .filter(|m| !m.is_owner() && !m.hpke_public_key.is_empty())
        .map(|m| (m.member_id.as_str(), m.hpke_public_key.as_slice()))
        .collect();
    epochs.iter().any(|ep| {
        need.iter().any(|(id, key)| {
            !ep.wraps.iter().any(|w| {
                w.wrap_method == HPKE && w.member_id == *id && w.recipient_public_key == *key
            })
        })
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
    /// Some retained epoch lacks a wrap for a resolved member — they can't read that slice of history until
    /// the owner backfills it (OPE-288). Orthogonal to `needs_reseal` (a write-epoch/forward-secrecy issue).
    needs_backfill: bool,
}

/// The result of [`DagVault::reseal`]: the (possibly unchanged) anchor to publish + its watermark, and
/// whether a repair was actually appended (`false` = nothing was stale, a no-op).
pub struct Resealed {
    pub anchor: Vec<u8>,
    pub watermark: Vec<u8>,
    pub resealed: bool,
}

/// The result of [`DagVault::backfill`]: the (possibly unchanged) anchor + its watermark, and whether
/// historical-read wraps were actually added (`false` = nothing was missing, a no-op).
pub struct Backfilled {
    pub anchor: Vec<u8>,
    pub watermark: Vec<u8>,
    pub backfilled: bool,
}

/// Whether `epoch`'s wraps serve the resolved membership: an RRK wrap for the owner, plus — for each resolved
/// non-owner member — an HPKE wrap addressed to their CURRENT key, and no wrap for anyone NOT resolved. A
/// mismatch means the epoch is stale vs the merged membership, so a reseal is due. Two independent checks:
///  - **member-id set equality** catches a LEAK (a removed member still wrapped) or a LOCKOUT (a resolved
///    member absent). Kept id-level so a benign leftover stale-key wrap for a still-current member (after a
///    rekey/backfill) does NOT read as a leak.
///  - **current-key EXISTS** (OPE-290): every resolved member has AT LEAST ONE wrap addressed to their
///    current `hpke_public_key`. A wrap left on a member's STALE key after a rekey race passes id-equality
///    but not this, so it is caught. Exists-form (not pair-set equality) so a coexisting old-key wrap is
///    ignored, not treated as churn. `recipient_public_key` is an unauthenticated hint (see `CoreWrap`): this
///    detects honest rekey races, not a malicious author who lies about the recipient over garbage ciphertext.
///
/// A resolved member with an empty/malformed `hpke_public_key` is EXCLUDED from both checks — it can be
/// neither wrapped nor matched, so demanding its coverage would wedge `needs_reseal` permanently true.
fn epoch_covers(epoch: &SealedEpoch, members: &MembershipView) -> bool {
    use std::collections::HashSet;
    let has_rrk = epoch.wraps.iter().any(|w| w.wrap_method == RRK_HPKE);
    let need = || {
        members
            .members
            .iter()
            .filter(|m| !m.is_owner() && !m.hpke_public_key.is_empty())
    };
    let wrapped_ids: HashSet<&str> = epoch
        .wraps
        .iter()
        .filter(|w| w.wrap_method == HPKE)
        .map(|w| w.member_id.as_str())
        .collect();
    let resolved_ids: HashSet<&str> = need().map(|m| m.member_id.as_str()).collect();
    let keys_current = need().all(|m| {
        epoch.wraps.iter().any(|w| {
            w.wrap_method == HPKE
                && w.member_id == m.member_id
                && w.recipient_public_key == m.hpke_public_key
        })
    });
    has_rrk && wrapped_ids == resolved_ids && keys_current
}

/// Map a facade anti-rollback failure onto the sealer's error vocabulary: a rolled-back anchor and a
/// corrupt floor stay distinct (mirroring the chain's `RevisionRollback` / `MalformedWatermark`); anything
/// else (a bad anchor) is a `BadKeyring`.
fn map_floor_err(e: dag_client::ClientError) -> VaultError {
    match e {
        dag_client::ClientError::RolledBack(detail) => VaultError::WatermarkRollback { detail },
        dag_client::ClientError::BadWatermark(_) => VaultError::MalformedWatermark,
        other => VaultError::BadKeyring(other.to_string()),
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
    ) -> Result<Provisioned, VaultError> {
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
    ) -> Result<Unlocked, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;

        let FoldedSealing { epochs, escrow, write_key_id, needs_reseal, needs_backfill } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // The RRK is wrapped under the passphrase KEK: derive it via that wrap's KDF.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(VaultError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
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
            .map_err(|_| VaultError::BadKeyring("owner key is not 32 bytes".into()))?;
        Ok(Unlocked {
            sealer,
            // The anti-rollback watermark is the anchor's frontier (opaque to us). unlock takes no floor —
            // it reports the cursor the caller persists and passes back as the floor on the next mutation.
            watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
            did_key: DidKey::from_public_key(&owner_key),
            needs_reseal,
            needs_backfill,
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
    ) -> Result<Recovered, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        // Anti-rollback: the served anchor is untrusted on recovery, so refuse one that dropped a frontier
        // op below the caller's floor before doing any work.
        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        // Resolve the current sealing → the escrow, and unwrap the RRK via the recovery code.
        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let FoldedSealing { epochs, escrow, write_key_id, needs_reseal, needs_backfill } = fold_sealing(&resolved.sealing, &resolved.members)?;
        let rec_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == RECOVERY)
            .ok_or(VaultError::MissingWrap)?;
        let rec_kdf = rec_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow recovery wrap missing kdf".into()))?;
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
        .map_err(|e| VaultError::BadKeyring(e.to_string()))?;

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
            needs_backfill,
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
    ) -> Result<Rekeyed, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing { escrow, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // Unwrap the RRK via the OLD passphrase, checking the derived identity is the resolved Owner.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(VaultError::MissingWrap)?;
        let old_kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
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
        .map_err(|e| VaultError::BadKeyring(e.to_string()))?;

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
    pub fn merge(&self, local: &[u8], remote: &[u8]) -> Result<Vec<u8>, VaultError> {
        dag_client::merge(local, remote).map_err(|e| VaultError::BadKeyring(e.to_string()))
    }

    /// The anchor's opaque anti-rollback watermark (its frontier op-id set) — the cursor the host persists
    /// alongside the anchor and passes back as the floor on the next mutation. Opaque bytes to every caller.
    pub fn watermark(&self, anchor: &[u8]) -> Result<Vec<u8>, VaultError> {
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
    ) -> Result<Vec<u8>, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let owner_id = ctx.member_id.as_str();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing { epochs, escrow, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // The owner unwraps the RRK via their passphrase (anti-substitution vs the resolved Owner key).
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(VaultError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
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
        .map_err(|e| VaultError::BadKeyring(e.to_string()))
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
    ) -> Result<Unlocked, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let me = resolved
            .members
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| VaultError::BadKeyring("not a member of this tree".into()))?;
        let FoldedSealing { epochs, write_key_id, needs_reseal, needs_backfill, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

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
            .map_err(|_| VaultError::BadKeyring("member key is not 32 bytes".into()))?;
        Ok(Unlocked {
            sealer,
            // A member unlock reports the same frontier watermark as the owner path (anti-rollback is not
            // owner-specific): the member persists it and passes it back as their floor.
            watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
            did_key: DidKey::from_public_key(&my_key),
            needs_reseal,
            needs_backfill,
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
    ) -> Result<Vec<u8>, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let owner_id = ctx.member_id.as_str();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing { epochs, escrow, .. } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // The owner authorizes via their passphrase-derived signing identity (anti-substitution). Removing
        // needs no RRK secret — the new DEK is wrapped to the RRK PUBLIC.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(VaultError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
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
            .map_or(Ok(0), |m| m.checked_add(1).ok_or(VaultError::RevisionOverflow))?;
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
            .map_err(|e| VaultError::BadKeyring(e.to_string()))
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
    ) -> Result<Resealed, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
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
            .ok_or(VaultError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
        validate_kdf(kdf)?;
        let root = derive_root(owner_passphrase.expose(), &KdfParams::from(kdf))?;
        if root.identity.verifying_key().to_bytes().as_slice() != founder.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        // Mint a covering epoch; the OWNER both authors and signs it (author == owner).
        let owner_id = founder.member_id.as_str();
        let sealing = covering_reseal_sealing(tree_id, owner_id, &escrow, &resolved.members, &epochs)?;
        let new_anchor = dag_client::append_reseal(anchor, owner_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Resealed {
            anchor: new_anchor,
            watermark,
            resealed: true,
        })
    }

    /// Member-authored self-heal of a stale write epoch (OPE-290). Identical repair to [`reseal`], but any
    /// ACTIVE member — not just the owner — can drive it: minting a covering epoch needs only PUBLIC keys
    /// (the RRK public in the escrow + each resolved member's HPKE key), and keyeo authorizes a Reseal by any
    /// member, so a member locked out by a stale merge no longer has to wait for the owner's device to come
    /// online. Authorizes via the member's `passphrase` + account `member_kdf` (their identity signs the op),
    /// mirroring [`unlock_as_member`]. The RRK wrap stays keyed to the OWNER (its holder). Idempotent + floor
    /// enforced, exactly like the owner path.
    pub fn reseal_as_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
        member_kdf: &KdfParams,
        floor: &[u8],
    ) -> Result<Resealed, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let owner_id = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?
            .member_id
            .clone();
        let me = resolved
            .members
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| VaultError::BadKeyring("not a member of this tree".into()))?;
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

        // The member authorizes via their passphrase + account kdf-derived identity (anti-substitution vs
        // their resolved key). No RRK secret is needed — the fresh DEK is wrapped to the RRK PUBLIC.
        validate_kdf(&CoreKdf::from(member_kdf))?;
        let root = derive_root(passphrase.expose(), member_kdf)?;
        if root.identity.verifying_key().to_bytes().as_slice() != me.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        // The member authors + signs the op; the RRK wrap stays keyed to the owner (its holder).
        let sealing = covering_reseal_sealing(tree_id, &owner_id, &escrow, &resolved.members, &epochs)?;
        let new_anchor = dag_client::append_reseal(anchor, member_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Resealed {
            anchor: new_anchor,
            watermark,
            resealed: true,
        })
    }

    /// Backfill historical READ access (OPE-288). A member added on one branch has no wrap for epochs minted
    /// concurrently on another branch before the merge, so after resolution they can't read history sealed
    /// under those epochs. The owner — who reaches every DEK via the RRK — re-wraps each retained epoch for
    /// every resolved member missing from it, appending an `added_wraps`-only op (no new epoch, membership
    /// inert; keyeo sees only an authored Reseal-kind op). Owner-authored (only the RRK opens the old DEKs).
    /// Idempotent: a no-op (`backfilled = false`) when no epoch is missing any resolved member. Enforces the
    /// anti-rollback `floor`; returns the new anchor + watermark. Orthogonal to `reseal` (forward secrecy).
    pub fn backfill(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        owner_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Backfilled, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let owner_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let FoldedSealing {
            epochs,
            escrow,
            needs_backfill,
            ..
        } = fold_sealing(&resolved.sealing, &resolved.members)?;

        // Idempotent: every retained epoch already wraps every resolved member → nothing to do.
        let unchanged = || -> Result<Backfilled, VaultError> {
            Ok(Backfilled {
                watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
                anchor: anchor.to_vec(),
                backfilled: false,
            })
        };
        if !needs_backfill {
            return unchanged();
        }

        // The owner authorizes via their passphrase-derived identity (anti-substitution vs the resolved
        // Owner key) and unwraps the RRK secret — the same open-all-DEKs path as `add_member`.
        let pass_wrap = escrow
            .wraps
            .iter()
            .find(|w| w.wrap_method == PASSPHRASE)
            .ok_or(VaultError::MissingWrap)?;
        let kdf = pass_wrap
            .kdf
            .as_ref()
            .ok_or_else(|| VaultError::BadKeyring("escrow passphrase wrap missing kdf".into()))?;
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

        // Open every epoch the RRK can reach; for each, add a wrap for any resolved non-owner member not
        // already covered by a wrap addressed to their CURRENT key (OPE-290: key-bound, so a member left on a
        // STALE key after a rekey race is re-wrapped too). (`epoch_deks` skips an un-openable epoch rather
        // than failing, so a corrupt epoch can't brick this.) Empty-key members are skipped — nothing to wrap.
        let deks = epoch_deks(&epochs, tree_id, owner_id, &rrk_secret)?;
        let mut added_wraps: Vec<AddedWrap> = Vec::new();
        for (key_id, _epoch, dek) in &deks {
            let epoch_wraps = epochs.iter().find(|e| &e.key_id == key_id).map(|e| e.wraps.as_slice()).unwrap_or(&[]);
            for m in &resolved.members.members {
                if m.is_owner() || m.hpke_public_key.is_empty() {
                    continue;
                }
                let covered = epoch_wraps.iter().any(|w| {
                    w.wrap_method == HPKE
                        && w.member_id == m.member_id
                        && w.recipient_public_key == m.hpke_public_key
                });
                if covered {
                    continue;
                }
                let wrap = member_wrap_epoch(&m.hpke_public_key, dek, tree_id, &m.member_id, key_id)?;
                added_wraps.push(AddedWrap {
                    key_id: key_id.clone(),
                    wrap,
                });
            }
        }

        // Every missing epoch was un-openable (skipped by `epoch_deks`) → nothing we can repair; no-op.
        if added_wraps.is_empty() {
            return unchanged();
        }

        let sealing = SealingPayload {
            new_epochs: vec![],
            added_wraps,
            escrow: None,
        }
        .to_bytes();
        let new_anchor = dag_client::append_backfill(anchor, owner_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Backfilled {
            anchor: new_anchor,
            watermark,
            backfilled: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_sealer::{EntryKind, SealContext};
    use keyeo_api::MemberView;
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

    /// A member's deterministic HPKE public key, so `membership` (the resolved view) and `member_wrap` (the
    /// epoch wrap) agree on what "the current key" is for the coverage checks (OPE-290).
    fn hpke_key(member: &str) -> Vec<u8> {
        format!("hpke-{member}").into_bytes()
    }

    /// A resolved membership: `owner` (role 1) plus each of `members` as an Editor (role 4).
    fn membership(owner: &str, members: &[&str]) -> MembershipView {
        let mv = |id: &str, role: i16| MemberView {
            member_id: id.to_string(),
            role,
            author_public_key: vec![],
            hpke_public_key: hpke_key(id),
        };
        let mut v = vec![mv(owner, 1)];
        v.extend(members.iter().map(|m| mv(m, 4)));
        MembershipView::new(v, false)
    }

    /// An HPKE wrap addressed to `member`'s CURRENT key (matches `membership`).
    fn member_wrap(member: &str) -> CoreWrap {
        member_wrap_keyed(member, &hpke_key(member))
    }
    /// An HPKE wrap for `member` addressed to an explicit `recipient` key — pass a non-current key to model a
    /// STALE-key wrap left after a rekey race (OPE-290).
    fn member_wrap_keyed(member: &str, recipient: &[u8]) -> CoreWrap {
        CoreWrap {
            member_id: member.to_string(),
            wrap_method: HPKE,
            nonce: vec![],
            wrapped_dek: vec![],
            kdf: None,
            ephemeral_public_key: vec![],
            recipient_public_key: recipient.to_vec(),
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

    /// Ordinal-inflation DoS defense (OPE-289): an ELIGIBLE (Remove-origin) epoch grinding an implausible
    /// ordinal is dropped by the plausibility bound (ordinal < minting-op count) — so it can neither win the
    /// write epoch nor sit in the retained set where a later `max()+1` re-epoch would `RevisionOverflow` and
    /// permanently brick removals/reseals. A plausible higher ordinal still wins, so the bound never
    /// over-rejects.
    #[test]
    fn fold_sealing_drops_an_epoch_with_an_implausible_ordinal() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &["bob"]);

        // A Remove op grinds an epoch at u32::MAX. Two minting ops → bound 2, so u32::MAX (>= 2) is dropped:
        // without the guard it is eligible and its huge ordinal would win AND brick every future re-epoch.
        let attack = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![rrk_wrap(), member_wrap("bob")], Some(escrow())),
            sealing_entry(9, b"evil", u32::MAX, Remove, vec![rrk_wrap(), member_wrap("bob")], None),
        ];
        let folded = fold_sealing(&attack, &members).unwrap();
        assert_eq!(folded.write_key_id, b"k0".to_vec(), "an implausible-ordinal epoch cannot win");
        assert!(
            folded.epochs.iter().all(|e| e.epoch < 2),
            "the u32::MAX epoch is dropped from the retained set, so max()+1 cannot overflow"
        );

        // Boundary: a legit Remove epoch at ordinal 1 (bound 2, 1 < 2) is retained and legitimately wins.
        let legit = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![rrk_wrap(), member_wrap("bob")], Some(escrow())),
            sealing_entry(9, b"k1", 1, Remove, vec![rrk_wrap(), member_wrap("bob")], None),
        ];
        assert_eq!(
            fold_sealing(&legit, &members).unwrap().write_key_id,
            b"k1".to_vec(),
            "a plausible higher ordinal is retained and wins — the bound does not over-reject"
        );
    }

    /// `needs_backfill` flags a resolved member missing a wrap in some RETAINED epoch (OPE-288) — the
    /// historical-READ gap a concurrent add leaves — and is ORTHOGONAL to `needs_reseal` (a write-epoch
    /// forward-secrecy signal): here the write epoch covers everyone, yet an older epoch doesn't. An extra
    /// (removed) member still wrapped in an old epoch does NOT trip it (removal is forward-only).
    #[test]
    fn needs_backfill_flags_a_member_missing_from_an_older_epoch() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &["bob", "carol"]); // resolved = owner + bob + carol

        // Genesis epoch 0 predates carol (wraps owner+bob only); the newer epoch 1 covers owner+bob+carol.
        // The WRITE epoch (1) covers the resolved set → no reseal — but carol can't read epoch-0 history.
        let gap = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![rrk_wrap(), member_wrap("bob")], Some(escrow())),
            sealing_entry(5, b"k1", 1, Remove, vec![rrk_wrap(), member_wrap("bob"), member_wrap("carol")], None),
        ];
        let folded = fold_sealing(&gap, &members).unwrap();
        assert!(!folded.needs_reseal, "the write epoch (k1) covers the resolved membership");
        assert!(folded.needs_backfill, "carol lacks a wrap in the older epoch k0");

        // Backfilled: every retained epoch wraps every resolved member → no gap.
        let complete = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![rrk_wrap(), member_wrap("bob"), member_wrap("carol")], Some(escrow())),
            sealing_entry(5, b"k1", 1, Remove, vec![rrk_wrap(), member_wrap("bob"), member_wrap("carol")], None),
        ];
        assert!(!fold_sealing(&complete, &members).unwrap().needs_backfill, "all epochs cover all members");

        // An EXTRA member (a removed dave still wrapped in the old epoch) is NOT a backfill gap.
        let extra = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![rrk_wrap(), member_wrap("bob"), member_wrap("carol"), member_wrap("dave")], Some(escrow())),
            sealing_entry(5, b"k1", 1, Remove, vec![rrk_wrap(), member_wrap("bob"), member_wrap("carol")], None),
        ];
        assert!(!fold_sealing(&extra, &members).unwrap().needs_backfill, "an extra removed member is not a gap");
    }

    /// Recipient-key binding in coverage (OPE-290): a wrap left on a member's STALE key (a rekey race) is
    /// detected via the exists-current-key clause, while a benign COEXISTING old+new wrap is NOT flagged —
    /// exists-form, not pair-set equality, so the leftover doesn't force spurious churn.
    #[test]
    fn epoch_covers_binds_the_recipient_key() {
        let members = membership("owner", &["bob"]); // bob's current key = hpke_key("bob")

        let ok = SealedEpoch { key_id: b"k".to_vec(), epoch: 0, wraps: vec![rrk_wrap(), member_wrap("bob")] };
        assert!(epoch_covers(&ok, &members), "a wrap to bob's current key covers");

        let stale = SealedEpoch {
            key_id: b"k".to_vec(),
            epoch: 0,
            wraps: vec![rrk_wrap(), member_wrap_keyed("bob", b"old-key")],
        };
        assert!(!epoch_covers(&stale, &members), "a wrap on bob's STALE key does not cover");

        let both = SealedEpoch {
            key_id: b"k".to_vec(),
            epoch: 0,
            wraps: vec![rrk_wrap(), member_wrap_keyed("bob", b"old-key"), member_wrap("bob")],
        };
        assert!(epoch_covers(&both, &members), "a coexisting current-key wrap covers; the old one is ignored");

        // needs_backfill uses the same key-bound test: a stale-key-only wrap counts as missing.
        let entries = vec![sealing_entry(
            0,
            b"k0",
            0,
            dag_client::SealingOrigin::Genesis,
            vec![rrk_wrap(), member_wrap_keyed("bob", b"old-key")],
            Some(escrow()),
        )];
        assert!(
            fold_sealing(&entries, &members).unwrap().needs_backfill,
            "a member wrapped only under a stale key needs a backfill"
        );
    }

    /// A resolved member with an empty/malformed HPKE key is EXCLUDED from coverage (OPE-290) — it can be
    /// neither wrapped nor matched, so it must not wedge `needs_reseal`/`needs_backfill` permanently true.
    #[test]
    fn coverage_excludes_an_empty_keyed_member() {
        use keyeo_api::MemberView;
        let members = MembershipView::new(
            vec![
                MemberView { member_id: "owner".into(), role: 1, author_public_key: vec![], hpke_public_key: hpke_key("owner") },
                MemberView { member_id: "ghost".into(), role: 4, author_public_key: vec![], hpke_public_key: vec![] },
            ],
            false,
        );
        let ep = SealedEpoch { key_id: b"k".to_vec(), epoch: 0, wraps: vec![rrk_wrap()] };
        assert!(epoch_covers(&ep, &members), "an empty-keyed member is excluded, so an RRK-only epoch covers");
        assert!(!any_epoch_missing_a_member(&[ep], &members), "and it isn't reported as a backfill gap");
    }

    /// OPE-290 companion: `member_epoch_deks` tries EVERY wrap addressed to the member, not just the first —
    /// so a DEAD stale-key wrap listed before the live one doesn't wrongly skip an epoch the member can open
    /// (without this, a key-bound backfill would be cosmetic).
    #[test]
    fn member_epoch_deks_opens_via_the_live_wrap_past_a_dead_one() {
        let tree = TREE;
        let kdf = KdfParams { salt: generate_salt().unwrap().to_vec(), memory_kib: 8, iterations: 1, parallelism: 1 };
        let root = derive_root(b"member pass", &kdf).unwrap();
        let dek = generate_dek().unwrap();
        let (member, key_id) = ("bob", b"k0");
        // A dead wrap to a DIFFERENT key, listed FIRST; then the live wrap to bob's real key.
        let other = generate_hpke_keypair().unwrap();
        let dead = member_wrap_epoch(&other.public, &dek, tree, member, key_id).unwrap();
        let live = member_wrap_epoch(&root.hpke_public, &dek, tree, member, key_id).unwrap();
        let ep = SealedEpoch { key_id: key_id.to_vec(), epoch: 0, wraps: vec![dead, live] };
        let deks = member_epoch_deks(&[ep], tree, member, &root.hpke_secret).unwrap();
        assert_eq!(deks.len(), 1, "the epoch opens via the live wrap despite a dead wrap first");
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
                recipient_public_key: vec![],
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
            matches!(rolled_back, Err(VaultError::WatermarkRollback { .. })),
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
            matches!(bad_floor, Err(VaultError::MalformedWatermark)),
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
