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
//! ReFound), change_passphrase (current-key Retarget). Membership authoring (add/remove with member-unlock),
//! the fuller effective-op fold (reset-merge carve-out / quorum-Commit), and the anti-rollback watermark
//! (OPE-284) land next; DagVault is now interchangeable with ChainVault behind the trait.

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
    build_recovery_escrow, epoch_deks, member_wrap_epoch, new_owner_secrets, rrk_wrap_epoch,
    sealer_set_from_deks, validate_kdf, CoreWrap, RecoveryEscrow, SealedEpoch, PASSPHRASE, RECOVERY,
};
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

/// Fold the effective ops' sealing deltas (in order) into the current epochs + escrow. `new_epochs` are
/// inserted (keyed by `key_id`), `added_wraps` are appended to the matching existing epoch (a wrap over an
/// unknown epoch is skipped — a delta whose epoch this replica hasn't/won't see), and the latest escrow
/// wins. Errors if no escrow was ever set.
fn fold_sealing(sealing: &[Vec<u8>]) -> Result<(Vec<SealedEpoch>, RecoveryEscrow), SealerError> {
    let mut epochs: Vec<SealedEpoch> = Vec::new();
    let mut escrow: Option<RecoveryEscrow> = None;
    for bytes in sealing {
        let payload: SealingPayload =
            serde_json::from_slice(bytes).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        for e in payload.new_epochs {
            epochs.push(e);
        }
        for aw in payload.added_wraps {
            if let Some(ep) = epochs.iter_mut().find(|e| e.key_id == aw.key_id) {
                ep.wraps.push(aw.wrap);
            }
        }
        if payload.escrow.is_some() {
            escrow = payload.escrow;
        }
    }
    let escrow =
        escrow.ok_or_else(|| SealerError::BadKeyring("dag keyring has no recovery escrow".into()))?;
    Ok((epochs, escrow))
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
        let rrk_wrap = rrk_wrap_epoch(&rrk_public, &dek, tree_id, member_id, &key_id, 0)?;
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

        let sealer = sealer_set_from_deks(tree_id, replica_id, vec![(key_id, 0, dek)])?;
        Ok(Provisioned {
            anchor,
            recovery_code: secrets.recovery_code,
            sealer,
            did_key,
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

        let (epochs, escrow) = fold_sealing(&resolved.sealing)?;

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
        let sealer = sealer_set_from_deks(tree_id, replica_id, deks)?;

        let owner_key: [u8; 32] = founder
            .author_public_key
            .as_slice()
            .try_into()
            .map_err(|_| SealerError::BadKeyring("owner key is not 32 bytes".into()))?;
        Ok(Unlocked {
            sealer,
            // TODO(OPE-284): the dag watermark is the frontier op-id set; empty until the anti-rollback
            // wiring lands. Provision+unlock don't exercise it.
            watermark: Vec::new(),
            did_key: DidKey::from_public_key(&owner_key),
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
        _floor: &[u8],
    ) -> Result<Recovered, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        // Resolve the current sealing → the escrow, and unwrap the RRK via the recovery code.
        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let (epochs, escrow) = fold_sealing(&resolved.sealing)?;
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
        let sealer = sealer_set_from_deks(tree_id, replica_id, deks)?;

        Ok(Recovered {
            anchor: new_anchor,
            recovery_code: secrets.recovery_code,
            sealer,
            watermark: Vec::new(),
            did_key,
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
        _floor: &[u8],
    ) -> Result<Rekeyed, SealerError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| SealerError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| SealerError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let (_epochs, escrow) = fold_sealing(&resolved.sealing)?;

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

        Ok(Rekeyed {
            anchor: new_anchor,
            recovery_code: secrets.recovery_code,
            watermark: Vec::new(),
        })
    }
}

impl DagVault {
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
        let (epochs, escrow) = fold_sealing(&resolved.sealing)?;

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
            .map(|(key_id, epoch, dek)| {
                member_wrap_epoch(&new_member_hpke_public, dek, tree_id, new_member_id, key_id, *epoch)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, SealContext};
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
