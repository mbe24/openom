//! The engine-agnostic client keyring **lifecycle** — the shared menu the two lockstep host consumers
//! (the web-worker RPC in [`crate::wasm`] and the Tauri invoke host in `openom-vault-host`) dispatch over
//! once, instead of hand-wiring 2 engines × 2 hosts. This is OPE-277 piece #1 of the swap seam
//! (plan/keyring-dag/design.swap-seam-decision.md).
//!
//! **Anchor-in / anchor-out + watermark, all engine-OPAQUE bytes.** A tree's trust state is an opaque
//! `anchor` (the chain's is its signed `Keyring`; a future dag anchor is its op closure) and its
//! anti-rollback cursor is an opaque `watermark`. Guardrail #1 of the gate: the anti-rollback floor lives
//! INSIDE these opaque bytes, never as a shared scalar — a `u32 revision` would be security-critical for
//! the chain and meaningless for the dag (structurally monotonic), the textbook model leak. So the seam
//! carries the floor in and the cursor out as bytes; only the concrete engine reads them.
//!
//! **Shared menu only.** Engine-SPECIFIC behaviour stays as inherent methods on the concrete engine types
//! — never forced through this trait. That deliberately includes **membership authoring** (add/remove
//! member, promote/demote) and **endorsement**: the chain authors through two authority models
//! (owner-via-RRK vs co-owner-via-member-wrap + a pinned trusted-signer set) and its endorse
//! (`blob_sync::countersign`) is a Blob CAS I/O loop — neither fits a pure, non-leaky shared signature, and
//! the gate's own guardrail #4 keeps sync engine-owned. The hosts reach authoring behind the engine enum's
//! own arms; "author/endorse in the menu" is honoured as a capability at the single dispatch site, not as
//! a trait method. (Gate amendment, recorded in the decision doc; revisit promoting `author` alone once
//! the dag lifecycle — OPE-273 — exists and its authoring model is concrete.)
//!
//! **Why this lives in openom-sealer, not the seam crate.** Every result carries a [`SealerSet`] plus
//! `RecoveryCode` / `DidKey` (client secret-handling types). The keyless `openom-keyring-seam` is the
//! *server's* binding surface (roles only today) — putting these there would poison it with client crypto
//! deps. So the trait lives with the sealer for now; its permanent home is a future `openom-vault` crate
//! above both engines (OPE-279 extraction, after the dag vault lands — deliberately not now, to avoid
//! moving the wasm cdylib in front of OPE-273 while the trait shape is still settling).

use openom_crypto::{Passphrase, RecoveryCode};
use openom_did::DidKey;
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};

use crate::vault;
use crate::{SealerError, SealerSet};

/// The tree + member context every lifecycle call needs: which tree is being operated on and who is
/// acting. These come from the caller's OWN expectation (the tree the app opened), NEVER the parsed,
/// untrusted keyring — the trusted-context invariant the vault's "the AEAD binds tree_id" security rests
/// on (see [`crate::vault`]).
pub struct VaultContext<'a> {
    pub tree_id: &'a TreeId,
    pub member_id: &'a MemberId,
    pub replica_id: &'a ReplicaId,
}

/// Result of [`KeyringLifecycle::provision`]: the initial trust `anchor` to publish + persist, the
/// one-time recovery code to show ONCE, the ready sealer, and the owner's stable `did:key`.
pub struct Provisioned {
    /// The engine-opaque trust state to publish (chain: the signed genesis keyring).
    pub anchor: Vec<u8>,
    pub recovery_code: RecoveryCode,
    pub sealer: SealerSet,
    pub did_key: DidKey,
}

/// Result of [`KeyringLifecycle::unlock`]: the sealer plus the opaque anti-rollback `watermark` the caller
/// must persist (never interpret).
pub struct Unlocked {
    pub sealer: SealerSet,
    /// The engine-opaque anti-rollback cursor to persist (chain: the keyring revision, as bytes).
    pub watermark: Vec<u8>,
    pub did_key: DidKey,
    /// Advisory: the current write epoch's wraps don't match the resolved membership, so a concurrent
    /// membership merge left it stale and a reseal is due (dag only — the chain, being linear, is always
    /// `false`). Never blocks unlock; the client repairs it out-of-band (OPE-282).
    pub needs_reseal: bool,
}

/// Result of [`KeyringLifecycle::recover`]: a new `anchor` + a NEW recovery code (both to publish/show),
/// the sealer, the new watermark, and the new owner's `did:key` (recovery mints a fresh identity).
pub struct Recovered {
    pub anchor: Vec<u8>,
    pub recovery_code: RecoveryCode,
    pub sealer: SealerSet,
    pub watermark: Vec<u8>,
    pub did_key: DidKey,
    /// See [`Unlocked::needs_reseal`] — recovery also returns a live sealer, so it carries the same signal.
    pub needs_reseal: bool,
}

/// Result of [`KeyringLifecycle::change_passphrase`]: the new `anchor` + a rotated recovery code + the new
/// watermark. The DEKs are unchanged, so any running sealer keeps working — no re-seal.
pub struct Rekeyed {
    pub anchor: Vec<u8>,
    pub recovery_code: RecoveryCode,
    pub watermark: Vec<u8>,
}

/// The client keyring lifecycle — the shared menu (see the module docs). `anchor` and `floor` are
/// engine-opaque bytes; results carry the new anchor to publish plus the opaque watermark to persist.
pub trait KeyringLifecycle {
    /// Create a brand-new encrypted tree.
    fn provision(
        &self,
        ctx: &VaultContext,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, SealerError>;

    /// Re-open an existing tree from its trusted `anchor` + passphrase (returning / a new device).
    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
    ) -> Result<Unlocked, SealerError>;

    /// Recover with the recovery code, re-establishing owner access under `new_passphrase`, preserving
    /// members + epochs. `floor` is the caller's opaque anti-rollback watermark (the served anchor is
    /// untrusted on recovery — see [`crate::vault::recover`]).
    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, SealerError>;

    /// Change the passphrase: re-wrap under a new KEK. The DEKs (and any running sealer) are unchanged, so
    /// the tree is not re-sealed. `floor` is the opaque anti-rollback watermark.
    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, SealerError>;
}

/// The linear-chain engine's lifecycle — openom's shipping keyring. Its anchor is the signed `Keyring`
/// bytes and its watermark is the keyring revision; each flow re-signs a new revision. Zero-sized: the
/// [`crate::vault`] flows are stateless free functions, so the engine choice is carried by the type, not
/// by held state. (The dag lifecycle impl is OPE-273.)
pub struct ChainVault;

impl ChainVault {
    /// Encode the chain's anti-rollback cursor (a keyring revision) as the opaque seam watermark.
    fn watermark(revision: u32) -> Vec<u8> {
        revision.to_be_bytes().to_vec()
    }

    /// Decode an opaque `floor` back to the chain's `min_revision`. Empty ⇒ no floor (0). A non-empty
    /// value that isn't a 4-byte revision is refused ([`SealerError::MalformedWatermark`]) rather than
    /// silently treated as 0 — dropping a corrupt floor would drop rollback protection.
    fn floor(bytes: &[u8]) -> Result<u32, SealerError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let b: [u8; 4] = bytes.try_into().map_err(|_| SealerError::MalformedWatermark)?;
        Ok(u32::from_be_bytes(b))
    }
}

impl KeyringLifecycle for ChainVault {
    fn provision(
        &self,
        ctx: &VaultContext,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, SealerError> {
        let p = vault::provision(passphrase, ctx.tree_id, ctx.member_id, ctx.replica_id)?;
        Ok(Provisioned {
            anchor: p.keyring,
            recovery_code: p.recovery_code,
            sealer: p.sealer,
            did_key: p.did_key,
        })
    }

    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
    ) -> Result<Unlocked, SealerError> {
        let u = vault::unlock(anchor, passphrase, ctx.tree_id, ctx.member_id, ctx.replica_id)?;
        Ok(Unlocked {
            sealer: u.sealer,
            watermark: Self::watermark(u.revision),
            did_key: u.did_key,
            needs_reseal: false, // a linear chain has no concurrent-merge stale epoch
        })
    }

    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, SealerError> {
        let r = vault::recover(
            anchor,
            recovery_code,
            new_passphrase,
            ctx.tree_id,
            ctx.member_id,
            ctx.replica_id,
            Self::floor(floor)?,
        )?;
        Ok(Recovered {
            anchor: r.keyring,
            recovery_code: r.recovery_code,
            sealer: r.sealer,
            watermark: Self::watermark(r.revision),
            did_key: r.did_key,
            needs_reseal: false,
        })
    }

    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, SealerError> {
        let re = vault::change_passphrase(
            anchor,
            old_passphrase,
            new_passphrase,
            ctx.tree_id,
            ctx.member_id,
            Self::floor(floor)?,
        )?;
        Ok(Rekeyed {
            anchor: re.keyring,
            recovery_code: re.recovery_code,
            watermark: Self::watermark(re.revision),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &[u8] = b"tree-uuid-16byte";
    const MEMBER: &str = "acct-1";

    fn ctx<'a>(tree: &'a TreeId, member: &'a MemberId, replica: &'a ReplicaId) -> VaultContext<'a> {
        VaultContext {
            tree_id: tree,
            member_id: member,
            replica_id: replica,
        }
    }

    /// Drive the whole four-flow spine through the trait object (not the free functions) on the chain
    /// engine: provision → unlock → change_passphrase → unlock-under-new → recover. Proves the shared menu
    /// fits the shipping keyring with the anti-rollback floor threaded as OPAQUE bytes (never a scalar) —
    /// the shape the two hosts will dispatch over.
    #[test]
    fn chain_vault_drives_the_lifecycle_through_the_trait() {
        let engine: &dyn KeyringLifecycle = &ChainVault;
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let replica = ReplicaId::new(b"replica-A");
        let pass = Passphrase::new(b"correct horse");

        // provision → the genesis anchor + a ready sealer.
        let p = engine.provision(&ctx(&tree, &member, &replica), &pass).unwrap();
        assert!(!p.anchor.is_empty());

        // unlock the genesis anchor → an opaque watermark, not a bare revision.
        let u = engine
            .unlock(&ctx(&tree, &member, &replica), &p.anchor, &pass)
            .unwrap();
        assert_eq!(u.watermark, ChainVault::watermark(1), "chain watermark = revision 1, as bytes");
        assert_eq!(u.did_key, p.did_key, "same identity across provision + unlock");

        // change_passphrase → a new anchor; the OLD passphrase must no longer unlock it. The floor is
        // passed as the opaque watermark from the unlock above.
        let new_pass = Passphrase::new(b"stronger horse battery");
        let re = engine
            .change_passphrase(&ctx(&tree, &member, &replica), &p.anchor, &pass, &new_pass, &u.watermark)
            .unwrap();
        assert_ne!(re.watermark, u.watermark, "a keyring change advances the watermark");
        assert!(
            engine
                .unlock(&ctx(&tree, &member, &replica), &re.anchor, &pass)
                .is_err(),
            "the old passphrase can't open the re-keyed anchor"
        );
        assert!(
            engine
                .unlock(&ctx(&tree, &member, &replica), &re.anchor, &new_pass)
                .is_ok(),
            "the new passphrase opens it"
        );

        // recover the re-keyed anchor with the CURRENT recovery code (change_passphrase rotated it — the
        // old code's wrap was replaced) — re-establishes access under yet another passphrase. Floor = the
        // watermark we're at.
        let recovered = engine
            .recover(
                &ctx(&tree, &member, &replica),
                &re.anchor,
                &re.recovery_code,
                &Passphrase::new(b"third passphrase"),
                &re.watermark,
            )
            .unwrap();
        assert_ne!(recovered.watermark, re.watermark, "recovery advances past the floor");
    }

    /// A non-empty floor that isn't a 4-byte revision is refused, not silently treated as "no floor" —
    /// dropping a corrupt local cursor would drop rollback protection.
    #[test]
    fn a_malformed_floor_is_refused_not_dropped() {
        assert_eq!(ChainVault::floor(&[]).unwrap(), 0, "empty floor = no floor");
        assert_eq!(ChainVault::floor(&7u32.to_be_bytes()).unwrap(), 7);
        assert!(matches!(
            ChainVault::floor(&[1, 2, 3]),
            Err(SealerError::MalformedWatermark)
        ));
    }

    /// The whole `KeyringLifecycle` contract, engine-agnostic: provision on one replica + seal; unlock on
    /// another (from the opaque anchor alone) opens it; change_passphrase then unlock-under-the-new-pass
    /// opens it; recover (with the provision recovery code) opens it. All over opaque anchors + watermarks
    /// + floors, so the body is identical for both engines.
    fn lifecycle_contract<E: KeyringLifecycle>(engine: &E) {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"correct horse");

        let p = engine
            .provision(&ctx(&tree, &member, &ReplicaId::new(b"rA")), &pass)
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&crate::SealContext::snapshot(0, Vec::new(), 0), b"parity data")
            .unwrap()
            .envelope;

        // unlock from the anchor alone opens the data, same owner identity.
        let u = engine
            .unlock(&ctx(&tree, &member, &ReplicaId::new(b"rB")), &p.anchor, &pass)
            .unwrap();
        assert_eq!(u.did_key, p.did_key);
        assert!(!u.watermark.is_empty(), "unlock reports an anti-rollback watermark, not a stub");
        assert_eq!(
            u.sealer.open_entry(crate::EntryKind::Snapshot, &sealed).unwrap(),
            b"parity data"
        );

        // change_passphrase — gated on the unlock floor — then unlock under the new passphrase opens the
        // same data, and the watermark has advanced past the floor.
        let new_pass = Passphrase::new(b"changed passphrase");
        let re = engine
            .change_passphrase(
                &ctx(&tree, &member, &ReplicaId::new(b"rA")),
                &p.anchor,
                &pass,
                &new_pass,
                &u.watermark,
            )
            .unwrap();
        assert_ne!(re.watermark, u.watermark, "a keyring change advances the watermark");
        let u2 = engine
            .unlock(&ctx(&tree, &member, &ReplicaId::new(b"rC")), &re.anchor, &new_pass)
            .unwrap();
        assert_eq!(
            u2.sealer.open_entry(crate::EntryKind::Snapshot, &sealed).unwrap(),
            b"parity data"
        );

        // recover (with the provision recovery code, a fresh passphrase) opens the same data. The served
        // anchor is the original, so its own frontier (`u.watermark`) is a satisfiable floor.
        let r = engine
            .recover(
                &ctx(&tree, &member, &ReplicaId::new(b"rD")),
                &p.anchor,
                &p.recovery_code,
                &Passphrase::new(b"recovered passphrase"),
                &u.watermark,
            )
            .unwrap();
        assert!(!r.watermark.is_empty(), "recovery reports an advanced watermark");
        assert_eq!(
            r.sealer.open_entry(crate::EntryKind::Snapshot, &sealed).unwrap(),
            b"parity data"
        );
    }

    /// Parity: the chain and dag engines satisfy the SAME lifecycle contract behaviorally — OPE-267's
    /// parity matrix carried through the real vaults, behind the trait.
    #[test]
    fn chain_and_dag_satisfy_the_same_lifecycle_contract() {
        lifecycle_contract(&ChainVault);
        lifecycle_contract(&crate::DagVault);
    }
}
