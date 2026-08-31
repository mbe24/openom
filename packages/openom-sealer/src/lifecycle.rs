//! The engine-agnostic client keyring **lifecycle** — the shared menu the two lockstep host consumers
//! (the web-worker RPC in [`crate::wasm`] and the Tauri invoke host in `openom-vault-host`) dispatch over
//! once, instead of hand-wiring 2 engines × 2 hosts. This is OPE-277 piece #1 of the swap seam
//! (plan/keyring-dag/design.swap-seam-decision.md).
//!
//! **Anchor-in / anchor-out over engine-OPAQUE bytes.** A tree's trust state is an opaque `anchor`: the
//! chain's is its signed `Keyring`; a future dag anchor is its op closure. The lifecycle takes an anchor
//! in and hands the new anchor (to publish + persist) back inside its result — no layer between the vault
//! and the engine interprets those bytes. Secret-holding, client-only, pure bytes→bytes: no I/O, no
//! network, so local authoring never blocks on the network.
//!
//! **Shared menu only.** Engine-SPECIFIC behaviour (the chain's draft-blob countersign exchange, a dag's
//! merge horizon) stays as inherent methods on the concrete engine types — never forced through this
//! trait. Membership authoring (add/remove member, promote/demote) is a second method group added in a
//! later slice; this slice establishes the four-flow vault spine.
//!
//! **Why this lives in openom-sealer, not the seam crate.** Every result carries a [`SealerSet`] (the
//! shared, engine-agnostic DEK sealing layer). `SealerSet` sits *above* `openom-keyring-seam` in the
//! dependency graph, so the seam crate cannot name it without a cycle — and for uniform enum-dispatch the
//! results must be *common* types, not per-engine associated types. So the trait lives here with the
//! sealer; the seam crate keeps the keyless `MembershipView` + `KeyringVerifier` vocabulary. (The
//! decision doc's "both traits in the seam crate" predates working the layering through; the seam crate's
//! own module doc already notes the lifecycle trait "lives with the sealer".)

use openom_crypto::{Passphrase, RecoveryCode};
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};

use crate::vault::{self, Provisioned, Recovered, Rekeyed, Unlocked};
use crate::SealerError;

/// The tree + member context every lifecycle call needs: which tree is being operated on and who is
/// acting. These come from the caller's OWN expectation (the tree the app opened), NEVER the parsed,
/// untrusted keyring — the trusted-context invariant the vault's "the AEAD binds tree_id" security rests
/// on (see [`crate::vault`]).
pub struct VaultContext<'a> {
    pub tree_id: &'a TreeId,
    pub member_id: &'a MemberId,
    pub replica_id: &'a ReplicaId,
}

/// The client keyring lifecycle — the shared menu (see the module docs). `anchor` is engine-opaque trust
/// state; results carry the new anchor to publish/persist plus the ready sealer material.
pub trait KeyringLifecycle {
    /// Create a brand-new encrypted tree. Returns the initial keyring anchor to publish, the one-time
    /// recovery code to show ONCE, the ready sealer, and the owner's stable `did:key`.
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
    /// members + epochs. `min_revision` is the caller's anti-rollback watermark floor (the served anchor
    /// is untrusted on recovery — see [`crate::vault::recover`]).
    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        min_revision: u32,
    ) -> Result<Recovered, SealerError>;

    /// Change the passphrase: re-wrap under a new KEK. The DEKs (and any running sealer) are unchanged, so
    /// the tree is not re-sealed. `min_revision` is the anti-rollback floor.
    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        min_revision: u32,
    ) -> Result<Rekeyed, SealerError>;
}

/// The linear-chain engine's lifecycle — openom's shipping keyring. Its anchor is the signed `Keyring`
/// bytes; each flow re-signs a new revision. Zero-sized: the [`crate::vault`] flows are stateless free
/// functions, so the engine choice is carried by the type, not by held state. (The dag lifecycle impl is
/// OPE-273.)
pub struct ChainVault;

impl KeyringLifecycle for ChainVault {
    fn provision(
        &self,
        ctx: &VaultContext,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, SealerError> {
        vault::provision(passphrase, ctx.tree_id, ctx.member_id, ctx.replica_id)
    }

    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
    ) -> Result<Unlocked, SealerError> {
        vault::unlock(anchor, passphrase, ctx.tree_id, ctx.member_id, ctx.replica_id)
    }

    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        min_revision: u32,
    ) -> Result<Recovered, SealerError> {
        vault::recover(
            anchor,
            recovery_code,
            new_passphrase,
            ctx.tree_id,
            ctx.member_id,
            ctx.replica_id,
            min_revision,
        )
    }

    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        min_revision: u32,
    ) -> Result<Rekeyed, SealerError> {
        vault::change_passphrase(
            anchor,
            old_passphrase,
            new_passphrase,
            ctx.tree_id,
            ctx.member_id,
            min_revision,
        )
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
    /// engine: provision → unlock → change_passphrase → unlock-under-new → recover. Proves the anchor-in /
    /// anchor-out shared menu fits the shipping keyring, which is what the two hosts will dispatch over.
    #[test]
    fn chain_vault_drives_the_lifecycle_through_the_trait() {
        let engine: &dyn KeyringLifecycle = &ChainVault;
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let replica = ReplicaId::new(b"replica-A");
        let pass = Passphrase::new(b"correct horse");

        // provision → the genesis anchor + a ready sealer.
        let p = engine.provision(&ctx(&tree, &member, &replica), &pass).unwrap();
        assert!(!p.keyring.is_empty());

        // unlock the genesis anchor.
        let u = engine
            .unlock(&ctx(&tree, &member, &replica), &p.keyring, &pass)
            .unwrap();
        assert_eq!(u.revision, 1);
        assert_eq!(u.did_key, p.did_key, "same identity across provision + unlock");

        // change_passphrase → a new anchor; the OLD passphrase must no longer unlock it.
        let new_pass = Passphrase::new(b"stronger horse battery");
        let re = engine
            .change_passphrase(&ctx(&tree, &member, &replica), &p.keyring, &pass, &new_pass, u.revision)
            .unwrap();
        assert!(re.revision > u.revision, "a keyring change advances the revision");
        assert!(
            engine
                .unlock(&ctx(&tree, &member, &replica), &re.keyring, &pass)
                .is_err(),
            "the old passphrase can't open the re-keyed anchor"
        );
        assert!(
            engine
                .unlock(&ctx(&tree, &member, &replica), &re.keyring, &new_pass)
                .is_ok(),
            "the new passphrase opens it"
        );

        // recover the re-keyed anchor with the CURRENT recovery code (change_passphrase rotated it — the
        // old code's wrap was replaced) — re-establishes access under yet another passphrase.
        let recovered = engine
            .recover(
                &ctx(&tree, &member, &replica),
                &re.keyring,
                &re.recovery_code,
                &Passphrase::new(b"third passphrase"),
                re.revision,
            )
            .unwrap();
        assert!(recovered.revision > re.revision, "recovery advances past the floor");
    }
}
