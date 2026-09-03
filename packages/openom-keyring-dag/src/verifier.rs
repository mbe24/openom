//! The DAG keyring's [`KeyringVerifier`] adapter (OPE-277) — the keyless server-side seam.
//!
//! `admit(prior_state, update)` reconstructs the resolver from the opaque trust state (pinned genesis +
//! the op closure), applies the new op, and reports the resolved [`MembershipView`] + whether membership
//! changed. This is where the DAG's admit-then-resolve model meets the seam's anchor/view vocabulary:
//! - a validly-signed op the resolver gives no effect resolves to `changed = false` — the seam's honest
//!   no-op case, which chain never has;
//! - the anti-rollback state lives INSIDE the opaque `state` bytes (the op closure), never a shared field;
//! - a `ReFound` / `RotateRecoveryAuthority` admission sets `reset_boundary` (the server's cooldown gate).
//!
//! State + update are the engine's own opaque encoding (the seam never inspects them). The op bytes are
//! the SAME `blob_sync` codec the transport publishes, so an op verifies identically however it arrived.

use keyeo_dag::{ApplyOutcome, Error as KeyeoError, Keyeo, MembershipAction, SignedOp, StrongRemove};
use openom_keyring_api::{Admitted, KeyringVerifier, MemberView, MembershipView, VerifyError};
use serde::{Deserialize, Serialize};

use crate::blob_sync::{decode_op, dto_to_minit, minit_to_dto, MemberInitDto};
use crate::{KeyringAccess, KeyringEngine, KeyringMemberInit, KeyringState};

/// The genesis facts a replica trusts out-of-band (first-sight pin): the founding membership + the
/// recovery authority. Both engines pin these; here they seed the resolver's construction base.
#[derive(Serialize, Deserialize)]
struct PinnedConfig {
    /// The group (tree) id the engine's genesis is scoped to. Taken from the signed genesis op at
    /// bootstrap, so every replayed op — whose signed group_id must match — is gated to this tree; a
    /// tampered value fails closed (the signed ops won't match).
    #[serde(default)]
    group_id: Vec<u8>,
    genesis: Vec<MemberInitDto>,
    reset_authority: Option<[u8; 32]>,
}

/// The DAG's opaque trust state: the pinned config + the admitted op closure (each entry the `blob_sync`
/// op encoding). The keyring channel is `NeverPrune`, so at family scale this stays small.
#[derive(Serialize, Deserialize)]
struct DagTrustState {
    pinned: PinnedConfig,
    ops: Vec<Vec<u8>>,
}

/// One admitted update. `Bootstrap` seeds first sight (pinned config + the genesis op); `Op` is every
/// subsequent op. The variant must match the presence of prior state.
#[derive(Serialize, Deserialize)]
enum UpdateDto {
    Bootstrap { pinned: PinnedConfig, genesis_op: Vec<u8> },
    Op { op: Vec<u8> },
}

/// The DAG keyring's keyless verifier. Holds no secrets and no state — everything comes in via
/// `prior_state`/`update` and goes out via the returned opaque state, exactly as the seam requires.
#[derive(Clone, Copy, Debug, Default)]
pub struct DagVerifier;

impl DagVerifier {
    fn build(pinned: &PinnedConfig) -> Result<KeyringEngine, VerifyError> {
        let genesis: Vec<KeyringMemberInit> = pinned
            .genesis
            .iter()
            .map(dto_to_minit)
            .collect::<Result<_, _>>()
            .map_err(|_| VerifyError::Malformed)?;
        let base = KeyringState::create(keyeo_dag::GroupId::new(pinned.group_id.clone()), &genesis)
            .with_reset_authority(pinned.reset_authority);
        Ok(Keyeo::new(base, KeyringAccess, StrongRemove))
    }

    /// Replay the stored (already-admitted) op closure onto a fresh engine. These were valid when first
    /// admitted, so a failure here is a corrupt/tampered state blob, not a new refusal.
    fn replay(engine: &mut KeyringEngine, ops: &[Vec<u8>]) -> Result<(), VerifyError> {
        for bytes in ops {
            let op = decode_op(bytes).map_err(|_| VerifyError::Malformed)?;
            engine.apply(op).map_err(|_| VerifyError::Malformed)?;
        }
        engine.flush().map_err(|_| VerifyError::Malformed)?;
        Ok(())
    }
}

pub(crate) fn view_of(state: &KeyringState, reset_boundary: bool) -> MembershipView {
    let members = state
        .members
        .iter()
        .filter(|(_, m)| m.is_active())
        .map(|(id, m)| MemberView {
            member_id: id.clone(),
            role: m.role.0,
            author_public_key: m.author_public_key.to_vec(),
            hpke_public_key: m.hpke_public_key.to_vec(),
        })
        .collect();
    MembershipView::new(members, reset_boundary)
}

/// Map a keyeo apply error/outcome to a neutral [`VerifyError`] for the NEW op (stored ops use `replay`).
fn classify(outcome: Result<ApplyOutcome<String, [u8; 32]>, KeyeoError<String>>) -> Result<(), VerifyError> {
    match outcome {
        Ok(ApplyOutcome::Applied { .. }) => Ok(()),
        // Missing a parent op — the update references history the verifier hasn't been given (re-fetch).
        Ok(ApplyOutcome::Buffered { .. }) => Err(VerifyError::Stale),
        Err(KeyeoError::BadSignature) | Err(KeyeoError::UnknownAuthor { .. }) => {
            Err(VerifyError::Unauthenticated)
        }
        Err(KeyeoError::StaleFork) => Err(VerifyError::Rollback),
        Err(_) => Err(VerifyError::Malformed),
    }
}

fn encode_state(state: &DagTrustState) -> Vec<u8> {
    postcard::to_allocvec(state).expect("DagTrustState serialization is infallible")
}

impl KeyringVerifier for DagVerifier {
    fn admit(&self, prior_state: Option<&[u8]>, update: &[u8]) -> Result<Admitted, VerifyError> {
        let upd: UpdateDto = postcard::from_bytes(update).map_err(|_| VerifyError::Malformed)?;
        match (prior_state, upd) {
            // First sight: seed the pinned config + the (inert, per OPE-271) genesis op as the root.
            (None, UpdateDto::Bootstrap { pinned, genesis_op }) => {
                let mut engine = DagVerifier::build(&pinned)?;
                let op = decode_op(&genesis_op).map_err(|_| VerifyError::Malformed)?;
                let update_ref = op.id().to_vec();
                classify(engine.apply(op))?;
                engine.flush().map_err(|_| VerifyError::Malformed)?;
                let view = view_of(engine.state(), false);
                // The tree id from the VERIFIED resolved state (bound into every op's signature; survives the
                // genesis Create fold), never from an unsigned side channel.
                let tree_id = engine.state().group_id.0.clone();
                let state = encode_state(&DagTrustState { pinned, ops: vec![genesis_op] });
                Ok(Admitted { state, view, changed: true, tree_id, update_ref })
            }
            // Every subsequent op: replay the closure, resolve before + after, diff the membership.
            (Some(prior), UpdateDto::Op { op: op_bytes }) => {
                let st: DagTrustState =
                    postcard::from_bytes(prior).map_err(|_| VerifyError::Malformed)?;
                let mut engine = DagVerifier::build(&st.pinned)?;
                DagVerifier::replay(&mut engine, &st.ops)?;
                let before = view_of(engine.state(), false).members;

                let op = decode_op(&op_bytes).map_err(|_| VerifyError::Malformed)?;
                let op_id = op.id();
                let is_reset = matches!(
                    op.action(),
                    MembershipAction::ReFound { .. } | MembershipAction::RotateRecoveryAuthority { .. }
                );
                classify(engine.apply(op))?;
                // (a) vs (b): an op unauthorized AT ITS CAUSAL POSITION is permanently ineffective on
                // every branch — refuse it (anti-spam), which is convergence-safe because no honest client
                // ever gives it effect. An op that merely lost a concurrent race is authorized-at-position
                // and MUST be kept (it may stand on a branch that hasn't seen the invalidator) — that is
                // the genuine admit-then-resolve no-op (changed=false), the case the chain can't represent.
                if engine.authorized_at_position(&op_id) == Some(false) {
                    return Err(VerifyError::Unauthorized);
                }
                engine.flush().map_err(|_| VerifyError::Malformed)?;

                let view = view_of(engine.state(), is_reset);
                let changed = view.members != before;
                let tree_id = engine.state().group_id.0.clone();
                let update_ref = op_id.to_vec();
                let mut ops = st.ops;
                ops.push(op_bytes);
                let state = encode_state(&DagTrustState { pinned: st.pinned, ops });
                Ok(Admitted { state, view, changed, tree_id, update_ref })
            }
            // A bootstrap against existing state, or an op with no prior state — malformed sequencing.
            _ => Err(VerifyError::Malformed),
        }
    }
}

/// Build a `Bootstrap` update from the pinned genesis + the signed genesis op — the first-sight input a
/// server (or client adoption path) admits. (Helper for callers/tests; the seam itself never constructs
/// updates.)
pub fn bootstrap_update(
    genesis: &[KeyringMemberInit],
    reset_authority: Option<[u8; 32]>,
    genesis_op: &crate::KeyringOp,
) -> Vec<u8> {
    let dto = UpdateDto::Bootstrap {
        pinned: PinnedConfig {
            // The group id comes from the signed genesis op — the authentic value every replayed op is
            // gated against (never trusted from an unsigned side channel).
            group_id: genesis_op.group_id.0.clone(),
            genesis: genesis.iter().map(minit_to_dto).collect(),
            reset_authority,
        },
        genesis_op: crate::blob_sync::encode_op(genesis_op),
    };
    postcard::to_allocvec(&dto).expect("UpdateDto serialization is infallible")
}

/// Build an `Op` update from a signed op — every non-genesis admission.
pub fn op_update(op: &crate::KeyringOp) -> Vec<u8> {
    let dto = UpdateDto::Op {
        op: crate::blob_sync::encode_op(op),
    };
    postcard::to_allocvec(&dto).expect("UpdateDto serialization is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{recovery, sign_op, KeyringMemberInit, KeyringRole};
    use keyeo_dag::MemberInit;

    fn sk(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
    }
    fn vk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }
    fn minit(id: &str, role: KeyringRole, seed: u8) -> KeyringMemberInit {
        MemberInit {
            id: id.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
        }
    }
    fn add(member: &str, role: KeyringRole, seed: u8) -> crate::KeyringAction {
        MembershipAction::Add {
            member: member.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
            member_proof: None,
        }
    }
    fn create(members: &[KeyringMemberInit]) -> crate::KeyringAction {
        MembershipAction::Create { initial_members: members.to_vec() }
    }

    #[test]
    fn dag_verifier_folds_admitted_ops_into_a_membership_view() {
        let v = DagVerifier;
        let gm = vec![minit("founder", KeyringRole::OWNER, 1)];
        let genesis_op = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        // bootstrap
        let boot = v
            .admit(None, &bootstrap_update(&gm, None, &genesis_op))
            .unwrap();
        assert!(boot.changed);
        assert_eq!(boot.view.members.len(), 1);
        assert_eq!(boot.view.owner().unwrap().member_id, "founder");

        // founder adds bob as a co-owner
        let add_bob = sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1));
        let step = v.admit(Some(&boot.state), &op_update(&add_bob)).unwrap();
        assert!(step.changed, "adding a member changes the view");
        let ids: Vec<_> = step.view.members.iter().map(|m| m.member_id.as_str()).collect();
        assert_eq!(ids, vec!["bob", "founder"]);
        assert_eq!(step.view.signers().count(), 2, "both are signers");
    }

    #[test]
    fn a_permanently_unauthorized_op_is_refused_not_admitted() {
        // dave is a Maintainer (never a signer), so his add is unauthorized AT ITS CAUSAL POSITION —
        // permanently ineffective on every branch. The verifier REFUSES it (anti-spam), where a naive
        // admit-then-resolve would keep it as a no-op that just wastes space.
        let v = DagVerifier;
        let gm = vec![
            minit("founder", KeyringRole::OWNER, 1),
            minit("dave", KeyringRole::MAINTAINER, 4),
        ];
        let genesis_op = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        let boot = v.admit(None, &bootstrap_update(&gm, None, &genesis_op)).unwrap();
        let daves_add = sign_op([2; 32], vec![[1; 32]], "dave", add("mallory", KeyringRole::EDITOR, 9), &sk(4));
        assert_eq!(
            v.admit(Some(&boot.state), &op_update(&daves_add)).unwrap_err(),
            VerifyError::Unauthorized,
            "an op unauthorized at its causal position is refused, not kept as a no-op"
        );
    }

    #[test]
    fn an_op_that_lost_a_concurrent_race_is_admitted_as_a_no_op() {
        // The genuine admit-then-resolve no-op the chain can't represent. bob (a co-owner) adds carol on
        // one branch while the founder CONCURRENTLY removes bob on another. bob's add WAS authorized at
        // its position, so it is kept (changed=false), NOT refused — a replica on the branch that hasn't
        // seen the removal needs it to converge.
        let v = DagVerifier;
        let gm = vec![
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
        ];
        let genesis_op = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        let boot = v.admit(None, &bootstrap_update(&gm, None, &genesis_op)).unwrap();

        let remove_bob = sign_op([2; 32], vec![[1; 32]], "founder", MembershipAction::Remove { member: "bob".into() }, &sk(1));
        let s1 = v.admit(Some(&boot.state), &op_update(&remove_bob)).unwrap();

        // bob's add is a child of genesis — concurrent with his own removal.
        let bob_adds_carol = sign_op([3; 32], vec![[1; 32]], "bob", add("carol", KeyringRole::EDITOR, 3), &sk(2));
        let out = v.admit(Some(&s1.state), &op_update(&bob_adds_carol)).unwrap();
        assert!(!out.changed, "bob's concurrently-invalidated add is admitted as a no-op, not refused");
        assert!(!out.view.members.iter().any(|m| m.member_id == "carol"), "and carol is not added");
    }

    #[test]
    fn a_recovery_admission_sets_the_reset_boundary() {
        let v = DagVerifier;
        let rvk = recovery::derive_rvk(&[42u8; 32]);
        let gm = vec![minit("founder", KeyringRole::OWNER, 1)];
        let genesis_op = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        let boot = v
            .admit(None, &bootstrap_update(&gm, Some(rvk.verifying_key().to_bytes()), &genesis_op))
            .unwrap();

        let refound = sign_op(
            [2; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::ReFound {
                member: "founder".into(),
                new_author_public_key: vk(7),
                new_hpke_public_key: [7; 32],
                era: 1,
            },
            &rvk,
        );
        let out = v.admit(Some(&boot.state), &op_update(&refound)).unwrap();
        assert!(out.view.reset_boundary, "a ReFound admission crosses the reset boundary");
        assert!(out.changed, "and the owner key changed");
        assert_eq!(out.view.owner().unwrap().author_public_key, vk(7).to_vec());
    }
}
