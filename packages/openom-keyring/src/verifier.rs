//! The chain keyring's [`KeyringVerifier`] adapter (OPE-277) — the keyless server-side seam.
//!
//! The chain is already pure bytes→bytes + keyless, so this is a thin adapter: an `update` (and the
//! persisted `state`) is a openom-keyring-api `MembershipEnvelope` wrapping the candidate/head `Keyring`; `admit`
//! unwraps it, rebuilds the anchor from the head, and runs `verify_transition` (falling back to
//! `verify_reset` for a recovery). It exports the verified `tree_id` + `update_ref` the server keys on. `changed` is the honest membership diff; `reset_boundary` is set when the candidate was
//! admitted as a reset. The chain's rich `ChainError` taxonomy is classed into the neutral
//! [`VerifyError`] (the full detail stays available inside the chain layer for diagnostics).

use openom_keyring_api::{
    Admitted, EngineKind, KeyringVerifier, MemberView, MembershipEnvelope, MembershipView, VerifyError,
};
use openom_protocol::v1::Keyring;
use openom_protocol::Message;
use openom_roles::MEMBER_OWNER;

use crate::{
    bootstrap_from_genesis, keyring_hash, verify_reset, verify_transition, ChainError, KeyringAnchor,
    VerifyingKey,
};

/// The chain keyring's keyless verifier. Holds no secrets and no state.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChainVerifier;

/// Unwrap the shared [`MembershipEnvelope`] to the chain's `Keyring` body. Both the incoming `update` and
/// the persisted `prior_state` are envelopes, so the seam sees ONE wire regardless of transport (the
/// managed endpoint's `KeyringUpdate.payload`, or the head we stored last time). Refuses a non-chain
/// envelope — the engine tag is a hint, but a wrong body here is malformed, not misparsed.
fn unwrap_keyring(bytes: &[u8]) -> Result<Keyring, VerifyError> {
    let env = MembershipEnvelope::decode(bytes).map_err(|_| VerifyError::Malformed)?;
    if env.engine_kind() != Ok(EngineKind::Chain) {
        return Err(VerifyError::Malformed);
    }
    Keyring::decode(env.body.as_slice()).map_err(|_| VerifyError::Malformed)
}

/// The engine-neutral [`MembershipView`] of a `Keyring` — the chain engine's public fold to the shared
/// seam vocabulary. Consumers that want the resolved membership (e.g. `openom-vault`'s moderators feed)
/// go through this rather than reading `Keyring.members` directly, so they stay engine-agnostic. The
/// caller MUST pass its VERIFIED, watermarked head; `reset_boundary` is `false` (this is the plain
/// resolved view, not an admission outcome).
pub fn membership_view(keyring: &Keyring) -> MembershipView {
    view_of(keyring, false)
}

fn view_of(k: &Keyring, reset_boundary: bool) -> MembershipView {
    let members = k
        .members
        .iter()
        .map(|m| MemberView {
            member_id: m.member_id.clone(),
            role: m.role as i16, // proto MemberRole (i32) → the shared i16 role axis (values 1..=5)
            author_public_key: m.author_public_key.clone(),
            hpke_public_key: m.hpke_public_key.clone(),
        })
        .collect();
    MembershipView::new(members, reset_boundary)
}

/// The prior head's recovery authority (RVK) as an optional slice — `None` (gate inactive) if the head
/// pinned none (pre-RVK keyring).
fn prior_rvk(anchor: &KeyringAnchor) -> Option<&[u8]> {
    (!anchor.recovery_verifying_key.is_empty()).then_some(anchor.recovery_verifying_key.as_slice())
}

/// Class the chain's error taxonomy into the neutral seam vocabulary.
fn classify(e: ChainError) -> VerifyError {
    match e {
        ChainError::Fork => VerifyError::Rollback,
        ChainError::NonSequential => VerifyError::Stale,
        ChainError::UnendorsedOrdinaryChange | ChainError::UnendorsedSetChange => {
            VerifyError::Unauthorized
        }
        ChainError::TreeMismatch
        | ChainError::LayoutAhead
        | ChainError::BadStructure(_)
        | ChainError::WrapIncomplete
        | ChainError::BadBootstrap
        | ChainError::RevisionOverflow => VerifyError::Malformed,
    }
}

/// The founder's verifying key, from the keyring's own founder — the sole OWNER-role member (the signer
/// set is derived from members now, OPE-309) — the first-sight trust root for a self-signed genesis.
fn founder_key(k: &Keyring) -> Option<VerifyingKey> {
    let founder = k.members.iter().find(|m| m.role == MEMBER_OWNER)?;
    let bytes: [u8; 32] = founder.author_public_key.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

impl KeyringVerifier for ChainVerifier {
    fn admit(&self, prior_state: Option<&[u8]>, update: &[u8]) -> Result<Admitted, VerifyError> {
        let candidate = unwrap_keyring(update)?;
        // The verified facts the seam exports (the server keys on these, never on the outer framing): the
        // tree id from the (signature-covered) keyring, and the canonical position — the chain's revision,
        // encoded as its opaque governing-ref (revision-only, which is what makes two racing same-revision
        // successors collide on the CAS key).
        let tree_id = candidate.tree_id.clone();
        let update_ref = crate::encode_governing_ref(candidate.revision);
        match prior_state {
            // First sight: accept a self-signed genesis (revision 1, signed by its own founder). The
            // server is not the security boundary — it trusts the founding keyring and re-verifies every
            // transition after.
            None => {
                let founder = founder_key(&candidate).ok_or(VerifyError::Malformed)?;
                bootstrap_from_genesis(&candidate, &founder).map_err(classify)?;
                Ok(Admitted {
                    state: update.to_vec(),
                    view: view_of(&candidate, false),
                    changed: true,
                    tree_id,
                    update_ref,
                })
            }
            Some(prior) => {
                let head = unwrap_keyring(prior)?;
                let anchor = KeyringAnchor::from_keyring(&head);
                match verify_transition(&anchor, &candidate) {
                    Ok(_) => {
                        let changed = candidate.members != head.members;
                        Ok(Admitted {
                            state: update.to_vec(),
                            view: view_of(&candidate, false),
                            changed,
                            tree_id,
                            update_ref,
                        })
                    }
                    // Not a valid ordinary transition — it may be a recovery reset (a fresh, deliberately
                    // unendorsed founder identity). A reset re-founds the signer set WITHOUT the old set's
                    // endorsement, but it must still CHAIN onto the head by revision + prev-hash, so it can
                    // neither roll back nor fork — otherwise a fork (a divergent rev-N+1 with a bogus
                    // prev-hash) would be smuggled in as a "reset". Gate the fallback on that continuity
                    // first, then on the prior head's recovery authority (RVK, inert if none).
                    Err(transition_err) => {
                        let chains_on_head = candidate.revision == head.revision + 1
                            && candidate.prev_keyring_hash == keyring_hash(&head);
                        match chains_on_head
                            .then(|| verify_reset(prior_rvk(&anchor), &candidate))
                        {
                            Some(Ok(_)) => Ok(Admitted {
                                state: update.to_vec(),
                                view: view_of(&candidate, true),
                                changed: true,
                                tree_id,
                                update_ref,
                            }),
                            // Not continuous, or not a valid reset: refuse with the original transition error
                            // (a fork/rollback stays a fork/rollback, never a reset).
                            _ => Err(classify(transition_err)),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keyring_hash, sign_keyring, SigningKey};
    use openom_protocol::v1::{KeyEpoch, KeyWrap, Member, MemberRole, WrapMethod};
    use openom_roles::MEMBER_OWNER;

    /// Wrap a keyring in the shared MembershipEnvelope (chain engine) — the wire `admit` now receives.
    fn env(k: &Keyring) -> Vec<u8> {
        MembershipEnvelope::wrap(EngineKind::Chain, k.encode_to_vec()).encode()
    }

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }
    fn pk(seed: u8) -> Vec<u8> {
        sk(seed).verifying_key().to_bytes().to_vec()
    }
    fn wrap(id: &str, method: WrapMethod) -> KeyWrap {
        KeyWrap {
            member_id: id.into(),
            wrap_method: method as i32,
            nonce: vec![],
            wrapped_dek: vec![1],
            kdf_params: None,
            ephemeral_public_key: vec![],
            recipient_public_key: vec![],
        }
    }

    /// A one-founder genesis re-keyed to `founder_seed`, self-signed — a valid genesis AND a valid reset.
    fn genesis(founder_seed: u8) -> Keyring {
        let mut g = Keyring {
            tree_id: b"tree-uuid-16byte".to_vec(),
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            members: vec![Member {
                member_id: "owner".into(),
                role: MEMBER_OWNER,
                author_public_key: pk(founder_seed),
                hpke_public_key: vec![9; 32],
            }],
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![0],
                epoch: 0,
                wraps: vec![wrap("owner", WrapMethod::RrkHpke)],
            }],
            ..Default::default()
        };
        sign_keyring(&mut g, &sk(founder_seed));
        g
    }

    /// A rev-2 successor of `prior` that adds ordinary editor "carol", founder-signed.
    fn add_carol(prior: &Keyring) -> Keyring {
        let mut k = prior.clone();
        k.revision = 2;
        k.prev_keyring_hash = keyring_hash(prior).to_vec();
        k.members.push(Member {
            member_id: "carol".into(),
            role: MemberRole::Editor as i32,
            author_public_key: pk(3),
            hpke_public_key: vec![9; 32],
        });
        k.epochs[0].wraps.push(wrap("carol", WrapMethod::X25519Hpke));
        k.signatures.clear();
        sign_keyring(&mut k, &sk(1));
        k
    }

    #[test]
    fn chain_verifier_bootstraps_a_genesis_then_admits_a_transition() {
        let v = ChainVerifier;
        let g = genesis(1);
        let boot = v.admit(None, &env(&g)).unwrap();
        assert!(boot.changed);
        assert_eq!(boot.view.owner().unwrap().member_id, "owner");
        assert!(!boot.view.reset_boundary);

        let next = add_carol(&g);
        let step = v.admit(Some(&boot.state), &env(&next)).unwrap();
        assert!(step.changed, "adding carol changes the view");
        assert!(step.view.members.iter().any(|m| m.member_id == "carol"));
    }

    #[test]
    fn chain_verifier_refuses_a_non_successor_and_flags_a_reset() {
        let v = ChainVerifier;
        let g = genesis(1);
        let boot = v.admit(None, &env(&g)).unwrap();

        // garbage bytes → Malformed
        assert_eq!(v.admit(Some(&boot.state), b"not a keyring").unwrap_err(), VerifyError::Malformed);

        // A self-signed re-founding under a fresh founder identity (seed 7) that still CHAINS onto the head
        // (rev 2, prev-hash = hash(g)) is not an ordinary successor, so it's admitted via verify_reset with
        // reset_boundary set.
        let mut reset = genesis(7);
        reset.revision = 2;
        reset.prev_keyring_hash = keyring_hash(&g).to_vec();
        reset.signatures.clear();
        sign_keyring(&mut reset, &sk(7));
        let out = v.admit(Some(&boot.state), &env(&reset)).unwrap();
        assert!(out.view.reset_boundary, "a re-founding is admitted as a reset");
        assert_eq!(out.view.owner().unwrap().author_public_key, pk(7), "owner re-keyed");

        // But a FORK — a rev-2 re-founding with a BOGUS prev-hash — is refused as a rollback/fork, NOT
        // smuggled in as a reset (the reset fallback is gated on head continuity).
        let mut fork = genesis(7);
        fork.revision = 2;
        fork.prev_keyring_hash = vec![0u8; 32];
        fork.signatures.clear();
        sign_keyring(&mut fork, &sk(7));
        assert_eq!(
            v.admit(Some(&boot.state), &env(&fork)).unwrap_err(),
            VerifyError::Rollback,
            "a fork is refused, never accepted as a reset"
        );
    }
}
