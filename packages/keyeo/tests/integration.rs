use keyeo::{
    self, dag::lamport::LamportTiebreak, dag::strong_remove::StrongRemove, keyeo as keyeo_fn,
    membership_commitment, ApplyOutcome, DefaultAccessControl, Ed25519, Epoch, Error, GroupState,
    Keyeo, MemberInit, MembershipAction, Op, Role,
};
use proptest::prelude::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, serde::Serialize)]
enum TestRole {
    Admin,
    Editor,
    Viewer,
}
impl Role for TestRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        use TestRole::*;
        matches!(
            (self, other),
            (Admin, _) | (Editor, Editor | Viewer) | (Viewer, Viewer)
        )
    }
}

fn make_keypair(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(seed)
}

fn alice_pk() -> [u8; 32] {
    make_keypair(&[1u8; 32]).verifying_key().to_bytes()
}
fn bob_pk() -> [u8; 32] {
    make_keypair(&[2u8; 32]).verifying_key().to_bytes()
}

fn cpk() -> [u8; 32] {
    make_keypair(&[3u8; 32]).verifying_key().to_bytes()
}

fn alice_admin_state() -> GroupState<[u8; 32], TestRole, Ed25519> {
    let pk = alice_pk();
    GroupState::create(&[MemberInit {
        id: pk,
        role: TestRole::Admin,
        author_public_key: pk,
        hpke_public_key: [0xaa; 32],
    }])
}

fn make_op(
    id: u64,
    parents: Vec<u64>,
    seed: &[u8; 32],
    action: MembershipAction<[u8; 32], TestRole, Ed25519>,
) -> Op<u64, [u8; 32], TestRole, Ed25519> {
    let sk = make_keypair(seed);
    let pk = sk.verifying_key().to_bytes();
    Op::new(id, parents, pk, action, [0u8; 64], pk).sign(&sk)
}

type TestEngine =
    Keyeo<Op<u64, [u8; 32], TestRole, Ed25519>, DefaultAccessControl<TestRole>, StrongRemove>;

/// A member init whose registered author key equals its id (matching `alice_pk`/`bob_pk`).
fn minit(id: [u8; 32], role: TestRole, hpke: [u8; 32]) -> MemberInit<[u8; 32], TestRole, Ed25519> {
    MemberInit {
        id,
        role,
        author_public_key: id,
        hpke_public_key: hpke,
    }
}

/// A `StrongRemove` engine seeded with `genesis` (constructor + a matching `Create` op at id 1).
fn strong_remove_engine(genesis: &[MemberInit<[u8; 32], TestRole, Ed25519>]) -> TestEngine {
    let mut k = Keyeo::new(
        GroupState::<[u8; 32], TestRole, Ed25519>::create(genesis),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    k.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: genesis.to_vec(),
        },
    ))
    .unwrap();
    k
}

fn is_member(k: &TestEngine, id: &[u8; 32]) -> bool {
    k.state().active_members().iter().any(|(m, _)| m == id)
}

// ── OPE-258: authority-aware resolution (Phase 0) ──
// RED until the resolver consults `AccessControl` at each op's causal position. Pins the
// authority-blind hole: a member who is NOT authorized to remove can still fire strong-remove's
// invalidation (rule 1) and suppress the victim's concurrent, *authorized* ops — even though the
// unauthorized remove itself never takes effect.
#[test]
fn an_unauthorized_remove_must_not_invalidate_the_victims_concurrent_ops() {
    let (alice, bob, carol) = (alice_pk(), bob_pk(), cpk());
    // Admin-only administration; bob is an Editor — NOT authorized to remove.
    let mut k = strong_remove_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Editor, [0xbb; 32]),
    ]);
    // Concurrent (both children of the Create op, id 1):
    //   op2: alice (Admin, authorized) adds carol
    //   op3: bob   (Editor, UNAUTHORIZED) removes alice
    k.apply(make_op(
        2,
        vec![1],
        &[1u8; 32],
        MembershipAction::Add {
            member: carol,
            role: TestRole::Editor,
            author_public_key: carol,
            hpke_public_key: [0xcc; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    k.apply(make_op(
        3,
        vec![1],
        &[2u8; 32],
        MembershipAction::Remove { member: alice },
    ))
    .unwrap();

    // Bob's remove is unauthorized → it must have NO effect: alice stays a member, and her concurrent,
    // authorized Add(carol) must survive. Today's authority-blind resolver fires rule 1 and drops carol.
    assert!(
        is_member(&k, &alice),
        "alice must remain — bob is not authorized to remove her"
    );
    assert!(
        is_member(&k, &carol),
        "alice's authorized Add(carol) must survive an unauthorized concurrent Remove(alice)"
    );
}

fn dave_pk() -> [u8; 32] {
    make_keypair(&[4u8; 32]).verifying_key().to_bytes()
}

proptest! {
    /// OPE-258 invariant: an op authored by an UNAUTHORIZED member never changes the resolved
    /// membership — it neither applies nor invalidates concurrent authorized ops. Resolve a fixed
    /// authorized baseline (admin alice creates {alice,bob,carol}, then concurrently adds dave and
    /// removes carol), then splice in an ARBITRARY op authored by bob (an Editor, where Admin is
    /// required) at an arbitrary existing parent, and assert the active membership is unchanged.
    #[test]
    fn an_unauthorized_op_never_changes_resolved_membership(
        kind in 0u8..4,
        target in 0usize..4,
        parent in 0usize..3,
    ) {
        use std::collections::BTreeSet;
        let (alice, bob, carol, dave) = (alice_pk(), bob_pk(), cpk(), dave_pk());

        let mut k = strong_remove_engine(&[
            minit(alice, TestRole::Admin, [0xaa; 32]),
            minit(bob, TestRole::Editor, [0xbb; 32]),
            minit(carol, TestRole::Editor, [0xcc; 32]),
        ]);
        k.apply(make_op(2, vec![1], &[1u8; 32], MembershipAction::Add {
            member: dave, role: TestRole::Editor, author_public_key: dave,
            hpke_public_key: [0xdd; 32], member_proof: None,
        })).unwrap();
        k.apply(make_op(3, vec![1], &[1u8; 32], MembershipAction::Remove { member: carol })).unwrap();
        let baseline: BTreeSet<[u8; 32]> =
            k.state().active_members().into_iter().map(|(m, _)| m).collect();

        // Adversarial: bob (Editor, unauthorized) authors an arbitrary membership op at an arbitrary
        // existing parent (parent 1 makes it concurrent with the add/remove above — the invalidation-
        // relevant case).
        let tgt = [alice, dave, carol, bob][target];
        let action = match kind {
            0 => MembershipAction::Add { member: tgt, role: TestRole::Admin, author_public_key: tgt,
                                         hpke_public_key: [0xee; 32], member_proof: None },
            1 => MembershipAction::Remove { member: tgt },
            2 => MembershipAction::ChangeRole { member: tgt, new_role: TestRole::Admin },
            _ => MembershipAction::Remove { member: alice },
        };
        let p = [1u64, 2, 3][parent];
        k.apply(make_op(100, vec![p], &[2u8; 32], action)).unwrap(); // seed [2;32] == bob

        let after: BTreeSet<[u8; 32]> =
            k.state().active_members().into_iter().map(|(m, _)| m).collect();
        prop_assert_eq!(baseline, after, "an unauthorized op must not change resolved membership");
    }
}

// ── Basic operations ──

#[test]
fn test_genesis() {
    let pk = alice_pk();
    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
        id: pk,
        role: TestRole::Admin,
        author_public_key: pk,
        hpke_public_key: [0xaa; 32],
    }]);
    let mut k = keyeo_fn(state, TestRole::Admin);
    assert!(k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: pk,
                    role: TestRole::Admin,
                    author_public_key: pk,
                    hpke_public_key: [0xaa; 32]
                }],
            }
        ))
        .is_ok());
}

#[test]
fn test_add_member() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let r = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Add {
                member: bob_pk(),
                role: TestRole::Editor,
                author_public_key: bob_pk(),
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { events } if events.len() == 1));
    assert_eq!(k.state().active_members().len(), 2);
}

#[test]
fn test_remove_member() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let _ = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Add {
                member: bob_pk(),
                role: TestRole::Editor,
                author_public_key: bob_pk(),
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let r = k
        .apply(make_op(
            2,
            vec![1],
            &[1u8; 32],
            MembershipAction::Remove { member: bob_pk() },
        ))
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { events } if events.len() == 1));
    assert_eq!(k.state().active_members().len(), 1);
}

#[test]
fn test_change_role() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let bpk = bob_pk();
    let _ = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Add {
                member: bpk,
                role: TestRole::Viewer,
                author_public_key: bpk,
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let r = k
        .apply(make_op(
            2,
            vec![1],
            &[1u8; 32],
            MembershipAction::ChangeRole {
                member: bpk,
                new_role: TestRole::Admin,
            },
        ))
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { events } if events.len() == 1));
    assert!(k.state().has_access(&bpk, &TestRole::Admin));
}

// ── Authorization ──

#[test]
fn test_unauthorized_add_has_no_effect() {
    // Admit-then-resolve: a validly signed but UNauthorized op is admitted (not rejected up front),
    // then the causal rebuild drops it — so it has no effect and emits no event. (Authorization is
    // no longer a synchronous apply() error; only authentication — bad sig / unknown author — is.)
    let pk = alice_pk();
    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
        id: pk,
        role: TestRole::Viewer,
        author_public_key: pk,
        hpke_public_key: [0xaa; 32],
    }]);
    let mut k = keyeo_fn(state, TestRole::Admin);
    let r = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Add {
                member: [0xcc; 32],
                role: TestRole::Editor,
                author_public_key: [0xcc; 32],
                hpke_public_key: [0xcc; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    assert!(
        matches!(r, ApplyOutcome::Applied { events } if events.is_empty()),
        "a dropped op emits no event"
    );
    assert_eq!(
        k.state().active_members().len(),
        1,
        "only the viewer remains"
    );
    assert!(
        !k.state()
            .active_members()
            .iter()
            .any(|(id, _)| *id == [0xcc; 32]),
        "unauthorized add had no effect"
    );
}

#[test]
fn test_unknown_author() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let err = k
        .apply(make_op(
            1,
            vec![],
            &[9u8; 32],
            MembershipAction::Add {
                member: [0xcc; 32],
                role: TestRole::Editor,
                author_public_key: [0xcc; 32],
                hpke_public_key: [0xcc; 32],
                member_proof: None,
            },
        ))
        .unwrap_err();
    assert!(matches!(err, Error::UnknownAuthor { .. }));
}

#[test]
fn test_bad_signature() {
    use ed25519_dalek::Signer;
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let pk = alice_pk();
    // Craft an op with a wrong signature (not from the canonical encoding)
    let bad = Op::new(
        1u64,
        vec![],
        pk,
        MembershipAction::Create {
            initial_members: vec![MemberInit {
                id: pk,
                role: TestRole::Admin,
                author_public_key: pk,
                hpke_public_key: [0xaa; 32],
            }],
        },
        make_keypair(&[9u8; 32]).sign(b"wrong").to_bytes(),
        pk,
    );
    assert!(matches!(k.apply(bad).unwrap_err(), Error::BadSignature));
}

#[test]
fn test_signature_bound_to_action() {
    // Replay/substitution: a signature that is valid for one action must NOT
    // verify when moved onto a different action. This is the whole point of the
    // engine recomputing the canonical encoding from the op's own fields.
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    // Alice legitimately signs Add(Bob).
    let honest = make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Add {
            member: bob_pk(),
            role: TestRole::Editor,
            author_public_key: bob_pk(),
            hpke_public_key: [0xbb; 32],
            member_proof: None,
        },
    );
    // Forge: reuse Alice's signature + author, but swap in a different action.
    let forged = Op::new(
        1u64,
        vec![],
        alice_pk(),
        MembershipAction::Remove { member: bob_pk() },
        honest.signature,
        alice_pk(),
    );
    assert!(matches!(k.apply(forged).unwrap_err(), Error::BadSignature));
}

// ── Buffered ops ──

#[test]
fn test_buffer_out_of_order() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let r = k
        .apply(make_op(
            2,
            vec![99],
            &[1u8; 32],
            MembershipAction::Add {
                member: bob_pk(),
                role: TestRole::Editor,
                author_public_key: bob_pk(),
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Buffered { .. }));
}

#[test]
fn test_buffered_returns_missing_parents() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let r = k
        .apply(make_op(
            2,
            vec![99, 100],
            &[1u8; 32],
            MembershipAction::Add {
                member: bob_pk(),
                role: TestRole::Editor,
                author_public_key: bob_pk(),
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    match r {
        ApplyOutcome::Buffered { missing_parents } => {
            assert_eq!(missing_parents.len(), 2);
            assert!(missing_parents.contains(&99));
            assert!(missing_parents.contains(&100));
        }
        _ => panic!("expected Buffered"),
    }
    assert_eq!(k.pending_count(), 1);
}

#[test]
fn test_flush_chained_pending() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    let _ = k.apply(make_op(
        1,
        vec![0],
        &[1u8; 32],
        MembershipAction::Add {
            member: bob_pk(),
            role: TestRole::Editor,
            author_public_key: bob_pk(),
            hpke_public_key: [0xbb; 32],
            member_proof: None,
        },
    ));
    let pk = alice_pk();
    assert!(k
        .apply(make_op(
            0,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: pk,
                    role: TestRole::Admin,
                    author_public_key: pk,
                    hpke_public_key: [0xaa; 32]
                }],
            }
        ))
        .is_ok());
    let events = k.flush().unwrap();
    assert!(!events.is_empty());
    assert_eq!(k.state().active_members().len(), 2);
    assert_eq!(k.pending_count(), 0);
}

#[test]
fn test_pending_buffer_bounded() {
    let mut k = keyeo_fn(alice_admin_state(), TestRole::Admin);
    for i in 0..1025 {
        let r = k.apply(make_op(
            i as u64 + 100,
            vec![9999],
            &[1u8; 32],
            MembershipAction::Add {
                member: [i as u8; 32],
                role: TestRole::Editor,
                author_public_key: [i as u8; 32],
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ));
        if i < 1024 {
            assert!(matches!(r.unwrap(), ApplyOutcome::Buffered { .. }));
        } else {
            assert!(r.is_err());
        }
    }
    assert_eq!(k.pending_count(), 1024);
}

// ── GroupState ──

#[test]
fn test_group_state_ops() {
    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[
        MemberInit {
            id: [1u8; 32],
            role: TestRole::Admin,
            author_public_key: [1u8; 32],
            hpke_public_key: [0xaa; 32],
        },
        MemberInit {
            id: [2u8; 32],
            role: TestRole::Editor,
            author_public_key: [2u8; 32],
            hpke_public_key: [0xbb; 32],
        },
    ]);
    assert!(state.has_access(&[1u8; 32], &TestRole::Admin));
    assert!(!state.has_access(&[2u8; 32], &TestRole::Admin));
}

// ── Resolver ──

#[test]
fn test_strong_remove_engine() {
    let mut k = Keyeo::new(
        alice_admin_state(),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    let bpk = bob_pk();
    let r = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: alice_pk(),
                    role: TestRole::Admin,
                    author_public_key: alice_pk(),
                    hpke_public_key: [0xaa; 32],
                }],
            },
        ))
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { .. }));
    let _ = k
        .apply(make_op(
            2,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: bpk,
                role: TestRole::Editor,
                author_public_key: bpk,
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let r = k
        .apply(make_op(
            3,
            vec![2],
            &[1u8; 32],
            MembershipAction::Remove { member: bpk },
        ))
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { events } if events.len() == 1));
    assert_eq!(k.state().active_members().len(), 1);
}

#[test]
fn test_concurrent_ops_converge() {
    let pk = alice_pk();
    let bpk = bob_pk();
    let cpk = cpk();
    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
        id: pk,
        role: TestRole::Admin,
        author_public_key: pk,
        hpke_public_key: [0xaa; 32],
    }]);
    let mut k = Keyeo::new(
        state,
        DefaultAccessControl::new(TestRole::Admin),
        LamportTiebreak,
    );
    let _ = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: pk,
                    role: TestRole::Admin,
                    author_public_key: pk,
                    hpke_public_key: [0xaa; 32],
                }],
            },
        ))
        .unwrap();
    let _ = k
        .apply(make_op(
            2,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: bpk,
                role: TestRole::Editor,
                author_public_key: bpk,
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let _ = k
        .apply(make_op(
            3,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: cpk,
                role: TestRole::Viewer,
                author_public_key: cpk,
                hpke_public_key: [0xcc; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    assert_eq!(k.state().active_members().len(), 3);
    assert!(k.state().has_access(&bpk, &TestRole::Editor));
    assert!(k.state().has_access(&cpk, &TestRole::Viewer));
}

#[test]
fn test_strong_remove_state_rebuild() {
    // Verify that StrongRemove's ignore set actually affects the authoritative state.
    // Two replicas apply the same concurrent ops in different orders.
    // After both converge, the state should be the same (removed member's ops ignored).
    let pk = alice_pk();
    let bpk = bob_pk();
    let cpk = cpk();

    // Replica A: apply ops in order 1, 2, 3
    let state_a = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
        id: pk,
        role: TestRole::Admin,
        author_public_key: pk,
        hpke_public_key: [0xaa; 32],
    }]);
    let mut k_a = Keyeo::new(
        state_a,
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    let _ = k_a
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: pk,
                    role: TestRole::Admin,
                    author_public_key: pk,
                    hpke_public_key: [0xaa; 32],
                }],
            },
        ))
        .unwrap();
    let _ = k_a
        .apply(make_op(
            2,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: bpk,
                role: TestRole::Editor,
                author_public_key: bpk,
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let _ = k_a
        .apply(make_op(
            3,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: cpk,
                role: TestRole::Viewer,
                author_public_key: cpk,
                hpke_public_key: [0xcc; 32],
                member_proof: None,
            },
        ))
        .unwrap();

    // Replica B: apply ops in reverse order 1, 3, 2
    let state_b = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
        id: pk,
        role: TestRole::Admin,
        author_public_key: pk,
        hpke_public_key: [0xaa; 32],
    }]);
    let mut k_b = Keyeo::new(
        state_b,
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    let _ = k_b
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: pk,
                    role: TestRole::Admin,
                    author_public_key: pk,
                    hpke_public_key: [0xaa; 32],
                }],
            },
        ))
        .unwrap();
    let _ = k_b
        .apply(make_op(
            3,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: cpk,
                role: TestRole::Viewer,
                author_public_key: cpk,
                hpke_public_key: [0xcc; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let _ = k_b
        .apply(make_op(
            2,
            vec![1],
            &[1u8; 32],
            MembershipAction::Add {
                member: bpk,
                role: TestRole::Editor,
                author_public_key: bpk,
                hpke_public_key: [0xbb; 32],
                member_proof: None,
            },
        ))
        .unwrap();

    // Both should have the same active members (3: alice + bob + charlie)
    let a_members = k_a.state().active_members();
    let b_members = k_b.state().active_members();
    assert_eq!(
        a_members.len(),
        b_members.len(),
        "same member count after convergence"
    );
    assert_eq!(a_members, b_members, "same members after convergence");
}

#[test]
fn test_strong_remove_ignores_removed_author_ops() {
    // Concurrent ops: Alice removes Bob, while Bob concurrently adds Charlie.
    // Both Alice and Bob are Admin, so both ops are authorized.
    // StrongRemove should ignore Bob's concurrent add op since Bob was removed.
    let pk = alice_pk();
    let bpk = bob_pk();
    let cpk = make_keypair(&[3u8; 32]).verifying_key().to_bytes();

    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[
        MemberInit {
            id: pk,
            role: TestRole::Admin,
            author_public_key: pk,
            hpke_public_key: [0xaa; 32],
        },
        MemberInit {
            id: bpk,
            role: TestRole::Admin,
            author_public_key: bpk,
            hpke_public_key: [0xbb; 32],
        },
    ]);
    let mut k = Keyeo::new(
        state,
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );

    // Create with both Alice and Bob as Admin
    let _ = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![
                    MemberInit {
                        id: pk,
                        role: TestRole::Admin,
                        author_public_key: pk,
                        hpke_public_key: [0xaa; 32],
                    },
                    MemberInit {
                        id: bpk,
                        role: TestRole::Admin,
                        author_public_key: bpk,
                        hpke_public_key: [0xbb; 32],
                    },
                ],
            },
        ))
        .unwrap();

    // Both ops are concurrent (parent = 1):
    // Bob adds Charlie (op 2), Alice removes Bob (op 3) — both authorized against parent state
    let _ = k
        .apply(make_op(
            2,
            vec![1],
            &[2u8; 32],
            MembershipAction::Add {
                member: cpk,
                role: TestRole::Viewer,
                author_public_key: cpk,
                hpke_public_key: [0xcc; 32],
                member_proof: None,
            },
        ))
        .unwrap();
    let _ = k
        .apply(make_op(
            3,
            vec![1],
            &[1u8; 32],
            MembershipAction::Remove { member: bpk },
        ))
        .unwrap();

    // Bob is removed, so Charlie should NOT be added (Bob's op is ignored by StrongRemove)
    let members = k.state().active_members();
    assert_eq!(
        members.len(),
        1,
        "only Alice should remain after Bob's removal"
    );
    assert!(
        !members.iter().any(|(id, _)| *id == cpk),
        "Charlie should not be present (Bob's concurrent add ignored)"
    );
}

#[test]
fn strong_remove_transitively_invalidates_accomplice_chain() {
    // Alice & Bob are admins. Concurrent with Alice removing Bob, Bob adds Charlie (admin), and
    // Charlie adds Dave — a causal chain hanging off Bob's illegitimate add. Removing Bob must drop
    // his add of Charlie AND, transitively, Charlie's add of Dave: neither may survive.
    let a = alice_pk();
    let b = bob_pk();
    let c = cpk(); // Charlie's key == keypair seed [3;32]
    let d = make_keypair(&[4u8; 32]).verifying_key().to_bytes();
    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[
        MemberInit {
            id: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
        },
        MemberInit {
            id: b,
            role: TestRole::Admin,
            author_public_key: b,
            hpke_public_key: [0xbb; 32],
        },
    ]);
    let mut k = Keyeo::new(
        state,
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    k.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: vec![
                MemberInit {
                    id: a,
                    role: TestRole::Admin,
                    author_public_key: a,
                    hpke_public_key: [0xaa; 32],
                },
                MemberInit {
                    id: b,
                    role: TestRole::Admin,
                    author_public_key: b,
                    hpke_public_key: [0xbb; 32],
                },
            ],
        },
    ))
    .unwrap();
    // Bob's branch: op2 (Bob adds Charlie as admin) → op4 (Charlie adds Dave).
    k.apply(make_op(
        2,
        vec![1],
        &[2u8; 32],
        MembershipAction::Add {
            member: c,
            role: TestRole::Admin,
            author_public_key: c,
            hpke_public_key: [0xcc; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    k.apply(make_op(
        4,
        vec![2],
        &[3u8; 32],
        MembershipAction::Add {
            member: d,
            role: TestRole::Viewer,
            author_public_key: d,
            hpke_public_key: [0xdd; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    // Concurrently (off the genesis), Alice removes Bob.
    k.apply(make_op(
        3,
        vec![1],
        &[1u8; 32],
        MembershipAction::Remove { member: b },
    ))
    .unwrap();
    k.flush().unwrap();

    let members: Vec<[u8; 32]> = k
        .state()
        .active_members()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(members.contains(&a), "Alice remains");
    assert!(!members.contains(&b), "Bob removed");
    assert!(
        !members.contains(&c),
        "Charlie: added by removed Bob's concurrent op"
    );
    assert!(
        !members.contains(&d),
        "Dave: added by never-valid Charlie (transitive)"
    );
    assert_eq!(members.len(), 1);
}

#[test]
fn mutual_remove_resolves_by_tiebreak() {
    // Alice and Bob (both admin) concurrently remove each other. Exactly one survives, and
    // deterministically — the remove with the smaller (depth, op_id) wins, so Alice (op 2) beats
    // Bob (op 3).
    let a = alice_pk();
    let b = bob_pk();
    let state = GroupState::<[u8; 32], TestRole, Ed25519>::create(&[
        MemberInit {
            id: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
        },
        MemberInit {
            id: b,
            role: TestRole::Admin,
            author_public_key: b,
            hpke_public_key: [0xbb; 32],
        },
    ]);
    let mut k = Keyeo::new(
        state,
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    k.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: vec![
                MemberInit {
                    id: a,
                    role: TestRole::Admin,
                    author_public_key: a,
                    hpke_public_key: [0xaa; 32],
                },
                MemberInit {
                    id: b,
                    role: TestRole::Admin,
                    author_public_key: b,
                    hpke_public_key: [0xbb; 32],
                },
            ],
        },
    ))
    .unwrap();
    k.apply(make_op(
        2,
        vec![1],
        &[1u8; 32],
        MembershipAction::Remove { member: b },
    ))
    .unwrap(); // Alice removes Bob
    k.apply(make_op(
        3,
        vec![1],
        &[2u8; 32],
        MembershipAction::Remove { member: a },
    ))
    .unwrap(); // Bob removes Alice
    k.flush().unwrap();

    let members: Vec<[u8; 32]> = k
        .state()
        .active_members()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        members.len(),
        1,
        "exactly one admin survives a mutual remove"
    );
    assert!(
        members.contains(&a),
        "Alice's remove (smaller op id) wins the tiebreak"
    );
}

#[test]
fn test_epoch_rotation_follows_membership_and_is_forward_secret() {
    // Two replicas built from the same genesis drawn to the same membership via ops applied in
    // DIFFERENT orders must converge: same active membership, same epoch, same history commitment.
    // The commitment is deterministic under arrival order, so key access converges even though each
    // engine mints its own randomized DEK wraps. Removing Bob drops him from the next epoch's wraps
    // (forward secrecy) while Alice keeps hers.
    let a = alice_pk();
    let b = bob_pk();
    let genesis = |_rp: u64| {
        GroupState::<[u8; 32], TestRole, Ed25519>::create(&[
            MemberInit {
                id: a,
                role: TestRole::Admin,
                author_public_key: a,
                hpke_public_key: [0xaa; 32],
            },
            MemberInit {
                id: b,
                role: TestRole::Editor,
                author_public_key: b,
                hpke_public_key: [0xbb; 32],
            },
        ])
    };

    let mut k1 = Keyeo::new(
        genesis(1),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    let mut k2 = Keyeo::new(
        genesis(2),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );

    // Replica 1: add Charlie on op 2 (Alice authors), remove Bob on op 3.
    let c = make_keypair(&[3u8; 32]).verifying_key().to_bytes();
    k1.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: vec![MemberInit {
                id: a,
                role: TestRole::Admin,
                author_public_key: a,
                hpke_public_key: [0xaa; 32],
            }],
        },
    ))
    .unwrap();
    k1.apply(make_op(
        2,
        vec![1],
        &[1u8; 32],
        MembershipAction::Add {
            member: b,
            role: TestRole::Editor,
            author_public_key: b,
            hpke_public_key: [0xbb; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    k1.apply(make_op(
        3,
        vec![1, 2],
        &[1u8; 32],
        MembershipAction::Add {
            member: c,
            role: TestRole::Viewer,
            author_public_key: c,
            hpke_public_key: [0xcc; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    k1.apply(make_op(
        4,
        vec![3],
        &[1u8; 32],
        MembershipAction::Remove { member: b },
    ))
    .unwrap();

    // Replica 2: same ops (same genesis membership), different application order — 1,2,4,3.
    k2.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: vec![MemberInit {
                id: a,
                role: TestRole::Admin,
                author_public_key: a,
                hpke_public_key: [0xaa; 32],
            }],
        },
    ))
    .unwrap();
    k2.apply(make_op(
        2,
        vec![1],
        &[1u8; 32],
        MembershipAction::Add {
            member: b,
            role: TestRole::Editor,
            author_public_key: b,
            hpke_public_key: [0xbb; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    k2.apply(make_op(
        4,
        vec![1, 2],
        &[1u8; 32],
        MembershipAction::Remove { member: b },
    ))
    .unwrap();
    k2.apply(make_op(
        3,
        vec![2, 4],
        &[1u8; 32],
        MembershipAction::Add {
            member: c,
            role: TestRole::Viewer,
            author_public_key: c,
            hpke_public_key: [0xcc; 32],
            member_proof: None,
        },
    ))
    .unwrap();

    // Same resolved membership and same commitment — the convergence anchor. The epoch *number* is a
    // local rotation counter and may differ across replicas (each passed through different
    // intermediate memberships), but the membership commitment is deterministic under arrival order,
    // so peers that resolve the same membership agree on the same epoch identity.
    let a1 = k1.state().active_members();
    let a2 = k2.state().active_members();
    assert_eq!(a1, a2, "concurrent membership converges across replicas");
    assert_eq!(a1.len(), 2, "final group is Alice + Charlie");
    assert_eq!(
        k1.state().history_commitment,
        k2.state().history_commitment,
        "deterministic commitment is identical even under different arrival order"
    );

    // Author the rotation epoch for the RESOLVED active set {Alice, Charlie} — Bob is excluded, so
    // his HPKE key is not wrapped (forward secrecy). Both replicas receive the same signed artifact and
    // reconcile to the same wraps. The commitment is computed the way the engine does (from the stored
    // member hpke keys) so reconcile matches.
    let active_keys = keyeo::epoch::membership_commitment(&[
        (a, TestRole::Admin, [0xaa; 32]),
        (c, TestRole::Viewer, [0xcc; 32]),
    ]);
    let active_hpke: Vec<([u8; 32], [u8; 32])> = vec![(a, [0xaa; 32]), (c, [0xcc; 32])];
    let epoch_art = Epoch::<u64, [u8; 32], Ed25519>::author(
        900,
        vec![4],
        a,
        active_keys,
        1,
        &active_hpke,
        &make_keypair(&[1u8; 32]),
    )
    .unwrap();
    k1.apply_epoch(epoch_art.clone()).unwrap();
    k2.apply_epoch(epoch_art).unwrap();

    // Force a causal rebuild on both replicas so the epoch reconciles into the state.
    let redundant = make_op(
        5,
        vec![4],
        &[1u8; 32],
        MembershipAction::ChangeRole {
            member: c,
            new_role: TestRole::Viewer,
        },
    );
    let _ = k1.apply(redundant.clone());
    let _ = k2.apply(redundant);

    // After reconcile, the group's age wraps are {Alice, Charlie} — Bob has none (forward secrecy).
    let verify = |engine: &Keyeo<_, _, _>| {
        let wraps: Vec<[u8; 32]> = engine.state().dek_wraps.iter().map(|w| w.member).collect();
        assert!(
            !wraps.contains(&b),
            "removed member has no wrap (forward secrecy)"
        );
        assert!(
            wraps.contains(&a) && wraps.contains(&c),
            "remaining members keep their wraps"
        );
    };
    verify(&k1);
    verify(&k2);

    // Both replicas reconcile to the SAME epoch artifact (same wraps on the same membership).
    assert_eq!(
        k1.state().dek_wraps,
        k2.state().dek_wraps,
        "single shared epoch after reconciliation"
    );
}

#[test]
fn rotation_is_stable_without_membership_change() {
    // Re-applying ops that don't change the resolved membership must not re-randomize the epoch —
    // the epoch key material is cached by commitment, so a stable group is deterministic (no churn).
    let a = alice_pk();
    let mut k = Keyeo::new(
        GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
            id: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
        }]),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    let _ = k
        .apply(make_op(
            1,
            vec![],
            &[1u8; 32],
            MembershipAction::Create {
                initial_members: vec![MemberInit {
                    id: a,
                    role: TestRole::Admin,
                    author_public_key: a,
                    hpke_public_key: [0xaa; 32],
                }],
            },
        ))
        .unwrap();

    // Author an epoch for the genesis membership {Alice} and apply it to the engine.
    let a_keys = membership_commitment(&[(a, TestRole::Admin, [0xaa; 32])]);
    let epoch_art = Epoch::<u64, [u8; 32], Ed25519>::author(
        100,
        vec![1],
        a,
        a_keys,
        1,
        &[(a, [0xaa; 32])],
        &make_keypair(&[1u8; 32]),
    )
    .unwrap();
    k.apply_epoch(epoch_art).unwrap();

    // Reconcile once by applying a redundant op, then capture the settled epoch/wraps.
    k.apply(make_op(
        2,
        vec![1],
        &[1u8; 32],
        MembershipAction::Add {
            member: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    assert_eq!(k.state().epoch, 1, "authored epoch reconciles in");
    let ep0 = k.state().epoch;
    let wraps0 = k.state().dek_wraps.clone();

    // A redundant add of the same member doesn't change membership; the reconciled epoch (and its
    // wraps) must be stable — the settled winner is reused, not re-randomized.
    k.apply(make_op(
        3,
        vec![2],
        &[1u8; 32],
        MembershipAction::Add {
            member: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
            member_proof: None,
        },
    ))
    .unwrap();
    assert_eq!(
        k.state().epoch,
        ep0,
        "epoch is stable across a non-mutating membership op"
    );
    assert_eq!(
        k.state().dek_wraps,
        wraps0,
        "wraps are stable across a non-mutating membership op"
    );
}

#[test]
fn spoofed_author_key_epoch_does_not_reconcile() {
    // G-E2: an epoch that claims an active member's id but is signed by a DIFFERENT key must not
    // reconcile in. `apply_epoch`'s signature check (G-E1) only proves self-consistency (the epoch
    // matches its own asserted key); authority is decided in `forge_epoch` against the member's
    // *registered* key. The spoof passes ingest but is filtered at reconcile, so no wraps settle.
    let a = alice_pk();
    let mut k = Keyeo::new(
        GroupState::<[u8; 32], TestRole, Ed25519>::create(&[MemberInit {
            id: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
        }]),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    k.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: vec![MemberInit {
                id: a,
                role: TestRole::Admin,
                author_public_key: a,
                hpke_public_key: [0xaa; 32],
            }],
        },
    ))
    .unwrap();

    // Well-formed wraps + commitment for {Alice}, author id = Alice — but signed by an impostor key.
    let commitment = membership_commitment(&[(a, TestRole::Admin, [0xaa; 32])]);
    let spoofed = Epoch::<u64, [u8; 32], Ed25519>::author(
        100,
        vec![1],
        a,
        commitment,
        1,
        &[(a, [0xaa; 32])],
        &make_keypair(&[9u8; 32]), // NOT Alice's registered key
    )
    .unwrap();
    // Ingest accepts it (the artifact is internally consistent with its own asserted key)...
    k.apply_epoch(spoofed).unwrap();

    // ...but it never reconciles: Alice's registered key doesn't match, so no wraps settle.
    assert!(
        k.state().dek_wraps.is_empty(),
        "epoch under a spoofed author key must not become the group's key material"
    );
}

#[test]
fn incomplete_wraps_epoch_does_not_reconcile() {
    // G-E3: an epoch whose wraps don't cover exactly the active set (here Bob is locked out) must not
    // reconcile — otherwise an active member is silently denied the DEK. Signed correctly by Alice and
    // carrying the right commitment, it still fails the `wraps_complete` gate in `forge_epoch`.
    let a = alice_pk();
    let b = bob_pk();
    let members = vec![
        MemberInit {
            id: a,
            role: TestRole::Admin,
            author_public_key: a,
            hpke_public_key: [0xaa; 32],
        },
        MemberInit {
            id: b,
            role: TestRole::Editor,
            author_public_key: b,
            hpke_public_key: [0xbb; 32],
        },
    ];
    let mut k = Keyeo::new(
        GroupState::<[u8; 32], TestRole, Ed25519>::create(&members),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
    );
    k.apply(make_op(
        1,
        vec![],
        &[1u8; 32],
        MembershipAction::Create {
            initial_members: members.clone(),
        },
    ))
    .unwrap();

    // Commitment covers {Alice, Bob}, but the wraps only cover Alice — Bob would be locked out.
    let commitment = membership_commitment(&[
        (a, TestRole::Admin, [0xaa; 32]),
        (b, TestRole::Editor, [0xbb; 32]),
    ]);
    let incomplete = Epoch::<u64, [u8; 32], Ed25519>::author(
        100,
        vec![1],
        a,
        commitment,
        1,
        &[(a, [0xaa; 32])], // missing Bob
        &make_keypair(&[1u8; 32]),
    )
    .unwrap();
    k.apply_epoch(incomplete).unwrap();

    assert!(
        k.state().dek_wraps.is_empty(),
        "an epoch that locks out an active member must not become the group's key material"
    );
}

// ── §3 re-add-across-concurrency: "Remove wins over a concurrent re-add" ──
//
// Genesis is {Alice(Admin), Bob(Editor)} for the concurrent cases (C1/C2, matching the design's
// "Bob is a genesis member who gets removed"); C3/C4 seed {Alice} only so the Add genuinely onboards.
// The `add` op re-adds Bob with his registered key (`author_public_key == b`).

fn readd_bob(id: u64, parents: Vec<u64>) -> Op<u64, [u8; 32], TestRole, Ed25519> {
    make_op(
        id,
        parents,
        &[1u8; 32], // authored by Alice (Admin)
        MembershipAction::Add {
            member: bob_pk(),
            role: TestRole::Editor,
            author_public_key: bob_pk(),
            hpke_public_key: [0xbb; 32],
            member_proof: None,
        },
    )
}

fn remove_bob(id: u64, parents: Vec<u64>) -> Op<u64, [u8; 32], TestRole, Ed25519> {
    make_op(
        id,
        parents,
        &[1u8; 32], // authored by Alice (Admin)
        MembershipAction::Remove { member: bob_pk() },
    )
}

#[test]
fn readd_c1a_concurrent_readd_is_suppressed() {
    // C1.A — R and A both branch off genesis (concurrent), Id(R)=2 < Id(A)=3. Remove wins. (G-R1)
    let a = alice_pk();
    let b = bob_pk();
    let mut k = strong_remove_engine(&[
        minit(a, TestRole::Admin, [0xaa; 32]),
        minit(b, TestRole::Editor, [0xbb; 32]),
    ]);
    k.apply(remove_bob(2, vec![1])).unwrap();
    k.apply(readd_bob(3, vec![1])).unwrap();
    assert!(
        !is_member(&k, &b),
        "an Add concurrent with the Remove is suppressed; Bob stays evicted"
    );
    assert!(is_member(&k, &a));

    // G-R6 — the suppressed member gets no epoch wrap. Author an epoch for the resolved set {Alice};
    // reconciliation must wrap the DEK to Alice only, never leaking one to the evicted Bob.
    let commitment = membership_commitment(&[(a, TestRole::Admin, [0xaa; 32])]);
    let epoch = Epoch::<u64, [u8; 32], Ed25519>::author(
        900,
        vec![2],
        a,
        commitment,
        1,
        &[(a, [0xaa; 32])],
        &make_keypair(&[1u8; 32]),
    )
    .unwrap();
    k.apply_epoch(epoch).unwrap();
    assert!(
        !k.state().dek_wraps.iter().any(|w| w.member == b),
        "no DEK wrap leaks to the evicted member (forward secrecy across the race)"
    );
    assert!(k.state().dek_wraps.iter().any(|w| w.member == a));
}

#[test]
fn readd_c1b_id_order_does_not_change_outcome() {
    // C1.B — same structure as C1.A but ids swapped so Id(R)=3 > Id(A)=2. The Kahn/id "lottery" is
    // bypassed: the outcome is identical (Bob removed). (G-R2)
    let a = alice_pk();
    let b = bob_pk();
    let mut k = strong_remove_engine(&[
        minit(a, TestRole::Admin, [0xaa; 32]),
        minit(b, TestRole::Editor, [0xbb; 32]),
    ]);
    k.apply(readd_bob(2, vec![1])).unwrap();
    k.apply(remove_bob(3, vec![1])).unwrap();
    assert!(
        !is_member(&k, &b),
        "flipping the id order does not change the outcome"
    );
    assert!(is_member(&k, &a));
}

#[test]
fn readd_c2_causal_readd_rejoins() {
    // C2 — Root → R → A: the re-add causally FOLLOWS the remove, so it is a legitimate re-onboarding
    // (not concurrent) and Bob rejoins. Its epoch carries an HPKE wrap for Bob. (G-R3)
    let a = alice_pk();
    let b = bob_pk();
    let mut k = strong_remove_engine(&[
        minit(a, TestRole::Admin, [0xaa; 32]),
        minit(b, TestRole::Editor, [0xbb; 32]),
    ]);
    k.apply(remove_bob(2, vec![1])).unwrap();
    k.apply(readd_bob(3, vec![2])).unwrap(); // A follows R
    assert!(is_member(&k, &b), "a causally-after re-add rejoins");

    // The rotation for {Alice, Bob} wraps the DEK to Bob too.
    let commitment = membership_commitment(&[
        (a, TestRole::Admin, [0xaa; 32]),
        (b, TestRole::Editor, [0xbb; 32]),
    ]);
    let epoch = Epoch::<u64, [u8; 32], Ed25519>::author(
        900,
        vec![3],
        a,
        commitment,
        1,
        &[(a, [0xaa; 32]), (b, [0xbb; 32])],
        &make_keypair(&[1u8; 32]),
    )
    .unwrap();
    k.apply_epoch(epoch).unwrap();
    assert!(
        k.state().dek_wraps.iter().any(|w| w.member == b),
        "the re-onboarded member receives an epoch wrap"
    );
}

#[test]
fn readd_c3_add_then_remove_evicts() {
    // C3 — Root → A → R: a standard historical add-then-remove. Bob is evicted. (G-R4)
    let a = alice_pk();
    let b = bob_pk();
    let mut k = strong_remove_engine(&[minit(a, TestRole::Admin, [0xaa; 32])]);
    k.apply(readd_bob(2, vec![1])).unwrap();
    k.apply(remove_bob(3, vec![2])).unwrap(); // R follows A
    assert!(!is_member(&k, &b), "add-then-remove still evicts");
    assert!(is_member(&k, &a));
}

#[test]
fn readd_c4_plain_add_onboards() {
    // C4 — Root → A, no Remove: a plain onboarding. Bob is active. (G-R5)
    let a = alice_pk();
    let b = bob_pk();
    let mut k = strong_remove_engine(&[minit(a, TestRole::Admin, [0xaa; 32])]);
    k.apply(readd_bob(2, vec![1])).unwrap();
    assert!(is_member(&k, &b), "a plain add onboards");
    assert!(is_member(&k, &a));
}

// ── Differential oracle vs p2panda-auth (round-2 R6) ──
// keyeo's StrongRemove is adapted from p2panda-auth. These transcribe p2panda's own mutual-remove
// test cases and RECORD keyeo's actual resolution — settling the R6 finding empirically (keyeo uses a
// pairwise tiebreak → one survivor; p2panda uses AuthorityGraphs+Tarjan-SCC → the whole cycle removed).

fn erin_pk() -> [u8; 32] {
    make_keypair(&[5u8; 32]).verifying_key().to_bytes()
}

#[test]
fn two_party_mutual_remove_leaves_one_survivor() {
    // alice and bob are both Admins; alice removes bob while bob concurrently removes alice.
    // keyeo: the lower-op-id remove (alice's) stands → alice survives, bob removed.
    // p2panda-auth: mutual destruction — BOTH removed, only claire remains (documented divergence).
    let (alice, bob, claire) = (alice_pk(), bob_pk(), cpk());
    let mut k = strong_remove_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Admin, [0xbb; 32]),
        minit(claire, TestRole::Editor, [0xcc; 32]),
    ]);
    k.apply(make_op(2, vec![1], &[1u8; 32], MembershipAction::Remove { member: bob })).unwrap(); // alice → bob
    k.apply(make_op(3, vec![1], &[2u8; 32], MembershipAction::Remove { member: alice })).unwrap(); // bob → alice
    assert!(is_member(&k, &alice), "keyeo: lower-id remover (alice) survives");
    assert!(!is_member(&k, &bob), "keyeo: bob removed by alice's surviving remove");
    assert!(is_member(&k, &claire));
}

#[test]
fn three_way_remove_cycle_resolves_to_one_removal() {
    // A→B, B→C, C→A, all concurrent, all Admins. keyeo resolves to a SINGLE removal; p2panda-auth
    // empties the whole 3-cycle (only D remains). Records keyeo's actual one-removal outcome.
    let (a, b, c, d) = (alice_pk(), bob_pk(), cpk(), dave_pk());
    let mut k = strong_remove_engine(&[
        minit(a, TestRole::Admin, [0xaa; 32]),
        minit(b, TestRole::Admin, [0xbb; 32]),
        minit(c, TestRole::Admin, [0xcc; 32]),
        minit(d, TestRole::Editor, [0xdd; 32]),
    ]);
    k.apply(make_op(2, vec![1], &[1u8; 32], MembershipAction::Remove { member: b })).unwrap(); // A → B
    k.apply(make_op(3, vec![1], &[2u8; 32], MembershipAction::Remove { member: c })).unwrap(); // B → C
    k.apply(make_op(4, vec![1], &[3u8; 32], MembershipAction::Remove { member: a })).unwrap(); // C → A
    let survivors: std::collections::BTreeSet<[u8; 32]> =
        k.state().active_members().into_iter().map(|(m, _)| m).collect();
    assert_eq!(survivors.len(), 3, "keyeo one-removal semantics (p2panda would leave 1)");
    assert!(survivors.contains(&d));
}

fn convergence_ops() -> Vec<Op<u64, [u8; 32], TestRole, Ed25519>> {
    let (bob, carol, dave, erin) = (bob_pk(), cpk(), dave_pk(), erin_pk());
    vec![
        make_op(2, vec![1], &[1u8; 32], MembershipAction::Remove { member: bob }), // alice → bob
        make_op(3, vec![1], &[2u8; 32], MembershipAction::Remove { member: carol }), // bob → carol (concurrent)
        make_op(4, vec![1], &[3u8; 32], MembershipAction::Add {
            member: dave, role: TestRole::Editor, author_public_key: dave, hpke_public_key: [0xd0; 32], member_proof: None,
        }), // carol adds dave (concurrent)
        make_op(5, vec![2], &[1u8; 32], MembershipAction::Add {
            member: erin, role: TestRole::Editor, author_public_key: erin, hpke_public_key: [0xe0; 32], member_proof: None,
        }), // alice adds erin (after op2)
    ]
}

fn resolve_convergence(order: &[usize]) -> std::collections::BTreeSet<[u8; 32]> {
    let (alice, bob, carol) = (alice_pk(), bob_pk(), cpk());
    let mut k = strong_remove_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Admin, [0xbb; 32]),
        minit(carol, TestRole::Admin, [0xcc; 32]),
    ]);
    let ops = convergence_ops();
    for &i in order {
        let _ = k.apply(ops[i].clone());
    }
    let _ = k.flush();
    k.state().active_members().into_iter().map(|(m, _)| m).collect()
}

proptest! {
    // BEC convergence: the resolved membership is independent of the order ops are delivered/applied
    // (out-of-order ops buffer, then flush). Any permutation must match the canonical in-order result.
    #[test]
    fn resolution_is_order_independent(
        order in Just((0..4usize).collect::<Vec<usize>>()).prop_shuffle()
    ) {
        let canonical = resolve_convergence(&[0, 1, 2, 3]);
        let shuffled = resolve_convergence(&order);
        prop_assert_eq!(canonical, shuffled, "resolved membership must not depend on application order");
    }
}

// ── v2 multi-signer quorum ──
// A test QuorumPolicy: eligible = the active Admins; requirement = unanimity of them. So a Commit's
// target takes effect only when every Admin (the proposer implicitly + the approvers) has approved.
struct AllAdmins;
impl keyeo::QuorumPolicy<[u8; 32], TestRole, Ed25519> for AllAdmins {
    fn eligible(
        &self,
        state: &GroupState<[u8; 32], TestRole, Ed25519>,
        _target: &MembershipAction<[u8; 32], TestRole, Ed25519>,
    ) -> std::collections::HashSet<[u8; 32]> {
        state
            .active_members()
            .into_iter()
            .filter(|(_, r)| *r == TestRole::Admin)
            .map(|(id, _)| id)
            .collect()
    }
    fn requirement(
        &self,
        state: &GroupState<[u8; 32], TestRole, Ed25519>,
        target: &MembershipAction<[u8; 32], TestRole, Ed25519>,
    ) -> keyeo::Requirement<[u8; 32]> {
        keyeo::Requirement::All(self.eligible(state, target))
    }
}

type QuorumEngine =
    Keyeo<Op<u64, [u8; 32], TestRole, Ed25519>, DefaultAccessControl<TestRole>, StrongRemove, AllAdmins>;

fn quorum_engine(genesis: &[MemberInit<[u8; 32], TestRole, Ed25519>]) -> QuorumEngine {
    let mut k = Keyeo::with_quorum(
        GroupState::<[u8; 32], TestRole, Ed25519>::create(genesis),
        DefaultAccessControl::new(TestRole::Admin),
        StrongRemove,
        AllAdmins,
    );
    k.apply(make_op(1, vec![], &[1u8; 32], MembershipAction::Create {
        initial_members: genesis.to_vec(),
    }))
    .unwrap();
    k
}

fn add_editor(member: [u8; 32], seed: u8) -> MembershipAction<[u8; 32], TestRole, Ed25519> {
    MembershipAction::Add {
        member,
        role: TestRole::Editor,
        author_public_key: member,
        hpke_public_key: [seed; 32],
        member_proof: None,
    }
}
fn qmember(k: &QuorumEngine, id: &[u8; 32]) -> bool {
    k.state().active_members().iter().any(|(m, _)| m == id)
}

#[test]
fn quorum_unanimity_applies_the_target() {
    let (alice, bob, carol, dave) = (alice_pk(), bob_pk(), cpk(), dave_pk());
    let mut k = quorum_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Admin, [0xbb; 32]),
        minit(carol, TestRole::Admin, [0xcc; 32]),
    ]);
    let pid = [7u8; 32];
    // alice proposes to add dave; bob and carol approve; alice commits — all three Admins → quorum met.
    k.apply(make_op(2, vec![1], &[1u8; 32], MembershipAction::Propose {
        proposal_id: pid,
        target: Box::new(add_editor(dave, 0xd0)),
    })).unwrap();
    k.apply(make_op(3, vec![2], &[2u8; 32], MembershipAction::Approve { proposal_id: pid })).unwrap();
    k.apply(make_op(4, vec![3], &[3u8; 32], MembershipAction::Approve { proposal_id: pid })).unwrap();
    k.apply(make_op(5, vec![4], &[1u8; 32], MembershipAction::Commit { proposal_id: pid })).unwrap();
    assert!(qmember(&k, &dave), "unanimity of Admins committed → target applied");
}

#[test]
fn quorum_one_short_does_not_apply() {
    let (alice, bob, carol, dave) = (alice_pk(), bob_pk(), cpk(), dave_pk());
    let mut k = quorum_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Admin, [0xbb; 32]),
        minit(carol, TestRole::Admin, [0xcc; 32]),
    ]);
    let pid = [7u8; 32];
    // alice proposes (implicit approval) + bob approves, then alice commits — carol never approved.
    k.apply(make_op(2, vec![1], &[1u8; 32], MembershipAction::Propose {
        proposal_id: pid,
        target: Box::new(add_editor(dave, 0xd0)),
    })).unwrap();
    k.apply(make_op(3, vec![2], &[2u8; 32], MembershipAction::Approve { proposal_id: pid })).unwrap();
    k.apply(make_op(4, vec![3], &[1u8; 32], MembershipAction::Commit { proposal_id: pid })).unwrap();
    assert!(!qmember(&k, &dave), "only 2 of 3 Admins approved → quorum not met → target NOT applied");
}

#[test]
fn quorum_a_concurrent_signer_add_joins_the_denominator() {
    // Backdating defense: alice proposes a change CONCURRENT with carol's addition as a 3rd Admin (the
    // Propose parents [1], not [2]). carol must still count in the denominator, so alice+bob alone can't
    // push it through without her — the proposal can't be backdated to a smaller signer set.
    let (alice, bob, carol, mallory) = (alice_pk(), bob_pk(), cpk(), dave_pk());
    let mut k = quorum_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Admin, [0xbb; 32]),
    ]);
    let pid = [7u8; 32];
    // carol is added as a 3rd Admin ...
    k.apply(make_op(2, vec![1], &[1u8; 32], MembershipAction::Add {
        member: carol, role: TestRole::Admin, author_public_key: carol, hpke_public_key: [0xcc; 32], member_proof: None,
    })).unwrap();
    // ... while alice concurrently proposes (parents [1]) + bob approves + alice commits.
    k.apply(make_op(3, vec![1], &[1u8; 32], MembershipAction::Propose {
        proposal_id: pid, target: Box::new(add_editor(mallory, 0xee)),
    })).unwrap();
    k.apply(make_op(4, vec![3], &[2u8; 32], MembershipAction::Approve { proposal_id: pid })).unwrap();
    k.apply(make_op(5, vec![4], &[1u8; 32], MembershipAction::Commit { proposal_id: pid })).unwrap();
    assert!(
        !qmember(&k, &mallory),
        "carol (concurrently added) is in the denominator; alice+bob alone is not unanimity"
    );
}

#[test]
fn quorum_backdating_across_a_deep_concurrent_signer_add_still_fails() {
    // The exotic shape the shallow test couldn't reach: carol is added as a 3rd Admin via a DEEP
    // concurrent chain (depth 3) whose OpId (22) sorts AFTER the attacker's Commit (12). Under the old
    // Commit-position/topo-order denominator, carol's add is emitted after the Commit, so she'd be absent
    // from the denominator and alice+bob alone would pass — a backdating win. The causal (has_path)
    // denominator includes her regardless of OpId/DAG shape, so unanimity still requires carol.
    let (alice, bob, carol, mallory) = (alice_pk(), bob_pk(), cpk(), dave_pk());
    let mut k = quorum_engine(&[
        minit(alice, TestRole::Admin, [0xaa; 32]),
        minit(bob, TestRole::Admin, [0xbb; 32]),
    ]);
    let pid = [7u8; 32];
    // Attacker chain (alice+bob), rooted at the Create, adds mallory without carol.
    k.apply(make_op(10, vec![1], &[1u8; 32], MembershipAction::Propose {
        proposal_id: pid, target: Box::new(add_editor(mallory, 0xee)),
    })).unwrap();
    k.apply(make_op(11, vec![10], &[2u8; 32], MembershipAction::Approve { proposal_id: pid })).unwrap();
    k.apply(make_op(12, vec![11], &[1u8; 32], MembershipAction::Commit { proposal_id: pid })).unwrap();
    // Concurrent deep chain (also rooted at the Create) that adds carol at depth 3, ids > 12.
    k.apply(make_op(20, vec![1], &[1u8; 32], MembershipAction::ChangeRole { member: bob, new_role: TestRole::Admin })).unwrap();
    k.apply(make_op(21, vec![20], &[1u8; 32], MembershipAction::ChangeRole { member: bob, new_role: TestRole::Admin })).unwrap();
    k.apply(make_op(22, vec![21], &[1u8; 32], MembershipAction::Add {
        member: carol, role: TestRole::Admin, author_public_key: carol, hpke_public_key: [0xcc; 32], member_proof: None,
    })).unwrap();
    assert!(qmember(&k, &carol), "sanity: carol was added");
    assert!(
        !qmember(&k, &mallory),
        "carol is a concurrent signer in the denominator; alice+bob is not unanimity of {{alice,bob,carol}}"
    );
}
