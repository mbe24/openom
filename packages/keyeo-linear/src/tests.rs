//! A concrete instantiation of the generic engine (`Id = String`, `R = TestRole`, `S = Ed25519`) plus a
//! test suite mirroring openom-keyring `chain.rs`'s coverage — proving the engine standalone, over
//! primitive types, with no openom payload in sight.

use super::*;
use crate::signing::sha256;
use keyeo_core::Ed25519;
use serde::Serialize;

// ---- the reference role: a single ordinal; founder == 1, signer == 1..=2 (co-owner == 2) ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
struct TestRole(i16);

impl keyeo_core::Role for TestRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        // Lower ordinal = stronger (Owner==1 is strongest), matching openom's ladder.
        self.0 <= other.0
    }
}
impl LinearRole for TestRole {
    fn is_founder(&self) -> bool {
        self.0 == 1
    }
    fn is_signer(&self) -> bool {
        (1..=2).contains(&self.0)
    }
}

const FOUNDER: TestRole = TestRole(1);
const CO_OWNER: TestRole = TestRole(2);
const EDITOR: TestRole = TestRole(4);

// ---- the reference doc ----

#[derive(Clone)]
struct TestDoc {
    group_id: GroupId,
    revision: Revision,
    prev_hash: DocHash,
    layout_version: u32,
    members: Vec<Signer<String, TestRole, [u8; 32]>>,
    governance: Governance,
    recovery_authority: Option<[u8; 32]>,
    signatures: Vec<[u8; 64]>,
    /// The member ids that have a "wrap" in the newest epoch — the wrap-completeness analogue.
    wrapped: std::collections::BTreeSet<String>,
    /// Opaque payload bytes the `payload_commitment` binds (a trivial stand-in for the binding's payload).
    payload: Vec<u8>,
}

impl LinearDoc for TestDoc {
    type Id = String;
    type R = TestRole;
    type S = Ed25519;

    fn group_id(&self) -> &GroupId {
        &self.group_id
    }
    fn revision(&self) -> Revision {
        self.revision
    }
    fn prev_hash(&self) -> &DocHash {
        &self.prev_hash
    }
    fn layout_version(&self) -> u32 {
        self.layout_version
    }
    fn members(&self) -> Vec<Signer<String, TestRole, [u8; 32]>> {
        self.members.clone()
    }
    fn governance(&self) -> Governance {
        self.governance
    }
    fn recovery_authority(&self) -> Option<[u8; 32]> {
        self.recovery_authority
    }
    fn signatures(&self) -> Vec<[u8; 64]> {
        self.signatures.clone()
    }
    fn payload_commitment(&self) -> PayloadCommitment {
        PayloadCommitment(sha256(&self.payload))
    }
    fn structure_ok(&self) -> Result<(), &'static str> {
        // Wrap-completeness analogue: every member must have a wrap in the newest epoch.
        for m in &self.members {
            if !self.wrapped.contains(&m.id) {
                return Err("wrap incomplete");
            }
        }
        Ok(())
    }
}

// ---- helpers ----

fn sk(seed: u8) -> edsign::SigningKey {
    edsign::SigningKey::from_seed(&[seed; 32])
}
fn vk(k: &edsign::SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn member(k: &edsign::SigningKey, id: &str, role: TestRole) -> Signer<String, TestRole, [u8; 32]> {
    Signer {
        id: id.into(),
        role,
        public_key: vk(k),
    }
}

/// Sign `doc` with each key over the engine's canonical bytes (signatures are excluded from those bytes).
fn sign(doc: &mut TestDoc, keys: &[&edsign::SigningKey]) {
    doc.signatures.clear();
    let msg = signing_bytes(doc);
    for k in keys {
        doc.signatures.push(k.sign(&msg).to_bytes());
    }
}

/// A genesis (revision 1): founder "owner" + the given co-owners + the given editors, every member wrapped.
fn genesis(
    founder: &edsign::SigningKey,
    co: &[(&edsign::SigningKey, &str)],
    editors: &[(&edsign::SigningKey, &str)],
) -> TestDoc {
    let mut members = vec![member(founder, "owner", FOUNDER)];
    for (k, id) in co {
        members.push(member(k, id, CO_OWNER));
    }
    for (k, id) in editors {
        members.push(member(k, id, EDITOR));
    }
    let wrapped = members.iter().map(|m| m.id.clone()).collect();
    let mut d = TestDoc {
        group_id: GroupId(b"group-1".to_vec()),
        revision: Revision(1),
        prev_hash: DocHash([0u8; 32]),
        layout_version: 1,
        members,
        governance: Governance { kind: 0, threshold: 0 },
        recovery_authority: None,
        signatures: vec![],
        wrapped,
        payload: vec![],
    };
    sign(&mut d, &[founder]);
    d
}

/// A well-formed successor: revision+1, chained hash, `mutate` applied, wraps refilled, then signed.
fn next(
    prior: &TestDoc,
    mutate: impl FnOnce(&mut TestDoc),
    sign_with: &[&edsign::SigningKey],
) -> TestDoc {
    let mut d = prior.clone();
    d.revision = Revision(prior.revision.0 + 1);
    d.prev_hash = doc_hash(prior);
    mutate(&mut d);
    d.wrapped = d.members.iter().map(|m| m.id.clone()).collect();
    sign(&mut d, sign_with);
    d
}

/// The trust anchor for an already-trusted doc (the `KeyringAnchor::from_keyring` analogue).
fn anchor(d: &TestDoc) -> Anchor<String, TestRole, [u8; 32]> {
    Anchor {
        group_id: d.group_id.clone(),
        revision: d.revision,
        doc_hash: doc_hash(d),
        signers: d.members.iter().filter(|m| m.role.is_signer()).cloned().collect(),
        governance: d.governance,
        recovery_authority: d.recovery_authority,
    }
}

fn add_editor<'a>(k: &'a edsign::SigningKey, id: &'a str) -> impl FnOnce(&mut TestDoc) + 'a {
    move |d: &mut TestDoc| d.members.push(member(k, id, EDITOR))
}
fn promote_to_coowner<'a>(id: &'a str) -> impl FnOnce(&mut TestDoc) + 'a {
    move |d: &mut TestDoc| d.members.iter_mut().find(|m| m.id == id).unwrap().role = CO_OWNER
}
fn set_rule(kind: u32, threshold: u32) -> impl FnOnce(&mut TestDoc) {
    move |d: &mut TestDoc| d.governance = Governance { kind, threshold }
}

// ---- signed-bytes / structure ----

#[test]
fn signing_bytes_bind_every_generic_field() {
    let f = sk(1);
    let g = genesis(&f, &[], &[]);
    let base = signing_bytes(&g);

    let mut d = g.clone();
    d.revision = Revision(2);
    assert_ne!(base, signing_bytes(&d), "revision is bound (anti-rollback)");

    let mut d = g.clone();
    d.governance = Governance { kind: 2, threshold: 2 };
    assert_ne!(base, signing_bytes(&d), "governance is bound");

    let mut d = g.clone();
    d.recovery_authority = Some([9u8; 32]);
    assert_ne!(base, signing_bytes(&d), "recovery authority presence is bound");

    let mut d = g.clone();
    d.members[0].role = CO_OWNER;
    assert_ne!(base, signing_bytes(&d), "a member role change is bound (via members)");

    let mut d = g.clone();
    d.payload = vec![1];
    assert_ne!(base, signing_bytes(&d), "the payload commitment is bound");

    // Signatures are NOT part of the signed bytes.
    let mut d = g.clone();
    d.signatures.push([7u8; 64]);
    assert_eq!(base, signing_bytes(&d), "signatures are excluded from the signed bytes");
}

// ---- happy path + walk ----

#[test]
fn happy_path_transition_and_walk() {
    let f = sk(1);
    let g = genesis(&f, &[], &[]);
    let a = bootstrap_genesis(&g, &vk(&f)).unwrap();
    assert_eq!(a.revision, Revision(1));

    let c1 = next(&g, add_editor(&sk(2), "bob"), &[&f]);
    let c2 = next(&c1, add_editor(&sk(3), "eve"), &[&f]);

    let out = verify_transition(&a, &c1).unwrap();
    assert_eq!(out.revision, Revision(2));

    assert_eq!(verify_walk(&a, &[c1.clone(), c2.clone()]).unwrap().revision, Revision(3));
    // A gap (skipping the first hop) is rejected.
    assert_eq!(verify_walk(&a, &[c2]), Err(LinearError::NonSequential));
}

// ---- ordering / chaining gates ----

#[test]
fn non_sequential_fork_and_overflow_are_distinct() {
    let f = sk(1);
    let g = genesis(&f, &[], &[]);
    let a = anchor(&g);

    // Skip a revision.
    let mut skip = g.clone();
    skip.revision = Revision(3);
    skip.prev_hash = doc_hash(&g);
    sign(&mut skip, &[&f]);
    assert_eq!(verify_transition(&a, &skip), Err(LinearError::NonSequential));

    // Right revision, wrong prev hash.
    let fork = next(&g, |d| d.prev_hash = DocHash([9u8; 32]), &[&f]);
    assert_eq!(verify_transition(&a, &fork), Err(LinearError::Fork));

    // At u32::MAX, every candidate overflows before the sequential check.
    let mut at_max = anchor(&g);
    at_max.revision = Revision(u32::MAX);
    assert_eq!(verify_transition(&at_max, &g), Err(LinearError::RevisionOverflow));

    // Different group.
    let mut other = anchor(&g);
    other.group_id = GroupId(b"other".to_vec());
    assert_eq!(verify_transition(&other, &g), Err(LinearError::GroupMismatch));
}

// ---- ordinary change ----

#[test]
fn ordinary_change_by_a_prior_signer_accepted_stranger_rejected() {
    let f = sk(1);
    let c = sk(2);
    let g = genesis(&f, &[(&c, "carol")], &[]);
    let a = anchor(&g);

    // The founder and the co-owner may each sign an ordinary change.
    verify_transition(&a, &next(&g, add_editor(&sk(9), "bob"), &[&f])).unwrap();
    verify_transition(&a, &next(&g, add_editor(&sk(9), "bob"), &[&c])).unwrap();

    // A stranger cannot.
    let stranger = sk(7);
    assert_eq!(
        verify_transition(&a, &next(&g, add_editor(&sk(9), "bob"), &[&stranger])),
        Err(LinearError::UnendorsedOrdinaryChange)
    );
}

// ---- governance kinds ----

#[test]
fn governance_kind0_founder_or_unanimity_gates_a_privileged_change() {
    let (f, aa, bb) = (sk(1), sk(2), sk(3));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b")], &[(&sk(5), "pend")]);
    let a = anchor(&g);

    // Promoting "pend" to co-owner is a signer-set change; under kind 0 the founder authorizes it.
    verify_transition(&a, &next(&g, promote_to_coowner("pend"), &[&f])).unwrap();
    // A lone co-owner cannot.
    assert_eq!(
        verify_transition(&a, &next(&g, promote_to_coowner("pend"), &[&aa])),
        Err(LinearError::UnendorsedSetChange)
    );
}

#[test]
fn governance_kind1_founder_only() {
    let (f, aa, bb) = (sk(1), sk(2), sk(3));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b")], &[(&sk(5), "pend")]);
    // Founder sets founder-only (a privileged change, authorized under prior kind 0 by the founder).
    let ruled = next(&g, set_rule(1, 0), &[&f]);
    let a = verify_transition(&anchor(&g), &ruled).unwrap();
    assert_eq!(a.governance, Governance { kind: 1, threshold: 0 });

    verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&f])).unwrap();
    // Even both co-owners together cannot (no unanimity path under founder-only).
    assert_eq!(
        verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&aa, &bb])),
        Err(LinearError::UnendorsedSetChange)
    );
}

#[test]
fn governance_kind2_founder_or_threshold_gates_a_signer_change() {
    let (f, aa, bb, cc) = (sk(1), sk(2), sk(3), sk(4));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b"), (&cc, "c")], &[(&sk(5), "pend")]);
    let ruled = next(&g, set_rule(2, 2), &[&f]);
    let a = verify_transition(&anchor(&g), &ruled).unwrap();
    assert_eq!(a.governance, Governance { kind: 2, threshold: 2 });

    // Promoting "pend" now needs 2 co-owners OR the founder.
    verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&aa, &bb])).unwrap();
    verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&f])).unwrap();
    assert_eq!(
        verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&aa])),
        Err(LinearError::UnendorsedSetChange)
    );
}

#[test]
fn governance_kind3_pure_threshold_has_no_founder_path() {
    let (f, aa, bb) = (sk(1), sk(2), sk(3));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b")], &[(&sk(5), "pend")]);
    // threshold(2) over ALL prior signers (founder counts as a signer).
    let ruled = next(&g, set_rule(3, 2), &[&f]);
    let a = verify_transition(&anchor(&g), &ruled).unwrap();

    // Two distinct signers meet 2-of; the founder alone (one signature) does not.
    verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&f, &aa])).unwrap();
    verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&aa, &bb])).unwrap();
    assert_eq!(
        verify_transition(&a, &next(&ruled, promote_to_coowner("pend"), &[&f])),
        Err(LinearError::UnendorsedSetChange)
    );
}

#[test]
fn governance_change_is_anti_downgrade() {
    let (f, aa, bb) = (sk(1), sk(2), sk(3));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b")], &[]);
    let ruled = next(&g, set_rule(2, 2), &[&f]);
    let a = verify_transition(&anchor(&g), &ruled).unwrap();

    // Weakening (2-of -> founder-or-unanimity) must still satisfy the CURRENT (2-of) rule.
    assert_eq!(
        verify_transition(&a, &next(&ruled, set_rule(0, 0), &[&aa])),
        Err(LinearError::UnendorsedSetChange)
    );
    verify_transition(&a, &next(&ruled, set_rule(0, 0), &[&aa, &bb])).unwrap();
}

#[test]
fn governance_lockout_is_refused() {
    let (f, aa, bb, cc) = (sk(1), sk(2), sk(3), sk(4));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b"), (&cc, "c")], &[]);
    // 4 signers; threshold(5) can never be satisfied even though the founder authorizes the change.
    assert_eq!(
        verify_transition(&anchor(&g), &next(&g, set_rule(3, 5), &[&f])),
        Err(LinearError::UnendorsedSetChange)
    );
}

// ---- self-removal ----

#[test]
fn self_removal_accepted_but_bundled_removal_rejected() {
    let (f, carol, dave) = (sk(1), sk(2), sk(3));
    let g = genesis(&f, &[(&carol, "carol"), (&dave, "dave")], &[]);
    let a = anchor(&g);

    // Carol removes only herself (demote to editor), self-signed → accepted.
    verify_transition(&a, &next(&g, |d| d.members.iter_mut().find(|m| m.id == "carol").unwrap().role = EDITOR, &[&carol])).unwrap();

    // Carol tries to demote herself AND dave → not a lone self-removal → rejected.
    let bundled = next(
        &g,
        |d| {
            for m in &mut d.members {
                if m.id == "carol" || m.id == "dave" {
                    m.role = EDITOR;
                }
            }
        },
        &[&carol],
    );
    assert_eq!(verify_transition(&a, &bundled), Err(LinearError::UnendorsedSetChange));
}

// ---- the HOLE case: a non-signer role cannot authorize ----

#[test]
fn an_editor_member_cannot_authorize_anything() {
    let (f, carol) = (sk(1), sk(2));
    // Carol is a keyed EDITOR (a valid author key, but a non-signer role).
    let g = genesis(&f, &[], &[(&carol, "carol")]);
    let a = anchor(&g);

    // An ordinary change signed by the editor → rejected (she is not a derived signer).
    assert_eq!(
        verify_transition(&a, &next(&g, add_editor(&sk(9), "bob"), &[&carol])),
        Err(LinearError::UnendorsedOrdinaryChange)
    );
    // Self-promotion to co-owner, self-signed → rejected (no phantom authority).
    assert_eq!(
        verify_transition(&a, &next(&g, promote_to_coowner("carol"), &[&carol])),
        Err(LinearError::UnendorsedSetChange)
    );
}

// ---- structural gates ----

#[test]
fn structural_gates_reject_bad_docs() {
    let f = sk(1);
    let g = genesis(&f, &[], &[]);
    let a = anchor(&g);

    // Two founders.
    let two = next(&g, |d| d.members.push(member(&sk(2), "co", FOUNDER)), &[&f]);
    assert!(matches!(verify_transition(&a, &two), Err(LinearError::BadStructure(_))));

    // Duplicate member id.
    let dup = next(&g, |d| d.members.push(member(&sk(2), "owner", EDITOR)), &[&f]);
    assert!(matches!(verify_transition(&a, &dup), Err(LinearError::BadStructure(_))));

    // A signer with a non-curve-point key (malformed) — caught by the scheme's accepts_key gate.
    let mut bad_pt = [0u8; 32];
    bad_pt[0] = 2; // y = 2 has no matching x on the curve
    let malformed = next(
        &g,
        |d| {
            d.members.push(Signer { id: "rogue".into(), role: CO_OWNER, public_key: bad_pt });
        },
        &[&f],
    );
    assert_eq!(
        verify_transition(&a, &malformed),
        Err(LinearError::BadStructure("signer key malformed"))
    );

    // The binding's structure_ok gate fires (a member without a wrap).
    let unwrapped = {
        let mut d = next(&g, add_editor(&sk(2), "bob"), &[&f]);
        d.wrapped.remove("bob");
        d
    };
    assert_eq!(
        verify_transition(&a, &unwrapped),
        Err(LinearError::Structure("wrap incomplete"))
    );
}

// ---- recovery authority ----

#[test]
fn establishing_a_recovery_authority_is_a_privileged_change() {
    let (f, aa, bb) = (sk(1), sk(2), sk(3));
    let g = genesis(&f, &[(&aa, "a"), (&bb, "b")], &[]);
    let a = anchor(&g);
    let rvk = vk(&sk(8));

    // A lone co-owner cannot plant a recovery authority; the founder can (kind 0 founder path).
    assert_eq!(
        verify_transition(&a, &next(&g, |d| d.recovery_authority = Some(rvk), &[&aa])),
        Err(LinearError::UnendorsedSetChange)
    );
    let out = verify_transition(&a, &next(&g, |d| d.recovery_authority = Some(rvk), &[&f])).unwrap();
    assert_eq!(out.recovery_authority, Some(rvk));
}

#[test]
fn rotating_a_recovery_authority_needs_the_old_authority_signature() {
    let f = sk(1);
    let rvk1 = sk(8);
    let rvk2 = vk(&sk(9));
    // Prior genesis pins rvk1.
    let g = {
        let mut d = genesis(&f, &[], &[]);
        d.recovery_authority = Some(vk(&rvk1));
        sign(&mut d, &[&f]);
        d
    };
    let a = anchor(&g);
    assert_eq!(a.recovery_authority, Some(vk(&rvk1)));

    // Rotate rvk1 -> rvk2: founder-signed AND old-RVK-signed → accepted.
    let out = verify_transition(&a, &next(&g, |d| d.recovery_authority = Some(rvk2), &[&f, &rvk1])).unwrap();
    assert_eq!(out.recovery_authority, Some(rvk2));
    // Founder-signed but NOT old-RVK-signed → rejected.
    assert_eq!(
        verify_transition(&a, &next(&g, |d| d.recovery_authority = Some(rvk2), &[&f])),
        Err(LinearError::UnendorsedSetChange)
    );
}

// ---- bootstrap + reset ----

#[test]
fn bootstrap_genesis_and_pinned() {
    let f = sk(1);
    let g = genesis(&f, &[], &[]);

    // Founder bootstraps with their own key; a stranger's key fails.
    assert_eq!(bootstrap_genesis(&g, &vk(&f)).unwrap().revision, Revision(1));
    assert_eq!(bootstrap_genesis(&g, &vk(&sk(2))), Err(LinearError::BadBootstrap));

    // A non-genesis revision is refused.
    let mut r2 = g.clone();
    r2.revision = Revision(2);
    sign(&mut r2, &[&f]);
    assert_eq!(bootstrap_genesis(&r2, &vk(&f)), Err(LinearError::BadBootstrap));

    // OOB pin: matching (group, revision, hash) accepted; a wrong hash rejected.
    let h = doc_hash(&g);
    bootstrap_pinned(&g, &GroupId(b"group-1".to_vec()), Revision(1), &h).unwrap();
    assert_eq!(
        bootstrap_pinned(&g, &GroupId(b"group-1".to_vec()), Revision(1), &DocHash([0u8; 32])),
        Err(LinearError::BadBootstrap)
    );
}

#[test]
fn verify_reset_accepts_a_reset_and_enforces_the_rvk_gate() {
    let f = sk(1);
    let g = genesis(&f, &[], &[]);
    // A genesis validates on its own terms.
    assert_eq!(verify_reset(None, &g).unwrap().revision, Revision(1));

    // A recovery-style reset: later revision, fresh founder identity, self-signed by the new key —
    // verify_transition would reject it, verify_reset accepts.
    let f2 = sk(2);
    let mut reset = g.clone();
    reset.revision = Revision(5);
    reset.prev_hash = DocHash([9u8; 32]);
    reset.members[0].public_key = vk(&f2);
    sign(&mut reset, &[&f2]);
    assert_eq!(verify_reset(None, &reset).unwrap().revision, Revision(5));

    // A doc signed by nobody in its own signer set is not a valid reset.
    let mut unsigned = g.clone();
    sign(&mut unsigned, &[&sk(3)]);
    assert_eq!(verify_reset(None, &unsigned), Err(LinearError::BadBootstrap));

    // RVK gate: once a prior RVK is pinned, the reset must carry the SAME authority AND be signed by it.
    let rvk = sk(8);
    let rvk_pub = vk(&rvk);
    let build = |pinned: [u8; 32], rvk_signs: bool| -> TestDoc {
        let f = sk(7);
        let mut d = genesis(&f, &[], &[]);
        d.recovery_authority = Some(pinned);
        let mut keys: Vec<&edsign::SigningKey> = vec![&f];
        if rvk_signs {
            keys.push(&rvk);
        }
        sign(&mut d, &keys);
        d
    };
    // Continuity + RVK-signature satisfied → accepted.
    assert!(verify_reset(Some(&rvk_pub), &build(rvk_pub, true)).is_ok());
    // Signed by the fresh founder but not the RVK → rejected (authorization).
    assert_eq!(
        verify_reset(Some(&rvk_pub), &build(rvk_pub, false)),
        Err(LinearError::UnendorsedSetChange)
    );
    // A different recovery root pinned → rejected (continuity).
    assert_eq!(
        verify_reset(Some(&rvk_pub), &build(vk(&sk(11)), true)),
        Err(LinearError::UnendorsedSetChange)
    );
    // No prior RVK → the gate is inert.
    assert!(verify_reset(None, &build(rvk_pub, false)).is_ok());
}
