//! Domain tests. The headline is **M2**: two relatives recording different birth dates both survive
//! as competing sourced claims — silent last-writer-wins would be genealogically wrong. Convergence
//! is inherited from `commute` but re-proven here *through* the family-tree op vocabulary.

use super::*;
use proptest::prelude::*;

fn rid(i: u8) -> ReplicaId {
    let mut r = [0u8; 16];
    r[0] = i;
    r
}

fn pid(i: u8) -> PersonId {
    vec![i]
}
fn cid(i: u8) -> ClaimId {
    vec![0xC0 | i]
}

#[test]
fn persons_add_and_remove() {
    let mut t = Tree::new(rid(1));
    t.apply(TreeOp::AddPerson { id: pid(1) });
    t.apply(TreeOp::AddPerson { id: pid(2) });
    assert!(t.has_person(&pid(1)));
    assert_eq!(t.persons().len(), 2);
    t.apply(TreeOp::RemovePerson { id: pid(1) });
    assert!(!t.has_person(&pid(1)));
    assert_eq!(t.persons(), vec![pid(2)]);
}

#[test]
fn competing_claims_both_survive() {
    // Two devices, offline, set the same person's birth date to different values.
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    a.apply(TreeOp::AddPerson { id: pid(1) });
    let oa = a
        .apply(TreeOp::AddClaim {
            person: pid(1),
            field: "birth.date".into(),
            claim: cid(1),
            value: "1901".into(),
            source: Some("gravestone".into()),
        })
        .pop()
        .unwrap();
    // b independently learns of the person and records a different date.
    b.doc_mut().merge_op(&a.persons_add_op(&pid(1))); // (helper below reconstructs the add)
    let ob = b
        .apply(TreeOp::AddClaim {
            person: pid(1),
            field: "birth.date".into(),
            claim: cid(2),
            value: "1903".into(),
            source: Some("parish record".into()),
        })
        .pop()
        .unwrap();

    a.doc_mut().merge_op(&ob);
    b.doc_mut().merge_op(&oa);

    let fact = a.fact(&pid(1), "birth.date");
    assert_eq!(fact.claims.len(), 2, "both competing claims are retained, not clobbered");
    let values: Vec<&str> = fact.claims.iter().map(|c| c.value.as_str()).collect();
    assert!(values.contains(&"1901") && values.contains(&"1903"));
    // Deterministic on both replicas.
    assert_eq!(a.fact(&pid(1), "birth.date"), b.fact(&pid(1), "birth.date"));
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
}

#[test]
fn preferred_pointer_selects_a_claim_and_falls_back_when_unset() {
    let mut t = Tree::new(rid(1));
    t.apply(TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(1), value: "1901".into(), source: None });
    t.apply(TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(2), value: "1903".into(), source: None });
    // No explicit preference yet → deterministic fallback (greatest claim id = cid(2) = "1903").
    assert_eq!(t.fact(&pid(1), "birth.date").preferred.unwrap().value, "1903");
    // Explicitly prefer the 1901 claim.
    t.apply(TreeOp::SetPreferredClaim { person: pid(1), field: "birth.date".into(), claim: cid(1) });
    assert_eq!(t.fact(&pid(1), "birth.date").preferred.unwrap().value, "1901");
}

#[test]
fn retracting_a_claim_removes_it() {
    let mut t = Tree::new(rid(1));
    t.apply(TreeOp::AddClaim { person: pid(1), field: "name.given".into(), claim: cid(1), value: "Jon".into(), source: None });
    t.apply(TreeOp::AddClaim { person: pid(1), field: "name.given".into(), claim: cid(2), value: "John".into(), source: None });
    t.apply(TreeOp::RetractClaim { person: pid(1), field: "name.given".into(), claim: cid(1) });
    let fact = t.fact(&pid(1), "name.given");
    assert_eq!(fact.claims.len(), 1);
    assert_eq!(fact.claims[0].value, "John");
}

fn fid(i: u8) -> FamilyId {
    vec![0xF0 | i]
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A fixed script → a fixed snapshot. The SAME script + hex is asserted in the wasm build
/// (`apps/test/treelog.int.js`), so this pins native↔wasm byte-for-byte parity: if either build
/// diverges, one of the two golden tests fails.
#[test]
fn treelog_snapshot_golden_vector() {
    let mut t = Tree::new([7u8; 16]);
    t.apply(TreeOp::AddPerson { id: vec![1] });
    t.apply(TreeOp::AddClaim { person: vec![1], field: "birth.date".into(), claim: vec![9], value: "1901".into(), source: None });
    let got = hex(&t.doc().snapshot());
    let expected = "01000000000000000200000000000000010707070707070707070707070707070701000000000000000101\
000000000000000101000000000000000002070707070707070707070707070707070100000000000000140200000001010000000a\
62697274682e64617465000000000000000109040000000000000009000000043139303100";
    assert_eq!(got, expected, "treelog snapshot encoding changed — update BOTH goldens (native + wasm)");
}

#[test]
fn a_marriage_added_as_one_batch_lands_atomically() {
    // "Add a marriage" spans records: a family, two spouses, a child. One batch, one action.
    let mut t = Tree::new(rid(1));
    let ops = t.apply_batch(vec![
        TreeOp::AddFamily { id: fid(0) },
        TreeOp::LinkSpouse { family: fid(0), person: pid(1) },
        TreeOp::LinkSpouse { family: fid(0), person: pid(2) },
        TreeOp::LinkChild { family: fid(0), person: pid(3), pedi: Pedigree::Birth },
    ]);
    assert_eq!(ops.len(), 4, "four self-contained ops, sealed together");
    assert_eq!(t.families(), vec![fid(0)]);
    assert_eq!(t.spouses_of(&fid(0)), vec![pid(1), pid(2)]);
    assert_eq!(t.children_of(&fid(0)), vec![(pid(3), Pedigree::Birth)]);
}

#[test]
fn concurrent_relationship_edits_both_survive() {
    // M3: device A adds a child to a family; device B adds a spouse to the same family.
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    let setup = a.apply(TreeOp::AddFamily { id: fid(0) });
    b.doc_mut().merge_op(&setup[0]);

    let child = a.apply(TreeOp::LinkChild { family: fid(0), person: pid(3), pedi: Pedigree::Adopted });
    let spouse = b.apply(TreeOp::LinkSpouse { family: fid(0), person: pid(1) });
    for o in &spouse {
        a.doc_mut().merge_op(o);
    }
    for o in &child {
        b.doc_mut().merge_op(o);
    }
    assert_eq!(a.children_of(&fid(0)), vec![(pid(3), Pedigree::Adopted)]);
    assert_eq!(a.spouses_of(&fid(0)), vec![pid(1)]);
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
}

#[test]
fn move_child_reparents_and_survives_a_concurrent_edit() {
    // M4: A re-parents a child F0 -> F1; B concurrently edits the child's name. Both survive.
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    let setup = a.apply_batch(vec![
        TreeOp::AddFamily { id: fid(0) },
        TreeOp::AddFamily { id: fid(1) },
        TreeOp::LinkChild { family: fid(0), person: pid(3), pedi: Pedigree::Birth },
    ]);
    for o in &setup {
        b.doc_mut().merge_op(o);
    }
    let mv = a.apply(TreeOp::MoveChild { person: pid(3), from: fid(0), to: fid(1), pedi: Pedigree::Birth });
    let edit = b.apply(TreeOp::AddClaim { person: pid(3), field: "name.given".into(), claim: cid(1), value: "Mary".into(), source: None });
    for o in &mv {
        b.doc_mut().merge_op(o);
    }
    for o in &edit {
        a.doc_mut().merge_op(o);
    }
    assert!(a.children_of(&fid(0)).is_empty(), "left the source family");
    assert_eq!(a.children_of(&fid(1)), vec![(pid(3), Pedigree::Birth)], "joined the destination");
    assert_eq!(a.fact(&pid(3), "name.given").preferred.unwrap().value, "Mary", "the concurrent edit survived");
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
}

#[test]
fn disjoint_fields_both_survive() {
    // M1: two devices edit different fields of the same person; neither clobbers the other.
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    let oa = a.apply(TreeOp::AddClaim { person: pid(1), field: "birth.place".into(), claim: cid(1), value: "London".into(), source: None });
    let ob = b.apply(TreeOp::AddClaim { person: pid(1), field: "death.date".into(), claim: cid(2), value: "1970".into(), source: None });
    for o in &ob {
        a.doc_mut().merge_op(o);
    }
    for o in &oa {
        b.doc_mut().merge_op(o);
    }
    assert_eq!(a.fact(&pid(1), "birth.place").preferred.unwrap().value, "London");
    assert_eq!(a.fact(&pid(1), "death.date").preferred.unwrap().value, "1970");
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
}

#[test]
fn delete_wins_but_the_concurrent_edit_is_not_lost() {
    // M5: A removes a person; B concurrently records a fact about them. The person leaves the
    // roster (delete wins), but the edit survives as an orphaned claim — never silently destroyed,
    // never a resurrection of the person.
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    let add = a.apply(TreeOp::AddPerson { id: pid(1) });
    for o in &add {
        b.doc_mut().merge_op(o);
    }
    let del = a.apply(TreeOp::RemovePerson { id: pid(1) });
    let edit = b.apply(TreeOp::AddClaim { person: pid(1), field: "note".into(), claim: cid(1), value: "was here".into(), source: None });
    for o in &edit {
        a.doc_mut().merge_op(o);
    }
    for o in &del {
        b.doc_mut().merge_op(o);
    }
    assert!(!a.has_person(&pid(1)), "delete wins: the person is off the roster");
    assert_eq!(a.fact(&pid(1), "note").claims.len(), 1, "the concurrent edit survives as an orphaned claim");
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
}

#[test]
fn a_long_offline_replica_catches_up_in_one_delta() {
    // M7: B is offline while A makes many edits, then catches up with a single delta.
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    for i in 0..12u8 {
        a.apply(TreeOp::AddPerson { id: pid(i) });
        a.apply(TreeOp::AddClaim { person: pid(i), field: "name.given".into(), claim: cid(0), value: format!("p{i}"), source: None });
    }
    let vv = b.doc().version();
    let delta = a.doc().delta_since(&vv);
    b.doc_mut().merge_bytes(&delta).unwrap();
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
    assert_eq!(b.persons().len(), 12);
}

fn mref(i: u8) -> MediaRef {
    vec![0xA0 | i]
}

#[test]
fn media_attaches_detaches_without_resurrection() {
    let mut a = Tree::new(rid(1));
    let mut b = Tree::new(rid(2));
    a.apply(TreeOp::AddPerson { id: pid(1) });
    let m1 = a.apply(TreeOp::AttachMedia { subject: pid(1), media: mref(0) });
    a.apply(TreeOp::AttachMedia { subject: pid(1), media: mref(1) });
    a.apply(TreeOp::DetachMedia { subject: pid(1), media: mref(0) });
    assert_eq!(a.media_of(&pid(1)), vec![mref(1)]);

    // A stale re-attach of the detached blob (delivered late to another replica) must not resurrect.
    for o in &m1 {
        b.doc_mut().merge_op(o);
    }
    for o in a.apply(TreeOp::AddPerson { id: pid(2) }).iter() {
        let _ = o;
    }
    // Bring b fully up to date, then confirm the detached blob stays gone.
    b.doc_mut().merge_bytes(&a.doc().snapshot()).unwrap();
    assert_eq!(b.media_of(&pid(1)), vec![mref(1)]);
    assert_eq!(a.doc().snapshot(), b.doc().snapshot());
}

// --- proposal / approval flow -------------------------------------------------------------------

#[test]
fn propose_review_commit_happy_path() {
    let mut owner = Tree::new(rid(1));
    owner.apply(TreeOp::AddPerson { id: pid(1) });
    // An editor drafts a proposal against the owner's current version.
    let proposal = Proposal {
        base: owner.version_cursor(),
        ops: vec![TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(1), value: "1901".into(), source: Some("parish".into()) }],
    };
    let review = owner.review(&proposal);
    assert!(review.conflicts.is_empty());
    assert_eq!(review.changes.len(), 1);
    assert!(matches!(&review.changes[0], Change::ClaimAdded { value, current_preferred: None, .. } if value == "1901"));

    let snap_before = owner.doc().snapshot();
    owner.review(&proposal);
    assert_eq!(owner.doc().snapshot(), snap_before, "review is read-only");

    owner.commit_proposal(&proposal);
    assert_eq!(owner.fact(&pid(1), "birth.date").preferred.unwrap().value, "1901");
}

#[test]
fn a_stale_proposal_on_a_moved_fact_is_flagged_and_keeps_both() {
    // M8: the editor drafts against a base; the head then advances the SAME fact. Review flags the
    // conflict; committing anyway keeps every claim (the claim model never silently drops one).
    let mut owner = Tree::new(rid(1));
    owner.apply(TreeOp::AddPerson { id: pid(1) });
    owner.apply(TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(1), value: "1901".into(), source: None });
    let proposal = Proposal {
        base: owner.version_cursor(),
        ops: vec![TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(2), value: "1903".into(), source: None }],
    };
    // The head moves the same fact after the proposal was drafted.
    owner.apply(TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(3), value: "1902".into(), source: None });

    let review = owner.review(&proposal);
    assert_eq!(review.conflicts, vec![Conflict { person: pid(1), field: "birth.date".into() }]);

    owner.commit_proposal(&proposal);
    assert_eq!(owner.fact(&pid(1), "birth.date").claims.len(), 3, "all three competing claims retained");
}

#[test]
fn a_proposal_on_an_untouched_fact_has_no_conflict() {
    let mut owner = Tree::new(rid(1));
    owner.apply(TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(1), value: "1901".into(), source: None });
    let proposal = Proposal {
        base: owner.version_cursor(),
        ops: vec![TreeOp::AddClaim { person: pid(1), field: "death.date".into(), claim: cid(2), value: "1970".into(), source: None }],
    };
    // The head moves a DIFFERENT fact — no conflict for the proposal's field.
    owner.apply(TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(3), value: "1902".into(), source: None });
    assert!(owner.review(&proposal).conflicts.is_empty());
}

#[test]
fn proposal_encodes_and_decodes() {
    let mut base = commute::VersionVector::new();
    base.insert(rid(1), 7);
    let proposal = Proposal {
        base,
        ops: vec![
            TreeOp::AddPerson { id: pid(1) },
            TreeOp::AddClaim { person: pid(1), field: "birth.date".into(), claim: cid(1), value: "1901".into(), source: Some("parish".into()) },
            TreeOp::MoveChild { person: pid(1), from: fid(0), to: fid(1), pedi: Pedigree::Adopted },
        ],
    };
    let bytes = proposal.encode();
    assert_eq!(Proposal::decode(&bytes).unwrap(), proposal);
}

#[test]
fn proposal_decode_never_panics_on_junk() {
    assert!(Proposal::decode(&[]).is_err());
    assert!(matches!(Proposal::decode(&[9]), Err(ProposalError::BadLayout)));
    assert!(Proposal::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 255]).is_err()); // forged base count
}

proptest! {
    #[test]
    fn proposal_round_trips_the_whole_vocabulary(ops in prop::collection::vec(treeop_strat(), 0..40)) {
        let proposal = Proposal { base: commute::VersionVector::new(), ops };
        let bytes = proposal.encode();
        prop_assert_eq!(Proposal::decode(&bytes).unwrap(), proposal);
    }

    #[test]
    fn proposal_decode_on_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Proposal::decode(&bytes);
    }
}

// A tiny helper for the M2 test: reconstruct the person-add op so replica b can learn the person
// without a full sync round. (In real use this rides normal delta sync.)
impl Tree {
    fn persons_add_op(&self, id: &[u8]) -> Op {
        // Re-derive by delta: the person add is the only op mentioning this id at this point.
        let ops = commute::codec::decode_ops(&self.doc.snapshot()).unwrap();
        ops.into_iter()
            .find(|o| matches!(&o.intent, OpIntent::AddElement { cell, elem, .. } if cell == &persons_cell() && elem.as_slice() == id))
            .unwrap()
    }
}

// --- convergence through the op vocabulary ------------------------------------------------------

fn field_of(f: u8) -> FieldKey {
    if f == 0 {
        "birth.date".into()
    } else {
        "name.given".into()
    }
}
fn pedi_of(p: u8) -> Pedigree {
    match p % 3 {
        0 => Pedigree::Birth,
        1 => Pedigree::Adopted,
        _ => Pedigree::Step,
    }
}

fn treeop_strat() -> impl Strategy<Value = TreeOp> {
    // Small fixed pools (persons 0..3, families 0..2, fields 0..2, claims 0..4) so concurrent ops
    // collide, exercising every merge path — including MoveChild, which expands to two ops.
    prop_oneof![
        (0u8..3).prop_map(|p| TreeOp::AddPerson { id: pid(p) }),
        (0u8..3).prop_map(|p| TreeOp::RemovePerson { id: pid(p) }),
        (0u8..3, 0u8..2, 0u8..4).prop_map(|(p, f, c)| TreeOp::AddClaim { person: pid(p), field: field_of(f), claim: cid(c), value: format!("v{c}"), source: None }),
        (0u8..3, 0u8..2, 0u8..4).prop_map(|(p, f, c)| TreeOp::SetPreferredClaim { person: pid(p), field: field_of(f), claim: cid(c) }),
        (0u8..3, 0u8..2, 0u8..4).prop_map(|(p, f, c)| TreeOp::RetractClaim { person: pid(p), field: field_of(f), claim: cid(c) }),
        (0u8..2).prop_map(|x| TreeOp::AddFamily { id: fid(x) }),
        (0u8..2).prop_map(|x| TreeOp::RemoveFamily { id: fid(x) }),
        (0u8..2, 0u8..3, 0u8..3).prop_map(|(x, p, pe)| TreeOp::LinkChild { family: fid(x), person: pid(p), pedi: pedi_of(pe) }),
        (0u8..2, 0u8..3).prop_map(|(x, p)| TreeOp::UnlinkChild { family: fid(x), person: pid(p) }),
        (0u8..2, 0u8..2, 0u8..3, 0u8..3).prop_map(|(f1, f2, p, pe)| TreeOp::MoveChild { person: pid(p), from: fid(f1), to: fid(f2), pedi: pedi_of(pe) }),
        (0u8..2, 0u8..3).prop_map(|(x, p)| TreeOp::LinkSpouse { family: fid(x), person: pid(p) }),
        (0u8..2, 0u8..3).prop_map(|(x, p)| TreeOp::UnlinkSpouse { family: fid(x), person: pid(p) }),
        (0u8..3, 0u8..2).prop_map(|(p, m)| TreeOp::AttachMedia { subject: pid(p), media: vec![0xA0 | m] }),
        (0u8..3, 0u8..2).prop_map(|(p, m)| TreeOp::DetachMedia { subject: pid(p), media: vec![0xA0 | m] }),
    ]
}

fn shuffle(v: &mut [usize], seed: u64) {
    let mut s = seed | 1;
    for i in (1..v.len()).rev() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.swap(i, (s % (i as u64 + 1)) as usize);
    }
}

proptest! {
    #[test]
    fn trees_converge_through_the_op_vocabulary(
        script in prop::collection::vec((0usize..3, treeop_strat()), 0..80),
        perm_seed in any::<u64>(),
    ) {
        let n = 3;
        let mut authors: Vec<Tree> = (0..n).map(|i| Tree::new(rid(i as u8))).collect();
        let mut ops: Vec<Op> = Vec::new();
        for (r, op) in &script {
            ops.extend(authors[*r].apply(op.clone()));
        }
        let reference = {
            let mut d = commute::Doc::new(rid(0));
            for op in &ops { d.merge_op(op); }
            d.snapshot()
        };
        for r in 0..n {
            let mut d = commute::Doc::new(rid(r as u8));
            let mut order: Vec<usize> = (0..ops.len()).collect();
            shuffle(&mut order, perm_seed ^ r as u64);
            for &i in &order { d.merge_op(&ops[i]); }
            prop_assert_eq!(d.snapshot(), reference.clone());
        }
    }
}
