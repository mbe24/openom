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
    let oa = a.apply(TreeOp::AddClaim {
        person: pid(1),
        field: "birth.date".into(),
        claim: cid(1),
        value: "1901".into(),
        source: Some("gravestone".into()),
    });
    // b independently learns of the person and records a different date.
    b.doc_mut().merge_op(&a.persons_add_op(&pid(1))); // (helper below reconstructs the add)
    let ob = b.apply(TreeOp::AddClaim {
        person: pid(1),
        field: "birth.date".into(),
        claim: cid(2),
        value: "1903".into(),
        source: Some("parish record".into()),
    });

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

fn treeop_strat() -> impl Strategy<Value = TreeOp> {
    prop_oneof![
        (0u8..3).prop_map(|p| TreeOp::AddPerson { id: pid(p) }),
        (0u8..3).prop_map(|p| TreeOp::RemovePerson { id: pid(p) }),
        (0u8..3, 0u8..2, 0u8..4).prop_map(|(p, f, c)| TreeOp::AddClaim {
            person: pid(p),
            field: if f == 0 { "birth.date".into() } else { "name.given".into() },
            claim: cid(c),
            value: format!("v{c}"),
            source: None,
        }),
        (0u8..3, 0u8..2, 0u8..4).prop_map(|(p, f, c)| TreeOp::SetPreferredClaim {
            person: pid(p),
            field: if f == 0 { "birth.date".into() } else { "name.given".into() },
            claim: cid(c),
        }),
        (0u8..3, 0u8..2, 0u8..4).prop_map(|(p, f, c)| TreeOp::RetractClaim {
            person: pid(p),
            field: if f == 0 { "birth.date".into() } else { "name.given".into() },
            claim: cid(c),
        }),
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
            ops.push(authors[*r].apply(op.clone()));
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
