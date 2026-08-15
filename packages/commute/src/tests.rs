//! Correctness tests for the commute kernel. The headline is the **convergence property**: any set
//! of concurrent ops, delivered to N replicas in arbitrary (and repeated) orders, converges to an
//! identical checkpoint. Everything else is a targeted example.

use super::*;
use proptest::prelude::*;

fn rid(i: u8) -> ReplicaId {
    let mut r = [0u8; 16];
    r[0] = i;
    r
}

fn cell(i: u8) -> CellId {
    vec![i]
}
fn elem(i: u8) -> ElemId {
    vec![0x80 | i]
}

// --- targeted examples --------------------------------------------------------------------------

#[test]
fn register_is_last_writer_by_stamp_across_replicas() {
    // Two replicas concurrently set the same register; the higher stamp wins deterministically,
    // whichever order each replica hears them in.
    let mut a = Doc::new(rid(1));
    let mut b = Doc::new(rid(2));
    let oa = a.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::I64(1901) });
    let ob = b.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::I64(1903) });
    // Both are lamport 1; replica 2 > replica 1 breaks the tie → 1903 wins on both.
    a.merge_op(&ob);
    b.merge_op(&oa);
    assert_eq!(a.register(&cell(0)), Some(&Value::I64(1903)));
    assert_eq!(a.checkpoint(), b.checkpoint());
}

#[test]
fn disjoint_registers_both_survive() {
    let mut a = Doc::new(rid(1));
    let mut b = Doc::new(rid(2));
    let oa = a.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::Text("place".into()) });
    let ob = b.apply_local(OpIntent::SetRegister { cell: cell(1), value: Value::Text("date".into()) });
    a.merge_op(&ob);
    b.merge_op(&oa);
    assert_eq!(a.register(&cell(0)), Some(&Value::Text("place".into())));
    assert_eq!(a.register(&cell(1)), Some(&Value::Text("date".into())));
    assert_eq!(a.checkpoint(), b.checkpoint());
}

#[test]
fn set_add_and_remove_resolve_by_stamp_no_resurrection() {
    // Add, then a later remove tombstones it; a re-delivered add (older stamp) never resurrects it.
    let mut d = Doc::new(rid(1));
    let add = d.apply_local(OpIntent::AddElement { cell: cell(0), elem: elem(0), value: Value::Null });
    let _rm = d.apply_local(OpIntent::RemoveElement { cell: cell(0), elem: elem(0) });
    assert!(d.set_elements(&cell(0)).is_empty());
    d.merge_op(&add); // stale re-delivery
    assert!(d.set_elements(&cell(0)).is_empty(), "an out-stamped add must not resurrect a tombstone");
}

#[test]
fn merge_is_idempotent() {
    let mut author = Doc::new(rid(1));
    let op = author.apply_local(OpIntent::AddElement { cell: cell(0), elem: elem(0), value: Value::I64(7) });
    let mut d = Doc::new(rid(2));
    d.merge_op(&op);
    let once = d.checkpoint();
    d.merge_op(&op);
    d.merge_op(&op);
    assert_eq!(d.checkpoint(), once);
}

// --- convergence property -----------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Action {
    replica: usize,
    intent: OpIntent,
}

fn value_strat() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::I64),
    ]
}

fn intent_strat() -> impl Strategy<Value = OpIntent> {
    // A small fixed pool of cells/elements so concurrent ops COLLIDE on the same target — otherwise
    // the interesting merge paths are almost never exercised.
    prop_oneof![
        (0u8..3, value_strat()).prop_map(|(c, v)| OpIntent::SetRegister { cell: cell(c), value: v }),
        (0u8..3, 0u8..3, value_strat()).prop_map(|(c, e, v)| OpIntent::AddElement { cell: cell(c), elem: elem(e), value: v }),
        (0u8..3, 0u8..3).prop_map(|(c, e)| OpIntent::RemoveElement { cell: cell(c), elem: elem(e) }),
    ]
}

fn action_strat(n: usize) -> impl Strategy<Value = Action> {
    (0..n, intent_strat()).prop_map(|(replica, intent)| Action { replica, intent })
}

/// Deterministic xorshift Fisher-Yates — no `rand`/wall-clock dependency; the whole point of the
/// kernel is that outcomes never depend on nondeterministic ordering.
fn shuffle(v: &mut [usize], seed: u64) {
    let mut s = seed | 1;
    for i in (1..v.len()).rev() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let j = (s % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

proptest! {
    #[test]
    fn replicas_converge_under_any_delivery_order(
        n_replicas in 2usize..=4,
        actions in prop::collection::vec(action_strat(4), 0..80),
        perm_seed in any::<u64>(),
    ) {
        let n = n_replicas;

        // Each action is applied LOCALLY on its origin replica (which stamps it). The origin's clock
        // only advances on its own ops here — modelling genuinely concurrent, offline edits.
        let mut authors: Vec<Doc> = (0..n).map(|i| Doc::new(rid(i as u8))).collect();
        let mut ops: Vec<Op> = Vec::new();
        for a in &actions {
            let r = a.replica % n;
            ops.push(authors[r].apply_local(a.intent.clone()));
        }

        // Reference: one replica hears every op in generation order.
        let reference = {
            let mut d = Doc::new(rid(0));
            for op in &ops { d.merge_op(op); }
            d.checkpoint()
        };

        // Every replica, hearing the full op multiset in a permuted order — and again (idempotence)
        // — must reach the identical checkpoint.
        for r in 0..n {
            let mut d = Doc::new(rid(r as u8));
            let mut order: Vec<usize> = (0..ops.len()).collect();
            shuffle(&mut order, perm_seed ^ (r as u64));
            for &i in &order { d.merge_op(&ops[i]); }
            for &i in &order { d.merge_op(&ops[i]); }
            prop_assert_eq!(d.checkpoint(), reference.clone());
        }
    }
}
