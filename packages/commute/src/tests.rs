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

        // Byte-level convergence: a fresh replica rebuilt from any replica's snapshot must produce
        // byte-identical snapshots — the canonical-encoding guarantee.
        let mut ref_doc = Doc::new(rid(0));
        for op in &ops { ref_doc.merge_op(op); }
        let snap = ref_doc.snapshot();
        let rebuilt = Doc::from_snapshot(rid(9), &snap).unwrap();
        prop_assert_eq!(rebuilt.snapshot(), snap);
    }
}

// --- codec + sync ------------------------------------------------------------------------------

#[test]
fn snapshot_round_trips() {
    let mut a = Doc::new(rid(1));
    a.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::Text("hi".into()) });
    a.apply_local(OpIntent::AddElement { cell: cell(1), elem: elem(0), value: Value::I64(5) });
    a.apply_local(OpIntent::RemoveElement { cell: cell(1), elem: elem(0) });
    let snap = a.snapshot();
    let b = Doc::from_snapshot(rid(2), &snap).unwrap();
    assert_eq!(a.checkpoint(), b.checkpoint());
    assert_eq!(a.snapshot(), b.snapshot());
}

#[test]
fn delta_since_ships_only_the_missing_ops() {
    let mut a = Doc::new(rid(1));
    let mut b = Doc::new(rid(2));
    // b catches up to a's first edit, then a makes a second — the delta carries only the second.
    let first = a.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::I64(1) });
    b.merge_op(&first);
    a.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::I64(2) });
    let delta_ops = codec::decode_ops(&a.delta_since(&b.version())).unwrap();
    assert_eq!(delta_ops.len(), 1, "only the op b hasn't seen");
    b.merge_bytes(&a.delta_since(&b.version())).unwrap();
    assert_eq!(a.checkpoint(), b.checkpoint());
}

#[test]
fn merge_bytes_on_junk_is_a_clean_error_not_a_panic() {
    let mut d = Doc::new(rid(1));
    assert!(d.merge_bytes(&[]).is_err());
    assert!(d.merge_bytes(&[9, 9, 9]).is_err()); // bad layout byte
    assert!(matches!(d.merge_bytes(&[0]), Err(DecodeError::BadLayout)));
}

#[test]
fn merge_bytes_error_leaves_the_document_unchanged() {
    // Transactional decode: a corrupt buffer applies nothing (decode fails before any integrate).
    let mut d = Doc::new(rid(1));
    d.apply_local(OpIntent::SetRegister { cell: cell(0), value: Value::I64(1) });
    let before = d.checkpoint();
    assert!(d.merge_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 5 /* count=5, but no ops follow */]).is_err());
    assert_eq!(d.checkpoint(), before, "a failed merge must not partially apply");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn snapshot_bytes_are_a_stable_golden_vector() {
    // Locks the canonical encoding: a change to the on-wire format (the sealed archive) breaks this
    // deliberately. Fixed replica + fixed ops ⇒ fixed bytes, forever (until a layout-version bump).
    let r = rid(7);
    let mut d = Doc::new(r);
    d.apply_local(OpIntent::SetRegister { cell: vec![1], value: Value::Text("Jon".into()) });
    d.apply_local(OpIntent::AddElement { cell: vec![2], elem: vec![9], value: Value::I64(-5) });
    let got = hex(&d.snapshot());
    let expected = "01000000000000000200000000000000010700000000000000000000000000000000\
0000000000000001010500000000000000034a6f6e00000000000000020700000000000000000000000000000001\
00000000000000010200000000000000010902fffffffffffffffb";
    assert_eq!(got, expected, "canonical snapshot encoding changed — bump LAYOUT_VERSION + migrate");
}

proptest! {
    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        // The untrusted-input boundary: any bytes decode to Ok or a typed Err, never a panic/OOM.
        let _ = codec::decode_ops(&bytes);
    }

    #[test]
    fn encode_decode_round_trips(
        actions in prop::collection::vec(action_strat(3), 0..40),
    ) {
        let mut d = Doc::new(rid(1));
        for a in &actions { d.apply_local(a.intent.clone()); }
        let bytes = d.snapshot();
        let ops = codec::decode_ops(&bytes).unwrap();
        // Re-encoding the decoded ops is a byte-for-byte fixpoint (canonical form is stable).
        prop_assert_eq!(codec::encode_ops(&ops), bytes);
    }

    // A nastier value alphabet — the edges where an encoder/decoder tends to break.
    #[test]
    fn round_trips_edge_case_values(
        texts in prop::collection::vec("\\PC*", 0..4),
        ints in prop::collection::vec(prop_oneof![Just(i64::MIN), Just(i64::MAX), Just(0i64), any::<i64>()], 0..4),
    ) {
        let mut d = Doc::new(rid(1));
        for (i, t) in texts.iter().enumerate() {
            d.apply_local(OpIntent::SetRegister { cell: vec![i as u8], value: Value::Text(t.clone()) });
        }
        for (i, n) in ints.iter().enumerate() {
            d.apply_local(OpIntent::AddElement { cell: vec![100 + i as u8], elem: vec![0], value: Value::I64(*n) });
        }
        // Boundary scalars too.
        d.apply_local(OpIntent::SetRegister { cell: vec![200], value: Value::U64(u64::MAX) });
        d.apply_local(OpIntent::SetRegister { cell: vec![201], value: Value::Bytes(vec![]) });

        let bytes = d.snapshot();
        let rebuilt = Doc::from_snapshot(rid(2), &bytes).unwrap();
        prop_assert_eq!(rebuilt.snapshot(), bytes);
        prop_assert_eq!(rebuilt.checkpoint(), d.checkpoint());
    }
}
