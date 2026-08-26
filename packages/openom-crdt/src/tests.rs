use std::collections::BTreeSet;

use openom_claim::envelope::{Claim, Record};
use proptest::prelude::*;
use serde_json::json;

use super::*;

fn did(n: u8) -> String {
    format!("did:key:z6Mk{n}")
}

fn anchor(id: &str, author: &str) -> Record {
    Record::try_from(json!({
        "id": id,
        "type": "openom.org/core/person/v1",
        "createdAt": 1,
        "createdBy": author,
    }))
    .unwrap()
}

fn name_claim(target: &str, given: &str, author: &str, at: i64) -> Record {
    let mut c = Claim::new(
        target,
        "openom.org/core/name/v1",
        json!({ "given": given }),
        author,
        at,
    );
    c.compute_id().unwrap();
    Record::Claim(c)
}

fn remove(target: &Record, author: &str) -> Op {
    Op::new(
        2,
        author,
        OpKind::Remove {
            target: target.id().to_owned(),
        },
    )
    .unwrap()
}

fn supersede(prior: &Record, replacement: Record, author: &str) -> Op {
    Op::new(
        2,
        author,
        OpKind::Supersede {
            prior: prior.id().to_owned(),
            replacement: Box::new(replacement),
        },
    )
    .unwrap()
}

fn revoke(remove_op: &Op, author: &str) -> Op {
    Op::new(
        3,
        author,
        OpKind::Revoke {
            removal: remove_op.id.clone(),
        },
    )
    .unwrap()
}

fn live(items: &[ChannelItem]) -> BTreeSet<String> {
    materialize(items)
        .into_iter()
        .map(|r| r.id().to_owned())
        .collect()
}

fn ids<const N: usize>(records: [&Record; N]) -> BTreeSet<String> {
    records.iter().map(|r| r.id().to_owned()).collect()
}

#[test]
fn asserts_materialize_as_live_records() {
    let a = anchor("pA", &did(1));
    let n = name_claim("pA", "Ada", &did(1), 1);
    let items = vec![
        ChannelItem::Assert(a.clone()),
        ChannelItem::Assert(n.clone()),
    ];
    assert_eq!(live(&items), ids([&a, &n]));
}

#[test]
fn same_author_remove_drops_the_record() {
    let n = name_claim("pA", "Ada", &did(1), 1);
    let items = vec![
        ChannelItem::Assert(n.clone()),
        ChannelItem::Op(remove(&n, &did(1))),
    ];
    assert!(materialize(&items).is_empty());
}

#[test]
fn other_author_remove_is_a_noop() {
    // Censorship resistance: you cannot delete a record you did not author.
    let n = name_claim("pA", "Ada", &did(1), 1);
    let items = vec![
        ChannelItem::Assert(n.clone()),
        ChannelItem::Op(remove(&n, &did(2))),
    ];
    assert_eq!(live(&items), ids([&n]));
}

#[test]
fn remove_of_an_unknown_target_is_a_noop() {
    let n = name_claim("pA", "Ada", &did(1), 1);
    let orphan = Op::new(
        2,
        did(1),
        OpKind::Remove {
            target: "sha256:does-not-exist".to_owned(),
        },
    )
    .unwrap();
    let items = vec![ChannelItem::Assert(n.clone()), ChannelItem::Op(orphan)];
    assert_eq!(live(&items), ids([&n]));
}

#[test]
fn same_author_supersede_replaces_the_record() {
    let old = name_claim("pA", "Ada", &did(1), 1);
    let new = name_claim("pA", "Ada Lovelace", &did(1), 2);
    let items = vec![
        ChannelItem::Assert(old.clone()),
        ChannelItem::Op(supersede(&old, new.clone(), &did(1))),
    ];
    assert_eq!(live(&items), ids([&new]));
}

#[test]
fn other_author_supersede_neither_removes_nor_injects() {
    // did(2) cannot remove did(1)'s prior; and a replacement authored by did(2) but attributed to
    // did(1) is a forgery, so it is dropped rather than injected as a fake corroboration.
    let old = name_claim("pA", "Ada", &did(1), 1);
    let forged = name_claim("pA", "Mallory", &did(1), 2); // attributed to did(1)...
    let items = vec![
        ChannelItem::Assert(old.clone()),
        ChannelItem::Op(supersede(&old, forged.clone(), &did(2))), // ...but written by did(2)
    ];
    assert_eq!(live(&items), ids([&old])); // prior survives, forged replacement dropped
}

#[test]
fn supersede_chain_keeps_only_the_last() {
    let a = name_claim("pA", "A", &did(1), 1);
    let b = name_claim("pA", "B", &did(1), 2);
    let c = name_claim("pA", "C", &did(1), 3);
    let items = vec![
        ChannelItem::Assert(a.clone()),
        ChannelItem::Op(supersede(&a, b.clone(), &did(1))),
        ChannelItem::Op(supersede(&b, c.clone(), &did(1))),
    ];
    assert_eq!(live(&items), ids([&c]));
}

#[test]
fn concurrent_supersede_of_one_prior_forks_into_two_live() {
    // Two devices, same author, edit the same record concurrently. Set-union keeps both replacements
    // (the prior dies once) — a documented, deterministic fork the UI can offer to collapse. Not LWW.
    let old = name_claim("pA", "Ada", &did(1), 1);
    let ondevice_a = name_claim("pA", "Ada L.", &did(1), 2);
    let ondevice_b = name_claim("pA", "Ada Lovelace", &did(1), 3);
    let items = vec![
        ChannelItem::Assert(old.clone()),
        ChannelItem::Op(supersede(&old, ondevice_a.clone(), &did(1))),
        ChannelItem::Op(supersede(&old, ondevice_b.clone(), &did(1))),
    ];
    assert_eq!(live(&items), ids([&ondevice_a, &ondevice_b]));
}

#[test]
fn same_author_revoke_restores_a_removed_record() {
    let n = name_claim("pA", "Ada", &did(1), 1);
    let r = remove(&n, &did(1));
    let items = vec![
        ChannelItem::Assert(n.clone()),
        ChannelItem::Op(r.clone()),
        ChannelItem::Op(revoke(&r, &did(1))),
    ];
    // Non-monotone liveness (dead → live again), still order-independent, and the *original* id is
    // restored — so anything bound to it survives the undo.
    assert_eq!(live(&items), ids([&n]));
}

#[test]
fn other_author_revoke_does_not_restore() {
    let n = name_claim("pA", "Ada", &did(1), 1);
    let r = remove(&n, &did(1));
    let items = vec![
        ChannelItem::Assert(n.clone()),
        ChannelItem::Op(r.clone()),
        ChannelItem::Op(revoke(&r, &did(2))), // not the remove's author
    ];
    assert!(materialize(&items).is_empty());
}

#[test]
fn revoke_of_an_unknown_or_non_remove_op_is_ignored() {
    let n = name_claim("pA", "Ada", &did(1), 1);
    let stray = Op::new(
        3,
        did(1),
        OpKind::Revoke {
            removal: "sha256:not-a-real-op".to_owned(),
        },
    )
    .unwrap();
    let items = vec![ChannelItem::Assert(n.clone()), ChannelItem::Op(stray)];
    assert_eq!(live(&items), ids([&n]));
}

#[test]
fn duplicate_items_are_idempotent() {
    let n = name_claim("pA", "Ada", &did(1), 1);
    let once = vec![ChannelItem::Assert(n.clone())];
    let twice = vec![
        ChannelItem::Assert(n.clone()),
        ChannelItem::Assert(n.clone()),
    ];
    assert_eq!(materialize(&once), materialize(&twice));
}

// --- content addressing & ingest -------------------------------------------------------------

#[test]
fn op_id_is_stable_when_the_embedded_replacement_is_signed() {
    // Signing the replacement record must not shift the enclosing op id (the embedded signature is
    // excluded from the op hash). Mirrors openom-claim's attaching-the-signature-does-not-change-id.
    let old = name_claim("pA", "Ada", &did(1), 1);
    let replacement = name_claim("pA", "Ada Lovelace", &did(1), 2);
    let unsigned = supersede(&old, replacement.clone(), &did(1));

    // Same op, but the embedded replacement now carries a signature field.
    let mut signed_value = serde_json::to_value(&replacement).unwrap();
    signed_value["signature"] = json!("sig-placeholder");
    let signed_replacement: Record = serde_json::from_value(signed_value).unwrap();
    let signed = Op::new(
        2,
        did(1),
        OpKind::Supersede {
            prior: old.id().to_owned(),
            replacement: Box::new(signed_replacement),
        },
    )
    .unwrap();

    assert_eq!(unsigned.id, signed.id);
}

#[test]
fn op_roundtrips_through_serde_and_verifies_its_id() {
    let old = name_claim("pA", "Ada", &did(1), 1);
    let new = name_claim("pA", "Ada Lovelace", &did(1), 2);
    for op in [
        remove(&old, &did(1)),
        supersede(&old, new.clone(), &did(1)),
        revoke(&remove(&old, &did(1)), &did(1)),
    ] {
        let item = ChannelItem::Op(op.clone());
        let back: ChannelItem =
            serde_json::from_value(serde_json::to_value(&item).unwrap()).unwrap();
        assert_eq!(back, item);
    }
}

#[test]
fn a_tampered_op_id_fails_ingest() {
    let old = name_claim("pA", "Ada", &did(1), 1);
    let mut v = serde_json::to_value(remove(&old, &did(1))).unwrap();
    v["createdBy"] = json!(did(2)); // content changed, stated id now stale
    assert!(matches!(Op::try_from(v), Err(CrdtError::IdMismatch)));
}

#[test]
fn an_op_with_a_forged_embedded_replacement_id_fails_ingest() {
    let old = name_claim("pA", "Ada", &did(1), 1);
    let new = name_claim("pA", "Ada Lovelace", &did(1), 2);
    let mut v = serde_json::to_value(supersede(&old, new, &did(1))).unwrap();
    v["replacement"]["value"] = json!({ "given": "Mallory" }); // embedded record's id now stale
                                                               // The embedded Record's verifying Deserialize rejects it while parsing the op.
    assert!(Op::try_from(v).is_err());
}

#[test]
fn channel_item_dispatches_on_type() {
    let claim = name_claim("pA", "Ada", &did(1), 1);
    let op = remove(&claim, &did(1));

    let as_assert: ChannelItem =
        serde_json::from_value(serde_json::to_value(&claim).unwrap()).unwrap();
    assert!(matches!(as_assert, ChannelItem::Assert(_)));

    let as_op: ChannelItem = serde_json::from_value(serde_json::to_value(&op).unwrap()).unwrap();
    assert!(matches!(as_op, ChannelItem::Op(_)));
}

// --- convergence -----------------------------------------------------------------------------

/// A representative channel: asserts, a remove, a superseded chain, a fork, and a revoke.
fn scenario() -> Vec<ChannelItem> {
    let keep = name_claim("pA", "keep", &did(1), 1);
    let deleted = name_claim("pA", "deleted", &did(1), 1);
    let del = remove(&deleted, &did(1));
    let base = name_claim("pB", "base", &did(2), 1);
    let edit = name_claim("pB", "edited", &did(2), 2);
    let undeleted = name_claim("pB", "undeleted", &did(2), 1);
    let undel = remove(&undeleted, &did(2));
    vec![
        ChannelItem::Assert(keep),
        ChannelItem::Assert(deleted),
        ChannelItem::Op(del),
        ChannelItem::Assert(base.clone()),
        ChannelItem::Op(supersede(&base, edit, &did(2))),
        ChannelItem::Assert(undeleted),
        ChannelItem::Op(undel.clone()),
        ChannelItem::Op(revoke(&undel, &did(2))),
    ]
}

proptest! {
    /// The fold depends only on the *set* of items — not their delivery order. This is the
    /// convergence guarantee: replicas that have seen the same operations agree without a shared clock.
    #[test]
    fn materialize_is_order_independent(shuffled in Just(scenario()).prop_shuffle()) {
        prop_assert_eq!(materialize(&shuffled), materialize(&scenario()));
    }
}
