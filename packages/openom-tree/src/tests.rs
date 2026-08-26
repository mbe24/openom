use super::Tree;
use openom_crdt::codec;
use serde_json::{json, Value};

const DID: &str = "did:key:z6MkA";
const PERSON: &str = "openom.org/core/person/v1";
const NAME: &str = "openom.org/core/name/v1";
const SAME_AS: &str = "openom.org/core/same_as/v1";

fn name_value(given: &str) -> Value {
    json!({ "parts": { "given": given } })
}

/// The content id of the single item a mint returned — for targeting a later remove/supersede/revoke.
fn only_id(batch: &[u8]) -> String {
    codec::decode(batch).unwrap()[0].id().to_owned()
}

#[test]
fn two_engines_converge_over_the_same_ops() {
    let mut a = Tree::new(DID);
    let pa = a.assert_anchor("pA", PERSON, 1).unwrap();
    let na = a.assert_claim("pA", NAME, name_value("Ada"), 1).unwrap();

    let mut b = Tree::new("did:key:z6MkB"); // a different replica...
    b.merge(&pa).unwrap();
    b.merge(&na).unwrap(); // ...that has seen the same ops

    assert_eq!(a.project(), b.project(), "same op set → same read model");
    assert_eq!(a.project().people.len(), 1);
    assert_eq!(a.project().people[0].id, "pA");
    assert_eq!(a.project().people[0].names.len(), 1);
}

#[test]
fn a_same_author_remove_drops_the_claim() {
    let mut a = Tree::new(DID);
    a.assert_anchor("pA", PERSON, 1).unwrap();
    let na = a.assert_claim("pA", NAME, name_value("Ada"), 1).unwrap();
    assert_eq!(a.project().people[0].names.len(), 1);

    a.remove(&only_id(&na), 2).unwrap();
    assert!(
        a.project().people[0].names.is_empty(),
        "the removed name is folded out"
    );
}

#[test]
fn supersede_replaces_a_claim() {
    let mut a = Tree::new(DID);
    a.assert_anchor("pA", PERSON, 1).unwrap();
    let na = a.assert_claim("pA", NAME, name_value("Ada"), 1).unwrap();
    a.supersede_claim(&only_id(&na), "pA", NAME, name_value("Ada Lovelace"), 2)
        .unwrap();

    // Exactly one name survives — the prior folded out, the replacement is in (not 0, not 2).
    assert_eq!(a.project().people[0].names.len(), 1);
}

#[test]
fn revoke_restores_a_removed_claim() {
    let mut a = Tree::new(DID);
    a.assert_anchor("pA", PERSON, 1).unwrap();
    let na = a.assert_claim("pA", NAME, name_value("Ada"), 1).unwrap();
    let rm = a.remove(&only_id(&na), 2).unwrap();
    assert!(a.project().people[0].names.is_empty());

    a.revoke(&only_id(&rm), 3).unwrap();
    assert_eq!(
        a.project().people[0].names.len(),
        1,
        "the revoke restored the removed name"
    );
}

#[test]
fn snapshot_load_roundtrips() {
    let mut a = Tree::new(DID);
    a.assert_anchor("pA", PERSON, 1).unwrap();
    a.assert_claim("pA", NAME, name_value("Ada"), 1).unwrap();
    let snap = a.snapshot().unwrap();

    let mut b = Tree::new(DID);
    b.load_snapshot(&snap).unwrap();
    assert_eq!(a.project(), b.project());
}

#[test]
fn resolve_id_returns_the_canonical_person() {
    let mut a = Tree::new(DID);
    a.assert_anchor("pB", PERSON, 1).unwrap();
    a.assert_anchor("pA", PERSON, 1).unwrap();
    a.assert_claim("pA", SAME_AS, json!({ "pair": ["pA", "pB"] }), 1)
        .unwrap();

    // pA + pB merge into one person; canonical id = the minimum anchor id ("pA").
    assert_eq!(a.resolve_id("pB").as_deref(), Some("pA"));
    assert_eq!(a.resolve_id("pA").as_deref(), Some("pA"));
    assert_eq!(a.resolve_id("nope"), None);
}

#[test]
fn live_claims_of_returns_matching_records() {
    let mut a = Tree::new(DID);
    a.assert_anchor("pA", PERSON, 1).unwrap();
    a.assert_claim("pA", NAME, name_value("Ada"), 1).unwrap();
    a.assert_claim("pA", "openom.org/core/sex/v1", json!({ "sex": "F" }), 1)
        .unwrap();

    let names = a.live_claims_of("pA", NAME);
    assert_eq!(names.len(), 1);
    assert_eq!(names[0]["value"], name_value("Ada"));
    assert!(a.live_claims_of("pA", "openom.org/core/date/v1").is_empty());
}
