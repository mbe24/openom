use super::*;
use proptest::prelude::*;
use serde_json::json;

fn person(id: &str) -> Value {
    json!({ "id": id, "type": TYPE_PERSON, "createdAt": 1, "createdBy": "did:key:z6MkA" })
}
fn claim(id: &str, pred: &str, target: &str, value: Value, author: &str) -> Value {
    json!({ "id": id, "type": "openom.org/core/claim/v1", "targetId": target,
            "predicate": pred, "value": value, "createdAt": 1, "createdBy": author })
}
fn same_as(id: &str, a: &str, b: &str, author: &str) -> Value {
    let [x, y] = sorted_pair(a, b);
    claim(id, P_SAME_AS, &x, json!({ "pair": [x, y] }), author)
}
fn different_from(id: &str, a: &str, b: &str, author: &str) -> Value {
    let [x, y] = sorted_pair(a, b);
    claim(id, P_DIFFERENT_FROM, &x, json!({ "pair": [x, y] }), author)
}
fn name(id: &str, target: &str, given: &str) -> Value {
    claim(
        id,
        P_NAME,
        target,
        json!({ "parts": { "given": given } }),
        "did:key:z6MkA",
    )
}
fn sex(id: &str, target: &str, s: &str, author: &str) -> Value {
    claim(id, P_SEX, target, json!({ "sex": s }), author)
}
fn tombstone(id: &str, target: &str) -> Value {
    claim(id, P_TOMBSTONE, target, json!({}), "did:key:z6MkA")
}

#[test]
fn merges_two_anchors_by_same_as() {
    let recs = vec![
        person("pB"),
        person("pA"),
        name("n1", "pA", "Ada"),
        name("n2", "pB", "Augusta"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people.len(), 1);
    assert_eq!(p.people[0].id, "pA"); // canonical = min anchor id
    assert_eq!(p.people[0].also, vec!["pB".to_string()]);
    assert_eq!(p.people[0].names.len(), 2); // both names retargeted to the one person
    assert!(p.conflicts.is_empty());
}

#[test]
fn different_from_cuts_the_merge() {
    let recs = vec![
        person("pA"),
        person("pB"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        different_from("d1", "pA", "pB", "did:key:z6MkB"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people.len(), 2);
    assert_eq!(
        p.conflicts,
        vec![Conflict {
            cut_pair: ["pA".into(), "pB".into()]
        }]
    );
}

#[test]
fn different_from_cuts_transitively() {
    let recs = vec![
        person("pA"),
        person("pB"),
        person("pC"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        same_as("s2", "pB", "pC", "did:key:z6MkA"),
        different_from("d1", "pA", "pC", "did:key:z6MkB"),
    ];
    let p = project(&recs, &Policy::default());
    // A+B merge; the B-C edge is skipped because it would place A and C together.
    let ids: Vec<_> = p.people.iter().map(|x| x.id.clone()).collect();
    assert_eq!(ids, vec!["pA".to_string(), "pC".to_string()]);
    assert_eq!(p.people[0].also, vec!["pB".to_string()]);
}

#[test]
fn tombstone_suppresses_a_name() {
    let recs = vec![
        person("pA"),
        name("n1", "pA", "Ada"),
        name("n2", "pA", "Typo"),
        tombstone("t1", "n2"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people[0].names.len(), 1);
    assert_eq!(p.people[0].names[0].claim_id, "n1");
}

#[test]
fn sex_resolves_by_author_majority() {
    let recs = vec![
        person("pA"),
        sex("x1", "pA", "female", "did:key:z6MkA"),
        sex("x2", "pA", "male", "did:key:z6MkB"),
        sex("x3", "pA", "male", "did:key:z6MkC"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people[0].sex.as_deref(), Some("male")); // 2 distinct authors vs 1
}

// ---- properties --------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Spec {
    Person(String),
    SameAs(String, String),
    Different(String, String),
    Name(String, String),
    Sex(String, String),
}

fn pid() -> impl Strategy<Value = String> {
    (0u8..6).prop_map(|i| format!("p{i}"))
}
fn sexval() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("male".into()),
        Just("female".into()),
        Just("unknown".into())
    ]
}
fn spec() -> impl Strategy<Value = Spec> {
    prop_oneof![
        pid().prop_map(Spec::Person),
        (pid(), pid()).prop_map(|(a, b)| Spec::SameAs(a, b)),
        (pid(), pid()).prop_map(|(a, b)| Spec::Different(a, b)),
        (pid(), "[a-z]{1,4}").prop_map(|(t, g)| Spec::Name(t, g)),
        (pid(), sexval()).prop_map(|(t, s)| Spec::Sex(t, s)),
    ]
}
// Stable id per record from its ORIGINAL index, so ids don't shift when the records are reordered.
fn into_record(spec: &Spec, i: usize) -> Value {
    let cid = format!("c{i}");
    match spec {
        Spec::Person(id) => person(id),
        Spec::SameAs(a, b) => same_as(&cid, a, b, "did:key:z6MkA"),
        Spec::Different(a, b) => different_from(&cid, a, b, "did:key:z6MkB"),
        Spec::Name(t, g) => name(&cid, t, g),
        Spec::Sex(t, s) => sex(&cid, t, s, "did:key:z6MkA"),
    }
}

proptest! {
    // Delivery order does not change the projection — the convergence guarantee.
    #[test]
    fn order_independent(specs in prop::collection::vec((spec(), any::<u64>()), 0..24)) {
        let records: Vec<Value> = specs.iter().enumerate().map(|(i, (s, _))| into_record(s, i)).collect();
        let a = project(&records, &Policy::default());

        // Reorder by the generated keys; the baked-in ids stay put.
        let mut indexed: Vec<(u64, Value)> =
            specs.iter().map(|(_, k)| *k).zip(records.iter().cloned()).collect();
        indexed.sort_by_key(|(k, _)| *k);
        let shuffled: Vec<Value> = indexed.into_iter().map(|(_, v)| v).collect();

        prop_assert_eq!(a, project(&shuffled, &Policy::default()));
    }

    // No asserted different_from ever ends with both anchors in one person.
    #[test]
    fn different_from_never_violated(specs in prop::collection::vec((spec(), any::<u64>()), 0..24)) {
        let records: Vec<Value> = specs.iter().enumerate().map(|(i, (s, _))| into_record(s, i)).collect();
        let proj = project(&records, &Policy::default());

        let mut person_of: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for (idx, p) in proj.people.iter().enumerate() {
            person_of.insert(p.id.clone(), idx);
            for a in &p.also {
                person_of.insert(a.clone(), idx);
            }
        }
        for (s, _) in &specs {
            if let Spec::Different(a, b) = s {
                if a != b {
                    if let (Some(ia), Some(ib)) = (person_of.get(a), person_of.get(b)) {
                        prop_assert_ne!(ia, ib, "different_from {}/{} ended up merged", a, b);
                    }
                }
            }
        }
    }
}
