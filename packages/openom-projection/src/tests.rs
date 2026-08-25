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
fn attest(id: &str, target: &str, verdict: &str, author: &str) -> Value {
    claim(id, P_ATTEST, target, json!({ "verdict": verdict }), author)
}
fn reattribute(id: &str, claim_target: &str, person: &str, author: &str) -> Value {
    claim(
        id,
        P_REATTRIBUTE,
        claim_target,
        json!({ "personId": person }),
        author,
    )
}
fn preferred(id: &str, person: &str, for_pred: &str, claim_ref: &str, author: &str) -> Value {
    claim(
        id,
        P_PREFERRED,
        person,
        json!({ "for": for_pred, "claimId": claim_ref }),
        author,
    )
}
// The content-ref of a name whose only intrinsic is its given part — matches the projection's name_ref.
fn given_ref(given: &str) -> String {
    openom_claim::content_ref(&json!({ "parts": { "given": given } })).unwrap()
}
fn parent(id: &str, child: &str, parent_person: &str, kind: &str, author: &str) -> Value {
    claim(
        id,
        P_PARENT,
        child,
        json!({ "parentPersonId": parent_person, "kind": kind }),
        author,
    )
}
fn partnership(id: &str, a: &str, b: &str, role: &str, author: &str) -> Value {
    let [x, y] = sorted_pair(a, b);
    claim(
        id,
        P_PARTNERSHIP,
        &x,
        json!({ "pair": [x, y], "role": role }),
        author,
    )
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

#[test]
fn reject_attestations_unmerge() {
    let recs = vec![
        person("pA"),
        person("pB"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        attest("a1", "s1", "reject", "did:key:z6MkB"),
        attest("a2", "s1", "reject", "did:key:z6MkC"),
    ];
    // score = 1 author + 0 support - 2 rejects = -1 < threshold 1 → not merged.
    assert_eq!(project(&recs, &Policy::default()).people.len(), 2);
}

#[test]
fn support_attestations_boost_confidence() {
    let sa = vec![
        person("pA"),
        person("pB"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        attest("a1", "s1", "support", "did:key:z6MkB"),
        attest("a2", "s1", "support", "did:key:z6MkC"),
    ];
    let strict = Policy {
        same_as_threshold: 3,
        ..Policy::default()
    };
    // 1 author + 2 independent support = 3 → merges even under a strict threshold…
    assert_eq!(project(&sa, &strict).people.len(), 1);
    // …whereas the bare same_as (score 1) would not.
    let bare = vec![
        person("pA"),
        person("pB"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
    ];
    assert_eq!(project(&bare, &strict).people.len(), 2);
}

#[test]
fn self_support_is_inadmissible() {
    let recs = vec![
        person("pA"),
        person("pB"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        attest("a1", "s1", "support", "did:key:z6MkA"), // same author as the claim → self-grading
    ];
    // score = 1 author + 0 independent support = 1; threshold 2 → not merged.
    let strict = Policy {
        same_as_threshold: 2,
        ..Policy::default()
    };
    assert_eq!(project(&recs, &strict).people.len(), 2);
}

#[test]
fn refuted_different_from_does_not_cut() {
    let recs = vec![
        person("pA"),
        person("pB"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        different_from("d1", "pA", "pB", "did:key:z6MkB"),
        attest("r1", "d1", "reject", "did:key:z6MkC"),
        attest("r2", "d1", "reject", "did:key:z6MkD"),
    ];
    // different_from score = 1 - 2 = -1 < threshold 1 → not a cut → the same_as merges.
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people.len(), 1);
    assert!(p.conflicts.is_empty());
}

#[test]
fn attestation_by_fingerprint_counts() {
    let sa = same_as("s1", "pA", "pB", "did:key:z6MkA");
    let fp = format!(
        "sha256:{}",
        openom_jcs::hex(&openom_claim::fingerprint(&sa).unwrap())
    );
    let recs = vec![
        person("pA"),
        person("pB"),
        sa.clone(),
        attest("r1", &fp, "reject", "did:key:z6MkB"),
        attest("r2", &fp, "reject", "did:key:z6MkC"),
    ];
    // Rejects targeting the fact fingerprint (not the claim id) still count → score -1 → not merged.
    assert_eq!(project(&recs, &Policy::default()).people.len(), 2);
}

#[test]
fn reattribute_rehomes_a_name_and_sex() {
    let recs = vec![
        person("pA"),
        person("pB"),
        name("n1", "pA", "Ada"),
        sex("x1", "pA", "female", "did:key:z6MkA"),
        reattribute("re1", "n1", "pB", "did:key:z6MkB"),
        reattribute("re2", "x1", "pB", "did:key:z6MkB"),
    ];
    let p = project(&recs, &Policy::default());
    let pa = p.people.iter().find(|x| x.id == "pA").unwrap();
    let pb = p.people.iter().find(|x| x.id == "pB").unwrap();
    assert!(pa.names.is_empty() && pa.sex.is_none()); // re-homed away
    assert_eq!(pb.names.len(), 1);
    assert_eq!(pb.sex.as_deref(), Some("female"));
}

#[test]
fn refuted_reattribute_does_not_apply() {
    let recs = vec![
        person("pA"),
        person("pB"),
        name("n1", "pA", "Ada"),
        reattribute("re1", "n1", "pB", "did:key:z6MkB"),
        attest("y1", "re1", "reject", "did:key:z6MkC"),
        attest("y2", "re1", "reject", "did:key:z6MkD"),
    ];
    // reattribute score = 1 - 2 = -1 < threshold → the name stays on pA.
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.people.iter().find(|x| x.id == "pA").unwrap().names.len(),
        1
    );
}

#[test]
fn competing_reattribute_resolves_by_score() {
    let recs = vec![
        person("pA"),
        person("pB"),
        person("pC"),
        name("n1", "pA", "Ada"),
        reattribute("re1", "n1", "pB", "did:key:z6MkB"),
        reattribute("re2", "n1", "pC", "did:key:z6MkC"),
        reattribute("re3", "n1", "pC", "did:key:z6MkD"), // pC: 2 authors → higher score
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.people.iter().find(|x| x.id == "pC").unwrap().names.len(),
        1
    );
    assert!(p
        .people
        .iter()
        .find(|x| x.id == "pB")
        .unwrap()
        .names
        .is_empty());
}

#[test]
fn preferred_selects_a_name() {
    let recs = vec![
        person("pA"),
        name("n1", "pA", "Ada"),
        name("n2", "pA", "Augusta"),
        preferred("pf1", "pA", P_NAME, &given_ref("Augusta"), "did:key:z6MkB"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people[0].preferred_name.as_deref(), Some("n2"));
}

#[test]
fn preferred_resolves_to_the_canonical_person_after_a_merge() {
    // The name is on pB; the preferred is asserted against pA; a same_as merges them.
    let recs = vec![
        person("pA"),
        person("pB"),
        name("n1", "pB", "Augusta"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
        preferred("pf1", "pA", P_NAME, &given_ref("Augusta"), "did:key:z6MkB"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people[0].id, "pA");
    assert_eq!(p.people[0].preferred_name.as_deref(), Some("n1"));
}

#[test]
fn preferred_ignored_when_absent_or_refuted() {
    // Points at a name the person doesn't have → no selection.
    let recs = vec![
        person("pA"),
        name("n1", "pA", "Ada"),
        preferred("pf1", "pA", P_NAME, &given_ref("Nobody"), "did:key:z6MkB"),
    ];
    assert_eq!(
        project(&recs, &Policy::default()).people[0].preferred_name,
        None
    );

    // Refuted below threshold → no selection.
    let recs2 = vec![
        person("pA"),
        name("n1", "pA", "Ada"),
        preferred("pf1", "pA", P_NAME, &given_ref("Ada"), "did:key:z6MkB"),
        attest("z1", "pf1", "reject", "did:key:z6MkC"),
        attest("z2", "pf1", "reject", "did:key:z6MkD"),
    ];
    assert_eq!(
        project(&recs2, &Policy::default()).people[0].preferred_name,
        None
    );
}

#[test]
fn equivalent_names_share_a_class() {
    // n2 (a different rendering) points at n1's content-ref via equivalent_to; n3 is unrelated.
    let n2 = claim(
        "n2",
        P_NAME,
        "pA",
        json!({ "parts": { "given": "Ada-cyr" }, "equivalent_to": [given_ref("Ada")] }),
        "did:key:z6MkA",
    );
    let recs = vec![
        person("pA"),
        name("n1", "pA", "Ada"),
        n2,
        name("n3", "pA", "Zed"),
    ];
    let p = project(&recs, &Policy::default());
    let names = &p.people[0].names;
    let cls = |cid: &str| {
        names
            .iter()
            .find(|v| v.claim_id == cid)
            .unwrap()
            .equiv_class
            .clone()
    };
    assert_eq!(cls("n1"), cls("n2")); // equivalent → one class
    assert_ne!(cls("n1"), cls("n3")); // unrelated → separate class
    assert_eq!(cls("n1"), "n1"); // class label = min claim_id in the component
}

#[test]
fn parent_child_edge() {
    let recs = vec![
        person("pChild"),
        person("pParent"),
        parent("r1", "pChild", "pParent", "biological", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.parent_child,
        vec![ParentChild {
            parent: "pParent".into(),
            child: "pChild".into(),
            kind: "biological".into()
        }]
    );
}

#[test]
fn partnership_edge() {
    let recs = vec![
        person("pA"),
        person("pB"),
        partnership("r1", "pB", "pA", "spouse", "did:key:z6MkA"), // endpoints in any order
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.partnerships,
        vec![Partnership {
            pair: ["pA".into(), "pB".into()],
            role: "spouse".into()
        }]
    );
}

#[test]
fn relationships_canonicalize_across_a_merge() {
    // The parent edge names pB; a same_as merges pB into pA → the edge points at pA.
    let recs = vec![
        person("pA"),
        person("pB"),
        person("pChild"),
        parent("r1", "pChild", "pB", "biological", "did:key:z6MkA"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.parent_child.len(), 1);
    assert_eq!(p.parent_child[0].parent, "pA");
    assert_eq!(p.parent_child[0].child, "pChild");
}

#[test]
fn refuted_relationship_is_dropped() {
    let recs = vec![
        person("pChild"),
        person("pParent"),
        parent("r1", "pChild", "pParent", "biological", "did:key:z6MkA"),
        attest("z1", "r1", "reject", "did:key:z6MkB"),
        attest("z2", "r1", "reject", "did:key:z6MkC"),
    ];
    // score = 1 - 2 = -1 < threshold → dropped.
    assert!(project(&recs, &Policy::default()).parent_child.is_empty());
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

    // The record slice is a SET: duplicating every record changes nothing.
    #[test]
    fn duplication_invariant(specs in prop::collection::vec((spec(), any::<u64>()), 0..24)) {
        let records: Vec<Value> = specs.iter().enumerate().map(|(i, (s, _))| into_record(s, i)).collect();
        let once = project(&records, &Policy::default());
        let mut doubled = records.clone();
        doubled.extend(records.iter().cloned());
        prop_assert_eq!(once, project(&doubled, &Policy::default()));
    }

    // Every person is well-formed: canonical id is the minimum member anchor, member sets are
    // disjoint across people, and each name claim belongs to exactly one person.
    #[test]
    fn people_are_wellformed(specs in prop::collection::vec((spec(), any::<u64>()), 0..24)) {
        let records: Vec<Value> = specs.iter().enumerate().map(|(i, (s, _))| into_record(s, i)).collect();
        let anchors: std::collections::BTreeSet<String> = specs.iter()
            .filter_map(|(s, _)| if let Spec::Person(id) = s { Some(id.clone()) } else { None })
            .collect();
        let proj = project(&records, &Policy::default());

        let mut seen_members = std::collections::BTreeSet::new();
        let mut seen_names = std::collections::BTreeSet::new();
        for p in &proj.people {
            prop_assert!(anchors.contains(&p.id));
            prop_assert!(seen_members.insert(p.id.clone()), "anchor {} in two people", p.id);
            for a in &p.also {
                prop_assert!(anchors.contains(a));
                prop_assert!(p.id < *a, "canonical id must be the minimum: {} !< {}", p.id, a);
                prop_assert!(seen_members.insert(a.clone()), "anchor {} in two people", a);
            }
            for n in &p.names {
                prop_assert!(seen_names.insert(n.claim_id.clone()), "name {} in two people", n.claim_id);
            }
        }
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
