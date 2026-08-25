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
fn biography(id: &str, target: &str, text: &str, author: &str) -> Value {
    claim(
        id,
        P_BIOGRAPHY,
        target,
        json!({ "format": "plain", "text": text }),
        author,
    )
}
fn custom_field(
    id: &str,
    tree: &str,
    field_id: &str,
    label: &str,
    ty: &str,
    author: &str,
) -> Value {
    claim(
        id,
        P_CUSTOM_FIELD,
        tree,
        json!({ "fieldId": field_id, "label": label, "type": ty }),
        author,
    )
}
fn custom_value(id: &str, person: &str, field_id: &str, value: Value, author: &str) -> Value {
    claim(
        id,
        P_CUSTOM_VALUE,
        person,
        json!({ "fieldId": field_id, "value": value }),
        author,
    )
}
fn tombstone(id: &str, target: &str) -> Value {
    claim(id, P_TOMBSTONE, target, json!({}), "did:key:z6MkA")
}
fn source(id: &str, title: &str, repository: &str, author: &str) -> Value {
    json!({ "id": id, "type": "openom.org/core/claim/v1", "predicate": P_SOURCE,
            "value": { "title": title, "repository": repository, "quality": "original" },
            "createdAt": 1, "createdBy": author })
}
// Attach an inline citation to an existing claim (as its top-level `citation` envelope field).
fn with_citation(mut c: Value, source_id: &str, locator: Value, extract: &str) -> Value {
    c["citation"] = json!({ "sourceId": source_id, "locator": locator, "extract": extract });
    c
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
fn event(id: &str) -> Value {
    json!({ "id": id, "type": TYPE_EVENT, "createdAt": 1, "createdBy": "did:key:z6MkA" })
}
fn event_type(id: &str, evt: &str, ty: &str, author: &str) -> Value {
    claim(id, P_EVENT_TYPE, evt, json!({ "type": ty }), author)
}
fn date(id: &str, evt: &str, edtf: &str, author: &str) -> Value {
    claim(id, P_DATE, evt, json!({ "edtf": edtf }), author)
}
fn participant(id: &str, evt: &str, person: &str, role: &str, author: &str) -> Value {
    claim(
        id,
        P_PARTICIPANT,
        evt,
        json!({ "personId": person, "role": role }),
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
fn biography_resolves() {
    let recs = vec![
        person("pA"),
        biography(
            "b1",
            "pA",
            "Born in Krakow, emigrated 1923.",
            "did:key:z6MkA",
        ),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.people[0].biography.as_deref(),
        Some("Born in Krakow, emigrated 1923.")
    );
}

#[test]
fn custom_fields_resolve_via_definition() {
    let recs = vec![
        person("pA"),
        custom_field(
            "cf1",
            "tree",
            "fld_job",
            "Occupation",
            "text",
            "did:key:z6MkA",
        ),
        custom_value("cv1", "pA", "fld_job", json!("Carpenter"), "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.people[0].custom_fields,
        vec![CustomField {
            field_id: "fld_job".into(),
            label: "Occupation".into(),
            field_type: "text".into(),
            value: json!("Carpenter"),
        }]
    );
}

#[test]
fn sources_resolve_from_citations() {
    let biog = with_citation(
        biography("b1", "pA", "Born in Krakow.", "did:key:z6MkA"),
        "src1",
        json!({ "page": "112", "entry": "3" }),
        "b. Krakow 1842",
    );
    let recs = vec![
        person("pA"),
        source(
            "src1",
            "St. Mary Parish Register",
            "London Metropolitan Archives",
            "did:key:z6MkA",
        ),
        biog,
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people[0].sources.len(), 1);
    let c = &p.people[0].sources[0];
    assert_eq!(c.claim_id, "b1");
    assert_eq!(c.predicate, P_BIOGRAPHY);
    assert_eq!(c.extract.as_deref(), Some("b. Krakow 1842"));
    assert_eq!(c.locator, Some(json!({ "page": "112", "entry": "3" })));
    assert_eq!(c.source.source_id, "src1");
    assert_eq!(c.source.title.as_deref(), Some("St. Mary Parish Register"));
    assert_eq!(
        c.source.repository.as_deref(),
        Some("London Metropolitan Archives")
    );
    assert_eq!(c.source.quality.as_deref(), Some("original"));
}

#[test]
fn citation_with_unresolved_source_still_surfaces() {
    let n = with_citation(name("n1", "pA", "Ada"), "srcX", json!(null), "");
    let recs = vec![person("pA"), n];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.people[0].sources.len(), 1);
    let c = &p.people[0].sources[0];
    assert_eq!(c.source.source_id, "srcX");
    assert_eq!(c.source.title, None); // source claim absent → reference surfaced, fields empty
}

#[test]
fn custom_value_without_definition_degrades() {
    let recs = vec![
        person("pA"),
        custom_value("cv1", "pA", "fld_x", json!(42), "did:key:z6MkA"),
    ];
    let cf = &project(&recs, &Policy::default()).people[0].custom_fields[0];
    assert_eq!(cf.field_id, "fld_x");
    assert_eq!(cf.label, "fld_x"); // degrade: label = fieldId
    assert_eq!(cf.field_type, "text");
    assert_eq!(cf.value, json!(42));
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

#[test]
fn birth_event_assembles() {
    let recs = vec![
        person("pA"),
        event("e1"),
        event_type("t1", "e1", "birth", "did:key:z6MkA"),
        date("d1", "e1", "1842~", "did:key:z6MkA"),
        participant("pt1", "e1", "pA", "child", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.events.len(), 1);
    let e = &p.events[0];
    assert_eq!(e.event_type.as_deref(), Some("birth"));
    assert_eq!(e.date_edtf.as_deref(), Some("1842~"));
    assert_eq!(e.date_min_year, Some(1842));
    assert_eq!(
        e.participants,
        vec![Participant {
            person: "pA".into(),
            role: "child".into()
        }]
    );
}

#[test]
fn event_participants_canonicalize() {
    // A marriage; participant pB merges into pA via a same_as → the event names pA.
    let recs = vec![
        person("pA"),
        person("pB"),
        person("pC"),
        event("e1"),
        event_type("t1", "e1", "marriage", "did:key:z6MkA"),
        participant("pt1", "e1", "pB", "spouse", "did:key:z6MkA"),
        participant("pt2", "e1", "pC", "spouse", "did:key:z6MkA"),
        same_as("s1", "pA", "pB", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    let e = &p.events[0];
    assert_eq!(e.event_type.as_deref(), Some("marriage"));
    assert_eq!(
        e.participants,
        vec![
            Participant {
                person: "pA".into(),
                role: "spouse".into()
            },
            Participant {
                person: "pC".into(),
                role: "spouse".into()
            },
        ]
    );
}

#[test]
fn union_groups_children_and_attaches_marriage() {
    let recs = vec![
        person("pA"),
        person("pB"),
        person("pC1"),
        person("pC2"),
        parent("r1", "pC1", "pA", "biological", "did:key:z6MkA"),
        parent("r2", "pC1", "pB", "biological", "did:key:z6MkA"),
        parent("r3", "pC2", "pA", "biological", "did:key:z6MkA"),
        parent("r4", "pC2", "pB", "biological", "did:key:z6MkA"),
        partnership("pn1", "pA", "pB", "spouse", "did:key:z6MkA"),
        event("e1"),
        event_type("t1", "e1", "marriage", "did:key:z6MkA"),
        participant("pt1", "e1", "pA", "spouse", "did:key:z6MkA"),
        participant("pt2", "e1", "pB", "spouse", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.unions.len(), 1);
    let u = &p.unions[0];
    assert_eq!(u.id, "union:pA+pB");
    assert_eq!(u.parents, vec!["pA".to_string(), "pB".to_string()]);
    assert_eq!(u.children, vec!["pC1".to_string(), "pC2".to_string()]);
    assert_eq!(u.marriage_event.as_deref(), Some("e1"));
}

#[test]
fn half_siblings_are_separate_unions() {
    // pC1 has parents A+B; pC2 has parents A+C → two unions sharing only A.
    let recs = vec![
        person("pA"),
        person("pB"),
        person("pC"),
        person("pC1"),
        person("pC2"),
        parent("r1", "pC1", "pA", "biological", "did:key:z6MkA"),
        parent("r2", "pC1", "pB", "biological", "did:key:z6MkA"),
        parent("r3", "pC2", "pA", "biological", "did:key:z6MkA"),
        parent("r4", "pC2", "pC", "biological", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(p.unions.len(), 2);
    let ab = p
        .unions
        .iter()
        .find(|u| u.parents == vec!["pA".to_string(), "pB".to_string()])
        .unwrap();
    let ac = p
        .unions
        .iter()
        .find(|u| u.parents == vec!["pA".to_string(), "pC".to_string()])
        .unwrap();
    assert_eq!(ab.children, vec!["pC1".to_string()]);
    assert_eq!(ac.children, vec!["pC2".to_string()]);
}

#[test]
fn childless_partnership_is_a_union() {
    let recs = vec![
        person("pA"),
        person("pB"),
        partnership("pn1", "pA", "pB", "spouse", "did:key:z6MkA"),
    ];
    let p = project(&recs, &Policy::default());
    assert_eq!(
        p.unions,
        vec![Union {
            id: "union:pA+pB".into(),
            parents: vec!["pA".into(), "pB".into()],
            children: vec![],
            marriage_event: None,
        }]
    );
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
