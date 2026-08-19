use super::*;
use json::JsonCodec;
use proptest::prelude::*;

fn c() -> JsonCodec {
    JsonCodec::default()
}

#[test]
fn parses_the_basics() {
    let v = c()
        .parse(br#"{"name":"Ada","born":1815,"alive":false,"kids":["a","b"],"note":null}"#)
        .unwrap();
    let ValueTree::Map(m) = v else {
        panic!("expected map")
    };
    assert_eq!(m[0], ("name".into(), ValueTree::Str("Ada".into())));
    assert_eq!(m[1], ("born".into(), ValueTree::Uint(1815)));
    assert_eq!(m[2], ("alive".into(), ValueTree::Bool(false)));
    assert_eq!(m[4], ("note".into(), ValueTree::Null));
}

#[test]
fn duplicate_keys_are_rejected() {
    // serde_json would silently keep the last — we refuse, since that IS a silent last-writer-wins.
    assert_eq!(
        c().parse(br#"{"a":1,"a":2}"#),
        Err(CodecError::DuplicateKey("a".into()))
    );
}

#[test]
fn floats_are_rejected() {
    assert_eq!(c().parse(b"1.5"), Err(CodecError::FloatNotRepresentable));
    assert_eq!(c().parse(b"1e3"), Err(CodecError::FloatNotRepresentable));
    assert_eq!(
        c().parse(br#"{"x":2.0}"#),
        Err(CodecError::FloatNotRepresentable)
    );
}

#[test]
fn integer_boundaries() {
    assert_eq!(
        c().parse(b"-9223372036854775808").unwrap(),
        ValueTree::Int(i64::MIN)
    );
    assert_eq!(
        c().parse(b"18446744073709551615").unwrap(),
        ValueTree::Uint(u64::MAX)
    );
    assert_eq!(
        c().parse(b"99999999999999999999999"),
        Err(CodecError::NumberOutOfRange)
    );
}

#[test]
fn unicode_escapes_and_surrogate_pairs() {
    assert_eq!(
        c().parse(r#""café""#.as_bytes()).unwrap(),
        ValueTree::Str("café".into())
    ); // raw utf-8
    assert_eq!(
        c().parse(r#""😀""#.as_bytes()).unwrap(),
        ValueTree::Str("😀".into())
    ); // astral, raw
    assert!(matches!(
        c().parse(br#""\ud83d""#),
        Err(CodecError::Malformed {
            what: "lone high surrogate",
            ..
        })
    ));
}

#[test]
fn bytes_have_no_json_form() {
    assert!(matches!(
        c().emit(&ValueTree::Bytes(vec![1, 2])),
        Err(CodecError::Unrepresentable(_))
    ));
}

#[test]
fn deep_nesting_is_bounded_not_a_stack_overflow() {
    let deep = "[".repeat(500);
    assert_eq!(c().parse(deep.as_bytes()), Err(CodecError::TooDeep));
}

#[test]
fn trailing_bytes_are_rejected() {
    assert!(matches!(
        c().parse(b"true false"),
        Err(CodecError::Malformed { .. })
    ));
}

// --- properties -------------------------------------------------------------------------------

/// JSON-representable values (no Bytes; non-negative goes through `Uint`, negative through `Int`,
/// matching the parser; map keys unique).
fn value_strat() -> impl Strategy<Value = ValueTree> {
    let leaf = prop_oneof![
        Just(ValueTree::Null),
        any::<bool>().prop_map(ValueTree::Bool),
        (i64::MIN..0).prop_map(ValueTree::Int),
        any::<u64>().prop_map(ValueTree::Uint),
        ".{0,6}".prop_map(ValueTree::Str),
    ];
    leaf.prop_recursive(4, 48, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(ValueTree::Seq),
            prop::collection::vec(("[a-z]{1,4}", inner), 0..4).prop_map(|kvs| {
                let mut seen = std::collections::HashSet::new();
                ValueTree::Map(
                    kvs.into_iter()
                        .filter(|(k, _)| seen.insert(k.clone()))
                        .collect(),
                )
            }),
        ]
    })
}

// --- mapping (JSON -> commute cells) ----------------------------------------------------------

#[test]
fn imports_scalars_and_a_keyed_collection_into_commute() {
    let codec = c();
    let doc = codec.parse(br#"{"title":"Smith Family","people":[{"id":"p1","name":"Ada"},{"id":"p2","name":"Bea"}]}"#).unwrap();
    // "title" is undeclared but scalar → auto LWW register; "people" is a declared keyed collection.
    let spec = MappingSpec {
        fields: vec![(
            "people".into(),
            FieldPolicy::Keyed {
                key_field: "id".into(),
            },
        )],
    };
    let plan = import(&doc, &spec, &codec).unwrap();

    let mut d = commute::Doc::new([0u8; 16]);
    for intent in plan.intents {
        d.apply_local(intent);
    }
    assert_eq!(
        d.register(b"title"),
        Some(&commute::Value::Text("Smith Family".into()))
    );
    let people = d.set_elements(b"people");
    assert_eq!(people.len(), 2);
    let ids: Vec<&[u8]> = people.iter().map(|(id, _)| id.as_slice()).collect();
    assert!(ids.contains(&&b"p1"[..]) && ids.contains(&&b"p2"[..]));
}

#[test]
fn an_undeclared_collection_is_a_hard_error() {
    let codec = c();
    let doc = codec.parse(br#"{"tags":["a","b"]}"#).unwrap(); // a collection with no declared policy
    assert_eq!(
        import(&doc, &MappingSpec::default(), &codec),
        Err(MapError::UndeclaredCollection("tags".into()))
    );
}

#[test]
fn duplicate_keys_within_a_collection_are_rejected() {
    let codec = c();
    let doc = codec
        .parse(br#"{"people":[{"id":"p1"},{"id":"p1"}]}"#)
        .unwrap();
    let spec = MappingSpec {
        fields: vec![(
            "people".into(),
            FieldPolicy::Keyed {
                key_field: "id".into(),
            },
        )],
    };
    assert_eq!(
        import(&doc, &spec, &codec),
        Err(MapError::DuplicateKey {
            field: "people".into(),
            key: "p1".into()
        })
    );
}

#[test]
fn import_then_export_reconstructs_the_document() {
    let codec = c();
    let doc = codec
        .parse(br#"{"title":"Smith","people":[{"id":"p1","name":"Ada"},{"id":"p2","name":"Bea"}]}"#)
        .unwrap();
    let spec = MappingSpec {
        fields: vec![(
            "people".into(),
            FieldPolicy::Keyed {
                key_field: "id".into(),
            },
        )],
    };
    let plan = import(&doc, &spec, &codec).unwrap();

    let mut d = commute::Doc::new([0u8; 16]);
    for intent in plan.intents {
        d.apply_local(intent);
    }
    let exported = export(&d, &spec, &codec).unwrap();
    let ValueTree::Map(m) = exported else {
        panic!("expected object")
    };

    // The scalar field round-trips.
    assert!(m
        .iter()
        .any(|(k, v)| k == "title" && *v == ValueTree::Str("Smith".into())));
    // The keyed collection comes back as an array of the original objects.
    let people = m
        .iter()
        .find(|(k, _)| k == "people")
        .map(|(_, v)| v)
        .unwrap();
    let ValueTree::Seq(elems) = people else {
        panic!("expected array")
    };
    assert_eq!(elems.len(), 2);
    for e in elems {
        assert!(
            matches!(e, ValueTree::Map(props) if props.iter().any(|(k, _)| k == "id") && props.iter().any(|(k, _)| k == "name"))
        );
    }
}

#[test]
fn an_atomic_field_stores_the_subtree_opaquely() {
    let codec = c();
    let doc = codec
        .parse(br#"{"settings":{"theme":"dark","n":3}}"#)
        .unwrap();
    let spec = MappingSpec {
        fields: vec![("settings".into(), FieldPolicy::Atomic)],
    };
    let plan = import(&doc, &spec, &codec).unwrap();
    let mut d = commute::Doc::new([0u8; 16]);
    for intent in plan.intents {
        d.apply_local(intent);
    }
    assert!(matches!(d.register(b"settings"), Some(commute::Value::Bytes(b)) if !b.is_empty()));
}

#[test]
fn a_value_identity_scalar_set_dedups_and_round_trips() {
    let codec = c();
    let doc = codec.parse(br#"{"tags":["red","green","red"]}"#).unwrap(); // the repeated "red" collapses
    let spec = MappingSpec {
        fields: vec![("tags".into(), FieldPolicy::ValueIdentity)],
    };
    let plan = import(&doc, &spec, &codec).unwrap();

    let mut d = commute::Doc::new([0u8; 16]);
    for intent in plan.intents {
        d.apply_local(intent);
    }
    assert_eq!(
        d.set_elements(b"tags").len(),
        2,
        "the set deduped the repeated value"
    );

    let ValueTree::Map(m) = export(&d, &spec, &codec).unwrap() else {
        panic!("object")
    };
    let ValueTree::Seq(vals) = m.iter().find(|(k, _)| k == "tags").map(|(_, v)| v).unwrap() else {
        panic!("array")
    };
    assert_eq!(vals.len(), 2);
    assert!(
        vals.contains(&ValueTree::Str("red".into()))
            && vals.contains(&ValueTree::Str("green".into()))
    );
}

fn id_order(seq: &ValueTree) -> Vec<String> {
    let ValueTree::Seq(elems) = seq else {
        panic!("array")
    };
    elems
        .iter()
        .map(|e| match e {
            ValueTree::Map(p) => match p.iter().find(|(k, _)| k == "id").map(|(_, v)| v) {
                Some(ValueTree::Str(s)) => s.clone(),
                _ => "?".into(),
            },
            _ => "?".into(),
        })
        .collect()
}

#[test]
fn keyed_ordered_sorts_by_the_order_field_on_export() {
    let codec = c();
    // Elements out of order; the order_field "n" drives export order.
    let doc = codec
        .parse(br#"{"kids":[{"id":"b","n":2},{"id":"a","n":1},{"id":"c","n":3}]}"#)
        .unwrap();
    let spec = MappingSpec {
        fields: vec![(
            "kids".into(),
            FieldPolicy::KeyedOrdered {
                key_field: "id".into(),
                order_field: "n".into(),
            },
        )],
    };
    let mut d = commute::Doc::new([0u8; 16]);
    for i in import(&doc, &spec, &codec).unwrap().intents {
        d.apply_local(i);
    }
    let ValueTree::Map(m) = export(&d, &spec, &codec).unwrap() else {
        panic!("object")
    };
    let kids = m.iter().find(|(k, _)| k == "kids").map(|(_, v)| v).unwrap();
    assert_eq!(id_order(kids), vec!["a", "b", "c"]);
}

#[test]
fn keyed_ordered_requires_the_order_field() {
    let codec = c();
    let doc = codec.parse(br#"{"kids":[{"id":"a"}]}"#).unwrap(); // missing "n"
    let spec = MappingSpec {
        fields: vec![(
            "kids".into(),
            FieldPolicy::KeyedOrdered {
                key_field: "id".into(),
                order_field: "n".into(),
            },
        )],
    };
    assert_eq!(
        import(&doc, &spec, &codec),
        Err(MapError::MissingKey {
            field: "kids".into(),
            key: "n".into()
        })
    );
}

#[test]
fn replace_mode_retracts_absent_elements_but_merge_keeps_them() {
    let codec = c();
    let spec = MappingSpec {
        fields: vec![(
            "people".into(),
            FieldPolicy::Keyed {
                key_field: "id".into(),
            },
        )],
    };
    let mut d = commute::Doc::new([0u8; 16]);
    for i in import(
        &codec
            .parse(br#"{"people":[{"id":"p1"},{"id":"p2"}]}"#)
            .unwrap(),
        &spec,
        &codec,
    )
    .unwrap()
    .intents
    {
        d.apply_local(i);
    }
    assert_eq!(d.set_elements(b"people").len(), 2);

    let doc2 = codec.parse(br#"{"people":[{"id":"p1"}]}"#).unwrap();

    // Merge keeps p2.
    let mut merged = d.clone();
    for i in import_mode(&doc2, &spec, &codec, ImportMode::Merge, Some(&merged))
        .unwrap()
        .intents
    {
        merged.apply_local(i);
    }
    assert_eq!(
        merged.set_elements(b"people").len(),
        2,
        "merge never removes"
    );

    // Replace retracts the absent p2.
    for i in import_mode(&doc2, &spec, &codec, ImportMode::Replace, Some(&d))
        .unwrap()
        .intents
    {
        d.apply_local(i);
    }
    let ids: Vec<Vec<u8>> = d
        .set_elements(b"people")
        .iter()
        .map(|(id, _)| id.to_vec())
        .collect();
    assert_eq!(
        ids,
        vec![b"p1".to_vec()],
        "replace retracted the element the document omitted"
    );
}

proptest! {
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = c().parse(&bytes);
    }

    #[test]
    fn emit_then_parse_round_trips(v in value_strat()) {
        let bytes = c().emit(&v).unwrap();
        prop_assert_eq!(c().parse(&bytes).unwrap(), v);
    }

    #[test]
    fn parse_then_emit_is_a_byte_fixpoint(v in value_strat()) {
        let once = c().emit(&v).unwrap();
        let reparsed = c().parse(&once).unwrap();
        prop_assert_eq!(c().emit(&reparsed).unwrap(), once);
    }
}
