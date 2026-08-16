use super::*;
use json::JsonCodec;
use proptest::prelude::*;

fn c() -> JsonCodec {
    JsonCodec::default()
}

#[test]
fn parses_the_basics() {
    let v = c().parse(br#"{"name":"Ada","born":1815,"alive":false,"kids":["a","b"],"note":null}"#).unwrap();
    let ValueTree::Map(m) = v else { panic!("expected map") };
    assert_eq!(m[0], ("name".into(), ValueTree::Str("Ada".into())));
    assert_eq!(m[1], ("born".into(), ValueTree::Uint(1815)));
    assert_eq!(m[2], ("alive".into(), ValueTree::Bool(false)));
    assert_eq!(m[4], ("note".into(), ValueTree::Null));
}

#[test]
fn duplicate_keys_are_rejected() {
    // serde_json would silently keep the last — we refuse, since that IS a silent last-writer-wins.
    assert_eq!(c().parse(br#"{"a":1,"a":2}"#), Err(CodecError::DuplicateKey("a".into())));
}

#[test]
fn floats_are_rejected() {
    assert_eq!(c().parse(b"1.5"), Err(CodecError::FloatNotRepresentable));
    assert_eq!(c().parse(b"1e3"), Err(CodecError::FloatNotRepresentable));
    assert_eq!(c().parse(br#"{"x":2.0}"#), Err(CodecError::FloatNotRepresentable));
}

#[test]
fn integer_boundaries() {
    assert_eq!(c().parse(b"-9223372036854775808").unwrap(), ValueTree::Int(i64::MIN));
    assert_eq!(c().parse(b"18446744073709551615").unwrap(), ValueTree::Uint(u64::MAX));
    assert_eq!(c().parse(b"99999999999999999999999"), Err(CodecError::NumberOutOfRange));
}

#[test]
fn unicode_escapes_and_surrogate_pairs() {
    assert_eq!(c().parse(r#""café""#.as_bytes()).unwrap(), ValueTree::Str("café".into())); // raw utf-8
    assert_eq!(c().parse(r#""😀""#.as_bytes()).unwrap(), ValueTree::Str("😀".into())); // astral, raw
    assert!(matches!(c().parse(br#""\ud83d""#), Err(CodecError::Malformed { what: "lone high surrogate", .. })));
}

#[test]
fn bytes_have_no_json_form() {
    assert!(matches!(c().emit(&ValueTree::Bytes(vec![1, 2])), Err(CodecError::Unrepresentable(_))));
}

#[test]
fn deep_nesting_is_bounded_not_a_stack_overflow() {
    let deep = "[".repeat(500);
    assert_eq!(c().parse(deep.as_bytes()), Err(CodecError::TooDeep));
}

#[test]
fn trailing_bytes_are_rejected() {
    assert!(matches!(c().parse(b"true false"), Err(CodecError::Malformed { .. })));
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
                ValueTree::Map(kvs.into_iter().filter(|(k, _)| seen.insert(k.clone())).collect())
            }),
        ]
    })
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
