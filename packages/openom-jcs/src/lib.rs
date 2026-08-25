#![doc = include_str!("../README.md")]

use std::cmp::Ordering;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A canonicalization failure.
#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    /// A floating-point number was encountered. Canonical content must be integer-only.
    #[error("floating-point numbers are not permitted in canonical JSON")]
    Float,
    /// A field-selective helper was handed a value that isn't a JSON object.
    #[error("expected a JSON object")]
    NotObject,
    /// Nesting exceeded [`MAX_DEPTH`] — a guard against stack overflow on adversarial input.
    #[error("value nesting exceeds the maximum depth of {MAX_DEPTH}")]
    TooDeep,
    /// The value could not be serialized to `serde_json::Value`.
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Maximum array/object nesting depth. Claim values are shallow; this is far above any legitimate
/// structure and exists only so a maliciously deep synced record fails with [`JcsError::TooDeep`]
/// instead of aborting the process with a stack overflow.
pub const MAX_DEPTH: usize = 128;

/// Canonicalize any [`Serialize`] value to RFC 8785 bytes.
pub fn to_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError> {
    to_canonical_value(&serde_json::to_value(value)?)
}

/// Canonicalize an already-parsed [`Value`] to RFC 8785 bytes.
pub fn to_canonical_value(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

/// Canonicalize **only** the named top-level fields (order-independent; absent keys are skipped).
/// This is the fingerprint primitive: `canonical_subset(claim, &["targetId","predicate","value"])`.
/// `value` must be a JSON object.
pub fn canonical_subset(value: &Value, include: &[&str]) -> Result<Vec<u8>, JcsError> {
    let obj = value.as_object().ok_or(JcsError::NotObject)?;
    let mut sub = serde_json::Map::new();
    for k in include {
        if let Some(v) = obj.get(*k) {
            sub.insert((*k).to_string(), v.clone());
        }
    }
    to_canonical_value(&Value::Object(sub))
}

/// Canonicalize a top-level object **excluding** the named fields — the id primitive:
/// `canonical_excluding(envelope, &["id","signature"])`. `value` must be a JSON object.
pub fn canonical_excluding(value: &Value, exclude: &[&str]) -> Result<Vec<u8>, JcsError> {
    let obj = value.as_object().ok_or(JcsError::NotObject)?;
    let mut sub = serde_json::Map::new();
    for (k, v) in obj {
        if !exclude.contains(&k.as_str()) {
            sub.insert(k.clone(), v.clone());
        }
    }
    to_canonical_value(&Value::Object(sub))
}

/// `sha256(JCS(value))` — the raw 32-byte content hash of a value's canonical form.
pub fn canonical_hash<T: Serialize>(value: &T) -> Result<[u8; 32], JcsError> {
    Ok(Sha256::digest(to_canonical(value)?).into())
}

/// Lowercase-hex SHA-256 of arbitrary bytes — the encoding used in `"sha256:"` content references.
pub fn hex256(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

/// Lowercase-hex encoding of arbitrary bytes. Shared so every crate in the content-addressing path
/// encodes hashes and signatures identically.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn write_value(out: &mut Vec<u8>, v: &Value, depth: usize) -> Result<(), JcsError> {
    if depth > MAX_DEPTH {
        return Err(JcsError::TooDeep);
    }
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // Only i64/u64 are canonical here; any float (even an integral 2.0) is rejected so the
            // float-free invariant can never be violated silently.
            if n.is_f64() {
                return Err(JcsError::Float);
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, e, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                write_value(out, &map[*k], depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Order two strings by their UTF-16 code-unit sequences (RFC 8785 §3.2.3).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) if x == y => continue,
            (Some(x), Some(y)) => return x.cmp(&y),
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Serialize a JSON string with RFC 8785 §3.2.2.2 minimal escaping: the two mandatory escapes
/// (`"` and `\`), the five short control escapes, `\u00xx` (lowercase) for the remaining C0 controls,
/// and every other character as literal UTF-8.
fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(b"\\u00");
                let code = c as u32;
                out.push(hex_lower((code >> 4) as u8));
                out.push(hex_lower((code & 0x0f) as u8));
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn hex_lower(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Arbitrary float-free JSON values, bounded depth.
    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| Value::Number(n.into())),
            ".*".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::hash_map("[a-zA-Z0-9]{0,6}", inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        // Float-free values always canonicalize, deterministically, without panicking.
        #[test]
        fn deterministic(v in arb_value()) {
            prop_assert_eq!(to_canonical_value(&v).unwrap(), to_canonical_value(&v).unwrap());
        }

        // Canonicalizing the reparse of a canonical form yields the identical bytes.
        #[test]
        fn idempotent(v in arb_value()) {
            let once = to_canonical_value(&v).unwrap();
            let reparsed: Value = serde_json::from_slice(&once).unwrap();
            prop_assert_eq!(&once, &to_canonical_value(&reparsed).unwrap());
        }

        // Any finite float is rejected, never silently accepted.
        #[test]
        fn floats_rejected(x in proptest::num::f64::NORMAL) {
            let v = serde_json::json!({ "k": x });
            prop_assert!(matches!(to_canonical_value(&v), Err(JcsError::Float)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: Value) -> String {
        String::from_utf8(to_canonical_value(&v).unwrap()).unwrap()
    }

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({ "b": 1, "a": 2, "c": { "y": 1, "x": 2 } });
        assert_eq!(canon(v), r#"{"a":2,"b":1,"c":{"x":2,"y":1}}"#);
    }

    #[test]
    fn utf16_order_differs_from_codepoint_order() {
        // U+10000 (astral: UTF-16 surrogate D800 DC00) vs U+E000 (BMP). In UTF-16, D800 < E000, so
        // the astral key sorts FIRST; in code-point/UTF-8 order 0x10000 > 0xE000 would put it LAST.
        // Passing proves we sort by UTF-16 code units, not BTreeMap/UTF-8 order.
        let astral = "\u{10000}";
        let bmp = "\u{e000}";
        let mut map = serde_json::Map::new();
        map.insert(bmp.to_string(), json!(1));
        map.insert(astral.to_string(), json!(2));
        let out = canon(Value::Object(map));
        let astral_pos = out.find(astral).unwrap();
        let bmp_pos = out.find(bmp).unwrap();
        assert!(
            astral_pos < bmp_pos,
            "astral key must sort before BMP key under UTF-16: {out}"
        );
    }

    #[test]
    fn rejects_floats() {
        assert!(matches!(
            to_canonical_value(&json!({ "x": 1.5 })),
            Err(JcsError::Float)
        ));
        // Even an integral-valued float is rejected — serde_json parses `2.0` as f64.
        let two_point_zero: Value = serde_json::from_str("2.0").unwrap();
        assert!(matches!(
            to_canonical_value(&two_point_zero),
            Err(JcsError::Float)
        ));
    }

    #[test]
    fn integers_pass_through() {
        assert_eq!(
            canon(json!({ "n": -42, "u": 9_007_199_254_740_993_i64 })),
            r#"{"n":-42,"u":9007199254740993}"#
        );
    }

    #[test]
    fn string_escaping_is_minimal() {
        // quote, backslash, short escapes, a C0 control (), and literal non-ASCII (ü, 😀).
        let v = json!({ "s": "a\"\\\n\u{07}ü😀" });
        assert_eq!(canon(v), "{\"s\":\"a\\\"\\\\\\n\\u0007ü😀\"}");
    }

    #[test]
    fn subset_and_excluding_pick_fields_order_independently() {
        let claim = json!({
            "id": "hash-1", "signature": "sig", "targetId": "p1",
            "predicate": "openom.org/core/name/v1", "value": { "given": "Ada" }
        });
        // fingerprint inputs, regardless of caller order:
        let fp = canonical_subset(&claim, &["value", "predicate", "targetId"]).unwrap();
        assert_eq!(
            String::from_utf8(fp).unwrap(),
            r#"{"predicate":"openom.org/core/name/v1","targetId":"p1","value":{"given":"Ada"}}"#
        );
        // id inputs = everything but id + signature:
        let id_bytes = canonical_excluding(&claim, &["id", "signature"]).unwrap();
        assert_eq!(
            String::from_utf8(id_bytes).unwrap(),
            r#"{"predicate":"openom.org/core/name/v1","targetId":"p1","value":{"given":"Ada"}}"#
        );
    }

    #[test]
    fn canonical_is_reserialization_stable() {
        let a = json!({ "z": [3, 2, 1], "a": "x", "m": { "b": true, "a": null } });
        let once = to_canonical_value(&a).unwrap();
        let reparsed: Value = serde_json::from_slice(&once).unwrap();
        let twice = to_canonical_value(&reparsed).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn rejects_pathologically_deep_nesting() {
        // Deeper than MAX_DEPTH must fail with TooDeep, not abort the process with a stack overflow.
        let mut v = json!(0);
        for _ in 0..(MAX_DEPTH + 5) {
            v = Value::Array(vec![v]);
        }
        assert!(matches!(to_canonical_value(&v), Err(JcsError::TooDeep)));
    }

    #[test]
    fn hex256_is_lowercase_64_chars() {
        let h = hex256(b"");
        // sha256("") is a known vector.
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn non_object_subset_errors() {
        assert!(matches!(
            canonical_subset(&json!([1, 2]), &["a"]),
            Err(JcsError::NotObject)
        ));
    }
}
