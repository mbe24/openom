#![no_main]
//! Canonicalizing arbitrary JSON must never panic, OOM, or hang — the content-hash input boundary
//! (deep nesting must return TooDeep, not overflow the stack). Also exercises the field-selective
//! helpers. Run: cd packages/openom-jcs && cargo +nightly fuzz run canonicalize
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = openom_jcs::to_canonical_value(&v);
        let _ = openom_jcs::canonical_excluding(&v, &["id", "signature"]);
        let _ = openom_jcs::canonical_subset(&v, &["targetId", "predicate", "value"]);
    }
});
