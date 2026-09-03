#![no_main]
//! Parsing an arbitrary string must never panic (no integer overflow on long digit runs), and
//! whenever both bounds are present the earliest must not exceed the latest.
//! Run: cd packages/edtf && cargo +nightly fuzz run parse
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(e) = edtf::parse(s) {
            if let (Some(min), Some(max)) = (e.min, e.max) {
                assert!(
                    (min.year, min.month, min.day) <= (max.year, max.month, max.day),
                    "min > max for {s:?}"
                );
            }
        }
    }
});
