#![no_main]
//! Merging arbitrary bytes must never panic — and on a decode error must leave the document
//! untouched (transactional decode). The receiving side of untrusted sync.
use commute::Doc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut d = Doc::new([0u8; 16]);
    let before = d.checkpoint();
    if d.merge_bytes(data).is_err() {
        assert_eq!(d.checkpoint(), before, "a failed merge must not partially apply");
    }
});
