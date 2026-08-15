#![no_main]
//! Decoding arbitrary bytes must never panic, OOM, or hang — the sealed-archive parse boundary.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = commute::codec::decode_ops(data);
});
