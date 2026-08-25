#![no_main]
//! Projecting an arbitrary array of record objects must never panic, OOM, or hang — the read-model
//! rebuild boundary (a hostile or malformed synced record set must degrade cleanly).
//! Run: cd packages/openom-projection && cargo +nightly fuzz run project
use libfuzzer_sys::fuzz_target;
use openom_projection::{project, Policy};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if let Ok(Value::Array(records)) = serde_json::from_slice::<Value>(data) {
        let _ = project(&records, &Policy::default());
    }
});
