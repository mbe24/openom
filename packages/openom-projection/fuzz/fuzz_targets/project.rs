#![no_main]
//! Ingesting + projecting an arbitrary array of record objects must never panic, OOM, or hang — the
//! read-model rebuild boundary (a hostile or malformed synced record set must degrade cleanly).
//! `Record::try_from` is the ingest boundary and must not panic on arbitrary input either.
//! Run: cd packages/openom-projection && cargo +nightly fuzz run project
use libfuzzer_sys::fuzz_target;
use openom_projection::{project, Policy, Record};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if let Ok(Value::Array(values)) = serde_json::from_slice::<Value>(data) {
        let records: Vec<Record> = values
            .into_iter()
            .filter_map(|v| Record::try_from(v).ok())
            .collect();
        let _ = project(&records, &Policy::default());
    }
});
