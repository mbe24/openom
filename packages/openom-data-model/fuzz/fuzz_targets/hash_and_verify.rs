#![no_main]
//! Hashing / verifying an arbitrary envelope must never panic, OOM, or hang — the synced-record
//! ingest boundary (a hostile createdBy or a deep value must fail cleanly, not crash).
//! Run: cd packages/openom-data-model && cargo +nightly fuzz run hash_and_verify
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = openom_data_model::content_hash(&v);
        let _ = openom_data_model::claim_id(&v);
        let _ = openom_data_model::fingerprint(&v);
        let _ = openom_data_model::verify(&v, &[0u8; 64]);
    }
});
