#![no_main]
//! Decoding an arbitrary did:key string must never panic or hang (the createdBy ingest boundary),
//! and encode→decode round-trips for any 32-byte key.
//! Run: cd packages/did && cargo +nightly fuzz run decode
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = did::decode_ed25519(s);
    }
    if data.len() >= 32 {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[..32]);
        let did = did::encode_ed25519(&pk);
        assert_eq!(did::decode_ed25519(&did).unwrap(), pk);
    }
});
