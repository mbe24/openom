#![no_main]
//! Decoding and opening arbitrary bytes must never panic, OOM, or hang — this is the exact surface a
//! keyless server and every envelope reader are exposed to on untrusted input. Decode to an Envelope
//! (fallible), then attempt to open it with a random key; only ever Ok or Err, never a crash.
use libfuzzer_sys::fuzz_target;
use openom_crypto::{generate_dek, open_envelope};
use openom_protocol::v1::Envelope;
use openom_protocol::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = Envelope::decode(data) {
        let dek = generate_dek().unwrap();
        let _ = open_envelope(dek.expose(), &env);
    }
});
