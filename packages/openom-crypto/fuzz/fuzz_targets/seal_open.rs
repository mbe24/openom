#![no_main]
//! Structured fuzzing of the seal→open envelope path with `arbitrary`-derived input.
//!
//! Two frozen invariants of the AEAD envelope (§5): a validly-sealed envelope ALWAYS opens back to
//! its exact plaintext, and any real change to the ciphertext must fail authentication. Driving the
//! header fields and plaintext from a typed `SealInput` lets libFuzzer explore odd lengths, empty
//! ids, and counter extremes far better than a hand-sliced byte buffer would.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use openom_crypto::{generate_dek, open_envelope, seal_envelope, SealParams};
use openom_protocol::v1::{Aead, Compression, Format, Kind};

#[derive(Arbitrary, Debug)]
struct SealInput {
    plaintext: Vec<u8>,
    /// Pick the AEAD suite (both are frozen options).
    aes_gcm: bool,
    key_id: Vec<u8>,
    tree_id: Vec<u8>,
    replica_id: Vec<u8>,
    replica_counter: u64,
    /// `Some((index, byte))` corrupts one ciphertext byte; `None` checks the clean round-trip.
    tamper: Option<(usize, u8)>,
}

fuzz_target!(|input: SealInput| {
    let dek = generate_dek().unwrap();
    let aead = if input.aes_gcm {
        Aead::Aes256Gcm
    } else {
        Aead::Xchacha20Poly1305
    };
    let params = SealParams {
        version: 1,
        kind: Kind::Snapshot,
        format: Format::OpenomJson,
        aead,
        compression: Compression::None,
        key_id: &input.key_id,
        tree_id: &input.tree_id,
        replica_id: &input.replica_id,
        replica_counter: input.replica_counter,
        prev_ciphertext_hash: b"",
        covers_through_seq: 0,
        blob_id: b"",
        author: None,
    };

    // If sealing rejects these params, there is nothing to check — only assert on a real envelope.
    let Ok(mut env) = seal_envelope(dek.expose(), &params, &input.plaintext) else {
        return;
    };

    match input.tamper {
        // A clean envelope must round-trip to the exact plaintext.
        None => {
            assert_eq!(
                open_envelope(dek.expose(), &env).unwrap(),
                input.plaintext,
                "a validly-sealed envelope must open back to its plaintext"
            );
        }
        // A genuine ciphertext change must fail authentication (never open, never panic).
        Some((idx, byte)) if !env.ciphertext.is_empty() => {
            let i = idx % env.ciphertext.len();
            if env.ciphertext[i] != byte {
                env.ciphertext[i] = byte;
                assert!(
                    open_envelope(dek.expose(), &env).is_err(),
                    "a corrupted ciphertext must not authenticate"
                );
            }
        }
        _ => {}
    }
});
