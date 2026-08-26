//! Property + fuzz-style tests for the frozen envelope path. The wire format can't change,
//! so these guard the invariants that matter most: a sealed envelope always opens back to
//! its plaintext; any tampering (ciphertext, header, or wrong key) is rejected; and decoding
//! untrusted bytes never panics — only ever Ok or Err. That last one is the fuzz surface a
//! keyless server and every reader are exposed to.

use openom_crypto::{generate_dek, open_envelope, seal_envelope, SealParams};
use openom_protocol::v1::{Aead, Compression, Envelope, Format, Kind};
use openom_protocol::Message;
use proptest::prelude::*;

fn params(aead: Aead) -> SealParams<'static> {
    SealParams {
        version: 1,
        kind: Kind::Snapshot,
        format: Format::OpenomJson,
        aead,
        compression: Compression::None,
        key_id: b"epoch-0",
        tree_id: b"tree-uuid-16byte",
        replica_id: b"replica-0",
        replica_counter: 0,
        prev_ciphertext_hash: b"",
        covers_through_seq: 0,
        blob_id: b"",
        author: None,
    }
}

fn aead() -> impl Strategy<Value = Aead> {
    prop_oneof![Just(Aead::Xchacha20Poly1305), Just(Aead::Aes256Gcm)]
}

proptest! {
    #[test]
    fn round_trips(plaintext in proptest::collection::vec(any::<u8>(), 0..2048), aead in aead()) {
        let dek = generate_dek().unwrap();
        let env = seal_envelope(dek.expose(), &params(aead), &plaintext).unwrap();
        prop_assert_eq!(open_envelope(dek.expose(), &env).unwrap(), plaintext);
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..1024),
        idx in any::<usize>(),
        aead in aead(),
    ) {
        let dek = generate_dek().unwrap();
        let mut env = seal_envelope(dek.expose(), &params(aead), &plaintext).unwrap();
        let i = idx % env.ciphertext.len();
        env.ciphertext[i] ^= 0xFF;
        prop_assert!(open_envelope(dek.expose(), &env).is_err());
    }

    #[test]
    fn the_wrong_key_is_rejected(plaintext in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let dek = generate_dek().unwrap();
        let other = generate_dek().unwrap();
        let env = seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), &plaintext).unwrap();
        prop_assert!(open_envelope(other.expose(), &env).is_err());
    }

    #[test]
    fn the_header_is_authenticated(
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        bump in 1u64..,
    ) {
        // The whole header is the AEAD's AAD, so changing any header field must break open —
        // even though the (untouched) ciphertext still matches its ciphertext_hash.
        let dek = generate_dek().unwrap();
        let mut env = seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), &plaintext).unwrap();
        let h = env.header.as_mut().unwrap();
        h.replica_counter = h.replica_counter.wrapping_add(bump);
        prop_assert!(open_envelope(dek.expose(), &env).is_err());
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Untrusted input: decode must return Ok/Err, never panic; and opening whatever it
        // decodes to must also never panic.
        if let Ok(env) = Envelope::decode(bytes.as_slice()) {
            let dek = generate_dek().unwrap();
            let _ = open_envelope(dek.expose(), &env);
        }
    }

    #[test]
    fn corrupting_a_valid_envelope_never_panics(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        smudge in proptest::collection::vec(any::<u8>(), 1..64),
        at in any::<usize>(),
    ) {
        // Seal a real envelope, splice random bytes into its encoded form, re-decode, open.
        let dek = generate_dek().unwrap();
        let env = seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), &plaintext).unwrap();
        let mut enc = env.encode_to_vec();
        let start = at % enc.len();
        for (k, b) in smudge.iter().enumerate() {
            let j = (start + k) % enc.len();
            enc[j] = *b;
        }
        if let Ok(env2) = Envelope::decode(enc.as_slice()) {
            let _ = open_envelope(dek.expose(), &env2);
        }
    }
}
