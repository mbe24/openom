//! The canonical serialized form of the key-material records (`Epoch` / `Wrap`), owned here because keyeo
//! owns the types — so every keyring engine shares ONE encoding.
//!
//! **Invariant (load-bearing for the chain's signature): this is the only encoding of these records in
//! existence.** A producer encodes once and signs/stores the bytes; a verifier hashes the STORED bytes and
//! decodes *those same bytes* for its gates. No consumer may decode-then-re-encode-to-hash — that would let
//! it accept bytes the signer never produced. Adding a field or variant to `Epoch`/`Wrap` changes these
//! bytes automatically (serde is structurally exhaustive), which is exactly the property the chain relies on
//! to keep every field bound in the signature; the round-trip + golden-bytes tests guard against a
//! `#[serde(skip)]` silently breaking it.

use serde::de::DeserializeOwned;

use crate::kdf::KdfParams;
use crate::keyring::{Epoch, RecipientId, Wrap};

/// Decoding a stored key-material blob failed: malformed postcard, or trailing bytes after an otherwise
/// valid value. Trailing bytes are rejected (not ignored) — a well-formed producer emits exactly the encoded
/// records, so extra bytes are a corrupt/hostile blob, and `postcard::from_bytes` would silently accept them.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    /// The bytes are not a valid postcard encoding of the expected records.
    #[error("malformed key-material encoding")]
    Malformed,
    /// A valid value was decoded but bytes remained after it.
    #[error("trailing bytes after key-material encoding")]
    TrailingBytes,
}

/// Encode an epoch list to its canonical bytes. Infallible for these owned, alloc-backed records (postcard
/// only errors on IO / size limits, neither of which applies to `to_allocvec` of in-memory data).
pub fn encode_epochs<Id: RecipientId>(epochs: &[Epoch<Id>]) -> Vec<u8> {
    postcard::to_allocvec(epochs).expect("postcard encode of key-material epochs is infallible")
}

/// Decode an epoch list from its canonical bytes, rejecting a malformed or trailing-byte blob.
pub fn decode_epochs<Id: RecipientId>(bytes: &[u8]) -> Result<Vec<Epoch<Id>>, CodecError> {
    decode_strict(bytes)
}

/// Encode a wrap list (a recovery escrow's KEK wraps) to its canonical bytes. Infallible — see
/// [`encode_epochs`].
pub fn encode_wraps<Id: RecipientId>(wraps: &[Wrap<Id>]) -> Vec<u8> {
    postcard::to_allocvec(wraps).expect("postcard encode of key-material wraps is infallible")
}

/// Decode a wrap list from its canonical bytes, rejecting a malformed or trailing-byte blob.
pub fn decode_wraps<Id: RecipientId>(bytes: &[u8]) -> Result<Vec<Wrap<Id>>, CodecError> {
    decode_strict(bytes)
}

/// Encode a single [`KdfParams`] record (a member's account KDF) to canonical bytes. Infallible — see
/// [`encode_epochs`].
pub fn encode_kdf_params(k: &KdfParams) -> Vec<u8> {
    postcard::to_allocvec(k).expect("postcard encode of kdf params is infallible")
}

/// Decode a [`KdfParams`] record from its canonical bytes, rejecting a malformed or trailing-byte blob.
pub fn decode_kdf_params(bytes: &[u8]) -> Result<KdfParams, CodecError> {
    decode_strict(bytes)
}

fn decode_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let (value, rest) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| CodecError::Malformed)?;
    if !rest.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::KeyId;
    use crate::keyring::{KekKind, WrapMethod};
    use crate::material::{EncappedKey, Nonce, WrappedDek, X25519PublicKey};

    /// A fully-populated sample exercising ALL wrap forms with every field a distinct non-default value — the
    /// oracle for the round-trip + per-field mutation guards (a `#[serde(skip)]` on any field would make
    /// `decode(encode(x)) != x`).
    fn sample_epochs() -> Vec<Epoch<String>> {
        vec![Epoch {
            key_id: KeyId::new(vec![1, 2, 3, 4]),
            ordinal: 9,
            wraps: vec![
                Wrap {
                    recipient: "alice".to_string(),
                    method: WrapMethod::MemberHpke {
                        encapped: EncappedKey::from_bytes([1u8; 32]),
                        recipient_key: X25519PublicKey::from_bytes([2u8; 32]),
                    },
                    ciphertext: WrappedDek::from_bytes([3u8; 48]),
                },
                Wrap {
                    recipient: "owner".to_string(),
                    method: WrapMethod::RrkHpke {
                        encapped: EncappedKey::from_bytes([4u8; 32]),
                        recipient_key: X25519PublicKey::from_bytes([5u8; 32]),
                    },
                    ciphertext: WrappedDek::from_bytes([6u8; 48]),
                },
            ],
        }]
    }

    fn sample_wraps() -> Vec<Wrap<String>> {
        vec![
            Wrap {
                recipient: "owner".to_string(),
                method: WrapMethod::Kek {
                    kind: KekKind::Passphrase,
                    kdf: KdfSample::kdf(),
                    nonce: Nonce::from_bytes([7u8; 24]),
                },
                ciphertext: WrappedDek::from_bytes([8u8; 48]),
            },
            Wrap {
                recipient: "owner".to_string(),
                method: WrapMethod::Kek {
                    kind: KekKind::RecoveryCode,
                    kdf: KdfSample::kdf(),
                    nonce: Nonce::from_bytes([9u8; 24]),
                },
                ciphertext: WrappedDek::from_bytes([10u8; 48]),
            },
        ]
    }

    struct KdfSample;
    impl KdfSample {
        fn kdf() -> crate::kdf::KdfParams {
            crate::kdf::KdfParams { salt: vec![1, 2], memory_kib: 19_456, iterations: 2, parallelism: 1 }
        }
    }

    #[test]
    fn epochs_round_trip() {
        let e = sample_epochs();
        assert_eq!(decode_epochs::<String>(&encode_epochs(&e)).unwrap(), e);
    }

    /// A pinned snapshot of the canonical bytes for a fixed sample — a tripwire for a postcard-version or
    /// serde-attribute change silently altering the wire. That would move the bytes the chain signs under
    /// its signatures, so this MUST NOT change accidentally; a deliberate format bump updates the digest
    /// (and, pre-release, regenerates fixtures — there is nothing deployed to stay compatible with).
    #[test]
    fn golden_epoch_encoding_is_stable() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(encode_epochs(&sample_epochs()));
        let hex = data_encoding::HEXLOWER.encode(&digest);
        assert_eq!(hex, "8b123b9ec9bd377b812b503cc39d5a1a3e7346949732cd2f73ab610308768501");
    }

    #[test]
    fn wraps_round_trip() {
        let w = sample_wraps();
        assert_eq!(decode_wraps::<String>(&encode_wraps(&w)).unwrap(), w);
    }

    #[test]
    fn kdf_params_round_trip_and_reject_trailing() {
        let k = crate::kdf::KdfParams { salt: vec![9, 8, 7], memory_kib: 19_456, iterations: 3, parallelism: 2 };
        assert_eq!(decode_kdf_params(&encode_kdf_params(&k)).unwrap(), k);
        let mut bytes = encode_kdf_params(&k);
        bytes.push(0);
        assert_eq!(decode_kdf_params(&bytes), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encode_epochs(&sample_epochs());
        bytes.push(0);
        assert_eq!(decode_epochs::<String>(&bytes), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn a_truncated_blob_is_malformed() {
        let bytes = encode_epochs(&sample_epochs());
        assert_eq!(decode_epochs::<String>(&bytes[..bytes.len() / 2]), Err(CodecError::Malformed));
    }

    /// Per-field binding: mutating ANY field of ANY wrap variant changes the encoded bytes — the empirical
    /// complement to the compile-time sentinel in the chain crate. If a future field is `#[serde(skip)]`ed,
    /// its mutation would leave the bytes unchanged and this fails.
    #[test]
    fn every_field_changes_the_bytes() {
        let base = encode_epochs(&sample_epochs());
        let mutate = |f: &dyn Fn(&mut Epoch<String>)| {
            let mut e = sample_epochs();
            f(&mut e[0]);
            encode_epochs(&e)
        };
        // Epoch-level fields.
        assert_ne!(base, mutate(&|e| e.key_id = KeyId::new(vec![9, 9])));
        assert_ne!(base, mutate(&|e| e.ordinal = 100));
        // Wrap-level + MemberHpke variant fields.
        assert_ne!(base, mutate(&|e| e.wraps[0].recipient = "zzz".into()));
        assert_ne!(base, mutate(&|e| e.wraps[0].ciphertext = WrappedDek::from_bytes([99u8; 48])));
        assert_ne!(base, mutate(&|e| {
            if let WrapMethod::MemberHpke { encapped, .. } = &mut e.wraps[0].method {
                *encapped = EncappedKey::from_bytes([99u8; 32]);
            }
        }));
        assert_ne!(base, mutate(&|e| {
            if let WrapMethod::MemberHpke { recipient_key, .. } = &mut e.wraps[0].method {
                *recipient_key = X25519PublicKey::from_bytes([99u8; 32]);
            }
        }));
        // The variant discriminant itself.
        assert_ne!(base, mutate(&|e| {
            if let WrapMethod::MemberHpke { encapped, recipient_key } = &e.wraps[0].method {
                e.wraps[0].method = WrapMethod::RrkHpke { encapped: *encapped, recipient_key: *recipient_key };
            }
        }));
    }

    #[test]
    fn kek_variant_fields_change_the_bytes() {
        let base = encode_wraps(&sample_wraps());
        let mutate = |f: &dyn Fn(&mut Wrap<String>)| {
            let mut w = sample_wraps();
            f(&mut w[0]);
            encode_wraps(&w)
        };
        assert_ne!(base, mutate(&|w| {
            if let WrapMethod::Kek { kind, .. } = &mut w.method {
                *kind = KekKind::RecoveryCode;
            }
        }));
        assert_ne!(base, mutate(&|w| {
            if let WrapMethod::Kek { nonce, .. } = &mut w.method {
                *nonce = Nonce::from_bytes([99u8; 24]);
            }
        }));
        assert_ne!(base, mutate(&|w| {
            if let WrapMethod::Kek { kdf, .. } = &mut w.method {
                kdf.iterations = 99;
            }
        }));
        assert_ne!(base, mutate(&|w| {
            if let WrapMethod::Kek { kdf, .. } = &mut w.method {
                kdf.salt = vec![0xEE];
            }
        }));
    }
}
