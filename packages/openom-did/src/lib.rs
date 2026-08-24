//! `did:key` for Ed25519 identities, plus a `member_id ⇄ did:key` resolution seam.
//!
//! A `did:key` is a self-certifying identifier: the key *is* the identifier, no registry needed.
//! For Ed25519 it is `did:key:z` + base58btc( multicodec(0xed01) ++ 32-byte-public-key ), which
//! always renders with the `z6Mk…` prefix. This is the byte-format the claim envelope's `createdBy`
//! will carry, so it is pinned here (phase 0) before any content-hash id is persisted cross-client.
//!
//! The crate is deliberately dependency-free — base58btc is ~40 lines below — so it compiles to wasm
//! with no surface, and the encoding can be audited in one file.

use std::collections::HashMap;

/// Multicodec header for an Ed25519 public key: `0xed` as an unsigned varint = the two bytes `ed 01`.
pub const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

const DID_KEY_PREFIX: &str = "did:key:";
/// Bitcoin/base58btc alphabet (multibase code `z`).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Upper bound on the base58 body length. An Ed25519 `did:key` body is ~48 chars; this cap is far
/// above that and exists so an adversarial `createdBy` can't drive the O(n²) big-integer decode for
/// minutes (base58 decode is quadratic in the input length).
const MAX_B58_LEN: usize = 128;

/// A `did:key` parse/decode failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidError {
    /// Missing the `did:key:` scheme prefix.
    #[error("not a did:key identifier")]
    NotDidKey,
    /// The method-specific id is not base58btc multibase (missing the `z` prefix).
    #[error("did:key is not base58btc multibase (expected a leading 'z')")]
    BadMultibase,
    /// A character outside the base58 alphabet.
    #[error("invalid base58btc character")]
    BadBase58,
    /// The multicodec header is not Ed25519 (`0xed01`).
    #[error("unsupported key type (expected the Ed25519 multicodec 0xed01)")]
    UnsupportedMulticodec,
    /// The decoded key is not 32 bytes.
    #[error("decoded key is not 32 bytes")]
    BadLength,
}

/// Encode a 32-byte Ed25519 public key as a `did:key` string (always `did:key:z6Mk…`).
pub fn encode_ed25519(public_key: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(2 + 32);
    buf.extend_from_slice(&ED25519_MULTICODEC);
    buf.extend_from_slice(public_key);
    let mut s = String::from(DID_KEY_PREFIX);
    s.push('z');
    s.push_str(&b58_encode(&buf));
    s
}

/// Decode a `did:key` string back to the 32-byte Ed25519 public key, validating every layer.
pub fn decode_ed25519(did: &str) -> Result<[u8; 32], DidError> {
    let method = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(DidError::NotDidKey)?;
    let b58 = method.strip_prefix('z').ok_or(DidError::BadMultibase)?;
    if b58.len() > MAX_B58_LEN {
        return Err(DidError::BadLength);
    }
    let bytes = b58_decode(b58)?;
    let rest = bytes
        .strip_prefix(&ED25519_MULTICODEC[..])
        .ok_or(DidError::UnsupportedMulticodec)?;
    rest.try_into().map_err(|_| DidError::BadLength)
}

// ---- member-resolution seam ---------------------------------------------------------------------

/// Resolve between an application `member_id` and its `did:key`. The keyring builds the concrete
/// directory from its members; consumers depend only on this trait, so the identity encoding stays
/// swappable and this crate never depends on the protocol/keyring types.
pub trait MemberResolver {
    /// The `did:key` for a member, if known.
    fn did_for(&self, member_id: &str) -> Option<&str>;
    /// The `member_id` for a `did:key`, if known.
    fn member_for(&self, did: &str) -> Option<&str>;
}

/// An in-memory `member_id ⇄ did:key` directory, built from `(member_id, ed25519_public_key)` pairs.
#[derive(Debug, Clone, Default)]
pub struct MemberDirectory {
    member_to_did: HashMap<String, String>,
    did_to_member: HashMap<String, String>,
}

impl MemberDirectory {
    /// Build a directory, deriving each member's `did:key` from its Ed25519 public key. A later pair
    /// with the same `member_id` overwrites an earlier one (keyring revisions are applied in order).
    pub fn from_members<I>(members: I) -> Self
    where
        I: IntoIterator<Item = (String, [u8; 32])>,
    {
        let mut dir = MemberDirectory::default();
        for (member_id, pk) in members {
            let did = encode_ed25519(&pk);
            dir.did_to_member.insert(did.clone(), member_id.clone());
            dir.member_to_did.insert(member_id, did);
        }
        dir
    }
}

impl MemberResolver for MemberDirectory {
    fn did_for(&self, member_id: &str) -> Option<&str> {
        self.member_to_did.get(member_id).map(String::as_str)
    }
    fn member_for(&self, did: &str) -> Option<&str> {
        self.did_to_member.get(did).map(String::as_str)
    }
}

// ---- base58btc ----------------------------------------------------------------------------------

fn b58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new(); // little-endian base58 digits
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

fn b58_decode(input: &str) -> Result<Vec<u8>, DidError> {
    let zeros = input.bytes().take_while(|&b| b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new(); // little-endian byte accumulator
    for c in input.bytes().skip(zeros) {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(DidError::BadBase58)? as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_known_vectors() {
        assert_eq!(b58_encode(b""), "");
        assert_eq!(b58_encode(&[0x00]), "1");
        assert_eq!(b58_encode(&[0x00, 0x00]), "11");
        assert_eq!(b58_encode(&[0x61]), "2g"); // the canonical base58 of byte 0x61
        assert_eq!(b58_decode("2g").unwrap(), vec![0x61]);
        assert_eq!(b58_decode("11").unwrap(), vec![0x00, 0x00]);
    }

    #[test]
    fn base58_roundtrips_arbitrary_bytes() {
        let samples: &[&[u8]] = &[
            &[0],
            &[0, 0, 1, 2, 3],
            &[255; 10],
            &[0xde, 0xad, 0xbe, 0xef],
        ];
        for s in samples {
            assert_eq!(&b58_decode(&b58_encode(s)).unwrap(), s);
        }
    }

    #[test]
    fn ed25519_did_has_z6mk_prefix_and_roundtrips() {
        // A fixed, distinctive public key (contents irrelevant — did:key doesn't validate the point).
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let did = encode_ed25519(&pk);
        assert!(
            did.starts_with("did:key:z6Mk"),
            "Ed25519 did:key must start z6Mk: {did}"
        );
        assert_eq!(decode_ed25519(&did).unwrap(), pk);
    }

    #[test]
    fn known_ed25519_vector() {
        // A canonical W3C did:key identifier, produced by other implementations. Decoding it (base58
        // → 0xed01 multicodec → 32-byte key) and re-encoding must reproduce the exact string — an
        // external, non-circular check that our codec agrees with the rest of the world.
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let pk = decode_ed25519(did).unwrap();
        assert_eq!(encode_ed25519(&pk), did);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(
            decode_ed25519("did:web:example.com"),
            Err(DidError::NotDidKey)
        );
        assert_eq!(
            decode_ed25519("did:key:Q6Mk..."),
            Err(DidError::BadMultibase)
        ); // no 'z'
           // A valid base58 'z' multibase but the wrong multicodec (0x00) → unsupported.
        let did = {
            let mut s = String::from("did:key:z");
            s.push_str(&b58_encode(&[0x00, 0x01, 1, 2, 3]));
            s
        };
        assert_eq!(decode_ed25519(&did), Err(DidError::UnsupportedMulticodec));
    }

    #[test]
    fn rejects_overlong_base58_without_hanging() {
        // A pathological createdBy must fail fast, not drive the O(n²) decode for minutes.
        let did = format!("did:key:z{}", "1".repeat(10_000));
        assert_eq!(decode_ed25519(&did), Err(DidError::BadLength));
    }

    #[test]
    fn member_directory_resolves_both_ways() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let dir = MemberDirectory::from_members([("m-a".to_string(), a), ("m-b".to_string(), b)]);
        let did_a = encode_ed25519(&a);
        assert_eq!(dir.did_for("m-a"), Some(did_a.as_str()));
        assert_eq!(dir.member_for(&did_a), Some("m-a"));
        assert_eq!(dir.did_for("m-x"), None);
    }
}
