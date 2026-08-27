#![doc = include_str!("../README.md")]

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

/// A validated Ed25519 `did:key` identity (`did:key:z6Mk…`). A distinct type from a bare `String`, so
/// at a boundary it can't be swapped with a recovery code, a member id, or any other string — and it
/// is guaranteed well-formed: every `DidKey` decodes to a 32-byte Ed25519 key. It is the stable author
/// id stamped as a claim's `createdBy`; the envelope itself keeps `createdBy` as an opaque string, so
/// this type guards the id where it is *handled* (vault outputs, the JS boundary), not on the wire.
///
/// No `Serialize`/`Deserialize`: this crate stays dependency-free (only `thiserror`), so a
/// serialization boundary converts explicitly via [`as_str`](DidKey::as_str) / [`into_string`]
/// (DidKey::into_string) and [`TryFrom`], keeping validation an explicit, visible step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DidKey(String);

impl DidKey {
    /// Wrap a `did:key` string, validating that it decodes to an Ed25519 key.
    pub fn parse(s: impl Into<String>) -> Result<Self, DidError> {
        let s = s.into();
        decode_ed25519(&s)?;
        Ok(DidKey(s))
    }

    /// The `did:key` for an Ed25519 public key — always valid, never fails.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        DidKey(encode_ed25519(public_key))
    }

    /// The `did:key` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 32-byte Ed25519 public key this id encodes.
    pub fn to_public_key(&self) -> [u8; 32] {
        // Infallible: a `DidKey` is validated on construction and is immutable.
        decode_ed25519(&self.0).expect("a DidKey is a validated did:key")
    }

    /// Consume into the owned `did:key` string — for a boundary that needs a plain `String` (a
    /// wasm-bindgen getter, an IPC DTO).
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for DidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for DidKey {
    type Error = DidError;
    fn try_from(s: String) -> Result<Self, DidError> {
        DidKey::parse(s)
    }
}

impl TryFrom<&str> for DidKey {
    type Error = DidError;
    fn try_from(s: &str) -> Result<Self, DidError> {
        DidKey::parse(s)
    }
}

impl From<DidKey> for String {
    fn from(d: DidKey) -> String {
        d.0
    }
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

// NOT a Kani target (deliberate). The base58 codec's correctness is the bijection
// `b58_decode(b58_encode(x)) == x`, but it is INTRACTABLE for Kani/CBMC: both directions are loops
// carrying `% 58` / `/ 58` on symbolic `u32`, and a global `#[kani::unwind]` must clear the 58-element
// `ALPHABET` position search, so CBMC bit-blasts a division-heavy circuit unrolled ~60× regardless of
// input size — runs were killed unconverged at both 32 bytes (18 min) and a 4-byte input (6 min). The
// same modular arithmetic verifies instantly in `openom-claim`'s Hlc math because there it is
// branch-free and O(1); it's the LOOP multiplier that blows up. base58's bijection stays covered by
// the proptest `did_key_roundtrips_for_any_pubkey` + the external W3C did:key vector below; deep
// coverage-guided fuzzing (cargo-fuzz) is the right heavier tool here, not model checking.

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Every 32-byte key round-trips through the full did:key path, always z6Mk-prefixed.
        #[test]
        fn did_key_roundtrips_for_any_pubkey(pk in any::<[u8; 32]>()) {
            let did = encode_ed25519(&pk);
            prop_assert!(did.starts_with("did:key:z6Mk"));
            prop_assert_eq!(decode_ed25519(&did).unwrap(), pk);
        }

        // base58btc encode/decode is a bijection on arbitrary bytes (incl. leading zeros).
        #[test]
        fn base58_roundtrips_any_bytes(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
            prop_assert_eq!(b58_decode(&b58_encode(&bytes)).unwrap(), bytes);
        }

        // decode never panics or hangs on arbitrary input — Ok or Err, always fast.
        #[test]
        fn decode_never_panics(s in ".*") {
            let _ = decode_ed25519(&s);
        }
    }
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
    fn didkey_is_a_validated_newtype() {
        let pk = [7u8; 32];
        let d = DidKey::from_public_key(&pk);
        assert!(d.as_str().starts_with("did:key:z6Mk"));
        assert_eq!(d.to_public_key(), pk);

        // parse round-trips a well-formed did:key and rejects junk / other DID methods.
        assert_eq!(DidKey::parse(d.as_str().to_owned()).unwrap(), d);
        assert!(DidKey::parse("did:web:example.com").is_err());
        assert!(DidKey::parse("not a did:key").is_err());

        // TryFrom<String> validates; From<DidKey> is the transparent inverse (for a String boundary).
        let s: String = d.clone().into();
        assert_eq!(DidKey::try_from(s).unwrap(), d);
        assert!(DidKey::try_from("did:web:x".to_string()).is_err());
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
