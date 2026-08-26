#![doc = include_str!("../README.md")]

use openom_sign::{Signature, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod envelope;
#[cfg(feature = "validation")]
pub mod schema;

/// Envelope field names — the frozen set the schema freeze (OPE-170) will type.
pub const F_ID: &str = "id";
pub const F_SIGNATURE: &str = "signature";
pub const F_TARGET_ID: &str = "targetId";
pub const F_PREDICATE: &str = "predicate";
pub const F_VALUE: &str = "value";
pub const F_CREATED_BY: &str = "createdBy";

/// Domain-separation tag: a claim signature can never verify as some other Ed25519 signature
/// elsewhere in the system (mirrors `openom-attestation-zkp`' domain prefix).
const SIGN_DOMAIN: &[u8] = b"openom-claim-v1";

/// A hashing/signing failure.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    /// Canonicalization failed (non-object envelope, or a float in the content).
    #[error("canonicalization failed: {0}")]
    Jcs(#[from] openom_jcs::JcsError),
    /// The envelope has no string `createdBy`.
    #[error("envelope has no string createdBy")]
    MissingCreatedBy,
    /// `createdBy` is not a valid `did:key`.
    #[error("createdBy is not a valid did:key: {0}")]
    BadCreatedBy(#[from] openom_did::DidError),
    /// A record has no string `type`.
    #[error("record has no string type")]
    MissingType,
    /// A record whose `type` this build doesn't recognize has no non-empty string `id` — it cannot be
    /// folded (the fold keys on `id`), so it is malformed rather than merely-unknown.
    #[error("unknown-type record has no id")]
    MissingId,
    /// A record whose `type` this build doesn't recognize used a content-addressed (`sha256:…`) `id`.
    /// Those are reserved for claims and operations; an unknown record carrying one is refused so it
    /// can never squat a claim's content-address in the first-writer-wins fold.
    #[error("unknown-type record uses a reserved content-addressed id: {0}")]
    ReservedId(String),
    /// A claim's stored `id` does not match a fresh hash of its content.
    #[error("claim id does not match its content")]
    IdMismatch,
    /// A record's JSON did not match the `{0}` shape.
    #[error("malformed {0} record: {1}")]
    Malformed(&'static str, serde_json::Error),
    /// Serializing a typed record to its canonical envelope failed.
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// The 32-byte content hash — the basis of both the `id` and the signed message.
pub fn content_hash(envelope: &Value) -> Result<[u8; 32], ClaimError> {
    let bytes = openom_jcs::canonical_excluding(envelope, &[F_ID, F_SIGNATURE])?;
    Ok(Sha256::digest(bytes).into())
}

/// The claim `id`: `"sha256:" + lowercase-hex(content_hash)`.
pub fn claim_id(envelope: &Value) -> Result<String, ClaimError> {
    Ok(format!(
        "sha256:{}",
        openom_jcs::hex(&content_hash(envelope)?)
    ))
}

/// The dedup/refutation **fingerprint**: `sha256(JCS(targetId, predicate, value))`.
pub fn fingerprint(envelope: &Value) -> Result<[u8; 32], ClaimError> {
    let bytes = openom_jcs::canonical_subset(envelope, &[F_TARGET_ID, F_PREDICATE, F_VALUE])?;
    Ok(Sha256::digest(bytes).into())
}

/// A **content reference** to an intrinsic value: `"sha256:" + hex(sha256(JCS(intrinsic)))`. This is
/// how `equivalent_to` / `derived_from` / `preferred.contentRef` point at *what a claim says* (§4.1)
/// rather than at a minted id — a reference stable across authors and unaffected by unrelated fields.
/// The caller supplies the intrinsic (for a name that is its parts+script+culture; otherwise the
/// whole `value`).
pub fn content_ref(intrinsic: &Value) -> Result<String, ClaimError> {
    Ok(format!(
        "sha256:{}",
        openom_jcs::hex256(&openom_jcs::to_canonical_value(intrinsic)?)
    ))
}

/// Sign an envelope with the author's Ed25519 key (must be the key behind `createdBy`). The signature
/// is over `DOMAIN‖content_hash` and is excluded from the id + fingerprint.
pub fn sign(envelope: &Value, key: &SigningKey) -> Result<[u8; 64], ClaimError> {
    let ch = content_hash(envelope)?;
    Ok(key.sign(&signing_message(&ch)).to_bytes())
}

/// The outcome of a signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigCheck {
    /// Valid for this content under the key behind `createdBy`.
    Valid,
    /// Does not verify — tampered content, wrong key, or a malformed signature.
    Bad,
}

/// Verify `sig` against the envelope's content and the public key behind its `createdBy` `did:key`.
/// Pure cryptography — no keyring/role authority check (that is a higher layer).
pub fn verify(envelope: &Value, sig: &[u8; 64]) -> Result<SigCheck, ClaimError> {
    let did = envelope
        .get(F_CREATED_BY)
        .and_then(Value::as_str)
        .ok_or(ClaimError::MissingCreatedBy)?;
    let pk = openom_did::decode_ed25519(did)?;
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Ok(SigCheck::Bad);
    };
    let ch = content_hash(envelope)?;
    // The seam's verify is verify_strict — additionally rejecting small-order keys / torsion components
    // (defence in depth for a load-bearing signature); the weaker plain verify is not reachable here.
    Ok(
        match vk.verify(&signing_message(&ch), &Signature::from_bytes(sig)) {
            Ok(()) => SigCheck::Valid,
            Err(_) => SigCheck::Bad,
        },
    )
}

fn signing_message(content_hash: &[u8; 32]) -> Vec<u8> {
    [SIGN_DOMAIN, content_hash.as_slice()].concat()
}

/// A value whose `id` is the hash of its own content. Every enveloped record — [`envelope::Claim`] and
/// the operations channel's `Op` — derives its id through the one canonicalization path here (JCS,
/// excluding the top-level `id` and `signature`), so there is never a second hashing implementation.
///
/// It is **not** blanket-implemented over [`Serialize`]: the excluded fields live at a *specific* depth
/// (the top level), so a type that *embeds* another record (an op embedding a [`envelope::Record`])
/// overrides [`hash_envelope`](ContentAddressed::hash_envelope) to strip the nested record's
/// `signature` before hashing — otherwise signing the inner record would shift the enclosing id. Each
/// type implements the trait explicitly.
pub trait ContentAddressed: serde::Serialize {
    /// The JSON to hash, normalized so anything excluded from the hash below the top level is already
    /// removed. Default = the plain serialization (correct for a flat envelope like [`envelope::Claim`]).
    fn hash_envelope(&self) -> Result<Value, ClaimError> {
        Ok(serde_json::to_value(self)?)
    }

    /// The content-hash id: `"sha256:" + hex(sha256(JCS(hash_envelope − id − signature)))`.
    fn content_id(&self) -> Result<String, ClaimError> {
        claim_id(&self.hash_envelope()?)
    }
}

impl ContentAddressed for envelope::Claim {}

#[cfg(test)]
mod proptests {
    use super::*;
    use openom_sign::SigningKey;
    use proptest::prelude::*;

    /// Arbitrary float-free JSON objects for a claim's `value`.
    fn arb_obj() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| Value::Number(n.into())),
            ".*".prop_map(Value::String),
        ];
        prop::collection::hash_map("[a-z]{1,6}", leaf, 0..6)
            .prop_map(|m| Value::Object(m.into_iter().collect()))
    }

    proptest! {
        // A claim signed by its createdBy key verifies; any content change flips it to Bad.
        #[test]
        fn sign_verify_and_tamper(seed in any::<[u8; 32]>(), value in arb_obj()) {
            let key = SigningKey::from_seed(&seed);
            let did = openom_did::encode_ed25519(&key.verifying_key().to_bytes());
            let mut c = envelope::Claim::new("t", "openom.org/core/name/v1", value, &did, 1);
            c.compute_id().unwrap();
            let v = c.to_value();
            let sig = sign(&v, &key).unwrap();
            prop_assert_eq!(verify(&v, &sig).unwrap(), SigCheck::Valid);

            let mut tampered = c.clone();
            tampered.created_at = c.created_at.wrapping_add(1);
            prop_assert_eq!(verify(&tampered.to_value(), &sig).unwrap(), SigCheck::Bad);
        }

        // id and fingerprint are pure functions of the envelope.
        #[test]
        fn id_and_fingerprint_deterministic(value in arb_obj()) {
            let v = envelope::Claim::new("t", "openom.org/core/name/v1", value, "did:key:z6MkX", 1).to_value();
            prop_assert_eq!(claim_id(&v).unwrap(), claim_id(&v).unwrap());
            prop_assert_eq!(fingerprint(&v).unwrap(), fingerprint(&v).unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A representative name claim on a person, authored by `author`'s did:key.
    fn claim(author_did: &str) -> Value {
        json!({
            "id": "sha256:PLACEHOLDER",
            "type": "openom.org/core/claim/v1",
            "targetId": "per_uuid",
            "predicate": "openom.org/core/name/v1",
            "value": { "parts": { "given": "Ada", "family": "Lovelace" } },
            "citation": { "sourceId": "src_hash", "locator": {}, "extract": "…" },
            "createdAt": 1771765800000_i64,
            "createdBy": author_did,
        })
    }

    fn signer(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_seed(&[seed; 32]);
        let did = openom_did::encode_ed25519(&key.verifying_key().to_bytes());
        (key, did)
    }

    #[test]
    fn id_excludes_id_and_signature_but_covers_value() {
        let (_, did) = signer(1);
        let c = claim(&did);
        let base = claim_id(&c).unwrap();
        assert!(base.starts_with("sha256:") && base.len() == 7 + 64);

        // Changing the id field or attaching a signature must not move the id.
        let mut c2 = c.clone();
        c2["id"] = json!("sha256:something-else");
        c2["signature"] = json!("AAAA");
        assert_eq!(claim_id(&c2).unwrap(), base);

        // Changing the asserted value must move it.
        let mut c3 = c.clone();
        c3["value"]["parts"]["given"] = json!("Augusta");
        assert_ne!(claim_id(&c3).unwrap(), base);
    }

    #[test]
    fn fingerprint_excludes_author_and_citation_but_not_value() {
        let (_, did_a) = signer(1);
        let (_, did_b) = signer(2);
        let fp = |v: &Value| fingerprint(v).unwrap();

        let a = claim(&did_a);
        // Same fact, different author → same fingerprint (but different id).
        let b = claim(&did_b);
        assert_eq!(fp(&a), fp(&b));
        assert_ne!(claim_id(&a).unwrap(), claim_id(&b).unwrap());

        // Same fact, different citation → same fingerprint.
        let mut c = claim(&did_a);
        c["citation"] = json!({ "sourceId": "other_src", "locator": {}, "extract": "x" });
        assert_eq!(fp(&a), fp(&c));

        // Different value → different fingerprint.
        let mut d = claim(&did_a);
        d["value"]["parts"]["family"] = json!("Byron");
        assert_ne!(fp(&a), fp(&d));
    }

    #[test]
    fn fingerprint_is_key_order_independent() {
        let (_, did) = signer(1);
        let a = claim(&did);
        let mut b = claim(&did);
        // Re-insert value with the parts in a different textual order — JCS must canonicalize both.
        b["value"] = json!({ "parts": { "family": "Lovelace", "given": "Ada" } });
        assert_eq!(fingerprint(&a).unwrap(), fingerprint(&b).unwrap());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (key, did) = signer(7);
        let c = claim(&did);
        let sig = sign(&c, &key).unwrap();
        assert_eq!(verify(&c, &sig).unwrap(), SigCheck::Valid);
    }

    #[test]
    fn tampered_content_fails_verification() {
        let (key, did) = signer(7);
        let c = claim(&did);
        let sig = sign(&c, &key).unwrap();
        let mut tampered = c.clone();
        tampered["value"]["parts"]["given"] = json!("Mallory");
        assert_eq!(verify(&tampered, &sig).unwrap(), SigCheck::Bad);
    }

    #[test]
    fn signature_from_a_key_other_than_created_by_fails() {
        let (wrong_key, _) = signer(9);
        let (_, did) = signer(7); // envelope claims author 7…
        let c = claim(&did);
        let sig = sign(&c, &wrong_key).unwrap(); // …but 9 signed it
        assert_eq!(verify(&c, &sig).unwrap(), SigCheck::Bad);
    }

    #[test]
    fn attaching_the_signature_does_not_change_the_id() {
        let (key, did) = signer(7);
        let c = claim(&did);
        let before = claim_id(&c).unwrap();
        let sig = sign(&c, &key).unwrap();
        let mut signed = c.clone();
        signed["signature"] = json!(openom_jcs::hex(&sig));
        assert_eq!(claim_id(&signed).unwrap(), before);
        // …and the signature still verifies with the field present.
        assert_eq!(verify(&signed, &sig).unwrap(), SigCheck::Valid);
    }

    #[test]
    fn id_covers_every_content_field() {
        let (_, did) = signer(1);
        let base = claim_id(&claim(&did)).unwrap();
        let moved = |mutate: &dyn Fn(&mut Value)| {
            let mut m = claim(&did);
            mutate(&mut m);
            claim_id(&m).unwrap() != base
        };
        assert!(moved(&|m| m["predicate"] = json!("openom.org/core/sex/v1")));
        assert!(moved(&|m| m["targetId"] = json!("per_other")));
        assert!(moved(&|m| m["createdAt"] = json!(1771765800001_i64)));
        assert!(moved(&|m| m["createdBy"] = json!(signer(2).1)));
        assert!(moved(&|m| m["citation"] = json!({ "sourceId": "other" })));
    }

    #[test]
    fn fingerprint_covers_target_and_predicate() {
        let (_, did) = signer(1);
        let base = fingerprint(&claim(&did)).unwrap();
        let mut t = claim(&did);
        t["targetId"] = json!("per_other");
        assert_ne!(fingerprint(&t).unwrap(), base);
        let mut p = claim(&did);
        p["predicate"] = json!("openom.org/core/sex/v1");
        assert_ne!(fingerprint(&p).unwrap(), base);
    }

    #[test]
    fn content_ref_is_stable_and_field_selective() {
        let a = json!({ "parts": { "given": "Ada" }, "script": "Latn" });
        let r1 = content_ref(&a).unwrap();
        assert!(r1.starts_with("sha256:") && r1.len() == 7 + 64);
        // JCS canonicalizes, so key order doesn't move the reference…
        let b = json!({ "script": "Latn", "parts": { "given": "Ada" } });
        assert_eq!(content_ref(&b).unwrap(), r1);
        // …but different intrinsic content does.
        assert_ne!(
            content_ref(&json!({ "parts": { "given": "Augusta" } })).unwrap(),
            r1
        );
    }

    #[test]
    fn a_did_encoding_a_non_curve_point_is_bad_not_error() {
        // A syntactically valid did:key (right multicodec + 32 bytes) whose bytes are not a valid
        // Ed25519 point must make verify() return Bad, never Err.
        let did = openom_did::encode_ed25519(&[0xff; 32]);
        let mut c = claim(&did);
        c["createdBy"] = json!(did);
        assert_eq!(verify(&c, &[0u8; 64]).unwrap(), SigCheck::Bad);
    }

    #[test]
    fn content_addressed_matches_the_claim_id_seam() {
        use crate::ContentAddressed;
        let (_, did) = signer(1);
        let c: crate::envelope::Claim = serde_json::from_value(claim(&did)).unwrap();
        assert_eq!(
            c.content_id().unwrap(),
            crate::claim_id(&c.to_value()).unwrap()
        );
    }

    #[test]
    fn verify_reports_errors_for_a_missing_or_bad_created_by() {
        let (key, did) = signer(7);
        let sig = sign(&claim(&did), &key).unwrap();

        let mut no_author = claim(&did);
        no_author.as_object_mut().unwrap().remove("createdBy");
        assert!(matches!(
            verify(&no_author, &sig),
            Err(ClaimError::MissingCreatedBy)
        ));

        let mut bad_author = claim(&did);
        bad_author["createdBy"] = json!("did:web:example.com");
        assert!(matches!(
            verify(&bad_author, &sig),
            Err(ClaimError::BadCreatedBy(_))
        ));
    }
}
