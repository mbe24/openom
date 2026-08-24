//! The claim-envelope hashing + signing seam (design.data-model-claims.v1.md §4).
//!
//! Every disputable fact is a **Claim** carried in a uniform envelope
//! `{ id, type, targetId, predicate, value, citation?, createdAt, createdBy, signature? }`. Three
//! derived quantities hang off that envelope, and getting their byte-inputs exactly right is
//! load-bearing — a divergence forks ids and corrupts dedup/refutation memory with no error anywhere:
//!
//! - **`id`** = `"sha256:" + hex( sha256( JCS(envelope, id & signature excluded) ) )`. Covers
//!   type/targetId/predicate/value/citation/createdAt/createdBy. Excluding `id` avoids self-reference;
//!   excluding `signature` makes the id identical whether or not the record is signed.
//! - **`fingerprint`** = `sha256( JCS(targetId, predicate, value) )`. Excludes `createdBy` and
//!   `citation`, so the same fact by different authors or with different sources shares one
//!   fingerprint — that is what makes corroboration count distinct authors and lets a re-import inherit
//!   a refuted fact's `reject`s (§4.2).
//! - **signature** (optional, tree-level `signed_claims`) = Ed25519 over `DOMAIN‖content_hash` by the
//!   key behind `createdBy` (a `did:key`). Domain-separated so it can't be replayed elsewhere;
//!   excluded from both the id and the fingerprint.
//!
//! This operates on the envelope as a [`serde_json::Value`]; the typed envelope struct + JSON Schema
//! are frozen separately (OPE-170) and reuse these primitives.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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
/// elsewhere in the system (mirrors `openom-attestations`' domain prefix).
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
    // verify_strict additionally rejects small-order keys / torsion components (defence in depth for
    // a load-bearing signature) — standard verify already rejects the non-canonical-S malleability.
    Ok(
        match vk.verify_strict(&signing_message(&ch), &Signature::from_bytes(sig)) {
            Ok(()) => SigCheck::Valid,
            Err(_) => SigCheck::Bad,
        },
    )
}

fn signing_message(content_hash: &[u8; 32]) -> Vec<u8> {
    [SIGN_DOMAIN, content_hash.as_slice()].concat()
}

#[cfg(test)]
mod proptests {
    use super::*;
    use ed25519_dalek::SigningKey;
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
            let key = SigningKey::from_bytes(&seed);
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
        let key = SigningKey::from_bytes(&[seed; 32]);
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
    fn a_did_encoding_a_non_curve_point_is_bad_not_error() {
        // A syntactically valid did:key (right multicodec + 32 bytes) whose bytes are not a valid
        // Ed25519 point must make verify() return Bad, never Err.
        let did = openom_did::encode_ed25519(&[0xff; 32]);
        let mut c = claim(&did);
        c["createdBy"] = json!(did);
        assert_eq!(verify(&c, &[0u8; 64]).unwrap(), SigCheck::Bad);
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
