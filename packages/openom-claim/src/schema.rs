//! JSON Schema (Draft 2020-12) validation of a serialized record against the frozen shape.
//!
//! Behind the `validation` feature and off the default/wasm build, so `jsonschema` never bloats the
//! browser bundle (mirrors `openom-model::schema`). The schema is the frozen contract; Rust re-derives
//! and checks the id/fingerprint/signature separately (the crate-root seam), since a JSON Schema can
//! constrain shape but not verify a content hash.

use serde_json::Value;

/// A compiled validator for `record.schema.json` (Draft 2020-12).
pub struct RecordSchema {
    validator: jsonschema::Validator,
}

impl RecordSchema {
    /// Compile the checked-in record schema.
    pub fn new() -> Self {
        let schema: Value = serde_json::from_str(include_str!("../schema/record.schema.json"))
            .expect("record.schema.json is valid JSON");
        let validator = jsonschema::options()
            .build(&schema)
            .expect("record.schema.json is a valid schema");
        Self { validator }
    }

    /// Does `instance` satisfy the schema (is it a valid Anchor or Claim)?
    pub fn is_valid(&self, instance: &Value) -> bool {
        self.validator.is_valid(instance)
    }
}

impl Default for RecordSchema {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{AttestTarget, Claim, Verdict, TYPE_PERSON};
    use crate::Hlc;
    use edsign::SigningKey;
    use serde_json::json;

    fn did() -> String {
        let key = SigningKey::from_seed(&[3u8; 32]);
        did::encode_ed25519(&key.verifying_key().to_bytes())
    }

    /// A logical-counter-zero HLC at `ms` epoch-milliseconds, for test fixtures.
    fn hlc(ms: i64) -> Hlc {
        Hlc::new(ms, 0)
    }

    #[test]
    fn a_real_claim_and_anchor_validate() {
        let s = RecordSchema::new();
        let d = did();

        let mut c = Claim::new(
            "b3d3f6b0-0000-4000-8000-000000000001",
            "openom.org/core/name/v1",
            json!({ "parts": { "given": "Ada", "family": "Lovelace" } }),
            &d,
            hlc(1771765800000),
        );
        c.compute_id().unwrap();
        assert!(s.is_valid(&c.to_value()), "a real name claim must validate");

        let anchor = json!({
            "id": "b3d3f6b0-0000-4000-8000-000000000002",
            "type": TYPE_PERSON,
            "createdAt": hlc(1771765800000).to_string(),
            "createdBy": d,
        });
        assert!(s.is_valid(&anchor), "a person anchor must validate");
    }

    #[test]
    fn attestation_value_is_constrained() {
        let s = RecordSchema::new();
        let d = did();

        let mut good = Claim::attestation(&AttestTarget::Claim("sha256:aa".into()), Verdict::Support, None, &d, hlc(1));
        good.compute_id().unwrap();
        assert!(s.is_valid(&good.to_value()));

        // A bad verdict is rejected by the attest refinement.
        let mut bad = good.clone();
        bad.value = json!({ "verdict": "maybe" });
        bad.compute_id().unwrap();
        assert!(
            !s.is_valid(&bad.to_value()),
            "verdict must be support|reject"
        );
    }

    #[test]
    fn junk_and_malformed_ids_are_rejected() {
        let s = RecordSchema::new();
        let d = did();
        assert!(!s.is_valid(&json!({})));

        // A claim with a non-sha256 id fails the pattern.
        let mut c = Claim::new("t", "openom.org/core/name/v1", json!({}), &d, hlc(1));
        c.compute_id().unwrap();
        let mut bad_id = c.to_value();
        bad_id["id"] = json!("not-a-hash");
        assert!(!s.is_valid(&bad_id));

        // A claim with the wrong `type` const fails.
        let mut bad_type = c.to_value();
        bad_type["type"] = json!("openom.org/core/person/v1");
        assert!(!s.is_valid(&bad_type));

        // A non-did createdBy fails the pattern.
        let mut bad_author = c.to_value();
        bad_author["createdBy"] = json!("alice");
        assert!(!s.is_valid(&bad_author));

        // An anchor with a malformed uuid id fails (pattern enforced, not just the `format` annotation).
        assert!(!s.is_valid(&json!({
            "id": "not-a-uuid", "type": TYPE_PERSON, "createdAt": hlc(1).to_string(), "createdBy": d
        })));

        // A claim with a non-hex signature fails the signature pattern.
        let mut bad_sig = c.to_value();
        bad_sig["signature"] = json!("nothex");
        assert!(!s.is_valid(&bad_sig));
    }
}
