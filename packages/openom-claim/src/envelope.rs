//! The frozen record shapes — the typed side of `record.schema.json`.
//!
//! Two shapes cover everything the store syncs:
//! - [`Anchor`] — pure identity (`id`, `type`, creation provenance); a Person/Event/Place/Tree.
//! - [`Claim`] — the universal envelope. Attestations and tombstones are just Claims with a specific
//!   `predicate` (there is no `targetType`); [`Claim::attestation`] / [`Claim::tombstone`] build them.
//!
//! The id / fingerprint / signature are derived by the crate-root seam ([`crate::claim_id`] etc.);
//! the bridge methods here ([`Claim::compute_id`], [`Claim::fingerprint`], [`Claim::sign_with`]) route
//! the typed value through it, so there is exactly one canonicalization path.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ClaimError;

/// Envelope `type` for every Claim (attestations + tombstones included).
pub const TYPE_CLAIM: &str = "openom.org/core/claim/v1";
pub const TYPE_PERSON: &str = "openom.org/core/person/v1";
pub const TYPE_EVENT: &str = "openom.org/core/event/v1";
pub const TYPE_PLACE: &str = "openom.org/core/place/v1";
pub const TYPE_TREE: &str = "openom.org/core/tree/v1";

pub const PREDICATE_ATTEST: &str = "openom.org/core/attest/v1";
pub const PREDICATE_TOMBSTONE: &str = "openom.org/core/tombstone/v1";

/// A pure identity anchor: `{ id, type, createdAt, createdBy }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anchor {
    pub id: String,
    #[serde(rename = "type")]
    pub type_uri: String,
    pub created_at: i64,
    pub created_by: String,
}

/// One citation: inline evidence for a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Citation {
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract: Option<String>,
}

/// `citation` may be a single object or an array (one assertion backed by several sources).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Citations {
    One(Citation),
    Many(Vec<Citation>),
}

/// An attestation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Support,
    Reject,
}

/// The universal claim envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    /// `"sha256:<hex>"` content-hash id; empty until [`Claim::compute_id`].
    pub id: String,
    #[serde(rename = "type")]
    pub type_uri: String,
    pub target_id: String,
    pub predicate: String,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citation: Option<Citations>,
    pub created_at: i64,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Claim {
    /// A claim asserting `value` under `predicate` about `target_id`. `id` starts empty — call
    /// [`compute_id`](Claim::compute_id) once the fields are final.
    pub fn new(
        target_id: impl Into<String>,
        predicate: impl Into<String>,
        value: Value,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Claim {
            id: String::new(),
            type_uri: TYPE_CLAIM.to_string(),
            target_id: target_id.into(),
            predicate: predicate.into(),
            value,
            citation: None,
            created_at,
            created_by: created_by.into(),
            signature: None,
        }
    }

    /// An attestation (`support`/`reject`) targeting a claim id or fingerprint.
    pub fn attestation(
        target: impl Into<String>,
        verdict: Verdict,
        reason: Option<String>,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        let mut value = serde_json::Map::new();
        value.insert(
            "verdict".into(),
            serde_json::to_value(verdict).expect("verdict serializes"),
        );
        if let Some(r) = reason {
            value.insert("reason".into(), Value::String(r));
        }
        Claim::new(
            target,
            PREDICATE_ATTEST,
            Value::Object(value),
            created_by,
            created_at,
        )
    }

    /// A tombstone removing the record `target` (by its id). Empty value; authority is role-gated by
    /// the projection, not here.
    pub fn tombstone(
        target: impl Into<String>,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Claim::new(
            target,
            PREDICATE_TOMBSTONE,
            Value::Object(serde_json::Map::new()),
            created_by,
            created_at,
        )
    }

    /// Serialize to the canonical JSON envelope.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("Claim serializes")
    }

    /// Compute and set `id = "sha256:" + hex(content_hash)`. Independent of the current `id` and any
    /// `signature` (both excluded from the hash), so it is safe to call before or after signing.
    pub fn compute_id(&mut self) -> Result<(), ClaimError> {
        self.id = crate::claim_id(&self.to_value())?;
        Ok(())
    }

    /// The dedup fingerprint of this claim.
    pub fn fingerprint(&self) -> Result<[u8; 32], ClaimError> {
        crate::fingerprint(&self.to_value())
    }

    /// Sign with the author's key (must match `createdBy`) and store the hex signature. The signature
    /// is excluded from the id, so calling this after [`compute_id`](Claim::compute_id) leaves the id
    /// unchanged.
    pub fn sign_with(&mut self, key: &SigningKey) -> Result<(), ClaimError> {
        let sig = crate::sign(&self.to_value(), key)?;
        self.signature = Some(openom_jcs::hex(&sig));
        Ok(())
    }

    /// Verify the embedded `signature` against this claim's content and `createdBy` key. `Ok(None)`
    /// when unsigned; a malformed signature string is `Ok(Some(SigCheck::Bad))`.
    pub fn verify(&self) -> Result<Option<crate::SigCheck>, ClaimError> {
        let Some(sig_hex) = &self.signature else {
            return Ok(None);
        };
        match hex_decode_64(sig_hex) {
            Some(sig) => Ok(Some(crate::verify(&self.to_value(), &sig)?)),
            None => Ok(Some(crate::SigCheck::Bad)),
        }
    }

    /// Does `id` still match a fresh hash of the current fields? Returns `false` if the claim was
    /// mutated after [`compute_id`](Claim::compute_id) — a cheap guard against a stale id. (An empty
    /// `id`, before `compute_id`, is never current.)
    pub fn id_is_current(&self) -> Result<bool, ClaimError> {
        Ok(self.id == crate::claim_id(&self.to_value())?)
    }
}

/// Decode a 128-char lowercase/uppercase hex string into 64 bytes; `None` if not exactly 128 hex chars.
fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    let b = s.as_bytes();
    if b.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn author() -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let did = openom_did::encode_ed25519(&key.verifying_key().to_bytes());
        (key, did)
    }

    #[test]
    fn claim_roundtrips_and_ids_match_the_seam() {
        let (_, did) = author();
        let mut c = Claim::new(
            "per_uuid",
            "openom.org/core/name/v1",
            json!({ "parts": { "given": "Ada" } }),
            &did,
            1771765800000,
        );
        c.compute_id().unwrap();

        assert!(c.id.starts_with("sha256:"));
        // The typed id equals the seam computed directly over the value.
        assert_eq!(c.id, crate::claim_id(&c.to_value()).unwrap());
        // Round-trips through JSON.
        let back: Claim = serde_json::from_value(c.to_value()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn attestation_and_tombstone_shapes() {
        let (_, did) = author();
        let att = Claim::attestation(
            "sha256:aa",
            Verdict::Reject,
            Some("1850 census".into()),
            &did,
            1,
        );
        assert_eq!(att.predicate, PREDICATE_ATTEST);
        assert_eq!(
            att.value,
            json!({ "verdict": "reject", "reason": "1850 census" })
        );

        let tomb = Claim::tombstone("sha256:bb", &did, 2);
        assert_eq!(tomb.predicate, PREDICATE_TOMBSTONE);
        assert_eq!(tomb.value, json!({}));
    }

    #[test]
    fn compute_id_then_sign_keeps_the_id() {
        let (key, did) = author();
        let mut c = Claim::new(
            "per_uuid",
            "openom.org/core/name/v1",
            json!({ "x": 1 }),
            &did,
            1,
        );
        c.compute_id().unwrap();
        let id_before = c.id.clone();
        c.sign_with(&key).unwrap();
        assert!(c.signature.is_some());
        assert_eq!(c.id, id_before, "signing must not move the id");
        // And the stored id still equals a fresh computation over the now-signed value.
        assert_eq!(c.id, crate::claim_id(&c.to_value()).unwrap());
    }

    #[test]
    fn typed_verify_and_id_drift_detection() {
        let (key, did) = author();
        let mut c = Claim::new(
            "per_uuid",
            "openom.org/core/name/v1",
            json!({ "x": 1 }),
            &did,
            1,
        );
        c.compute_id().unwrap();
        assert!(c.verify().unwrap().is_none(), "unsigned → None");
        assert!(c.id_is_current().unwrap());

        c.sign_with(&key).unwrap();
        assert_eq!(c.verify().unwrap(), Some(crate::SigCheck::Valid));
        assert!(c.id_is_current().unwrap(), "signing must not move the id");

        // Mutating content after computing the id/signature invalidates both — detectably.
        c.value = json!({ "x": 2 });
        assert!(!c.id_is_current().unwrap());
        assert_eq!(c.verify().unwrap(), Some(crate::SigCheck::Bad));

        // A malformed signature string is Bad, not an error.
        c.signature = Some("zz".into());
        assert_eq!(c.verify().unwrap(), Some(crate::SigCheck::Bad));
    }

    #[test]
    fn citation_accepts_one_or_many() {
        let one: Claim = serde_json::from_value(json!({
            "id": "sha256:x", "type": TYPE_CLAIM, "targetId": "t", "predicate": "openom.org/core/name/v1",
            "value": {}, "citation": { "sourceId": "s" }, "createdAt": 1, "createdBy": "did:key:z6MkX"
        }))
        .unwrap();
        assert!(matches!(one.citation, Some(Citations::One(_))));

        let many: Claim = serde_json::from_value(json!({
            "id": "sha256:x", "type": TYPE_CLAIM, "targetId": "t", "predicate": "openom.org/core/name/v1",
            "value": {}, "citation": [{ "sourceId": "s1" }, { "sourceId": "s2" }], "createdAt": 1, "createdBy": "did:key:z6MkX"
        }))
        .unwrap();
        assert!(matches!(many.citation, Some(Citations::Many(v)) if v.len() == 2));
    }
}
