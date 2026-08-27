//! The frozen record shapes — the typed side of `record.schema.json`.
//!
//! A [`Record`] is everything the store syncs — one of three shapes:
//! - [`Anchor`] — pure identity (`id`, `type`, creation provenance); a Person/Event/Place/Tree.
//! - [`Claim`] — the universal envelope. An attestation is just a Claim with the `attest` predicate
//!   ([`Claim::attestation`]); there is no `targetType`, and — deliberately — **no tombstone claim**:
//!   deletion and edit-supersession are *operations*, not records, so they live in the operations
//!   channel as their own type and can never be handed to something expecting a [`Record`].
//! - [`Unknown`](Record::Unknown) — a record of a `type` this build doesn't recognize, kept verbatim.
//!   The forward-compat seam: an older client carries a newer version's data type through untouched
//!   instead of dropping it or halting the batch. Which types are *known* is a closed-world concern of
//!   the schema + projection layer, not this ingest boundary.
//!
//! Parsing a [`Record`] from JSON (`TryFrom<Value>`) is the parse-don't-validate ingest boundary — it
//! dispatches on `type`, verifies a Claim's content-hash `id`, and preserves an unrecognized type as
//! [`Unknown`](Record::Unknown) behind two id guards (non-empty, non-`sha256:`). The id / fingerprint /
//! signature are derived by the crate-root seam ([`crate::claim_id`] etc.); the bridge methods here
//! ([`Claim::compute_id`], …) route the typed value through it, so there is one canonicalization path.

use openom_sign::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ClaimError, Hlc};

/// Envelope `type` for every Claim (attestations + tombstones included).
pub const TYPE_CLAIM: &str = "openom.org/core/claim/v1";
pub const TYPE_PERSON: &str = "openom.org/core/person/v1";
pub const TYPE_EVENT: &str = "openom.org/core/event/v1";
pub const TYPE_PLACE: &str = "openom.org/core/place/v1";
pub const TYPE_TREE: &str = "openom.org/core/tree/v1";

pub const PREDICATE_ATTEST: &str = "openom.org/core/attest/v1";
/// The predicate of the one **existence** claim minted alongside every anchor — the proposition "this
/// individual is real", value `{}`. It is the single root a person's existence hangs on: it is the
/// citation host for evidence of existence, and other authors support/refute it via `attest` rather
/// than minting their own. Auto-minted by the engine (see `openom_tree::Tree::assert_anchor`).
pub const PREDICATE_EXISTENCE: &str = "openom.org/core/existence/v1";

/// A pure identity anchor: `{ id, type, createdAt, createdBy }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anchor {
    pub id: String,
    #[serde(rename = "type")]
    pub type_uri: String,
    pub created_at: Hlc,
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

/// The target of an attestation: *either* a specific claim (by its content-hash `id`) *or* a fact (by
/// its `fingerprint`, so the vote follows the fact across authors and re-imports — §4.1). Both are
/// `sha256:…` strings; this enum forces the writer to declare which, so a claim id and a fingerprint
/// can't be conflated at the one place attestations are built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestTarget {
    /// A specific claim instance, by its content-hash `id`.
    Claim(String),
    /// A fact, by its dedup `fingerprint` (`sha256:` hex).
    Fingerprint(String),
}

impl AttestTarget {
    /// The `sha256:` string stored as the attestation's `targetId`.
    pub fn as_str(&self) -> &str {
        match self {
            AttestTarget::Claim(s) | AttestTarget::Fingerprint(s) => s,
        }
    }
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
    pub created_at: Hlc,
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
        created_at: Hlc,
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

    /// An attestation (`support`/`reject`) targeting a claim (by id) or a fact (by fingerprint) — the
    /// [`AttestTarget`] forces the caller to say which, so the two `sha256:` string kinds can't be
    /// conflated here.
    pub fn attestation(
        target: &AttestTarget,
        verdict: Verdict,
        reason: Option<String>,
        created_by: impl Into<String>,
        created_at: Hlc,
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
            target.as_str(),
            PREDICATE_ATTEST,
            Value::Object(value),
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

    /// The authorship judgment for the embedded `signature` against this claim's content and
    /// `createdBy` key. **Fail-closed**: an unsigned claim is [`Unsigned`](crate::Authorship::Unsigned);
    /// a present signature that verifies is [`Verified`](crate::Authorship::Verified); anything else — a
    /// bad signature, a malformed signature string, or an undecodable `createdBy`/content — is
    /// [`Forged`](crate::Authorship::Forged). There is no error or `Option` for a caller to unwrap past
    /// a forgery.
    pub fn verify(&self) -> crate::Authorship {
        use crate::Authorship;
        let Some(sig_hex) = &self.signature else {
            return Authorship::Unsigned;
        };
        match hex_decode_64(sig_hex) {
            // A verify error (undecodable key, unhashable content) folds to Forged — never trust it.
            Some(sig) => match crate::verify(&self.to_value(), &sig) {
                Ok(crate::SigCheck::Valid) => Authorship::Verified,
                _ => Authorship::Forged,
            },
            None => Authorship::Forged,
        }
    }

    /// Does `id` still match a fresh hash of the current fields? Returns `false` if the claim was
    /// mutated after [`compute_id`](Claim::compute_id) — a cheap guard against a stale id. (An empty
    /// `id`, before `compute_id`, is never current.)
    pub fn id_is_current(&self) -> Result<bool, ClaimError> {
        Ok(self.id == crate::claim_id(&self.to_value())?)
    }
}

/// A record the store syncs: a pure-identity [`Anchor`], a [`Claim`], or an [`Unknown`](Record::Unknown)
/// record whose `type` this build doesn't recognize — the claim-model **data**. Operations (delete,
/// edit-supersession) are **not** records; they live in the operations channel as their own type, so an
/// operation can never be passed where a `Record` is expected (the projection, the exporter). This is
/// the coarse data-vs-operations boundary made a compile-time fact.
///
/// `Unknown` is the forward-compatibility seam: the mechanism (this crate + `openom-crdt`) treats a
/// record's `type` as **shape**, not **vocabulary** — it folds records by id and author and never needs
/// to know what a type *means*. So a record of a type introduced by a newer app version is preserved
/// verbatim rather than rejected: an older client carries it through the fold and re-syncs it untouched
/// instead of dropping it or halting the batch. Deciding which types are *known* (and rendering them) is
/// a closed-world concern that lives in the schema + projection layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Record {
    Anchor(Anchor),
    Claim(Claim),
    /// A record whose `type` is neither [`TYPE_CLAIM`] nor a known anchor type — kept as its full,
    /// original JSON so it round-trips byte-for-byte. Its `id` is guaranteed present, non-empty, and
    /// **not** content-addressed (`sha256:…`) — see [`Record::try_from`].
    Unknown(Value),
}

impl<'de> Deserialize<'de> for Record {
    /// Deserialize routes through [`Record::try_from`], so the same parse-don't-validate ingest
    /// boundary (dispatch on `type`; verify a claim's content-hash id) applies whether a record is read
    /// from a JSON document or deserialized while embedded in an operation — there is no id-skipping
    /// path. `Serialize` is a plain untagged serialization of the inner `Anchor`/`Claim`.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Record::try_from(v).map_err(serde::de::Error::custom)
    }
}

impl Record {
    /// The record's id (`sha256:…` for a Claim, a UUID for an Anchor, the preserved `id` for an Unknown).
    pub fn id(&self) -> &str {
        match self {
            Record::Anchor(a) => &a.id,
            Record::Claim(c) => &c.id,
            Record::Unknown(v) => v.get("id").and_then(Value::as_str).unwrap_or_default(),
        }
    }

    /// The record's envelope `type` URI.
    pub fn type_uri(&self) -> &str {
        match self {
            Record::Anchor(a) => &a.type_uri,
            Record::Claim(c) => &c.type_uri,
            Record::Unknown(v) => v.get("type").and_then(Value::as_str).unwrap_or_default(),
        }
    }

    /// Serialize back to the canonical JSON envelope. For an [`Unknown`](Record::Unknown) this is the
    /// original JSON verbatim, so a type this build doesn't understand re-syncs unchanged.
    pub fn to_value(&self) -> Value {
        match self {
            Record::Anchor(a) => serde_json::to_value(a).expect("Anchor serializes"),
            Record::Claim(c) => c.to_value(),
            Record::Unknown(v) => v.clone(),
        }
    }

    /// The record's author (`createdBy`).
    pub fn created_by(&self) -> &str {
        match self {
            Record::Anchor(a) => &a.created_by,
            Record::Claim(c) => &c.created_by,
            Record::Unknown(v) => v
                .get("createdBy")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        }
    }

    /// The record's creation timestamp (`createdAt`; provenance only, never a tiebreak). An
    /// [`Unknown`](Record::Unknown) record's `createdAt` is parsed from its preserved JSON, falling back
    /// to the epoch if it is absent or in a form this build doesn't recognize.
    pub fn created_at(&self) -> Hlc {
        match self {
            Record::Anchor(a) => a.created_at,
            Record::Claim(c) => c.created_at,
            Record::Unknown(v) => v
                .get("createdAt")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<Value> for Record {
    type Error = ClaimError;

    /// The parse-don't-validate ingest boundary: dispatch on `type`, deserialize the matching shape,
    /// and — for a Claim, whose `id` is content-derived — verify the stored id equals a fresh hash of
    /// its content (an Anchor's id is a random UUID, so there is nothing to recompute). A `type` this
    /// build doesn't recognize is **not** rejected: it is preserved verbatim as an
    /// [`Unknown`](Record::Unknown) (the forward-compat seam) after the two id guards below. After this,
    /// a `Record` in hand means "a well-formed record whose id is correct or opaque-but-safe".
    fn try_from(v: Value) -> Result<Self, Self::Error> {
        let type_uri = v
            .get("type")
            .and_then(Value::as_str)
            .ok_or(ClaimError::MissingType)?
            .to_owned();
        match type_uri.as_str() {
            TYPE_CLAIM => {
                let c: Claim =
                    serde_json::from_value(v).map_err(|e| ClaimError::Malformed("claim", e))?;
                if !c.id_is_current()? {
                    return Err(ClaimError::IdMismatch);
                }
                Ok(Record::Claim(c))
            }
            TYPE_PERSON | TYPE_EVENT | TYPE_PLACE | TYPE_TREE => {
                let a: Anchor =
                    serde_json::from_value(v).map_err(|e| ClaimError::Malformed("anchor", e))?;
                Ok(Record::Anchor(a))
            }
            // Unknown type: preserve opaquely so newer-version data flows through an older client
            // untouched. Two guards keep the fold sound: the record must have a non-empty string `id`
            // (the fold keys on it), and that id must NOT be content-addressed (`sha256:…`) — those are
            // reserved for claims/ops, and first-writer-wins-by-id would otherwise let an unknown record
            // squat a claim's slot. A legitimate new anchor type uses a UUID id, so it passes.
            _ => {
                let id = v
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or(ClaimError::MissingId)?;
                if id.starts_with("sha256:") {
                    return Err(ClaimError::ReservedId(id.to_owned()));
                }
                Ok(Record::Unknown(v))
            }
        }
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

    /// A logical-counter-zero HLC at `ms` epoch-milliseconds, for test fixtures.
    fn hlc(ms: i64) -> Hlc {
        Hlc::new(ms, 0)
    }

    fn author() -> (SigningKey, String) {
        let key = SigningKey::from_seed(&[5u8; 32]);
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
            hlc(1771765800000),
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
    fn attestation_shape() {
        let (_, did) = author();
        let att = Claim::attestation(
            &AttestTarget::Claim("sha256:aa".into()),
            Verdict::Reject,
            Some("1850 census".into()),
            &did,
            hlc(1),
        );
        assert_eq!(att.predicate, PREDICATE_ATTEST);
        assert_eq!(
            att.value,
            json!({ "verdict": "reject", "reason": "1850 census" })
        );
    }

    #[test]
    fn record_try_from_dispatches_and_verifies_the_id() {
        let (_, did) = author();

        // A valid claim parses as Record::Claim…
        let mut c = Claim::new(
            "per_uuid",
            "openom.org/core/name/v1",
            json!({ "x": 1 }),
            &did,
            hlc(1),
        );
        c.compute_id().unwrap();
        let rec = Record::try_from(c.to_value()).unwrap();
        assert!(matches!(rec, Record::Claim(_)));
        assert_eq!(rec.id(), c.id.as_str());

        // …a person anchor parses as Record::Anchor…
        let anchor = json!({
            "id": "b3d3f6b0-0000-4000-8000-000000000002",
            "type": TYPE_PERSON, "createdAt": hlc(1).to_string(), "createdBy": did,
        });
        assert!(matches!(
            Record::try_from(anchor).unwrap(),
            Record::Anchor(_)
        ));

        // …a claim whose id no longer matches its content is rejected (parse-don't-validate)…
        let mut tampered = c.to_value();
        tampered["value"] = json!({ "x": 2 });
        assert!(matches!(
            Record::try_from(tampered),
            Err(crate::ClaimError::IdMismatch)
        ));

        // …an unknown type is now PRESERVED opaquely (forward-compat), not rejected…
        let widget = json!({
            "id": "widget-uuid", "type": "openom.org/core/widget/v1",
            "createdAt": 1, "createdBy": did, "extra": { "n": 1 },
        });
        let rec = Record::try_from(widget.clone()).unwrap();
        assert!(matches!(rec, Record::Unknown(_)));
        assert_eq!(
            rec.to_value(),
            widget,
            "an unknown type round-trips verbatim"
        );

        // …but a missing type is still rejected.
        assert!(matches!(
            Record::try_from(json!({})),
            Err(crate::ClaimError::MissingType)
        ));
    }

    #[test]
    fn unknown_records_are_preserved_but_guarded() {
        let (_, did) = author();

        // A novel anchor type with a UUID id is preserved verbatim — including a field a typed Anchor
        // would drop (`tonnage`), so nothing is lost when an older client carries it forward.
        let vessel = json!({
            "id": "vessel-uuid", "type": "openom.org/core/vessel/v1",
            "createdAt": hlc(7).to_string(), "createdBy": did, "tonnage": 200,
        });
        let rec = Record::try_from(vessel.clone()).unwrap();
        assert!(matches!(rec, Record::Unknown(_)));
        assert_eq!(rec.id(), "vessel-uuid");
        assert_eq!(rec.type_uri(), "openom.org/core/vessel/v1");
        assert_eq!(rec.created_by(), did);
        assert_eq!(rec.created_at(), hlc(7), "createdAt parsed from the preserved JSON string");
        assert_eq!(rec.to_value(), vessel);

        // Deserialize (the embedded-in-an-operation path) routes through the same boundary.
        let back: Record = serde_json::from_value(vessel.clone()).unwrap();
        assert_eq!(back, Record::Unknown(vessel));

        // An unknown type with no id can't be folded (the fold keys on id) → rejected.
        assert!(matches!(
            Record::try_from(json!({ "type": "openom.org/core/vessel/v1" })),
            Err(crate::ClaimError::MissingId)
        ));
        // An unknown type carrying a content-addressed id would squat a claim's slot → rejected.
        assert!(matches!(
            Record::try_from(json!({
                "id": "sha256:deadbeef", "type": "openom.org/core/vessel/v1",
                "createdAt": 1, "createdBy": did,
            })),
            Err(crate::ClaimError::ReservedId(_))
        ));
    }

    #[test]
    fn record_serde_roundtrips_and_verifies_embedded_ids() {
        let (_, did) = author();
        let mut c = Claim::new(
            "per_uuid",
            "openom.org/core/name/v1",
            json!({ "given": "Ada" }),
            &did,
            hlc(1),
        );
        c.compute_id().unwrap();
        let rec = Record::Claim(c);

        // Serialize → Deserialize round-trips; Deserialize goes through the verifying TryFrom.
        let back: Record = serde_json::from_value(serde_json::to_value(&rec).unwrap()).unwrap();
        assert_eq!(back, rec);

        // A tampered id (content changed, id now stale) fails at deserialize — not only at top-level
        // ingest, so an operation embedding a forged replacement record is rejected too.
        let mut tampered = serde_json::to_value(&rec).unwrap();
        tampered["value"] = json!({ "given": "Mallory" });
        assert!(serde_json::from_value::<Record>(tampered).is_err());
    }

    #[test]
    fn compute_id_then_sign_keeps_the_id() {
        let (key, did) = author();
        let mut c = Claim::new(
            "per_uuid",
            "openom.org/core/name/v1",
            json!({ "x": 1 }),
            &did,
            hlc(1),
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
            hlc(1),
        );
        c.compute_id().unwrap();
        assert_eq!(c.verify(), crate::Authorship::Unsigned, "unsigned");
        assert!(c.id_is_current().unwrap());

        c.sign_with(&key).unwrap();
        assert_eq!(c.verify(), crate::Authorship::Verified);
        assert!(c.id_is_current().unwrap(), "signing must not move the id");

        // Mutating content after computing the id/signature invalidates both — detectably.
        c.value = json!({ "x": 2 });
        assert!(!c.id_is_current().unwrap());
        assert_eq!(c.verify(), crate::Authorship::Forged);

        // A malformed signature string is Forged (fail-closed), not an error.
        c.signature = Some("zz".into());
        assert_eq!(c.verify(), crate::Authorship::Forged);
    }

    #[test]
    fn citation_accepts_one_or_many() {
        let one: Claim = serde_json::from_value(json!({
            "id": "sha256:x", "type": TYPE_CLAIM, "targetId": "t", "predicate": "openom.org/core/name/v1",
            "value": {}, "citation": { "sourceId": "s" }, "createdAt": hlc(1).to_string(), "createdBy": "did:key:z6MkX"
        }))
        .unwrap();
        assert!(matches!(one.citation, Some(Citations::One(_))));

        let many: Claim = serde_json::from_value(json!({
            "id": "sha256:x", "type": TYPE_CLAIM, "targetId": "t", "predicate": "openom.org/core/name/v1",
            "value": {}, "citation": [{ "sourceId": "s1" }, { "sourceId": "s2" }], "createdAt": hlc(1).to_string(), "createdBy": "did:key:z6MkX"
        }))
        .unwrap();
        assert!(matches!(many.citation, Some(Citations::Many(v)) if v.len() == 2));
    }
}
