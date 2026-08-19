//! Signed attestations — an independent **sidecar**, never tree ops (see `plan/design.attestations.md`).
//!
//! A member vouches for a fact by Ed25519-signing that fact's canonical content hash
//! (`openom-model::content_hash`). Signed, not zero-knowledge: a signature attributes the claim and
//! is tamper-evident. The sidecar is its own document that **rides the generic `journal` substrate**
//! (a snapshot + an op-log): [`AttestationDoc`] is the snapshot, [`AttestOp`] is an update — see
//! [`AttestationDoc::to_snapshot`] / [`AttestationDoc::encode_op`].
//!
//! Scope of THIS crate = the **mechanism**: the record, signature verification, and the document's
//! merge semantics (concurrent attests union; revoke tombstones then hard-purges on compaction).
//! It deliberately does NOT decide **who** may attest/revoke (role authority = OPE-104) or **whose
//! key this is** (the attester registry = OPE-105) — resolution and authorization are layered on top.
//! The write surface gets its own server-side abuse meter (a new metered endpoint, like the
//! delta-log meter) — that lives in the server track, not here.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain-separation prefix so an attestation signature can never be replayed as some other Ed25519
/// signature elsewhere in the system.
const DOMAIN: &[u8] = b"openom-attestation-v1";

/// An Ed25519 public key (the attester identity — resolved to a person by the registry, OPE-105).
pub type PubKey = [u8; 32];
/// A fact's canonical content hash (`openom-model::content_hash`) — the binding target.
pub type FactHash = [u8; 32];

/// One member's signed vouch for a fact.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub attester: PubKey,
    pub fact_hash: FactHash,
    /// Ed25519 signature (64 bytes) over `DOMAIN ‖ fact_hash`.
    pub signature: Vec<u8>,
}

impl Attestation {
    /// Sign a vouch for `fact_hash` with `key`.
    pub fn create(key: &SigningKey, fact_hash: FactHash) -> Self {
        let signature = key.sign(&Self::message(&fact_hash)).to_bytes().to_vec();
        Attestation { attester: key.verifying_key().to_bytes(), fact_hash, signature }
    }

    /// Verify the signature attributes `fact_hash` to `attester`. Pure cryptography — independent of
    /// any registry or role check.
    pub fn verify(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.attester) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = self.signature.as_slice().try_into() else {
            return false;
        };
        vk.verify(&Self::message(&self.fact_hash), &Signature::from_bytes(&sig_bytes)).is_ok()
    }

    fn message(fact_hash: &FactHash) -> Vec<u8> {
        [DOMAIN, fact_hash.as_slice()].concat()
    }

    fn key(&self) -> (PubKey, FactHash) {
        (self.attester, self.fact_hash)
    }
}

/// A change to the sidecar.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AttestOp {
    Attest(Attestation),
    Revoke { attester: PubKey, fact_hash: FactHash },
}

/// Errors applying or decoding ops.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum AttestError {
    #[error("attestation signature does not verify")]
    BadSignature,
    #[error("malformed sidecar bytes")]
    Decode,
}

/// The attestation sidecar document. Active vouches, plus tombstones for revoked (attester, fact)
/// pairs so a re-delivered attest can't resurrect a revoke — until compaction hard-purges them.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttestationDoc {
    active: Vec<Attestation>,
    revoked: Vec<(PubKey, FactHash)>,
}

impl AttestationDoc {
    pub fn new() -> Self {
        Self::default()
    }

    fn is_revoked(&self, key: &(PubKey, FactHash)) -> bool {
        self.revoked.iter().any(|r| r == key)
    }

    /// Apply one op. An `Attest` whose signature doesn't verify is rejected. A valid attest unions
    /// into the set — concurrent attests of distinct (attester, fact) all coexist, and the same
    /// (attester, fact) is idempotent — unless that key is tombstoned (revoke wins until compaction).
    /// `Revoke` removes the vouch and tombstones the key. Authority (who may do this) is OPE-104's job.
    pub fn apply(&mut self, op: AttestOp) -> Result<(), AttestError> {
        match op {
            AttestOp::Attest(a) => {
                if !a.verify() {
                    return Err(AttestError::BadSignature);
                }
                let key = a.key();
                if !self.is_revoked(&key) && !self.active.iter().any(|x| x.key() == key) {
                    self.active.push(a);
                }
            }
            AttestOp::Revoke { attester, fact_hash } => {
                let key = (attester, fact_hash);
                self.active.retain(|x| x.key() != key);
                if !self.is_revoked(&key) {
                    self.revoked.push(key);
                }
            }
        }
        Ok(())
    }

    /// Active vouches for a given fact.
    pub fn for_fact<'a>(&'a self, fact_hash: &'a FactHash) -> impl Iterator<Item = &'a Attestation> {
        self.active.iter().filter(move |a| &a.fact_hash == fact_hash)
    }

    /// Is there an active vouch by `attester` on `fact_hash`?
    pub fn is_attested(&self, attester: &PubKey, fact_hash: &FactHash) -> bool {
        self.active.iter().any(|a| &a.attester == attester && &a.fact_hash == fact_hash)
    }

    /// Compaction: **hard-purge** — drop the revoke tombstones so a revoked vouch leaves no trace
    /// (the bad-divorce / known-liar case). Stability-gated by the caller: only compact past the
    /// point every replica has seen the revokes, else a lagging re-delivered attest could resurrect
    /// one (the same accepted caveat as any tombstone GC).
    pub fn compact(&mut self) {
        self.revoked.clear();
    }

    // --- journal substrate: the doc is the snapshot, an op is an update ---

    /// Snapshot bytes for the `journal` store.
    pub fn to_snapshot(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("AttestationDoc serializes")
    }

    /// Load from snapshot bytes.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, AttestError> {
        serde_json::from_slice(bytes).map_err(|_| AttestError::Decode)
    }

    /// Encode one op for the op-log.
    pub fn encode_op(op: &AttestOp) -> Vec<u8> {
        serde_json::to_vec(op).expect("AttestOp serializes")
    }

    /// Decode one op from the op-log.
    pub fn decode_op(bytes: &[u8]) -> Result<AttestOp, AttestError> {
        serde_json::from_slice(bytes).map_err(|_| AttestError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn hash(seed: u8) -> FactHash {
        [seed; 32]
    }

    #[test]
    fn signature_attributes_the_fact_and_tamper_is_caught() {
        let a = Attestation::create(&key(1), hash(9));
        assert!(a.verify());

        let mut tampered = a.clone();
        tampered.fact_hash = hash(10); // vouch now claims a different fact than what was signed
        assert!(!tampered.verify());

        let mut wrong_signer = a.clone();
        wrong_signer.attester = key(2).verifying_key().to_bytes();
        assert!(!wrong_signer.verify());
    }

    #[test]
    fn concurrent_attests_union_and_are_idempotent() {
        let mut doc = AttestationDoc::new();
        let f = hash(9);
        doc.apply(AttestOp::Attest(Attestation::create(&key(1), f))).unwrap();
        doc.apply(AttestOp::Attest(Attestation::create(&key(2), f))).unwrap(); // different attester, same fact
        doc.apply(AttestOp::Attest(Attestation::create(&key(1), hash(8)))).unwrap(); // same attester, other fact
        doc.apply(AttestOp::Attest(Attestation::create(&key(1), f))).unwrap(); // idempotent re-attest

        assert_eq!(doc.for_fact(&f).count(), 2);
        assert!(doc.is_attested(&key(1).verifying_key().to_bytes(), &f));
        assert!(doc.is_attested(&key(2).verifying_key().to_bytes(), &f));
    }

    #[test]
    fn revoke_tombstones_then_compaction_hard_purges() {
        let mut doc = AttestationDoc::new();
        let (k, f) = (key(1), hash(9));
        let pk = k.verifying_key().to_bytes();
        doc.apply(AttestOp::Attest(Attestation::create(&k, f))).unwrap();
        assert!(doc.is_attested(&pk, &f));

        // Revoke removes it and tombstones the key.
        doc.apply(AttestOp::Revoke { attester: pk, fact_hash: f }).unwrap();
        assert!(!doc.is_attested(&pk, &f));
        // A re-delivered attest is suppressed by the tombstone.
        doc.apply(AttestOp::Attest(Attestation::create(&k, f))).unwrap();
        assert!(!doc.is_attested(&pk, &f));

        // Compaction hard-purges the tombstone — no trace remains (accepted caveat: a lagging
        // re-delivered attest could now resurrect it).
        doc.compact();
        doc.apply(AttestOp::Attest(Attestation::create(&k, f))).unwrap();
        assert!(doc.is_attested(&pk, &f));
    }

    #[test]
    fn a_bad_signature_op_is_rejected() {
        let mut doc = AttestationDoc::new();
        let mut a = Attestation::create(&key(1), hash(9));
        a.signature[0] ^= 0xFF; // corrupt
        assert_eq!(doc.apply(AttestOp::Attest(a)), Err(AttestError::BadSignature));
        assert_eq!(doc.for_fact(&hash(9)).count(), 0);
    }

    #[test]
    fn snapshot_and_op_round_trip_through_journal_bytes() {
        let mut doc = AttestationDoc::new();
        let op = AttestOp::Attest(Attestation::create(&key(1), hash(9)));
        doc.apply(op.clone()).unwrap();

        let snap = doc.to_snapshot();
        assert_eq!(AttestationDoc::from_snapshot(&snap).unwrap(), doc);

        let bytes = AttestationDoc::encode_op(&op);
        assert_eq!(AttestationDoc::decode_op(&bytes).unwrap(), op);
    }
}
