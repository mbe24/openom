//! The engine's canonical, domain-separated signing bytes — the exact byte string a signer's key signs
//! over a [`LinearDoc`](crate::LinearDoc). Same branchless, length-prefixed, fixed-width discipline as the
//! chain's `keyring_signing_bytes` (openom-keyring-chain) and the envelope AAD, so a Rust and a JS/WASM verifier
//! agree byte-for-byte.
//!
//! The whole point of the §4 layout: the ENGINE builds this message from the SAME accessor values it
//! reasons on, so "what the engine decides on" and "what is signed" are the same values — divergence is
//! structurally impossible. Every generic field is covered here; the rest of the binding's payload is
//! bound through the opaque `payload_commitment` the binding computes.

use crate::{DocHash, Governance, GroupId, LinearDoc, PayloadCommitment, Revision, Signer};
use keyeo_core::{CanonicalBytes, Postcard, SignatureScheme};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Domain-separation tag for the engine's signed message. Disjoint from any other signed byte string in
/// the family (the envelope AAD, the DAG op bytes, the chain's `openom:keyring`) so a signature can never
/// be replayed across contexts.
const DOMAIN_TAG: &[u8] = b"keyeo:linear:v1";

/// The exhaustive set of engine-signed fields, gathered from a [`LinearDoc`]'s accessors. Kept as a struct
/// (rather than positional args) so [`write_signed_bytes`] can destructure it under
/// `#[deny(unused_variables)]`: adding a signed field is a compile error until it is written below — the
/// same compile-time-exhaustiveness security control the chain's `keyring_signing_bytes` carries.
struct SignedFields<'a, Id, R, Pk> {
    group_id: &'a GroupId,
    revision: Revision,
    prev_hash: &'a DocHash,
    layout_version: u32,
    members: &'a [Signer<Id, R, Pk>],
    governance: Governance,
    recovery_authority: Option<&'a Pk>,
    payload_commitment: PayloadCommitment,
}

/// The canonical bytes an authorized signer signs over `doc`. Public because a binding that *authors*
/// revisions must sign these exact bytes (and hash them for the next revision's `prev_hash`, see
/// [`doc_hash`]); the engine and the binding therefore agree by construction.
pub fn signing_bytes<D: LinearDoc>(doc: &D) -> Vec<u8> {
    // Owned holders for the accessor values that return by value, so `SignedFields` can borrow them.
    let members = doc.members();
    let recovery = doc.recovery_authority();
    write_signed_bytes(SignedFields {
        group_id: doc.group_id(),
        revision: doc.revision(),
        prev_hash: doc.prev_hash(),
        layout_version: doc.layout_version(),
        members: &members,
        governance: doc.governance(),
        recovery_authority: recovery.as_ref(),
        payload_commitment: doc.payload_commitment(),
    })
}

/// SHA-256 of `doc`'s [`signing_bytes`] — the value the *next* revision records as its `prev_hash`, and the
/// `doc_hash` a verified [`Anchor`](crate::Anchor) carries. Hashing the signing bytes (not any wire form)
/// keeps the chain reproducible across Rust/wasm.
pub fn doc_hash<D: LinearDoc>(doc: &D) -> DocHash {
    DocHash(sha256(&signing_bytes(doc)))
}

/// The exhaustive encoder. `#[deny(unused_variables)]` over the destructured `SignedFields` (and each
/// `Signer` / `Governance`) is the guard: a newly-added signed field cannot silently escape the signed
/// bytes. Taken by value (it holds only references + `Copy` scalars) so the destructure moves cleanly.
#[deny(unused_variables)]
fn write_signed_bytes<Id, R, Pk>(fields: SignedFields<'_, Id, R, Pk>) -> Vec<u8>
where
    Id: Serialize,
    R: Serialize,
    Pk: AsRef<[u8]>,
{
    let SignedFields {
        group_id,
        revision,
        prev_hash,
        layout_version,
        members,
        governance,
        recovery_authority,
        payload_commitment,
    } = fields;

    let mut out = Vec::with_capacity(256);
    put_bytes(&mut out, DOMAIN_TAG);
    put_bytes(&mut out, &group_id.0);
    put_u32(&mut out, revision.0);
    put_bytes(&mut out, &prev_hash.0);
    put_u32(&mut out, layout_version);

    put_u32(&mut out, members.len() as u32);
    for m in members {
        let Signer {
            id,
            role,
            public_key,
        } = m;
        put_serialized(&mut out, id);
        put_serialized(&mut out, role);
        put_bytes(&mut out, public_key.as_ref());
    }

    let Governance { kind, threshold } = governance;
    put_u32(&mut out, kind);
    put_u32(&mut out, threshold);

    match recovery_authority {
        Some(k) => {
            put_u32(&mut out, 1);
            put_bytes(&mut out, k.as_ref());
        }
        None => {
            put_u32(&mut out, 0);
            put_bytes(&mut out, &[]);
        }
    }

    put_bytes(&mut out, &payload_commitment.0);
    out
}

/// Length-prefixed postcard encoding of a `Serialize` value (member id / role) — deterministic and
/// byte-identical across native and wasm, via keyeo-core's `Postcard` seam. Length-prefixed so a variable
/// field can't blur into its neighbour (the `"ab"+"c" == "a"+"bc"` forgery class).
fn put_serialized<T: Serialize>(out: &mut Vec<u8>, v: &T) {
    let mut tmp = Vec::new();
    Postcard(v).write_canonical(&mut tmp);
    put_bytes(out, &tmp);
}

/// The scheme-generic SHA-256 helper.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// 4-byte big-endian length prefix, then the bytes.
#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

// ---- scheme-generic signature-quorum evaluation (generalizes openom-keyring-chain's keyring.rs) ----

/// Deduplicate keys by their raw bytes so a repeated key can't make a quorum easier to satisfy (the
/// `verify_keyring_*` dedup discipline, made generic over `AsRef<[u8]>`).
fn dedup_keys<S: SignatureScheme>(keys: &[S::PublicKey]) -> Vec<S::PublicKey> {
    let mut out: Vec<S::PublicKey> = Vec::new();
    for k in keys {
        if !out.iter().any(|e| e.as_ref() == k.as_ref()) {
            out.push(k.clone());
        }
    }
    out
}

/// True if some `sig` in `sigs` verifies under some key in `trusted` — the any-of / 1-of-N rule. The
/// signatures are unattributed: every trusted key is tried against every signature, so a forged
/// attribution hint can neither help nor mislead (generalizes `verify_keyring_any`).
pub(crate) fn verify_any<S: SignatureScheme>(
    msg: &[u8],
    sigs: &[S::Signature],
    trusted: &[S::PublicKey],
) -> bool {
    sigs.iter()
        .any(|sig| trusted.iter().any(|key| S::verify(key, msg, sig).is_ok()))
}

/// Count of DISTINCT `required` keys (deduped) that verify at least one signature — the tally a threshold
/// / unanimity rule reads.
fn count_valid<S: SignatureScheme>(
    msg: &[u8],
    sigs: &[S::Signature],
    required: &[S::PublicKey],
) -> usize {
    dedup_keys::<S>(required)
        .iter()
        .filter(|key| sigs.iter().any(|sig| S::verify(key, msg, sig).is_ok()))
        .count()
}

/// Unanimity: every DISTINCT key in `required` verifies a signature. Fail-closed — an empty `required`
/// set is NOT unanimity (generalizes `verify_keyring_all`).
pub(crate) fn verify_all<S: SignatureScheme>(
    msg: &[u8],
    sigs: &[S::Signature],
    required: &[S::PublicKey],
) -> bool {
    let deduped = dedup_keys::<S>(required);
    !deduped.is_empty()
        && deduped
            .iter()
            .all(|key| sigs.iter().any(|sig| S::verify(key, msg, sig).is_ok()))
}

/// At least `m` DISTINCT keys in `required` verify a signature. `m == 0` is vacuously satisfied (matching
/// `verify_keyring_threshold`; callers never gate on zero). Generalizes `verify_keyring_threshold`.
pub(crate) fn verify_threshold<S: SignatureScheme>(
    msg: &[u8],
    sigs: &[S::Signature],
    required: &[S::PublicKey],
    m: usize,
) -> bool {
    if m == 0 {
        return true;
    }
    count_valid::<S>(msg, sigs, required) >= m
}
