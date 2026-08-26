#![forbid(unsafe_code)]
//! The Ed25519 sign/verify seam (§0, OPE-205).
//!
//! `ed25519-dalek` exposes **two** verify methods: `verify_strict` (rejects small-order / torsion
//! public keys and non-canonical signatures) and the `Verifier` trait's plain `verify` (weaker). A
//! signature over attacker-influenced key material — a keyring signer's key, a member's author key —
//! must always use the strict one. Rather than trust every call site (and every future one) to import
//! the right trait and pick the right method, this crate makes the weak path **impossible to write**:
//!
//! - It is the *only* crate in the workspace that depends on `ed25519-dalek`. Every other crate holds
//!   these newtypes instead of the raw dalek types, so `use ed25519_dalek::Verifier` has nothing to
//!   apply to and does not compile there.
//! - [`VerifyingKey`] does **not** implement (nor expose, via `Deref`/`AsRef`/`into_inner`) the
//!   `Verifier` trait. Its only verify is [`VerifyingKey::verify`], which is `verify_strict`.
//!
//! So the policy "always verify_strict" is enforced at `cargo build`, not by a CI lint. The dependency
//! edge is half the guarantee: keep `ed25519-dalek` out of every other crate's `Cargo.toml` (and out of
//! `[workspace.dependencies]` once the last excluded consumer is gone) so this stays true.
//!
//! The crate is deliberately **pure**: no RNG (identities are minted by callers — `openom-crypto`'s
//! HKDF-derived owner identity, or a test helper — and handed in as a 32-byte seed via [`from_seed`]),
//! no serde (every wire crossing is raw bytes, converted at the boundary via `to_bytes`/`from_bytes`),
//! no `did:key` (that composes at call sites over the 32-byte public key). That keeps it deterministic
//! and wasm-trivial — the one place to audit or upgrade the signature library.
//!
//! [`from_seed`]: SigningKey::from_seed

use ed25519_dalek::Signer;

/// A signing or verification failure. Deliberately coarse (no dalek types leak through), matching the
/// boolean/`is_ok()` way every caller consumes the outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The 32 bytes are not a valid Ed25519 public key (bad point encoding).
    #[error("public key is not a valid Ed25519 point")]
    MalformedKey,
    /// The signature does not verify under this key (wrong key, tampered message, small-order /
    /// torsion key, or a non-canonical signature — `verify_strict` rejects all of them).
    #[error("signature does not verify")]
    BadSignature,
}

/// An Ed25519 signing key. The seed is **not** readable — there is no accessor, no `Deref`, no serde —
/// so it can only sign, never be exfiltrated by safe code; it scrubs on drop (the inner dalek key's
/// `zeroize` feature, proven below). Mint one from a caller-supplied 32-byte seed via [`Self::from_seed`].
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Build a signing key from a 32-byte seed (e.g. `openom-crypto`'s HKDF-derived owner identity, or
    /// a test helper's random seed). Deterministic: the same seed always yields the same key.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Sign `msg` (the caller is responsible for domain-separating it).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }
}

// A redacted Debug so a struct that embeds a SigningKey (e.g. an author identity) can derive Debug
// without ever printing the seed. Hand-written, not derived, so it never forwards to the inner type.
impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

// Compile-time confirmation (not an assumption) that the signing seed scrubs on drop: a concrete
// `where` bound checked at definition, so this fails to compile if ed25519-dalek's `zeroize` feature
// ever stops providing ZeroizeOnDrop for its SigningKey (the seed our newtype holds).
#[allow(dead_code)]
fn _signing_key_zeroizes_on_drop()
where
    ed25519_dalek::SigningKey: zeroize::ZeroizeOnDrop,
{
}

/// An Ed25519 verifying (public) key. Its **only** verify is [`Self::verify`] = `verify_strict`; it does
/// not implement or expose the `Verifier` trait, so the weak plain-`verify` path is uncallable. Public
/// material, so `Copy`/`Debug`/`Eq` are fine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parse a 32-byte compressed public key. This is decompression-only (it does **not** reject
    /// small-order / torsion points — that is [`Self::verify`]'s job, so a construction failure stays
    /// distinct from a verification failure, exactly as the raw library draws the line).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| SignError::MalformedKey)
    }

    /// The 32-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify `sig` over `msg` with `verify_strict` — additionally rejecting small-order / torsion
    /// public keys and non-canonical signatures. This is the single verify in the workspace.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SignError> {
        self.0
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig.0))
            .map_err(|_| SignError::BadSignature)
    }
}

/// A detached Ed25519 signature (64 bytes). Holds raw bytes, not a dalek `Signature`, so there is no
/// inner library type to leak a plain-verify path through and the byte round-trip is total.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wrap 64 signature bytes (infallible — validity is checked at verify time).
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(*bytes)
    }

    /// The 64 signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Signature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::from_seed(&[7u8; 32]);
        let vk = key.verifying_key();
        let sig = key.sign(b"the family tree");
        assert!(vk.verify(b"the family tree", &sig).is_ok());
    }

    #[test]
    fn a_tampered_message_is_rejected() {
        let key = SigningKey::from_seed(&[7u8; 32]);
        let vk = key.verifying_key();
        let sig = key.sign(b"original");
        assert_eq!(vk.verify(b"tampered", &sig), Err(SignError::BadSignature));
    }

    #[test]
    fn a_wrong_key_is_rejected() {
        let a = SigningKey::from_seed(&[1u8; 32]);
        let b = SigningKey::from_seed(&[2u8; 32]);
        let sig = a.sign(b"msg");
        assert_eq!(
            b.verifying_key().verify(b"msg", &sig),
            Err(SignError::BadSignature)
        );
    }

    #[test]
    fn from_seed_is_deterministic() {
        let a = SigningKey::from_seed(&[9u8; 32]);
        let b = SigningKey::from_seed(&[9u8; 32]);
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    fn signature_and_public_key_byte_round_trip() {
        let key = SigningKey::from_seed(&[3u8; 32]);
        let vk = key.verifying_key();
        let sig = key.sign(b"x");
        assert_eq!(
            VerifyingKey::from_bytes(&vk.to_bytes()).unwrap(),
            vk,
            "public key survives to_bytes → from_bytes"
        );
        assert!(vk
            .verify(b"x", &Signature::from_bytes(&sig.to_bytes()))
            .is_ok());
    }

    #[test]
    fn malformed_public_key_is_a_construction_error() {
        // y = 2 has no matching x on the curve — a non-decompressable encoding.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert_eq!(VerifyingKey::from_bytes(&bad), Err(SignError::MalformedKey));
    }

    /// The load-bearing regression guard: prove our `verify` is `verify_strict`, not the permissive
    /// `Verifier::verify`, by a vector the two disagree on. With the public key set to the neutral
    /// element (order 1, a small-order point), the verification equation `[S]B = R + [k]A` collapses to
    /// `[S]B = R`, so the signature `(R, S) = (B, 1)` verifies under the *permissive* equation for ANY
    /// message — a classic small-order forgery. `verify_strict` rejects it because A is small-order.
    ///
    /// The vector is self-checking: if the hardcoded basepoint encoding were wrong, the permissive
    /// `assert` below would fail loudly rather than let a bad vector pass. If this test ever starts
    /// failing because our `verify` accepts, the strict check has been silently lost.
    #[test]
    fn our_verify_is_strict_a_small_order_forgery_is_rejected() {
        // A = neutral element: y = 1, encoded little-endian with a clear sign bit.
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 1;

        // Forgery for A = identity: S = 1, R = [1]B = the Ed25519 basepoint (RFC 8032 encoding:
        // 0x58 followed by 0x66 repeated).
        let mut sig_bytes = [0x66u8; 64];
        sig_bytes[0] = 0x58; // R = basepoint
        for b in &mut sig_bytes[32..] {
            *b = 0; // S = ...
        }
        sig_bytes[32] = 1; // ... = 1 (little-endian)

        let dalek_vk = ed25519_dalek::VerifyingKey::from_bytes(&a_bytes).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Sanity: the permissive verify ACCEPTS the forgery (else the vector is wrong).
        assert!(
            dalek_vk.verify(b"any message", &dalek_sig).is_ok(),
            "small-order forgery must pass permissive verify — the vector is wrong otherwise"
        );

        // The seam: our verify (verify_strict) REJECTS it.
        let our_vk = VerifyingKey::from_bytes(&a_bytes).unwrap();
        assert_eq!(
            our_vk.verify(b"any message", &Signature::from_bytes(&sig_bytes)),
            Err(SignError::BadSignature),
            "openom-sign must reject a small-order public key (verify_strict)"
        );
    }

    proptest::proptest! {
        #[test]
        fn signed_messages_verify_and_any_tamper_flips(seed in proptest::prelude::any::<[u8; 32]>(), msg in ".*") {
            let key = SigningKey::from_seed(&seed);
            let vk = key.verifying_key();
            let sig = key.sign(msg.as_bytes());
            proptest::prop_assert!(vk.verify(msg.as_bytes(), &sig).is_ok());

            // Flip one signature byte → reject.
            let mut bad = sig.to_bytes();
            bad[0] ^= 0x01;
            proptest::prop_assert!(vk.verify(msg.as_bytes(), &Signature::from_bytes(&bad)).is_err());
        }
    }
}
