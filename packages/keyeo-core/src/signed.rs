//! [`Signed<T>`] — an authenticated envelope binding a canonical body to the key that signed it.
//!
//! The one construction path is [`Signed::sign`] (which signs the body's [`CanonicalBytes`]); the one way to
//! reach the body is [`Signed::verify`] (which hands it back only if the signature checks). So two whole
//! classes of bug are made *unrepresentable*:
//! - "a body reached the wire without being signed" — there is no public constructor that skips signing, and
//! - "code trusted a body without verifying it" — `body` is private, and `verify` is the only accessor.
//!
//! Paired with an **exhaustive-destructure** [`CanonicalBytes`] impl on `T` (`let T { a, b, c } = self;` with
//! no `..`), the remaining half is covered too: adding a field to the signed body is a *compile error* until it
//! is written into the canonical bytes. Together they close the "forgot to sign field X" bug class the way the
//! type system is meant to — a mistake becomes a build failure, not a silent security hole.
//!
//! The signer's public key is the envelope's authenticity anchor; it is not part of the signed body (verifying
//! *with* it already binds the body to it). Establishing that the key is *authorized* (an allowed signer at the
//! relevant point) is a separate, higher layer's job — [`Signed`] proves authorship, not authority.

use crate::{CanonicalBytes, SignatureScheme};

/// A body `T` bound to the public key that signed its canonical bytes. Construct with [`Signed::sign`], read
/// with [`Signed::verify`]. `body` is deliberately private: no consumer can read unauthenticated data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T, S: SignatureScheme> {
    body: T,
    signer: S::PublicKey,
    signature: S::Signature,
}

impl<T: CanonicalBytes, S: SignatureScheme> Signed<T, S> {
    /// Sign `body` with an Ed25519 key (keyeo's single signing seam, via `edsign`). The signature covers
    /// exactly `body`'s [`CanonicalBytes`] — so *what is signed* is defined solely by `T`'s encoding, and a
    /// field can only be added to the signed set by adding it to `T` (and thus to its exhaustive encoding).
    pub fn sign(body: T, signing_key: &edsign::SigningKey) -> Self
    where
        S: SignatureScheme<PublicKey = [u8; 32], Signature = [u8; 64]>,
    {
        let mut buf = Vec::new();
        body.write_canonical(&mut buf);
        let signature = signing_key.sign(&buf).to_bytes();
        let signer = signing_key.verifying_key().to_bytes();
        Signed { body, signer, signature }
    }

    /// Verify the signature over the body's canonical bytes and, only if it holds, return the body. This is the
    /// **only** way to read `body`, so a caller cannot act on an unverified payload — the compiler enforces it.
    pub fn verify(&self) -> Option<&T> {
        let mut buf = Vec::new();
        self.body.write_canonical(&mut buf);
        S::verify(&self.signer, &buf, &self.signature)
            .ok()
            .map(|()| &self.body)
    }

    /// The public key that produced the signature. An authenticity anchor and the input to a separate
    /// *authority* check (is this key an allowed signer?) — not proof of authority on its own.
    pub fn signer(&self) -> &S::PublicKey {
        &self.signer
    }
}

// Wire serialization — `(body, signer, signature)`. The Ed25519 signature is a `[u8; 64]`, which has NO serde
// derive (serde covers `[u8; N]` only for N <= 32), so it rides as a length-checked byte vec. Deserialize
// populates the PRIVATE `body` but grants no read access — `verify()` is still the only way in, so a
// wire-supplied `Signed` with a mismatched body/signature simply fails `verify()`. Serde is a CONSTRUCTION path
// (like `sign`), not a read path: the sole-carrier invariant is unchanged. Concrete to `Ed25519` (keyeo's only
// scheme); add another impl if a second scheme ever needs the wire form.
impl<T: serde::Serialize> serde::Serialize for Signed<T, crate::Ed25519> {
    fn serialize<Sz: serde::Serializer>(&self, s: Sz) -> Result<Sz::Ok, Sz::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Signed", 3)?;
        st.serialize_field("body", &self.body)?;
        st.serialize_field("signer", &self.signer)?;
        st.serialize_field("signature", &&self.signature[..])?;
        st.end()
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Signed<T, crate::Ed25519> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Repr<T> {
            body: T,
            signer: [u8; 32],
            signature: Vec<u8>,
        }
        let r = Repr::<T>::deserialize(d)?;
        let signature: [u8; 64] = r
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("Signed: signature must be 64 bytes"))?;
        Ok(Signed {
            body: r.body,
            signer: r.signer,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ed25519;

    /// A trivial signed body with an exhaustive-destructure encoding — the shape every real signed body uses.
    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Body {
        n: u64,
        flag: bool,
    }
    impl CanonicalBytes for Body {
        #[deny(unused_variables)]
        fn write_canonical(&self, out: &mut Vec<u8>) {
            // No `..`: a new field here would fail to compile until it is encoded (and thus signed).
            let Body { n, flag } = self;
            out.extend_from_slice(b"test:body:v1");
            out.extend_from_slice(&n.to_le_bytes());
            out.push(u8::from(*flag));
        }
    }

    #[test]
    fn signs_verifies_and_rejects_any_tamper() {
        let sk = edsign::SigningKey::from_seed(&[7u8; 32]);
        let signed: Signed<Body, Ed25519> = Signed::sign(Body { n: 42, flag: true }, &sk);

        // The only accessor returns the body iff the signature holds.
        assert_eq!(signed.verify(), Some(&Body { n: 42, flag: true }));

        // Tamper the body → verification fails (the body is bound by the signature).
        let mut tampered = signed.clone();
        tampered.body.flag = false;
        assert_eq!(tampered.verify(), None);

        // Tamper the signer key → fails (the tampered key didn't produce this signature).
        let mut wrong_key = signed.clone();
        wrong_key.signer = edsign::SigningKey::from_seed(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(wrong_key.verify(), None);
    }

    #[test]
    fn serde_round_trip_preserves_the_verifiable_envelope() {
        let sk = edsign::SigningKey::from_seed(&[7u8; 32]);
        let signed: Signed<Body, Ed25519> = Signed::sign(Body { n: 42, flag: true }, &sk);

        let bytes = postcard::to_allocvec(&signed).unwrap();
        let back: Signed<Body, Ed25519> = postcard::from_bytes(&bytes).unwrap();

        // The deserialized envelope still verifies and yields the same body — deserialize is a construction
        // path, not a read path, so `verify()` remains the gate.
        assert_eq!(back.verify(), Some(&Body { n: 42, flag: true }));
        assert_eq!(back, signed, "the whole envelope round-trips");

        // A 63-byte signature is rejected at deserialize (length is checked on the way into the [u8; 64]).
        #[derive(serde::Serialize)]
        struct BadRepr {
            body: Body,
            signer: [u8; 32],
            signature: Vec<u8>,
        }
        let bad = postcard::to_allocvec(&BadRepr {
            body: Body { n: 1, flag: false },
            signer: [0u8; 32],
            signature: vec![0u8; 63],
        })
        .unwrap();
        assert!(postcard::from_bytes::<Signed<Body, Ed25519>>(&bad).is_err(), "a wrong-length signature is rejected");
    }

    #[test]
    fn distinct_bodies_yield_distinct_signatures() {
        let sk = edsign::SigningKey::from_seed(&[7u8; 32]);
        let a: Signed<Body, Ed25519> = Signed::sign(Body { n: 1, flag: true }, &sk);
        let b: Signed<Body, Ed25519> = Signed::sign(Body { n: 1, flag: false }, &sk);
        assert_ne!(a.signature, b.signature, "the flag is inside the signed bytes");
    }
}
