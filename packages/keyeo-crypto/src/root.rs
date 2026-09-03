//! Root-key derivation: turn a passphrase into the keys the unlock flow needs — the
//! **KEK** that wraps the DEK, the **Ed25519 identity** that signs the keyring, and the
//! **X25519 HPKE keypair** that receives a shared DEK wrap when this account is a member
//! of someone else's tree.
//!
//! One Argon2id run (the single slow, memory-hard step) produces a 256-bit master; HKDF-
//! SHA256 then expands it into independent 32-byte keys under distinct `info` labels.
//! They are **siblings** — none is derived from another — so a KEK compromise can never
//! yield the signing or HPKE key. Argon2id output is already uniform, so HKDF-Expand is the
//! textbook way to split it; a second Argon2id would only double the ~1s cost for no gain.
//!
//! The HKDF `info` labels are supplied by the caller ([`RootLabels`]) so this crate stays
//! domain-free — openom-crypto passes the frozen `openom:*` constants. Only [`derive_rvk`]'s
//! label (`keyeo:rvk:v1`) is owned here, since both keyring engines derive the same RVK.
//!
//! ## Frozen construction (a second implementation must reproduce this byte-for-byte)
//! - master = Argon2id(passphrase, params)  — 32 bytes (same as [`derive_kek`]).
//! - HKDF-SHA256 with **Extract salt = empty** (`Hkdf::new(None, master)`).
//! - Expand 32-byte outputs with the exact ASCII labels the caller pins; the HPKE output is
//!   the IKM fed to the KEM's DeriveKeyPair (`derive_hpke_keypair`).

use edsign::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    derive_hpke_keypair, derive_kek, CryptoError, HpkePrivate, KdfParams, Kek, HPKE_PUBLIC_LEN,
    KEY_LEN,
};

/// HKDF `info` label for the Recovery Verification Key. **Frozen.** Domain-separated from every other
/// use of the recovery-root secret (never reuse a scalar across roles). Byte-identical to
/// `openom_keyring_dag::recovery::RVK_HKDF_INFO` — both engines derive the same RVK.
const HKDF_RVK_INFO: &[u8] = b"keyeo:rvk:v1";

/// The three HKDF `info` labels [`derive_root`] expands the Argon2id master under — one each for the
/// KEK, the Ed25519 owner identity seed, and the X25519 HPKE keypair IKM. openom-crypto pins these to
/// the frozen `openom:kek:v1` / `openom:identity:v1` / `openom:hpke:v1` constants.
pub struct RootLabels {
    pub kek: &'static [u8],
    pub identity: &'static [u8],
    pub hpke: &'static [u8],
}

/// Derive the **Recovery Verification Key** (RVK) — the Ed25519 key that authorizes a keyring
/// reset/recovery — from the recovery-root (RRK) secret. BOTH keyring engines (chain + dag) call this, so
/// a recovery is verifiable identically whichever engine authored it. Deterministic and domain-separated:
/// HKDF-SHA256(rrk_secret) under the frozen RVK label, then an Ed25519 key from the 32-byte output — via
/// the shared [`edsign::derive_signing_key`], so this is byte-identical to `openom_keyring_dag::recovery::derive_rvk`
/// (an openom-vault cross-check test guards the two).
pub fn derive_rvk(rrk_secret: &[u8; 32]) -> SigningKey {
    edsign::derive_signing_key(rrk_secret, HKDF_RVK_INFO)
}

/// The keys a passphrase unlocks: the DEK-wrapping KEK, the keyring-signing identity, and
/// the X25519 HPKE keypair (secret + public) for receiving a shared DEK wrap.
pub struct RootKeys {
    pub kek: Kek,
    pub identity: SigningKey,
    pub hpke_secret: HpkePrivate,
    pub hpke_public: [u8; HPKE_PUBLIC_LEN],
}

/// Derive [`RootKeys`] from a passphrase under the caller-supplied `labels` (see the module docs for the
/// frozen construction). The passphrase should already be a [`Zeroizing`] buffer at the call site; this
/// scrubs every intermediate (the master, the identity seed, and the HPKE IKM) on the way out.
pub fn derive_root(
    passphrase: &[u8],
    params: &KdfParams,
    labels: &RootLabels,
) -> Result<RootKeys, CryptoError> {
    // The Argon2id output is the HKDF master (derive_kek is exactly that Argon2id step). It is typed
    // Kek by reuse; only the labels.kek expansion below is the KEK the caller wraps with.
    let master = derive_kek(passphrase, params)?;
    let hk = Hkdf::<Sha256>::new(None, master.expose());

    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(labels.kek, kek.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (kek)".into()))?;

    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(labels.identity, seed.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (identity)".into()))?;
    let identity = SigningKey::from_seed(&seed);

    let mut hpke_ikm = Zeroizing::new([0u8; 32]);
    hk.expand(labels.hpke, hpke_ikm.as_mut_slice())
        .map_err(|_| CryptoError::Kdf("hkdf expand (hpke)".into()))?;
    let hpke = derive_hpke_keypair(&hpke_ikm);

    Ok(RootKeys {
        kek: kek.into(),
        identity,
        hpke_secret: hpke.secret.into(),
        hpke_public: hpke.public,
    })
}

// The owner identity's seed scrubs on drop — proven at compile time inside `edsign` (the crate
// that owns the key type), so there is no dalek `zeroize` bound to restate here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_salt;

    // The same byte labels openom-crypto pins — the derive_root properties below (the HKDF split into
    // KEK/identity/HPKE, key independence, determinism) are label-value-independent, but using the real
    // labels keeps this test a faithful twin of the production derivation.
    fn labels() -> RootLabels {
        RootLabels {
            kek: b"openom:kek:v1",
            identity: b"openom:identity:v1",
            hpke: b"openom:hpke:v1",
        }
    }

    // Tiny Argon2id cost so these tests run in sub-milliseconds. The cost is a security property
    // (it's the passphrase brute-force defense) exercised in the field at production strength, NOT in
    // unit logic tests — what derive_root's tests check is cost-INDEPENDENT. The production cost is
    // pinned in kdf.rs.
    fn cheap(salt: Vec<u8>) -> KdfParams {
        KdfParams { salt, memory_kib: 8, iterations: 1, parallelism: 1 }
    }
    fn params() -> KdfParams {
        cheap(vec![7u8; 16])
    }

    #[test]
    fn is_deterministic_for_the_same_passphrase() {
        let a = derive_root(b"correct horse", &params(), &labels()).unwrap();
        let b = derive_root(b"correct horse", &params(), &labels()).unwrap();
        assert_eq!(a.kek.expose(), b.kek.expose());
        // The identity's seed is not readable (edsign holds it opaquely); its public key is a
        // faithful proxy for "same identity" — a deterministic function of the seed.
        assert_eq!(
            a.identity.verifying_key().to_bytes(),
            b.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn a_different_passphrase_gives_different_keys() {
        let a = derive_root(b"passphrase-one", &params(), &labels()).unwrap();
        let b = derive_root(b"passphrase-two", &params(), &labels()).unwrap();
        assert_ne!(a.kek.expose(), b.kek.expose());
        assert_ne!(
            a.identity.verifying_key().to_bytes(),
            b.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn a_different_salt_gives_different_keys() {
        let a = derive_root(b"same pass", &cheap(vec![1u8; 16]), &labels()).unwrap();
        let b = derive_root(b"same pass", &cheap(vec![2u8; 16]), &labels()).unwrap();
        assert_ne!(a.kek.expose(), b.kek.expose());
        assert_ne!(
            a.identity.verifying_key().to_bytes(),
            b.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn kek_and_identity_are_independent() {
        // Siblings: the KEK bytes and the identity seed must not coincide. The seed is opaque, so
        // compare via the public key — had the seed equalled the KEK, an identity derived from the KEK
        // bytes would reproduce this public key.
        let r = derive_root(b"whatever", &params(), &labels()).unwrap();
        assert_ne!(
            SigningKey::from_seed(r.kek.expose())
                .verifying_key()
                .to_bytes(),
            r.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn the_hpke_keypair_is_deterministic_independent_and_usable() {
        use crate::{hpke_unwrap_dek, hpke_wrap_dek, Dek};
        let a = derive_root(b"member pass", &params(), &labels()).unwrap();
        let b = derive_root(b"member pass", &params(), &labels()).unwrap();
        assert_eq!(
            a.hpke_secret.expose(),
            b.hpke_secret.expose(),
            "same passphrase => same HPKE key"
        );
        assert_eq!(a.hpke_public, b.hpke_public);
        // Independent from the KEK and the identity seed (siblings). The identity seed is opaque, so
        // compare via the public key (see kek_and_identity_are_independent).
        assert_ne!(a.kek.expose(), a.hpke_secret.expose());
        assert_ne!(
            SigningKey::from_seed(a.hpke_secret.expose())
                .verifying_key()
                .to_bytes(),
            a.identity.verifying_key().to_bytes()
        );
        // The derived public/secret actually form a working HPKE pair.
        let w = hpke_wrap_dek(&a.hpke_public, &Dek::new([9u8; KEY_LEN]), b"info").unwrap();
        let out = hpke_unwrap_dek(
            a.hpke_secret.expose(),
            &w.encapped_key,
            &w.ciphertext,
            b"info",
        )
        .unwrap();
        assert_eq!(out.expose(), &[9u8; KEY_LEN]);

        let c = derive_root(b"other pass", &params(), &labels()).unwrap();
        assert_ne!(
            a.hpke_public, c.hpke_public,
            "different passphrase => different HPKE key"
        );
    }

    #[test]
    fn the_derived_identity_signs_and_verifies() {
        let r = derive_root(b"signer", &params(), &labels()).unwrap();
        let msg = b"keyring bytes";
        let sig = r.identity.sign(msg);
        assert!(r.identity.verifying_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn salt_is_usable_from_the_generator() {
        // Smoke: a real CSPRNG salt flows through without panicking.
        let salt = generate_salt().unwrap().to_vec();
        let _ = derive_root(b"pass", &cheap(salt), &labels()).unwrap();
    }

    #[test]
    fn rvk_is_deterministic_and_domain_separated() {
        // Same secret => same RVK; and the RVK is not just the identity from the same bytes (its own label).
        let secret = [3u8; 32];
        assert_eq!(
            derive_rvk(&secret).verifying_key().to_bytes(),
            derive_rvk(&secret).verifying_key().to_bytes()
        );
        assert_ne!(
            derive_rvk(&secret).verifying_key().to_bytes(),
            SigningKey::from_seed(&secret).verifying_key().to_bytes()
        );
    }
}
