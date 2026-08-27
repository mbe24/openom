//! High-level envelope sealing — the one call the client uses to turn plaintext into a
//! complete, wire-ready [`Envelope`], and back.
//!
//! It owns the two things easy to get wrong by hand: generating a fresh per-AEAD nonce
//! (24 bytes XChaCha20 / 12 bytes AES-GCM) from the CSPRNG, and computing
//! `ciphertext_hash = SHA-256(ciphertext)` *after* sealing (the field is excluded from
//! the AAD precisely because it's circular otherwise, §5). Compression is the caller's
//! concern: `seal_envelope` seals the plaintext **as given** and just records
//! `params.compression`, so zstd (and its WASM cost) stays out of this layer.

use openom_protocol::aad::author_signing_bytes;
use openom_protocol::v1::{Aead, Compression, Envelope, Format, Header, Kind};
use openom_sign::SigningKey;
use sha2::{Digest, Sha256};

use crate::{open, seal, CryptoError, KEY_LEN};

/// Optional author attribution for a shared-tree entry (§B3 launch gate). When present, the member's
/// Ed25519 author key signs the entry — naming them (`member_id`) and the keyring revision that governs
/// it — so peers can verify authorship + role via `openom_keyring::verify_entry`. `None` seals an *unattributed*
/// entry (empty `author_signature`), the V1 communal-DEK model.
pub struct AuthorIdentity {
    pub signing_key: SigningKey,
    pub member_id: String,
    pub keyring_revision: u32,
}

/// Inputs for a sealed envelope's header (everything but the nonce + ciphertext_hash,
/// which [`seal_envelope`] fills in).
pub struct SealParams<'a> {
    pub version: u32,
    pub kind: Kind,
    pub format: Format,
    pub aead: Aead,
    pub compression: Compression,
    pub key_id: &'a [u8],
    pub tree_id: &'a [u8],
    pub replica_id: &'a [u8],
    pub replica_counter: u64,
    pub prev_ciphertext_hash: &'a [u8],
    pub covers_through_seq: u64,
    /// KIND_MEDIA only; empty otherwise.
    pub blob_id: &'a [u8],
    /// Author attribution for a shared tree (§B3). `None` → unattributed (V1). Borrowed like every
    /// other field — the caller owns the [`AuthorIdentity`] (e.g. the sealer holds it for the session).
    pub author: Option<&'a AuthorIdentity>,
}

fn nonce_len(aead: Aead) -> Result<usize, CryptoError> {
    match aead {
        Aead::Xchacha20Poly1305 => Ok(24),
        Aead::Aes256Gcm => Ok(12),
        _ => Err(CryptoError::UnsupportedAead(aead as i32)),
    }
}

/// Seal `plaintext` under `dek` into a complete [`Envelope`]: mint a fresh nonce,
/// build the header, seal (binding the whole header as AAD), and set `ciphertext_hash`.
///
/// This is the thin CSPRNG shim over [`seal_envelope_with_nonce`]: it mints the fresh per-AEAD nonce
/// and delegates the deterministic work.
pub fn seal_envelope(
    dek: &[u8; KEY_LEN],
    params: &SealParams,
    plaintext: &[u8],
) -> Result<Envelope, CryptoError> {
    let mut nonce = vec![0u8; nonce_len(params.aead)?];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    seal_envelope_with_nonce(nonce, dek, params, plaintext)
}

/// The deterministic core of [`seal_envelope`], with the `nonce` supplied by the caller: build the
/// header, sign the attribution (§B3) into the AAD, seal, and set `ciphertext_hash`. Same inputs →
/// same [`Envelope`] byte-for-byte, so the header/AAD/author-signing-binding logic is testable and
/// Kani-verifiable without the RNG. **Contract:** `nonce` must be unique per (key, message) and the
/// right length for `params.aead` (24 XChaCha20 / 12 AES-GCM) — [`seal_envelope`] guarantees both.
pub fn seal_envelope_with_nonce(
    nonce: Vec<u8>,
    dek: &[u8; KEY_LEN],
    params: &SealParams,
    plaintext: &[u8],
) -> Result<Envelope, CryptoError> {
    let mut header = Header {
        kind: params.kind as i32,
        format: params.format as i32,
        aead: params.aead as i32,
        compression: params.compression as i32,
        key_id: params.key_id.to_vec(),
        nonce,
        tree_id: params.tree_id.to_vec(),
        replica_id: params.replica_id.to_vec(),
        replica_counter: params.replica_counter,
        ciphertext_hash: Vec::new(), // set after sealing (excluded from the AAD, §5)
        prev_ciphertext_hash: params.prev_ciphertext_hash.to_vec(),
        covers_through_seq: params.covers_through_seq,
        replaces_ciphertext_hash: Vec::new(),
        author_signature: Vec::new(),
        blob_id: params.blob_id.to_vec(),
        author_member_id: params
            .author
            .as_ref()
            .map(|a| a.member_id.to_string())
            .unwrap_or_default(),
        keyring_revision: params.author.as_ref().map_or(0, |a| a.keyring_revision),
    };

    // Attribution (§B3): sign the entry with the member's author key BEFORE sealing, so the signature
    // lands inside the AAD (stripping it then breaks the AEAD tag — fail-closed). author_signing_bytes
    // binds SHA-256(plaintext) + the attribution fields and excludes nonce/ciphertext_hash/itself, so
    // it's computable here (pre-seal).
    if let Some(author) = &params.author {
        let msg = author_signing_bytes(
            params.version,
            &header,
            Sha256::digest(plaintext).as_slice(),
        );
        header.author_signature = author.signing_key.sign(&msg).to_bytes().to_vec();
    }

    let ciphertext = seal(params.version, &header, dek, plaintext)?;
    header.ciphertext_hash = Sha256::digest(&ciphertext).to_vec();

    Ok(Envelope {
        version: params.version,
        header: Some(header),
        ciphertext,
    })
}

/// Open an [`Envelope`] under `dek`: check `ciphertext_hash` (the reader-side integrity
/// check, matching the server's keyless one), then AEAD-open. Returns the plaintext.
pub fn open_envelope(dek: &[u8; KEY_LEN], envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
    let header = envelope.header.as_ref().ok_or(CryptoError::Open)?;
    if Sha256::digest(&envelope.ciphertext).as_slice() != header.ciphertext_hash.as_slice() {
        return Err(CryptoError::Open);
    }
    open(envelope.version, header, dek, &envelope.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_dek;

    fn params(aead: Aead) -> SealParams<'static> {
        SealParams {
            version: 1,
            kind: Kind::Snapshot,
            format: Format::OpenomJson,
            aead,
            compression: Compression::None,
            key_id: b"epoch-0",
            tree_id: b"tree-uuid-16byte",
            replica_id: b"replica-0",
            replica_counter: 3,
            prev_ciphertext_hash: b"",
            covers_through_seq: 0,
            blob_id: b"",
            author: None,
        }
    }

    #[test]
    fn round_trip_xchacha() {
        let dek = generate_dek().unwrap();
        let env = seal_envelope(
            dek.expose(),
            &params(Aead::Xchacha20Poly1305),
            b"the family tree",
        )
        .unwrap();
        let h = env.header.as_ref().unwrap();
        assert_eq!(h.nonce.len(), 24);
        assert_eq!(h.ciphertext_hash, Sha256::digest(&env.ciphertext).to_vec());
        assert_eq!(
            open_envelope(dek.expose(), &env).unwrap(),
            b"the family tree"
        );
    }

    #[test]
    fn round_trip_aesgcm() {
        let dek = generate_dek().unwrap();
        let env = seal_envelope(dek.expose(), &params(Aead::Aes256Gcm), b"snapshot").unwrap();
        assert_eq!(env.header.as_ref().unwrap().nonce.len(), 12);
        assert_eq!(open_envelope(dek.expose(), &env).unwrap(), b"snapshot");
    }

    #[test]
    fn nonces_are_fresh_per_seal() {
        let dek = generate_dek().unwrap();
        let a = seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), b"x").unwrap();
        let b = seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), b"x").unwrap();
        assert_ne!(a.header.unwrap().nonce, b.header.unwrap().nonce);
        assert_ne!(a.ciphertext, b.ciphertext); // different nonce → different ciphertext
    }

    // (The seal→verify_entry round-trip lives in openom-keyring's entry tests, which can depend on both
    // this crate's seal_envelope and its own verify_entry.)

    #[test]
    fn no_author_leaves_entry_unattributed() {
        let dek = generate_dek().unwrap();
        let env = seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), b"x").unwrap();
        let h = env.header.unwrap();
        assert!(
            h.author_signature.is_empty()
                && h.author_member_id.is_empty()
                && h.keyring_revision == 0
        );
    }

    #[test]
    fn with_nonce_is_deterministic() {
        // The extracted pure core: same (nonce, dek, params, plaintext) → byte-identical envelope. This
        // is the property the RNG in seal_envelope otherwise hides — and what makes the header/AAD/seal
        // logic verifiable without entropy.
        let dek = generate_dek().unwrap();
        let nonce = vec![7u8; 24];
        let a =
            seal_envelope_with_nonce(nonce.clone(), dek.expose(), &params(Aead::Xchacha20Poly1305), b"x")
                .unwrap();
        let b = seal_envelope_with_nonce(nonce, dek.expose(), &params(Aead::Xchacha20Poly1305), b"x")
            .unwrap();
        assert_eq!(a, b, "the nonce is the only entropy; fixing it makes seal deterministic");
        assert_eq!(open_envelope(dek.expose(), &a).unwrap(), b"x");
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let dek = generate_dek().unwrap();
        let mut env =
            seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), b"payload").unwrap();
        env.ciphertext[0] ^= 0xFF; // hash no longer matches, and the tag would fail too
        assert!(matches!(
            open_envelope(dek.expose(), &env),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn wrong_dek_fails() {
        let dek = generate_dek().unwrap();
        let env =
            seal_envelope(dek.expose(), &params(Aead::Xchacha20Poly1305), b"payload").unwrap();
        let other = generate_dek().unwrap();
        assert!(matches!(
            open_envelope(other.expose(), &env),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn dev_key_seals_real_ciphertext() {
        // §16: the dev key produces real ciphertext (inspectable, but not plaintext),
        // tagged with the reserved DEV_KEY_ID the server refuses in production.
        let dev = crate::dev_dek();
        let mut p = params(Aead::Xchacha20Poly1305);
        p.key_id = crate::DEV_KEY_ID;
        let env = seal_envelope(&dev, &p, b"local dev tree").unwrap();
        assert_ne!(env.ciphertext.as_slice(), b"local dev tree".as_slice());
        assert_eq!(env.header.as_ref().unwrap().key_id, crate::DEV_KEY_ID);
        assert_eq!(open_envelope(&dev, &env).unwrap(), b"local dev tree");
    }
}
