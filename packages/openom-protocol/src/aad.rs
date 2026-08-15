//! Canonical AAD encoding (data-format spec §5).
//!
//! The whole `Header` is bound to its ciphertext as AEAD *additional authenticated
//! data*, so the server can't swap `aead`, `key_id`, `tree_id`, `covers_through_seq`,
//! etc. without the key-holder detecting it on decrypt. Protobuf serialization is
//! **not** canonical, so the AAD is a dedicated byte string built by **length-prefixed
//! concatenation in a fixed field order**, fixed-width integers, and **branchless**
//! encoding (every field every time, zeros where N/A) — so a Rust build and a
//! WASM/JS build produce byte-identical AAD. `version` (the `Envelope.version`) is
//! first, making AAD-vN byte-disjoint across format versions.
//!
//! Deliberately **not** exported across the wasm-bindgen boundary: `seal`/`open` take
//! the header + plaintext and build the AAD internally, so no JS twin of this encoder
//! can drift from it (openom-crypto owns the only call sites).

use crate::v1::{Header, Keyring};

/// Build the canonical AAD for an envelope with wire `version` and `header` (§5).
///
/// Field order matches the proto: version, then `kind, format, aead, compression`
/// (each a 4-byte big-endian enum), `key_id, nonce, tree_id, replica_id` (each a
/// 4-byte big-endian length then bytes), `replica_counter` (8-byte BE),
/// `prev_ciphertext_hash` (framed bytes), `covers_through_seq` (8-byte BE), then
/// `replaces_ciphertext_hash, author_signature, blob_id` (framed bytes).
/// `ciphertext_hash` is **excluded** (it derives from the ciphertext the AEAD tag
/// already authenticates — binding it would be circular; see below).
pub fn header_aad(version: u32, header: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    put_u32(&mut out, version);
    put_u32(&mut out, header.kind as u32);
    put_u32(&mut out, header.format as u32);
    put_u32(&mut out, header.aead as u32);
    put_u32(&mut out, header.compression as u32);
    put_bytes(&mut out, &header.key_id);
    put_bytes(&mut out, &header.nonce);
    put_bytes(&mut out, &header.tree_id);
    put_bytes(&mut out, &header.replica_id);
    put_u64(&mut out, header.replica_counter);
    // `ciphertext_hash` is deliberately NOT in the AAD: it's SHA-256(ciphertext), and
    // the ciphertext is produced by the AEAD *using* this AAD — binding it would be
    // circular. It's also redundant (the AEAD tag already authenticates the ciphertext)
    // and is verified keylessly by the server on upload / by the reader on open.
    put_bytes(&mut out, &header.prev_ciphertext_hash);
    put_u64(&mut out, header.covers_through_seq);
    put_bytes(&mut out, &header.replaces_ciphertext_hash);
    put_bytes(&mut out, &header.author_signature);
    put_bytes(&mut out, &header.blob_id);
    out
}

/// Domain-separated, length-prefixed AAD binding a DEK wrap to its context (§4):
/// `(tree_id, key_id, member_id, wrap_method, epoch)`, so a wrap can't be transplanted
/// between members, epochs, or trees. The leading domain tag makes it byte-disjoint
/// from the header AAD (which starts with a bare version integer).
pub fn wrap_aad(
    tree_id: &[u8],
    key_id: &[u8],
    member_id: &str,
    wrap_method: i32,
    epoch: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    put_bytes(&mut out, b"openom:wrap:v1");
    put_bytes(&mut out, tree_id);
    put_bytes(&mut out, key_id);
    put_bytes(&mut out, member_id.as_bytes());
    put_u32(&mut out, wrap_method as u32);
    put_u32(&mut out, epoch);
    out
}

/// The canonical, domain-separated byte string the owner's Ed25519 key signs over the
/// keyring (§4): every keyring field **except `signature`**, length- and count-prefixed
/// so a signature can't be replayed onto a different keyring or another structure. The
/// `revision` (anti-rollback) and `signer_key_id` are covered.
pub fn keyring_signing_bytes(keyring: &Keyring) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    put_bytes(&mut out, b"openom:keyring:v1");
    put_bytes(&mut out, &keyring.tree_id);
    put_u32(&mut out, keyring.revision);
    put_bytes(&mut out, &keyring.signer_key_id);
    put_u32(&mut out, keyring.epochs.len() as u32);
    for epoch in &keyring.epochs {
        put_bytes(&mut out, &epoch.key_id);
        put_u32(&mut out, epoch.epoch);
        put_u32(&mut out, epoch.wraps.len() as u32);
        for w in &epoch.wraps {
            put_bytes(&mut out, w.member_id.as_bytes());
            put_u32(&mut out, w.wrap_method as u32);
            put_bytes(&mut out, &w.nonce);
            put_bytes(&mut out, &w.wrapped_dek);
            // kdf_params: a presence flag then its four fields, always encoded (zeros
            // when absent) so the layout stays branchless.
            match &w.kdf_params {
                Some(k) => {
                    put_u32(&mut out, 1);
                    put_bytes(&mut out, &k.salt);
                    put_u32(&mut out, k.memory_kib);
                    put_u32(&mut out, k.iterations);
                    put_u32(&mut out, k.parallelism);
                }
                None => {
                    put_u32(&mut out, 0);
                    put_bytes(&mut out, &[]);
                    put_u32(&mut out, 0);
                    put_u32(&mut out, 0);
                    put_u32(&mut out, 0);
                }
            }
            put_bytes(&mut out, &w.ephemeral_public_key);
        }
    }
    out
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
#[inline]
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
/// 4-byte big-endian length prefix, then the bytes — the framing that defeats the
/// `"ab"+"c" == "a"+"bc"` forgery class (§5).
#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{Aead, Compression, Format, Kind};

    fn sample() -> Header {
        Header {
            kind: Kind::Snapshot as i32,
            format: Format::OpenomJson as i32,
            aead: Aead::Xchacha20Poly1305 as i32,
            compression: Compression::None as i32,
            key_id: vec![0xAA, 0xBB],
            nonce: vec![0x01; 24],
            tree_id: vec![0x11; 16],
            replica_id: vec![0x22; 4],
            replica_counter: 5,
            ciphertext_hash: vec![0x33; 32],
            prev_ciphertext_hash: vec![],
            covers_through_seq: 0,
            replaces_ciphertext_hash: vec![],
            author_signature: vec![],
            blob_id: vec![],
        }
    }

    /// Independently-constructed expected layout — proves the encoder matches §5
    /// byte-for-byte. This is the anchor a JS/WASM twin must also reproduce.
    #[test]
    fn matches_documented_layout() {
        let mut want = Vec::new();
        for v in [1u32 /*version*/, 1 /*kind*/, 1 /*format*/, 2 /*aead*/, 1 /*compression*/] {
            want.extend_from_slice(&v.to_be_bytes());
        }
        let framed = |want: &mut Vec<u8>, b: &[u8]| {
            want.extend_from_slice(&(b.len() as u32).to_be_bytes());
            want.extend_from_slice(b);
        };
        framed(&mut want, &[0xAA, 0xBB]); // key_id
        framed(&mut want, &[0x01; 24]); // nonce
        framed(&mut want, &[0x11; 16]); // tree_id
        framed(&mut want, &[0x22; 4]); // replica_id
        want.extend_from_slice(&5u64.to_be_bytes()); // replica_counter
        // ciphertext_hash is excluded from the AAD (circular + redundant).
        framed(&mut want, &[]); // prev_ciphertext_hash
        want.extend_from_slice(&0u64.to_be_bytes()); // covers_through_seq
        framed(&mut want, &[]); // replaces_ciphertext_hash
        framed(&mut want, &[]); // author_signature
        framed(&mut want, &[]); // blob_id
        assert_eq!(header_aad(1, &sample()), want);
    }

    #[test]
    fn version_is_first_and_disjoint() {
        let h = sample();
        let v1 = header_aad(1, &h);
        let v2 = header_aad(2, &h);
        assert_eq!(&v1[..4], &1u32.to_be_bytes());
        assert_eq!(&v2[..4], &2u32.to_be_bytes());
        assert_ne!(v1, v2, "AAD-v1 and AAD-v2 must be byte-disjoint");
    }

    /// Branchless/kind-agnostic: two headers with identical field *sizes* produce the
    /// same AAD length regardless of `kind` — layout never forks on the object kind.
    #[test]
    fn branchless_layout_independent_of_kind() {
        let snap = sample();
        let mut media = sample();
        media.kind = Kind::Media as i32;
        assert_eq!(header_aad(1, &snap).len(), header_aad(1, &media).len());
    }

    /// Length framing: shifting a byte between two adjacent `bytes` fields changes the
    /// AAD (no `"ab"+"c" == "a"+"bc"` forgery).
    #[test]
    fn length_framing_prevents_concatenation_forgery() {
        let mut a = sample();
        a.key_id = vec![0xAA, 0xBB];
        a.nonce = vec![0xCC];
        let mut b = sample();
        b.key_id = vec![0xAA];
        b.nonce = vec![0xBB, 0xCC];
        assert_ne!(header_aad(1, &a), header_aad(1, &b));
    }

    #[test]
    fn deterministic() {
        assert_eq!(header_aad(1, &sample()), header_aad(1, &sample()));
    }

    #[test]
    fn wrap_aad_binds_every_context_field() {
        let base = wrap_aad(b"tree", b"key", "member", 1, 0);
        assert_eq!(base, wrap_aad(b"tree", b"key", "member", 1, 0)); // deterministic
        assert_ne!(base, wrap_aad(b"TREE", b"key", "member", 1, 0)); // tree_id
        assert_ne!(base, wrap_aad(b"tree", b"KEY", "member", 1, 0)); // key_id
        assert_ne!(base, wrap_aad(b"tree", b"key", "other", 1, 0)); // member_id
        assert_ne!(base, wrap_aad(b"tree", b"key", "member", 2, 0)); // wrap_method
        assert_ne!(base, wrap_aad(b"tree", b"key", "member", 1, 1)); // epoch
    }

    #[test]
    fn wrap_aad_is_disjoint_from_header_aad() {
        // The domain tag prevents a header AAD from ever colliding with a wrap AAD.
        assert_ne!(wrap_aad(b"", b"", "", 0, 0), header_aad(0, &Header::default()));
    }

    #[test]
    fn keyring_signing_bytes_covers_and_ignores_signature() {
        use crate::v1::{KeyEpoch, KeyWrap, KdfParams};
        let mut kr = Keyring {
            tree_id: vec![0x11; 16],
            revision: 1,
            signer_key_id: vec![0xAB; 4],
            signature: vec![0xFF; 64], // must NOT affect the signed bytes
            epochs: vec![KeyEpoch {
                key_id: vec![1, 2, 3],
                epoch: 0,
                wraps: vec![KeyWrap {
                    member_id: "acct".into(),
                    wrap_method: 1,
                    nonce: vec![7; 24],
                    wrapped_dek: vec![9; 48],
                    kdf_params: Some(KdfParams {
                        salt: vec![5; 16],
                        memory_kib: 19456,
                        iterations: 2,
                        parallelism: 1,
                    }),
                    ephemeral_public_key: vec![],
                }],
            }],
        };
        let a = keyring_signing_bytes(&kr);
        kr.signature = vec![0x00; 64];
        assert_eq!(a, keyring_signing_bytes(&kr), "signature is excluded from signed bytes");
        kr.revision = 2;
        assert_ne!(a, keyring_signing_bytes(&kr), "revision is covered (anti-rollback)");
    }
}
