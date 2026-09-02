//! Canonical AAD encoding (data-format spec §5) for the ENVELOPE + DEK-wrap paths.
//!
//! The whole `Header` is bound to its ciphertext as AEAD *additional authenticated data*, so the server
//! can't swap `aead`, `key_id`, `tree_id`, `covers_through_seq`, etc. without the key-holder detecting it on
//! decrypt. Protobuf serialization is **not** canonical, so the AAD is a dedicated byte string built by
//! **length-prefixed concatenation in a fixed field order**, fixed-width integers, and **branchless**
//! encoding (every field every time, zeros where N/A) — so a Rust build and a WASM/JS build produce
//! byte-identical AAD. `version` (the `Envelope.version`) is first, making AAD-vN byte-disjoint across
//! format versions.
//!
//! Lives HERE (openom-crypto), colocated with the `seal`/`open`/`wrap` code that is its only caller
//! (OPE-279): `seal`/`open` take the header + plaintext and build the AAD internally, so no JS twin of this
//! encoder can drift from it. (The keyring's own signing bytes are the chain engine's concern and live in
//! the keyring crate.)

use openom_protocol::v1::Header;

/// Build the canonical AAD for an envelope with wire `version` and `header` (§5).
///
/// Field order matches the proto: version, then `kind, format, aead, compression` (each a 4-byte
/// big-endian enum), `key_id, nonce, tree_id, replica_id` (each a 4-byte big-endian length then bytes),
/// `replica_counter` (8-byte BE), `prev_ciphertext_hash` (framed bytes), `covers_through_seq` (8-byte BE),
/// then `replaces_ciphertext_hash, author_signature, blob_id` (framed bytes). `ciphertext_hash` is
/// **excluded** (it derives from the ciphertext the AEAD tag already authenticates — binding it would be
/// circular).
#[deny(unused_variables)]
pub(crate) fn header_aad(version: u32, header: &Header) -> Vec<u8> {
    // Exhaustive destructure (no `..`) + deny(unused): adding a Header field is a compile error here
    // until it is bound into the AAD or explicitly excluded — the guard against silently leaving a new
    // field unauthenticated (OPE-277 crypto review). Byte order below is UNCHANGED (layout is signed).
    let Header {
        kind,
        format,
        aead,
        compression,
        key_id,
        nonce,
        tree_id,
        replica_id,
        replica_counter,
        // `ciphertext_hash` EXCLUDED: it's SHA-256(ciphertext), and the ciphertext is produced by the
        // AEAD *using* this AAD — binding it would be circular; the AEAD tag already authenticates it.
        ciphertext_hash: _,
        prev_ciphertext_hash,
        covers_through_seq,
        replaces_ciphertext_hash,
        author_signature,
        author_member_id,
        governing_ref,
        blob_id,
    } = header;
    let mut out = Vec::with_capacity(160);
    put_u32(&mut out, version);
    put_u32(&mut out, *kind as u32);
    put_u32(&mut out, *format as u32);
    put_u32(&mut out, *aead as u32);
    put_u32(&mut out, *compression as u32);
    put_bytes(&mut out, key_id);
    put_bytes(&mut out, nonce);
    put_bytes(&mut out, tree_id);
    put_bytes(&mut out, replica_id);
    put_u64(&mut out, *replica_counter);
    put_bytes(&mut out, prev_ciphertext_hash);
    put_u64(&mut out, *covers_through_seq);
    put_bytes(&mut out, replaces_ciphertext_hash);
    put_bytes(&mut out, author_signature);
    put_bytes(&mut out, blob_id);
    // Attribution fields (§B3): bound so the keyless server can't rewrite who authored an entry or which
    // keyring revision governs it without the key-holder detecting it on decrypt.
    put_bytes(&mut out, author_member_id.as_bytes());
    // Opaque engine-produced governing reference (length-prefixed, so unambiguous). Replaces the old
    // chain-only keyring_revision scalar (OPE-277 GoverningRef).
    put_bytes(&mut out, governing_ref);
    out
}

/// The canonical, domain-separated byte string a member's Ed25519 **author** key signs to attribute an
/// entry on a shared tree (§B3 launch gate; pins `design.sharing.md` §3.3). Covers every header field
/// that exists **before sealing** — so it is computable pre-seal — plus `SHA-256(plaintext)` to bind the
/// actual content. Deliberately EXCLUDES: `nonce` (minted inside seal, unknown at sign time; the AEAD tag
/// binds it anyway), `ciphertext_hash` (derives from the ciphertext this ultimately produces — circular),
/// and `author_signature` itself. The `openom:author:v1` tag makes it byte-disjoint from the keyring
/// (`openom:keyring`), wrap (`openom:wrap:v1`), and header AAD (bare version) byte strings — load-bearing,
/// because a founder/co-owner's author key IS their signer key (`chain.rs` requires it), so only the
/// domain tag separates an author signature from a keyring signature.
///
/// Verification order (client): AEAD-open the entry (authenticates the header, incl. `author_signature`,
/// against this exact ciphertext) → compute `SHA-256(plaintext)` → rebuild these bytes → Ed25519-verify
/// against the claimed member's `author_public_key` at the governing keyring revision.
#[deny(unused_variables)]
pub fn author_signing_bytes(version: u32, header: &Header, plaintext_hash: &[u8]) -> Vec<u8> {
    // Exhaustive destructure (no `..`) + deny(unused): a new Header field can't slip out of what the
    // author signs without a compile error. EXCLUDES nonce (minted inside seal), ciphertext_hash
    // (circular), and author_signature itself. Byte order UNCHANGED (this is signed).
    let Header {
        kind,
        format,
        aead,
        compression,
        key_id,
        nonce: _,
        tree_id,
        replica_id,
        replica_counter,
        ciphertext_hash: _,
        prev_ciphertext_hash,
        covers_through_seq,
        replaces_ciphertext_hash,
        author_signature: _,
        author_member_id,
        governing_ref,
        blob_id,
    } = header;
    let mut out = Vec::with_capacity(224);
    put_bytes(&mut out, b"openom:author:v1");
    put_u32(&mut out, version);
    put_u32(&mut out, *kind as u32);
    put_u32(&mut out, *format as u32);
    put_u32(&mut out, *aead as u32);
    put_u32(&mut out, *compression as u32);
    put_bytes(&mut out, key_id);
    put_bytes(&mut out, tree_id);
    put_bytes(&mut out, replica_id);
    put_u64(&mut out, *replica_counter);
    put_bytes(&mut out, prev_ciphertext_hash);
    put_u64(&mut out, *covers_through_seq);
    put_bytes(&mut out, replaces_ciphertext_hash);
    put_bytes(&mut out, blob_id);
    put_bytes(&mut out, author_member_id.as_bytes());
    // Opaque engine-produced governing reference (length-prefixed, so unambiguous). Replaces the old
    // chain-only keyring_revision scalar (OPE-277 GoverningRef).
    put_bytes(&mut out, governing_ref);
    put_bytes(&mut out, plaintext_hash);
    out
}

/// Domain-separated, length-prefixed AAD binding a DEK wrap to its context (§4):
/// `(tree_id, key_id, member_id, wrap_method)`, so a wrap can't be transplanted between members,
/// epochs, or trees. `key_id` is a fresh random per-epoch salt, so it already identifies the epoch — no
/// epoch scalar is needed here (and the epoch counter is signature-covered upstream: `keyring_signing_bytes`
/// on the chain, the op signature over `sealing` on the dag). The leading domain tag makes it byte-disjoint
/// from the header AAD (which starts with a bare version integer).
pub fn wrap_aad(tree_id: &[u8], key_id: &[u8], member_id: &str, wrap_method: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    put_bytes(&mut out, b"openom:wrap:v2");
    put_bytes(&mut out, tree_id);
    put_bytes(&mut out, key_id);
    put_bytes(&mut out, member_id.as_bytes());
    put_u32(&mut out, wrap_method as u32);
    out
}

/// Domain-separated AAD for a **recovery-root-key private-key wrap** (§4). Unlike a
/// per-epoch DEK wrap, the recovery root key is tree-scoped, not epoch-scoped, so it binds
/// only `(tree_id, member_id, wrap_method)` under its own `openom:rrk:v1` tag — byte-
/// disjoint from `wrap_aad` (so an RRK wrap can never be reinterpreted as an epoch-DEK
/// wrap even when it reuses the passphrase/recovery `wrap_method` values).
pub fn rrk_wrap_aad(tree_id: &[u8], member_id: &str, wrap_method: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    put_bytes(&mut out, b"openom:rrk:v1");
    put_bytes(&mut out, tree_id);
    put_bytes(&mut out, member_id.as_bytes());
    put_u32(&mut out, wrap_method as u32);
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
    use openom_protocol::v1::{Aead, Compression, Format, Kind};

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
            author_member_id: String::new(),
            governing_ref: vec![],
        }
    }

    /// Independently-constructed expected layout — proves the encoder matches §5
    /// byte-for-byte. This is the anchor a JS/WASM twin must also reproduce.
    #[test]
    fn matches_documented_layout() {
        let mut want = Vec::new();
        for v in [
            1u32, /*version*/
            1,    /*kind*/
            1,    /*format*/
            2,    /*aead*/
            1,    /*compression*/
        ] {
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
        framed(&mut want, &[]); // prev_ciphertext_hash
        want.extend_from_slice(&0u64.to_be_bytes()); // covers_through_seq
        framed(&mut want, &[]); // replaces_ciphertext_hash
        framed(&mut want, &[]); // author_signature
        framed(&mut want, &[]); // blob_id
        framed(&mut want, &[]); // author_member_id
        framed(&mut want, &[]); // governing_ref (length-prefixed opaque bytes; empty here)
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

    // ---- author_signing_bytes (§B3 launch gate) ----

    fn attributed() -> Header {
        let mut h = sample();
        h.kind = Kind::Delta as i32;
        h.author_member_id = "member-1".into();
        h.governing_ref = 3u32.to_be_bytes().to_vec();
        h
    }

    /// Independently-constructed expected layout — the anchor a JS/WASM twin must reproduce.
    #[test]
    fn author_signing_bytes_documented_layout() {
        let h = attributed();
        let hash = [0x44u8; 32];
        let mut want = Vec::new();
        let framed = |w: &mut Vec<u8>, b: &[u8]| {
            w.extend_from_slice(&(b.len() as u32).to_be_bytes());
            w.extend_from_slice(b);
        };
        framed(&mut want, b"openom:author:v1");
        for v in [
            1u32, /*version*/
            Kind::Delta as u32,
            1, /*format*/
            2, /*aead*/
            Compression::None as u32,
        ] {
            want.extend_from_slice(&v.to_be_bytes());
        }
        framed(&mut want, &[0xAA, 0xBB]); // key_id
        framed(&mut want, &[0x11; 16]); // tree_id
        framed(&mut want, &[0x22; 4]); // replica_id
        want.extend_from_slice(&5u64.to_be_bytes()); // replica_counter
        framed(&mut want, &[]); // prev_ciphertext_hash
        want.extend_from_slice(&0u64.to_be_bytes()); // covers_through_seq
        framed(&mut want, &[]); // replaces_ciphertext_hash
        framed(&mut want, &[]); // blob_id
        framed(&mut want, b"member-1"); // author_member_id
        framed(&mut want, &3u32.to_be_bytes()); // governing_ref (length-prefixed; chain = revision 3)
        framed(&mut want, &hash); // SHA-256(plaintext)
        assert_eq!(author_signing_bytes(1, &h, &hash), want);
    }

    /// Excludes nonce, ciphertext_hash, and author_signature — changing any leaves the signing bytes
    /// unchanged (so the signature is computable pre-seal and doesn't self-reference).
    #[test]
    fn author_signing_bytes_excludes_seal_derived_fields() {
        let h = attributed();
        let hash = [0x44u8; 32];
        let base = author_signing_bytes(1, &h, &hash);
        for mutate in [
            |x: &mut Header| x.nonce = vec![0xEE; 24],
            |x: &mut Header| x.ciphertext_hash = vec![0xEE; 32],
            |x: &mut Header| x.author_signature = vec![0xEE; 64],
        ] {
            let mut m = h.clone();
            mutate(&mut m);
            assert_eq!(
                author_signing_bytes(1, &m, &hash),
                base,
                "seal-derived field must not affect signing bytes"
            );
        }
    }

    /// Binds content + attribution: changing the plaintext hash, the claimed author, the governing
    /// revision, or the kind all change the signing bytes (so none can be swapped under a fixed signature).
    #[test]
    fn author_signing_bytes_binds_content_and_attribution() {
        let h = attributed();
        let hash = [0x44u8; 32];
        let base = author_signing_bytes(1, &h, &hash);
        assert_ne!(author_signing_bytes(1, &h, &[0x55; 32]), base, "plaintext hash bound");
        let mut a = h.clone();
        a.author_member_id = "member-2".into();
        assert_ne!(author_signing_bytes(1, &a, &hash), base, "author_member_id bound");
        let mut r = h.clone();
        r.governing_ref = 4u32.to_be_bytes().to_vec();
        assert_ne!(author_signing_bytes(1, &r, &hash), base, "governing_ref bound");
        let mut k = h.clone();
        k.kind = Kind::Proposal as i32;
        assert_ne!(author_signing_bytes(1, &k, &hash), base, "kind bound (no re-seal a proposal as a delta)");
    }

    /// Domain-separated from every other signed/authenticated byte string, so a signature can't be
    /// cross-replayed (a founder's author key IS their signer key — only the tag separates the contexts).
    #[test]
    fn author_signing_bytes_domain_disjoint() {
        let h = attributed();
        let asb = author_signing_bytes(1, &h, &[0x44; 32]);
        assert_eq!(&asb[..4], &(b"openom:author:v1".len() as u32).to_be_bytes());
        assert_eq!(&asb[4..20], b"openom:author:v1");
        // header_aad starts with a bare version int (0,0,0,1), not a framed tag → disjoint at byte 0..4.
        assert_ne!(asb[..4], header_aad(1, &h)[..4]);
    }

    #[test]
    fn wrap_aad_binds_every_context_field() {
        let base = wrap_aad(b"tree", b"key", "member", 1);
        assert_eq!(base, wrap_aad(b"tree", b"key", "member", 1)); // deterministic
        assert_ne!(base, wrap_aad(b"TREE", b"key", "member", 1)); // tree_id
        assert_ne!(base, wrap_aad(b"tree", b"KEY", "member", 1)); // key_id (also the per-epoch identity)
        assert_ne!(base, wrap_aad(b"tree", b"key", "other", 1)); // member_id
        assert_ne!(base, wrap_aad(b"tree", b"key", "member", 2)); // wrap_method
    }

    #[test]
    fn wrap_aad_is_disjoint_from_header_aad() {
        // The domain tag prevents a header AAD from ever colliding with a wrap AAD.
        assert_ne!(wrap_aad(b"", b"", "", 0), header_aad(0, &Header::default()));
    }

    #[test]
    fn rrk_wrap_aad_binds_each_input() {
        // The rrk wrap AAD must bind (tree_id, member_id, wrap_method) so a wrap can't be transplanted.
        // Kills a constant/empty rrk_wrap_aad: non-empty, and every input moves the bytes.
        let base = rrk_wrap_aad(b"tree-16-byte-abc", "member", 1);
        assert!(!base.is_empty());
        assert_ne!(base, rrk_wrap_aad(b"other-16byte-abc", "member", 1), "tree_id is bound");
        assert_ne!(base, rrk_wrap_aad(b"tree-16-byte-abc", "other", 1), "member_id is bound");
        assert_ne!(base, rrk_wrap_aad(b"tree-16-byte-abc", "member", 2), "wrap_method is bound");
    }
}
