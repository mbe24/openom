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

use crate::v1::{
    AuthorizedSigner, Header, KdfParams, KeyEpoch, KeyWrap, Keyring, Member, RecoveryKey,
};

/// Build the canonical AAD for an envelope with wire `version` and `header` (§5).
///
/// Field order matches the proto: version, then `kind, format, aead, compression`
/// (each a 4-byte big-endian enum), `key_id, nonce, tree_id, replica_id` (each a
/// 4-byte big-endian length then bytes), `replica_counter` (8-byte BE),
/// `prev_ciphertext_hash` (framed bytes), `covers_through_seq` (8-byte BE), then
/// `replaces_ciphertext_hash, author_signature, blob_id` (framed bytes).
/// `ciphertext_hash` is **excluded** (it derives from the ciphertext the AEAD tag
/// already authenticates — binding it would be circular; see below).
#[deny(unused_variables)]
pub fn header_aad(version: u32, header: &Header) -> Vec<u8> {
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

/// The canonical, domain-separated byte string an authorized signer's Ed25519 key
/// signs over the keyring (§4): every keyring field **except `signatures`**, length- and
/// count-prefixed so a signature can't be replayed onto a different keyring or another
/// structure. The `openom:keyring` tag separates this from the header/wrap AAD;
/// `layout_version` is first (after the tag) and is the sole version axis — a
/// fail-closed forward selector, like `Envelope.version` — so any future keyring layout
/// is byte-disjoint from this one. Covered: `revision`/`prev_keyring_hash` (anti-rollback
/// and history chain), the `authorized_signers` trust set, the `members` role/key manifest,
/// and the epochs/wraps. `signatures` is excluded, so every signer signs identical bytes
/// and their signatures collect independently.
#[deny(unused_variables)]
pub fn keyring_signing_bytes(keyring: &Keyring) -> Vec<u8> {
    // Exhaustive destructure (no `..`) + deny(unused): adding a Keyring/RecoveryKey/etc. field is a
    // compile error here until it is signed or explicitly excluded. This is the guard that would have
    // prevented the recovery_verifying_key signing-omission (OPE-277 crypto review). Byte order UNCHANGED.
    let Keyring {
        tree_id,
        epochs,
        revision,
        layout_version,
        prev_keyring_hash,
        authorized_signers,
        members,
        // `signatures` EXCLUDED by design: every signer signs identical bytes, so their signatures
        // collect independently — the one field that must NOT be in its own signed bytes.
        signatures: _,
        recovery_keys,
        governance_kind,
        governance_threshold,
    } = keyring;

    let mut out = Vec::with_capacity(256);
    put_bytes(&mut out, b"openom:keyring");
    put_u32(&mut out, *layout_version);
    put_bytes(&mut out, tree_id);
    put_u32(&mut out, *revision);
    put_bytes(&mut out, prev_keyring_hash);

    put_u32(&mut out, authorized_signers.len() as u32);
    for s in authorized_signers {
        let AuthorizedSigner { public_key, member_id, role } = s;
        put_bytes(&mut out, public_key);
        put_bytes(&mut out, member_id.as_bytes());
        put_u32(&mut out, *role as u32);
    }

    put_u32(&mut out, members.len() as u32);
    for m in members {
        let Member { member_id, role, author_public_key, hpke_public_key } = m;
        put_bytes(&mut out, member_id.as_bytes());
        put_u32(&mut out, *role as u32);
        put_bytes(&mut out, author_public_key);
        put_bytes(&mut out, hpke_public_key);
    }

    put_u32(&mut out, epochs.len() as u32);
    for ep in epochs {
        let KeyEpoch { key_id, epoch, wraps } = ep;
        put_bytes(&mut out, key_id);
        put_u32(&mut out, *epoch);
        put_u32(&mut out, wraps.len() as u32);
        for w in wraps {
            put_wrap(&mut out, w);
        }
    }

    put_u32(&mut out, recovery_keys.len() as u32);
    for rk in recovery_keys {
        // The RVK (recovery_verifying_key) MUST be signed — the omission the crypto review caught. The
        // destructure now makes forgetting it a compile error.
        let RecoveryKey { public_key, member_id, wraps, recovery_verifying_key } = rk;
        put_bytes(&mut out, public_key);
        put_bytes(&mut out, member_id.as_bytes());
        put_u32(&mut out, wraps.len() as u32);
        for w in wraps {
            put_wrap(&mut out, w);
        }
        put_bytes(&mut out, recovery_verifying_key);
    }
    // Governance rule — signed, so it's tamper-evident and a change to it is authorized like a set change.
    put_u32(&mut out, *governance_kind);
    put_u32(&mut out, *governance_threshold);
    out
}

/// Encode one `KeyWrap` into the keyring signing bytes: `member_id, wrap_method, nonce,
/// wrapped_dek`, then a branchless `kdf_params` (presence flag + four fields, zeros when
/// absent), then `ephemeral_public_key`. Shared by the epoch wraps and the recovery-key
/// wraps so the two never drift.
#[deny(unused_variables)]
fn put_wrap(out: &mut Vec<u8>, w: &KeyWrap) {
    // Exhaustive destructure (no `..`) + deny(unused): a new KeyWrap/KdfParams field can't slip out of
    // the signed/AAD wrap encoding. Byte order UNCHANGED.
    let KeyWrap { member_id, wrap_method, nonce, wrapped_dek, kdf_params, ephemeral_public_key } = w;
    put_bytes(out, member_id.as_bytes());
    put_u32(out, *wrap_method as u32);
    put_bytes(out, nonce);
    put_bytes(out, wrapped_dek);
    match kdf_params {
        Some(k) => {
            let KdfParams { salt, memory_kib, iterations, parallelism } = k;
            put_u32(out, 1);
            put_bytes(out, salt);
            put_u32(out, *memory_kib);
            put_u32(out, *iterations);
            put_u32(out, *parallelism);
        }
        None => {
            put_u32(out, 0);
            put_bytes(out, &[]);
            put_u32(out, 0);
            put_u32(out, 0);
            put_u32(out, 0);
        }
    }
    put_bytes(out, ephemeral_public_key);
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
                                                     // ciphertext_hash is excluded from the AAD (circular + redundant).
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
                                          // nonce EXCLUDED (minted at seal)
        framed(&mut want, &[0x11; 16]); // tree_id
        framed(&mut want, &[0x22; 4]); // replica_id
        want.extend_from_slice(&5u64.to_be_bytes()); // replica_counter
                                                     // ciphertext_hash EXCLUDED (circular)
        framed(&mut want, &[]); // prev_ciphertext_hash
        want.extend_from_slice(&0u64.to_be_bytes()); // covers_through_seq
        framed(&mut want, &[]); // replaces_ciphertext_hash
        framed(&mut want, &[]); // blob_id
                                // author_signature EXCLUDED (self)
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
        assert_ne!(
            author_signing_bytes(1, &h, &[0x55; 32]),
            base,
            "plaintext hash bound"
        );
        let mut a = h.clone();
        a.author_member_id = "member-2".into();
        assert_ne!(
            author_signing_bytes(1, &a, &hash),
            base,
            "author_member_id bound"
        );
        let mut r = h.clone();
        r.governing_ref = 4u32.to_be_bytes().to_vec();
        assert_ne!(
            author_signing_bytes(1, &r, &hash),
            base,
            "governing_ref bound"
        );
        let mut k = h.clone();
        k.kind = Kind::Proposal as i32;
        assert_ne!(
            author_signing_bytes(1, &k, &hash),
            base,
            "kind bound (no re-seal a proposal as a delta)"
        );
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
        assert_ne!(
            wrap_aad(b"", b"", "", 0),
            header_aad(0, &Header::default())
        );
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

    #[test]
    fn keyring_signing_bytes_binds_each_wrap_field() {
        use crate::v1::{KeyEpoch, KeyWrap};
        // put_wrap encodes each KeyWrap field into the signed bytes; a changed wrap field must change
        // them (kills put_wrap being stubbed to a no-op, which would leave every wrap unbound).
        let kr = |member: &str, nonce: Vec<u8>, method: i32| Keyring {
            tree_id: vec![],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![],
            members: vec![],
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![],
                epoch: 0,
                wraps: vec![KeyWrap {
                    member_id: member.into(),
                    wrap_method: method,
                    nonce,
                    wrapped_dek: vec![9; 48],
                    kdf_params: None,
                    ephemeral_public_key: vec![],
                }],
            }],
            ..Default::default()
        };
        let base = keyring_signing_bytes(&kr("acct", vec![7; 24], 1));
        assert_ne!(base, keyring_signing_bytes(&kr("other", vec![7; 24], 1)), "wrap member_id bound");
        assert_ne!(base, keyring_signing_bytes(&kr("acct", vec![8; 24], 1)), "wrap nonce bound");
        assert_ne!(base, keyring_signing_bytes(&kr("acct", vec![7; 24], 2)), "wrap method bound");
    }

    #[test]
    fn keyring_signing_bytes_covers_and_ignores_signatures() {
        use crate::v1::{AuthorizedSigner, KdfParams, KeyEpoch, KeyWrap, KeyringSignature, Member};
        let mut kr = Keyring {
            tree_id: vec![0x11; 16],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![AuthorizedSigner {
                public_key: vec![0xAB; 32],
                member_id: "acct".into(),
                role: 1, // FOUNDER
            }],
            members: vec![Member {
                member_id: "acct".into(),
                role: 1, // OWNER
                author_public_key: vec![],
                hpke_public_key: vec![],
            }],
            // must NOT affect the signed bytes
            signatures: vec![KeyringSignature {
                signer_public_key: vec![0xAB; 32],
                signature: vec![0xFF; 64],
            }],
            recovery_keys: vec![],
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
            ..Default::default()
        };
        let a = keyring_signing_bytes(&kr);
        kr.signatures[0].signature = vec![0x00; 64];
        kr.signatures.push(KeyringSignature {
            signer_public_key: vec![1; 32],
            signature: vec![2; 64],
        });
        assert_eq!(
            a,
            keyring_signing_bytes(&kr),
            "signatures are excluded from signed bytes"
        );
        kr.revision = 2;
        assert_ne!(
            a,
            keyring_signing_bytes(&kr),
            "revision is covered (anti-rollback)"
        );

        // The signer set, the member/role manifest, and the history-chain link are covered.
        let mut set_change = kr.clone();
        set_change.revision = 1;
        set_change.authorized_signers[0].role = 2; // FOUNDER -> CO_OWNER
        assert_ne!(
            a,
            keyring_signing_bytes(&set_change),
            "authorized_signers are covered"
        );
        let mut role_change = kr.clone();
        role_change.revision = 1;
        role_change.members[0].role = 4; // OWNER -> EDITOR
        assert_ne!(
            a,
            keyring_signing_bytes(&role_change),
            "members are covered"
        );
        let mut chained = kr.clone();
        chained.revision = 1;
        chained.prev_keyring_hash = vec![0x77; 32];
        assert_ne!(
            a,
            keyring_signing_bytes(&chained),
            "prev_keyring_hash is covered"
        );

        // The recovery verifying key (RVK) is covered — an untrusted server must not be able to
        // substitute OR blank it undetectably, or the reset-authorization gate that trusts it is defeated
        // (OPE-277 crypto review).
        use crate::v1::RecoveryKey;
        let mut with_rvk = kr.clone();
        with_rvk.revision = 1;
        with_rvk.recovery_keys = vec![RecoveryKey {
            public_key: vec![0x22; 32],
            member_id: "acct".into(),
            wraps: vec![],
            recovery_verifying_key: vec![0xAA; 32],
        }];
        let with = keyring_signing_bytes(&with_rvk);
        let mut swapped = with_rvk.clone();
        swapped.recovery_keys[0].recovery_verifying_key = vec![0xBB; 32];
        assert_ne!(with, keyring_signing_bytes(&swapped), "recovery_verifying_key substitution is covered");
        let mut blanked = with_rvk.clone();
        blanked.recovery_keys[0].recovery_verifying_key = vec![];
        assert_ne!(with, keyring_signing_bytes(&blanked), "recovery_verifying_key blanking is covered");
    }

    #[test]
    fn keyring_signing_bytes_layout_version_disjoint() {
        let mut kr = Keyring {
            tree_id: vec![1; 16],
            revision: 1,
            layout_version: 1,
            ..Default::default()
        };
        let v1 = keyring_signing_bytes(&kr);
        kr.layout_version = 2;
        assert_ne!(
            v1,
            keyring_signing_bytes(&kr),
            "layout_version must make signing bytes disjoint"
        );
    }
}
