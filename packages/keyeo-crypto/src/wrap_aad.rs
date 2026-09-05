//! The DEK-wrap AAD — the keyring key-material binding that stops a wrap being transplanted between
//! members, epochs, or trees.
//!
//! A wrap is authenticated against the tuple `(group_id, key_id, member_id, wrap_method)` — all keyring
//! identifiers, no application content. `key_id` is a fresh random per-epoch salt, so it already
//! identifies the epoch; no separate epoch scalar is needed. The AAD is a dedicated byte string built by
//! **length-prefixed concatenation in a fixed field order** with a leading domain tag, so a Rust build and
//! a WASM/JS build produce byte-identical bytes, and the tag makes it byte-disjoint from every other AAD
//! (the RRK-secret wrap below, and any content/envelope AAD a consumer layers above).
//!
//! This is keyeo's own binding — retagged `keyeo:` — so the keyring key material is self-contained here,
//! not in an application crate. The 4-byte-big-endian length-prefix encoder is the same one the format has
//! always used; only the domain tag changed.

/// `4-byte big-endian length prefix, then the bytes` — the framing that defeats the
/// `"ab"+"c" == "a"+"bc"` forgery class.
#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// AAD binding an epoch-DEK wrap to its context: `(group_id, key_id, member_id, wrap_method)`, so a wrap
/// can't be transplanted between members, epochs, or trees. `key_id` is a fresh per-epoch salt, so it
/// already identifies the epoch. The leading domain tag makes it byte-disjoint from [`rrk_wrap_aad`] and
/// from any content AAD.
pub fn wrap_aad(group_id: &[u8], key_id: &[u8], member_id: &str, wrap_method: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    put_bytes(&mut out, b"keyeo:wrap:v1");
    put_bytes(&mut out, group_id);
    put_bytes(&mut out, key_id);
    put_bytes(&mut out, member_id.as_bytes());
    put_u32(&mut out, wrap_method as u32);
    out
}

/// AAD for a **recovery-root-key private-key wrap**. Unlike a per-epoch DEK wrap, the recovery root key is
/// tree-scoped, not epoch-scoped, so it binds only `(group_id, member_id, wrap_method)` under its own
/// `keyeo:rrk:v1` tag — byte-disjoint from [`wrap_aad`], so an RRK wrap can never be reinterpreted as an
/// epoch-DEK wrap even when it reuses the passphrase/recovery `wrap_method` values.
pub fn rrk_wrap_aad(group_id: &[u8], member_id: &str, wrap_method: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    put_bytes(&mut out, b"keyeo:rrk:v1");
    put_bytes(&mut out, group_id);
    put_bytes(&mut out, member_id.as_bytes());
    put_u32(&mut out, wrap_method as u32);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_aad_binds_every_context_field() {
        let base = wrap_aad(b"tree", b"key", "member", 1);
        assert_eq!(base, wrap_aad(b"tree", b"key", "member", 1)); // deterministic
        assert_ne!(base, wrap_aad(b"TREE", b"key", "member", 1)); // group_id
        assert_ne!(base, wrap_aad(b"tree", b"KEY", "member", 1)); // key_id (also the per-epoch identity)
        assert_ne!(base, wrap_aad(b"tree", b"key", "other", 1)); // member_id
        assert_ne!(base, wrap_aad(b"tree", b"key", "member", 2)); // wrap_method
    }

    #[test]
    fn rrk_wrap_aad_binds_each_input() {
        let base = rrk_wrap_aad(b"tree-16-byte-abc", "member", 1);
        assert!(!base.is_empty());
        assert_ne!(base, rrk_wrap_aad(b"other-16byte-abc", "member", 1), "group_id is bound");
        assert_ne!(base, rrk_wrap_aad(b"tree-16-byte-abc", "other", 1), "member_id is bound");
        assert_ne!(base, rrk_wrap_aad(b"tree-16-byte-abc", "member", 2), "wrap_method is bound");
    }

    #[test]
    fn wrap_and_rrk_aads_are_byte_disjoint() {
        // The distinct domain tags keep an epoch-DEK wrap and an RRK-secret wrap from ever colliding,
        // even with identical (group, member, method) — so one can never be reinterpreted as the other.
        assert_ne!(wrap_aad(b"g", b"k", "m", 1), rrk_wrap_aad(b"g", "m", 1));
        assert_ne!(wrap_aad(b"", b"", "", 0), rrk_wrap_aad(b"", "", 0));
    }

    #[test]
    fn length_framing_prevents_concatenation_forgery() {
        // `("a","bc") != ("ab","c")` — the length prefixes make adjacent fields unambiguous, so two
        // different field splits can never produce the same AAD.
        assert_ne!(wrap_aad(b"a", b"bc", "m", 1), wrap_aad(b"ab", b"c", "m", 1));
    }
}
