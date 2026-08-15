//! DEK wrapping (§4) — seal a per-tree DEK under a per-member KEK, bound to the
//! `(tree_id, key_id, member_id, wrap_method, epoch)` context so a wrap can't be
//! transplanted between members, epochs, or trees.
//!
//! The wrap AEAD is XChaCha20-Poly1305 (24-byte random nonce). This is the indirection
//! that lets the passphrase change, and lets a tree be shared, without re-encrypting
//! the data: only the small wrap is re-made, never the payloads.

use openom_protocol::aad::wrap_aad;
use zeroize::Zeroizing;

use crate::seal::{xchacha_open, xchacha_seal};
use crate::{CryptoError, Key32, KEY_LEN};

/// XChaCha20-Poly1305 nonce length for a wrap.
const WRAP_NONCE_LEN: usize = 24;

/// The binding tuple a wrap is authenticated against (§4).
pub struct WrapContext<'a> {
    pub tree_id: &'a [u8],
    pub key_id: &'a [u8],
    pub member_id: &'a str,
    /// `WrapMethod` value (e.g. `WRAP_METHOD_PASSPHRASE_ARGON2ID`).
    pub wrap_method: i32,
    pub epoch: u32,
}

/// The output of a wrap: the random nonce and the sealed DEK, to store in a `KeyWrap`.
pub struct WrappedDek {
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// Wrap `dek` under `kek`, bound to `ctx`. Generates a fresh nonce.
pub fn wrap_dek(
    kek: &Key32,
    dek: &[u8; KEY_LEN],
    ctx: &WrapContext,
) -> Result<WrappedDek, CryptoError> {
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let aad = wrap_aad(ctx.tree_id, ctx.key_id, ctx.member_id, ctx.wrap_method, ctx.epoch);
    let wrapped_dek = xchacha_seal(kek, &nonce, &aad, dek)?;
    Ok(WrappedDek { nonce: nonce.to_vec(), wrapped_dek })
}

/// Unwrap a DEK: verify the wrap against `kek` + `ctx` and return the DEK (zeroizing).
/// A wrong KEK, a corrupted wrap, or a mismatched context all fail as
/// [`CryptoError::Open`].
pub fn unwrap_dek(
    kek: &Key32,
    nonce: &[u8],
    wrapped_dek: &[u8],
    ctx: &WrapContext,
) -> Result<Key32, CryptoError> {
    let aad = wrap_aad(ctx.tree_id, ctx.key_id, ctx.member_id, ctx.wrap_method, ctx.epoch);
    let dek_bytes = Zeroizing::new(xchacha_open(kek, nonce, &aad, wrapped_dek)?);
    let dek: [u8; KEY_LEN] = dek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyLength)?;
    Ok(Zeroizing::new(dek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_dek;

    fn ctx() -> WrapContext<'static> {
        WrapContext {
            tree_id: b"tree-uuid-16byte",
            key_id: b"epoch-0-key",
            member_id: "acct-123",
            wrap_method: 1, // WRAP_METHOD_PASSPHRASE_ARGON2ID
            epoch: 0,
        }
    }

    fn kek() -> Key32 {
        Zeroizing::new([42u8; KEY_LEN])
    }

    #[test]
    fn round_trip() {
        let dek = generate_dek().unwrap();
        let w = wrap_dek(&kek(), &dek, &ctx()).unwrap();
        let unwrapped = unwrap_dek(&kek(), &w.nonce, &w.wrapped_dek, &ctx()).unwrap();
        assert_eq!(*unwrapped, *dek);
    }

    #[test]
    fn wrong_kek_fails() {
        let dek = generate_dek().unwrap();
        let w = wrap_dek(&kek(), &dek, &ctx()).unwrap();
        let other: Key32 = Zeroizing::new([7u8; KEY_LEN]);
        assert!(matches!(
            unwrap_dek(&other, &w.nonce, &w.wrapped_dek, &ctx()),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn transplant_across_context_fails() {
        // A wrap made for one member/tree/epoch must not open under another (§4).
        let dek = generate_dek().unwrap();
        let w = wrap_dek(&kek(), &dek, &ctx()).unwrap();
        for tampered in [
            WrapContext { member_id: "acct-999", ..ctx() },
            WrapContext { tree_id: b"other-tree-16byt", ..ctx() },
            WrapContext { key_id: b"epoch-1-key", ..ctx() },
            WrapContext { epoch: 1, ..ctx() },
            WrapContext { wrap_method: 2, ..ctx() },
        ] {
            assert!(matches!(
                unwrap_dek(&kek(), &w.nonce, &w.wrapped_dek, &tampered),
                Err(CryptoError::Open)
            ));
        }
    }

    #[test]
    fn wrapped_dek_is_not_plaintext() {
        let dek = generate_dek().unwrap();
        let w = wrap_dek(&kek(), &dek, &ctx()).unwrap();
        assert_ne!(w.wrapped_dek.as_slice(), dek.as_slice());
        assert!(w.wrapped_dek.len() > KEY_LEN); // + AEAD tag
    }
}
