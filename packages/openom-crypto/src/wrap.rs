//! DEK wrapping (§4) — seal a per-tree DEK under a per-member KEK, bound to the
//! `(tree_id, key_id, member_id, wrap_method)` context so a wrap can't be
//! transplanted between members, epochs, or trees. `key_id` is a fresh random salt per epoch, so it
//! *is* the epoch's identity — the AAD needs no separate epoch scalar (OPE-281).
//!
//! The wrap AEAD is XChaCha20-Poly1305 (24-byte random nonce). This is the indirection
//! that lets the passphrase change, and lets a tree be shared, without re-encrypting
//! the data: only the small wrap is re-made, never the payloads.

use crate::aad::{rrk_wrap_aad, wrap_aad};
use zeroize::Zeroizing;

use keyeo_crypto::aead::{xchacha_open, xchacha_seal};
use crate::{CryptoError, Dek, Kek, RrkSecret, KEY_LEN};

/// XChaCha20-Poly1305 nonce length for a wrap.
const WRAP_NONCE_LEN: usize = 24;

/// The binding tuple a wrap is authenticated against (§4). No epoch field: `key_id` is a per-epoch random
/// salt, so it already uniquely identifies the epoch, and the epoch counter is signature-covered upstream.
pub struct WrapContext<'a> {
    pub tree_id: &'a [u8],
    pub key_id: &'a [u8],
    pub member_id: &'a str,
    /// `WrapMethod` value (e.g. `WRAP_METHOD_PASSPHRASE_ARGON2ID`).
    pub wrap_method: i32,
}

/// The output of a wrap: the random nonce and the sealed DEK, to store in a `KeyWrap`.
pub struct WrappedDek {
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// Wrap `dek` under `kek`, bound to `ctx`. Generates a fresh nonce, then delegates to the pure
/// [`wrap_dek_with_nonce`].
pub fn wrap_dek(kek: &Kek, dek: &Dek, ctx: &WrapContext) -> Result<WrappedDek, CryptoError> {
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    wrap_dek_with_nonce(nonce, kek, dek, ctx)
}

/// The deterministic core of [`wrap_dek`], with the `nonce` supplied by the caller: build the wrap
/// AAD from `ctx` and seal. Same inputs → same wrap, so the context-binding property is testable and
/// Kani-verifiable without the RNG. **Contract:** `nonce` must be a fresh, unique 24-byte value.
pub fn wrap_dek_with_nonce(
    nonce: [u8; WRAP_NONCE_LEN],
    kek: &Kek,
    dek: &Dek,
    ctx: &WrapContext,
) -> Result<WrappedDek, CryptoError> {
    let aad = wrap_aad(ctx.tree_id, ctx.key_id, ctx.member_id, ctx.wrap_method);
    let wrapped_dek = xchacha_seal(kek.expose(), &nonce, &aad, dek.expose())?;
    Ok(WrappedDek {
        nonce: nonce.to_vec(),
        wrapped_dek,
    })
}

/// Unwrap a DEK: verify the wrap against `kek` + `ctx` and return the DEK (zeroizing).
/// A wrong KEK, a corrupted wrap, or a mismatched context all fail as
/// [`CryptoError::Open`].
pub fn unwrap_dek(
    kek: &Kek,
    nonce: &[u8],
    wrapped_dek: &[u8],
    ctx: &WrapContext,
) -> Result<Dek, CryptoError> {
    let aad = wrap_aad(ctx.tree_id, ctx.key_id, ctx.member_id, ctx.wrap_method);
    let dek_bytes = Zeroizing::new(xchacha_open(kek.expose(), nonce, &aad, wrapped_dek)?);
    let dek: [u8; KEY_LEN] = dek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyLength)?;
    Ok(Dek::new(dek))
}

/// Wrap the recovery root key's 32-byte private key under `kek`, bound to the tree-scoped
/// rrk AAD (not the epoch tuple). Used for the founder's passphrase and recovery-code wraps
/// of the RRK private key.
pub fn wrap_rrk_secret(
    kek: &Kek,
    secret: &RrkSecret,
    tree_id: &[u8],
    member_id: &str,
    wrap_method: i32,
) -> Result<WrappedDek, CryptoError> {
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    wrap_rrk_secret_with_nonce(nonce, kek, secret, tree_id, member_id, wrap_method)
}

/// The deterministic core of [`wrap_rrk_secret`], with the `nonce` supplied by the caller. Same
/// inputs → same wrap. **Contract:** `nonce` must be a fresh, unique 24-byte value.
pub fn wrap_rrk_secret_with_nonce(
    nonce: [u8; WRAP_NONCE_LEN],
    kek: &Kek,
    secret: &RrkSecret,
    tree_id: &[u8],
    member_id: &str,
    wrap_method: i32,
) -> Result<WrappedDek, CryptoError> {
    let aad = rrk_wrap_aad(tree_id, member_id, wrap_method);
    let wrapped_dek = xchacha_seal(kek.expose(), &nonce, &aad, secret.expose())?;
    Ok(WrappedDek {
        nonce: nonce.to_vec(),
        wrapped_dek,
    })
}

/// Unwrap the recovery root key's private key under `kek`, verifying the tree-scoped rrk
/// AAD. A wrong KEK / corrupted wrap / mismatched context all fail as [`CryptoError::Open`].
pub fn unwrap_rrk_secret(
    kek: &Kek,
    nonce: &[u8],
    wrapped: &[u8],
    tree_id: &[u8],
    member_id: &str,
    wrap_method: i32,
) -> Result<RrkSecret, CryptoError> {
    let aad = rrk_wrap_aad(tree_id, member_id, wrap_method);
    let bytes = Zeroizing::new(xchacha_open(kek.expose(), nonce, &aad, wrapped)?);
    let secret: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyLength)?;
    Ok(RrkSecret::new(secret))
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
        }
    }

    fn kek() -> Kek {
        Kek::new([42u8; KEY_LEN])
    }

    #[test]
    fn round_trip() {
        let dek = generate_dek().unwrap();
        let w = wrap_dek(&kek(), &dek, &ctx()).unwrap();
        let unwrapped = unwrap_dek(&kek(), &w.nonce, &w.wrapped_dek, &ctx()).unwrap();
        assert_eq!(unwrapped.expose(), dek.expose());
    }

    #[test]
    fn wrong_kek_fails() {
        let dek = generate_dek().unwrap();
        let w = wrap_dek(&kek(), &dek, &ctx()).unwrap();
        let other = Kek::new([7u8; KEY_LEN]);
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
            WrapContext {
                member_id: "acct-999",
                ..ctx()
            },
            WrapContext {
                tree_id: b"other-tree-16byt",
                ..ctx()
            },
            // A different epoch is a different key_id (a fresh per-epoch salt), which this covers.
            WrapContext {
                key_id: b"epoch-1-key",
                ..ctx()
            },
            WrapContext {
                wrap_method: 2,
                ..ctx()
            },
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
        assert_ne!(w.wrapped_dek.as_slice(), dek.expose().as_slice());
        assert!(w.wrapped_dek.len() > KEY_LEN); // + AEAD tag
    }
}
