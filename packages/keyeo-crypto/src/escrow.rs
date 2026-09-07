//! The recovery-escrow wrap ops — seal the recovery-root SECRET under a KEK so the owner can reach it from
//! a passphrase or the printed recovery code, and open it again.
//!
//! Unlike a DEK wrap, the recovery root key is TREE-scoped, not epoch-scoped, so these bind only the group
//! (via `rrk_wrap_aad`, no `key_id`) — the "re-wrap, not rotate" invariant: the escrow stays valid across
//! every epoch, so a passphrase change re-seals only this small wrap, never the data. That is why the escrow
//! ops take a bare [`GroupId`] rather than a [`GroupContext`](crate::GroupContext).

use zeroize::Zeroizing;

use crate::aead::{xchacha_open, xchacha_seal};
use crate::GroupId;
use crate::keyring::{KekKind, RecipientId, Wrap, WrapMethod};
use crate::wrap_aad::rrk_wrap_aad;
use crate::{CryptoError, KdfParams, Kek, Key32, KEY_LEN};
use crate::{Nonce, WrappedDek};

/// XChaCha20-Poly1305 nonce length for a KEK wrap.
const KEK_NONCE_LEN: usize = 24;

const fn kek_method_tag(kind: KekKind) -> i32 {
    match kind {
        KekKind::Passphrase => WrapMethod::TAG_PASSPHRASE_KEK,
        KekKind::RecoveryCode => WrapMethod::TAG_RECOVERY_KEK,
    }
}

/// KEK-wrap a 32-byte `secret` (the recovery-root secret) under `kek`, bound to the tree-scoped rrk AAD.
/// Generates a fresh nonce; delegates to [`kek_wrap_with_nonce`].
///
/// # Errors
/// Returns [`CryptoError`] if the RNG or the KEK seal fails.
pub fn kek_wrap<Id: RecipientId>(
    secret: &[u8],
    recipient: Id,
    kind: KekKind,
    kek: &Kek,
    kdf: KdfParams,
    group_id: &GroupId,
) -> Result<Wrap<Id>, CryptoError> {
    let mut nonce = [0u8; KEK_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    kek_wrap_with_nonce(
        Nonce::from_bytes(nonce),
        secret,
        recipient,
        kind,
        kek,
        kdf,
        group_id,
    )
}

/// The deterministic core of [`kek_wrap`], with the `nonce` supplied by the caller — same inputs yield the
/// same wrap, so the context-binding property is testable without the RNG. **Contract:** `nonce` must be a
/// fresh, unique 24-byte value.
///
/// # Errors
/// Returns [`CryptoError`] on a bad nonce length or if the seal fails.
pub fn kek_wrap_with_nonce<Id: RecipientId>(
    nonce: Nonce,
    secret: &[u8],
    recipient: Id,
    kind: KekKind,
    kek: &Kek,
    kdf: KdfParams,
    group_id: &GroupId,
) -> Result<Wrap<Id>, CryptoError> {
    let aad = rrk_wrap_aad(
        group_id.as_bytes(),
        &recipient.aad_bytes(),
        kek_method_tag(kind),
    );
    let ciphertext = xchacha_seal(kek.expose(), nonce.as_ref(), &aad, secret)?;
    Ok(Wrap {
        recipient,
        method: WrapMethod::Kek { kind, kdf, nonce },
        ciphertext: WrappedDek::try_from(ciphertext.as_slice()).map_err(|_| CryptoError::Hpke)?,
    })
}

/// Open a KEK escrow wrap under `kek`, returning the sealed 32-byte secret (zeroizing). Rebuilds the
/// tree-scoped rrk AAD from the wrap's own recipient + method, so a wrong KEK / tampered wrap / mismatched
/// group all fail as [`CryptoError::Open`]. A DEK (HPKE) wrap is not an escrow wrap and is rejected.
///
/// # Errors
/// Returns [`CryptoError`] on a wrong KEK, tampered wrap, or mismatched context; a non-escrow (DEK)
/// wrap is rejected.
pub fn unwrap_kek<Id: RecipientId>(
    wrap: &Wrap<Id>,
    kek: &Kek,
    group_id: &GroupId,
) -> Result<Key32, CryptoError> {
    let (kind, nonce) = match &wrap.method {
        WrapMethod::Kek { kind, nonce, .. } => (*kind, nonce),
        _ => return Err(CryptoError::Open),
    };
    let aad = rrk_wrap_aad(
        group_id.as_bytes(),
        &wrap.recipient.aad_bytes(),
        kek_method_tag(kind),
    );
    let plaintext = Zeroizing::new(xchacha_open(
        kek.expose(),
        nonce.as_ref(),
        &aad,
        wrap.ciphertext.as_ref(),
    )?);
    let secret: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyLength)?;
    Ok(Zeroizing::new(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> KdfParams {
        KdfParams {
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn escrow_round_trips_under_the_right_kek() {
        let group = GroupId::new(b"tree".to_vec());
        let kek = Kek::new([42u8; 32]);
        let secret = [9u8; 32];
        let wrap = kek_wrap(
            &secret,
            "owner".to_string(),
            KekKind::Passphrase,
            &kek,
            kdf(),
            &group,
        )
        .unwrap();
        assert_eq!(wrap.method.tag(), WrapMethod::TAG_PASSPHRASE_KEK);
        let opened = unwrap_kek(&wrap, &kek, &group).unwrap();
        assert_eq!(&*opened, &secret);
    }

    #[test]
    fn a_wrong_kek_or_group_fails() {
        let group = GroupId::new(b"tree".to_vec());
        let kek = Kek::new([42u8; 32]);
        let wrap = kek_wrap(
            &[9u8; 32],
            "owner".to_string(),
            KekKind::RecoveryCode,
            &kek,
            kdf(),
            &group,
        )
        .unwrap();
        // wrong KEK
        assert!(matches!(
            unwrap_kek(&wrap, &Kek::new([7u8; 32]), &group),
            Err(CryptoError::Open)
        ));
        // wrong group rebuilds a different AAD → the tag fails
        let other = GroupId::new(b"tree-B".to_vec());
        assert!(matches!(
            unwrap_kek(&wrap, &kek, &other),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn the_two_kek_kinds_bind_distinctly() {
        // A passphrase wrap and a recovery-code wrap of the same secret to the same recipient carry
        // different AADs (their method tag differs), so neither can be reinterpreted as the other.
        let group = GroupId::new(b"tree".to_vec());
        let kek = Kek::new([42u8; 32]);
        let nonce = Nonce::from_bytes([5u8; 24]);
        let pass = kek_wrap_with_nonce(
            nonce,
            &[9u8; 32],
            "owner".to_string(),
            KekKind::Passphrase,
            &kek,
            kdf(),
            &group,
        )
        .unwrap();
        let rec = kek_wrap_with_nonce(
            nonce,
            &[9u8; 32],
            "owner".to_string(),
            KekKind::RecoveryCode,
            &kek,
            kdf(),
            &group,
        )
        .unwrap();
        // Same secret, KEK, nonce, recipient — only the method differs, and that moves the ciphertext.
        assert_ne!(pass.ciphertext, rec.ciphertext);
    }
}
