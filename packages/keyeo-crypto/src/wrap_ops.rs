//! The keyring wrap operations — seal an epoch DEK to a recipient, and open it again.
//!
//! Each op builds the wrap AAD from the [`GroupContext`] (group + epoch) plus the recipient and the
//! method, so a wrap is bound to exactly one group, epoch, recipient, and method and can't be transplanted.
//! These are the HPKE (public-key) wraps — a member's own key, or the recovery root's public key. The
//! symmetric KEK escrow of the RRK secret is a separate concern.

use crate::hpke_wrap::{hpke_unwrap_dek, hpke_wrap_dek};
use crate::keyring::{GroupContext, RecipientId, Wrap, WrapMethod};
use crate::wrap_aad::wrap_aad;
use crate::X25519PublicKey;
use crate::{CryptoError, Dek};

/// HPKE-wrap `dek` to a member's X25519 public key — the per-member wrap that gives them access to this
/// epoch.
///
/// # Errors
/// Returns [`CryptoError`] if the HPKE seal fails.
pub fn member_wrap<Id: RecipientId>(
    dek: &Dek,
    recipient: Id,
    recipient_key: X25519PublicKey,
    ctx: &GroupContext,
) -> Result<Wrap<Id>, CryptoError> {
    let aad = wrap_aad(
        ctx.group_id.as_bytes(),
        ctx.key_id.as_bytes(),
        &recipient.aad_bytes(),
        WrapMethod::TAG_MEMBER_HPKE,
    );
    let w = hpke_wrap_dek(recipient_key.as_ref(), dek, &aad)?;
    Ok(Wrap {
        recipient,
        method: WrapMethod::MemberHpke {
            encapped: w.encapped_key,
            recipient_key,
        },
        ciphertext: w.ciphertext,
    })
}

/// HPKE-wrap `dek` to the recovery root's public key — the founder's cross-epoch access, sealed to a key
/// whose secret the escrow protects. Distinct from a member wrap by its method (an AAD input).
///
/// # Errors
/// Returns [`CryptoError`] if the HPKE seal fails.
pub fn rrk_wrap<Id: RecipientId>(
    dek: &Dek,
    recipient: Id,
    rrk_public: X25519PublicKey,
    ctx: &GroupContext,
) -> Result<Wrap<Id>, CryptoError> {
    let aad = wrap_aad(
        ctx.group_id.as_bytes(),
        ctx.key_id.as_bytes(),
        &recipient.aad_bytes(),
        WrapMethod::TAG_RRK_HPKE,
    );
    let w = hpke_wrap_dek(rrk_public.as_ref(), dek, &aad)?;
    Ok(Wrap {
        recipient,
        method: WrapMethod::RrkHpke {
            encapped: w.encapped_key,
            recipient_key: rrk_public,
        },
        ciphertext: w.ciphertext,
    })
}

/// Open the epoch DEK from an HPKE wrap (member or recovery-root) with the recipient's X25519 secret. The
/// AAD is rebuilt from the wrap's own recipient + method + the context, so a wrap tampered onto another
/// recipient/epoch/group fails the AEAD tag. A KEK escrow wrap is not a DEK wrap — it is opened elsewhere —
/// so it is rejected here.
///
/// # Errors
/// Returns [`CryptoError`] if the wrap is a non-DEK (escrow) wrap or the AEAD open fails.
pub fn unwrap_dek<Id: RecipientId>(
    wrap: &Wrap<Id>,
    hpke_secret: &[u8],
    ctx: &GroupContext,
) -> Result<Dek, CryptoError> {
    let (encapped, tag) = match &wrap.method {
        WrapMethod::MemberHpke { encapped, .. } => (encapped, WrapMethod::TAG_MEMBER_HPKE),
        WrapMethod::RrkHpke { encapped, .. } => (encapped, WrapMethod::TAG_RRK_HPKE),
        WrapMethod::Kek { .. } => return Err(CryptoError::Hpke),
    };
    let aad = wrap_aad(
        ctx.group_id.as_bytes(),
        ctx.key_id.as_bytes(),
        &wrap.recipient.aad_bytes(),
        tag,
    );
    hpke_unwrap_dek(
        hpke_secret,
        encapped.as_ref(),
        wrap.ciphertext.as_ref(),
        &aad,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke_wrap::derive_hpke_keypair;
    use crate::{GroupId, KeyId};

    fn ctx_ids() -> (GroupId, KeyId) {
        (
            GroupId::new(b"tree".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
        )
    }

    #[test]
    fn member_wrap_round_trips_and_binds_its_context() {
        let kp = derive_hpke_keypair(&[7u8; 32]);
        let dek = Dek::new([9u8; 32]);
        let (group, key_id) = ctx_ids();
        let ctx = GroupContext {
            group_id: &group,
            key_id: &key_id,
        };
        let wrap = member_wrap(
            &dek,
            "alice".to_string(),
            X25519PublicKey::from_bytes(kp.public),
            &ctx,
        )
        .unwrap();

        // Round-trips under the right secret + context.
        let opened = unwrap_dek(&wrap, &*kp.secret, &ctx).unwrap();
        assert_eq!(opened.expose(), dek.expose());

        // A different epoch (key_id) rebuilds a different AAD → the tag fails.
        let other_key = KeyId::new(b"epoch-1".to_vec());
        let other_ctx = GroupContext {
            group_id: &group,
            key_id: &other_key,
        };
        assert!(matches!(
            unwrap_dek(&wrap, &*kp.secret, &other_ctx),
            Err(CryptoError::Hpke)
        ));

        // A different group fails too.
        let other_group = GroupId::new(b"tree-B".to_vec());
        let other_group_ctx = GroupContext {
            group_id: &other_group,
            key_id: &key_id,
        };
        assert!(matches!(
            unwrap_dek(&wrap, &*kp.secret, &other_group_ctx),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn the_wrong_secret_cannot_open() {
        let kp = derive_hpke_keypair(&[7u8; 32]);
        let other = derive_hpke_keypair(&[8u8; 32]);
        let dek = Dek::new([1u8; 32]);
        let (group, key_id) = ctx_ids();
        let ctx = GroupContext {
            group_id: &group,
            key_id: &key_id,
        };
        let wrap = member_wrap(
            &dek,
            "alice".to_string(),
            X25519PublicKey::from_bytes(kp.public),
            &ctx,
        )
        .unwrap();
        assert!(matches!(
            unwrap_dek(&wrap, &*other.secret, &ctx),
            Err(CryptoError::Hpke)
        ));
    }

    #[test]
    fn rrk_wrap_round_trips_and_carries_its_method() {
        let kp = derive_hpke_keypair(&[3u8; 32]);
        let dek = Dek::new([5u8; 32]);
        let (group, key_id) = ctx_ids();
        let ctx = GroupContext {
            group_id: &group,
            key_id: &key_id,
        };
        let wrap = rrk_wrap(
            &dek,
            "owner".to_string(),
            X25519PublicKey::from_bytes(kp.public),
            &ctx,
        )
        .unwrap();
        assert_eq!(wrap.method.tag(), WrapMethod::TAG_RRK_HPKE);
        let opened = unwrap_dek(&wrap, &*kp.secret, &ctx).unwrap();
        assert_eq!(opened.expose(), dek.expose());
    }
}
