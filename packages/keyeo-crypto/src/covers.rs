//! Wrap-completeness predicates — does an epoch's wraps cover the membership it should?
//!
//! Two predicates over two semantics, because the callers genuinely differ:
//!
//! - [`missing`] is a SUBSET / lockout-only check: which required recipients lack a covering wrap. A
//!   consumer's acceptance gate ("reject an epoch that locks a member out") and its backfill ("re-wrap the
//!   members who are missing one") both use it. Extra wraps — to a since-removed member — are ignored.
//! - [`covers_exact`] is a SET-EQUALITY check: `missing` is empty AND no member wrap addresses a recipient
//!   outside the required set. The extra half is the forward-secrecy / LEAK check — a removed member still
//!   wrapped must force a reseal — which `missing` deliberately does not do.
//!
//! Both are key-bound where asked: a [`RecipientDescriptor`] with `expected_key = Some(k)` is covered only
//! by a wrap addressed to that CURRENT key, so a stale-key wrap left after a rekey race does not count
//! toward coverage. The leak check, though, is id-level, so a benign leftover stale-key wrap for a
//! still-required member is not mistaken for a leak (the granularity asymmetry a rekey race needs).

use std::collections::HashSet;

use crate::keyring::{Epoch, RecipientId, Wrap, WrapMethod};
use crate::X25519PublicKey;

/// A recipient the caller requires an epoch to cover. `expected_key = Some(k)` demands the wrap be
/// addressed to that current X25519 key (the rekey-race guard); `None` matches any wrap to the id.
#[derive(Clone, Debug)]
pub struct RecipientDescriptor<Id: RecipientId> {
    pub id: Id,
    pub expected_key: Option<X25519PublicKey>,
}

fn key_ok(recipient_key: &X25519PublicKey, expected: Option<&X25519PublicKey>) -> bool {
    expected.is_none_or(|k| recipient_key == k)
}

/// A `MemberHpke` wrap addressed to this descriptor (a member's per-epoch DEK access).
fn member_covers<Id: RecipientId>(wrap: &Wrap<Id>, d: &RecipientDescriptor<Id>) -> bool {
    match &wrap.method {
        WrapMethod::MemberHpke { recipient_key, .. } => {
            wrap.recipient == d.id && key_ok(recipient_key, d.expected_key.as_ref())
        }
        _ => false,
    }
}

/// An `RrkHpke` wrap addressed to this descriptor (the recovery root's cross-epoch access).
fn rrk_covers<Id: RecipientId>(wrap: &Wrap<Id>, d: &RecipientDescriptor<Id>) -> bool {
    match &wrap.method {
        WrapMethod::RrkHpke { recipient_key, .. } => {
            wrap.recipient == d.id && key_ok(recipient_key, d.expected_key.as_ref())
        }
        _ => false,
    }
}

/// The required recipients an epoch does NOT cover — the `required` members lacking a member wrap, plus the
/// recovery root (`rrk`) if its RRK wrap is absent.
///
/// Subset semantics: a wrap to a recipient outside
/// `required` is ignored (that is [`covers_exact`]'s concern). The lockout gate is `missing(..).is_empty()`;
/// a backfill re-wraps exactly the returned ids.
pub fn missing<Id: RecipientId>(
    epoch: &Epoch<Id>,
    required: &[RecipientDescriptor<Id>],
    rrk: &RecipientDescriptor<Id>,
) -> Vec<Id> {
    let mut out = Vec::new();
    for d in required {
        if !epoch.wraps.iter().any(|w| member_covers(w, d)) {
            out.push(d.id.clone());
        }
    }
    if !epoch.wraps.iter().any(|w| rrk_covers(w, rrk)) {
        out.push(rrk.id.clone());
    }
    out
}

/// Set-equality coverage: every `required` member and the `rrk` are covered (no lockout) AND no member wrap
/// addresses a recipient outside `required` (no leak — a since-removed member still wrapped).
///
/// This is the
/// reseal trigger: `!covers_exact(..)` means the epoch must be resealed to the resolved membership.
pub fn covers_exact<Id: RecipientId>(
    epoch: &Epoch<Id>,
    required: &[RecipientDescriptor<Id>],
    rrk: &RecipientDescriptor<Id>,
) -> bool {
    if !missing(epoch, required, rrk).is_empty() {
        return false; // a lockout
    }
    // Leak check, id-level: a member wrap to anyone outside `required` is a since-removed member who can
    // still open this epoch. (A stale-KEY wrap to a still-required member is not a leak — it is in
    // `required`, just didn't count toward coverage above — which is why this is id-level, not key-level.)
    let required_ids: HashSet<&Id> = required.iter().map(|d| &d.id).collect();
    !epoch.wraps.iter().any(|w| {
        matches!(w.method, WrapMethod::MemberHpke { .. }) && !required_ids.contains(&w.recipient)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::KeyId;
    use crate::{EncappedKey, WrappedDek};

    fn member_wrap(recipient: &str, key: u8) -> Wrap<String> {
        Wrap {
            recipient: recipient.to_string(),
            method: WrapMethod::MemberHpke {
                encapped: EncappedKey::from_bytes([0u8; 32]),
                recipient_key: X25519PublicKey::from_bytes([key; 32]),
            },
            ciphertext: WrappedDek::from_bytes([0u8; 48]),
        }
    }

    fn rrk_wrap(recipient: &str, key: u8) -> Wrap<String> {
        Wrap {
            recipient: recipient.to_string(),
            method: WrapMethod::RrkHpke {
                encapped: EncappedKey::from_bytes([0u8; 32]),
                recipient_key: X25519PublicKey::from_bytes([key; 32]),
            },
            ciphertext: WrappedDek::from_bytes([0u8; 48]),
        }
    }

    fn epoch(wraps: Vec<Wrap<String>>) -> Epoch<String> {
        Epoch {
            key_id: KeyId::new(vec![1]),
            ordinal: 1,
            wraps,
        }
    }

    fn desc(id: &str, key: Option<u8>) -> RecipientDescriptor<String> {
        RecipientDescriptor {
            id: id.to_string(),
            expected_key: key.map(|k| X25519PublicKey::from_bytes([k; 32])),
        }
    }

    #[test]
    fn a_complete_epoch_covers_and_has_nothing_missing() {
        let ep = epoch(vec![
            rrk_wrap("owner", 9),
            member_wrap("alice", 1),
            member_wrap("bob", 2),
        ]);
        let required = vec![desc("alice", Some(1)), desc("bob", Some(2))];
        let rrk = desc("owner", None);
        assert!(missing(&ep, &required, &rrk).is_empty());
        assert!(covers_exact(&ep, &required, &rrk));
    }

    #[test]
    fn a_locked_out_member_is_missing_and_breaks_covers() {
        let ep = epoch(vec![rrk_wrap("owner", 9), member_wrap("alice", 1)]); // bob has no wrap
        let required = vec![desc("alice", Some(1)), desc("bob", Some(2))];
        let rrk = desc("owner", None);
        assert_eq!(missing(&ep, &required, &rrk), vec!["bob".to_string()]);
        assert!(!covers_exact(&ep, &required, &rrk));
    }

    #[test]
    fn a_leaked_removed_member_breaks_covers_but_is_not_missing() {
        // bob was removed (not in required) yet still has a wrap — a forward-secrecy leak.
        let ep = epoch(vec![
            rrk_wrap("owner", 9),
            member_wrap("alice", 1),
            member_wrap("bob", 2),
        ]);
        let required = vec![desc("alice", Some(1))];
        let rrk = desc("owner", None);
        assert!(
            missing(&ep, &required, &rrk).is_empty(),
            "missing is subset-only, so it doesn't see the leak"
        );
        assert!(
            !covers_exact(&ep, &required, &rrk),
            "covers_exact does — a removed member must force a reseal"
        );
    }

    #[test]
    fn an_absent_rrk_wrap_is_missing() {
        let ep = epoch(vec![member_wrap("alice", 1)]); // no rrk wrap
        let required = vec![desc("alice", Some(1))];
        let rrk = desc("owner", None);
        assert_eq!(missing(&ep, &required, &rrk), vec!["owner".to_string()]);
        assert!(!covers_exact(&ep, &required, &rrk));
    }

    #[test]
    fn a_stale_key_wrap_does_not_cover_but_a_coexisting_current_one_does() {
        let required = vec![desc("alice", Some(1))]; // alice's CURRENT key is 1
        let rrk = desc("owner", None);
        // Only a stale-key (key 8) wrap → not covered → missing.
        let stale = epoch(vec![rrk_wrap("owner", 9), member_wrap("alice", 8)]);
        assert_eq!(missing(&stale, &required, &rrk), vec!["alice".to_string()]);
        // A current-key wrap coexisting with the stale one → covered, and the leftover is not a leak.
        let both = epoch(vec![
            rrk_wrap("owner", 9),
            member_wrap("alice", 8),
            member_wrap("alice", 1),
        ]);
        assert!(missing(&both, &required, &rrk).is_empty());
        assert!(covers_exact(&both, &required, &rrk));
    }
}
