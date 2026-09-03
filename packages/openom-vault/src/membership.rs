//! The role feed the claim engine's fold consumes: the `did:key`s currently authorized to moderate
//! (Maintainer or above) per a keyring. A pure function of a (verified, resolved) [`MembershipView`] —
//! engine-neutral (chain or dag), no I/O, no clock. Lives in the vault layer, above both engines, because
//! it consumes a resolved membership — it is not the membership engine itself (OPE-308).

use std::collections::BTreeSet;

use openom_keyring_api::{MembershipView, ROLE_MAINTAINER, ROLE_OWNER};

/// The `did:key`s of members whose CURRENT role grants direct cross-author edit authority — Maintainer
/// or above (Owner, Co-owner, Maintainer). This is exactly the set `openom_crdt::materialize` treats as
/// authorized to Remove / Supersede / Revoke any claim; feed it in on unlock and on every governing
/// keyring change.
///
/// `view` MUST be resolved from the caller's verified, watermarked head — authority is only as
/// trustworthy as the keyring it is read from, so never derive this from an unverified network keyring. A
/// member whose `author_public_key` is not a 32-byte Ed25519 key is skipped (it could not have authored
/// an entry anyway), so the function is total and never panics on malformed input.
pub fn moderators(view: &MembershipView) -> BTreeSet<String> {
    // Roles are power-descending: Owner(1) < Co-owner(2) < Maintainer(3) < Editor(4) < Viewer(5). Ranks
    // 1..=3 moderate; 0 (unspecified) and 4/5 do not.
    let moderator_rank = ROLE_OWNER..=ROLE_MAINTAINER;
    view.members
        .iter()
        .filter(|m| moderator_rank.contains(&m.role))
        .filter_map(|m| <[u8; 32]>::try_from(m.author_public_key.as_slice()).ok())
        .map(|pk| openom_did::encode_ed25519(&pk))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_keyring_api::MemberView;

    fn member(id: &str, role: i16, pk: [u8; 32]) -> MemberView {
        MemberView {
            member_id: id.into(),
            role,
            author_public_key: pk.to_vec(),
            hpke_public_key: vec![],
        }
    }

    fn view(members: Vec<MemberView>) -> MembershipView {
        MembershipView::new(members, false)
    }

    #[test]
    fn only_maintainer_and_above_are_moderators() {
        let (owner, coowner, admin, editor, viewer) =
            ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]);
        // Roles in openom-keyring-api's convention: Owner=1, CoOwner=2, Maintainer=3, Editor=4, Viewer=5.
        let v = view(vec![
            member("o", 1, owner),
            member("co", 2, coowner),
            member("m", 3, admin), // Maintainer (role 3)
            member("e", 4, editor),
            member("v", 5, viewer),
        ]);
        let mods = moderators(&v);
        assert_eq!(mods.len(), 3, "Owner + Co-owner + Maintainer");
        for pk in [owner, coowner, admin] {
            assert!(mods.contains(&openom_did::encode_ed25519(&pk)));
        }
        for pk in [editor, viewer] {
            assert!(!mods.contains(&openom_did::encode_ed25519(&pk)));
        }
    }

    #[test]
    fn an_unspecified_role_is_not_a_moderator() {
        let v = view(vec![member("u", 0, [7u8; 32])]); // role 0 == unspecified
        assert!(moderators(&v).is_empty());
    }

    #[test]
    fn a_malformed_author_key_is_skipped_not_panicking() {
        let v = view(vec![MemberView {
            member_id: "x".into(),
            role: 1, // Owner
            author_public_key: vec![1, 2, 3], // not 32 bytes
            hpke_public_key: vec![],
        }]);
        assert!(moderators(&v).is_empty());
    }
}
