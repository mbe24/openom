//! The role feed the claim engine's fold consumes: the `did:key`s currently authorized to moderate
//! (Maintainer or above) per a keyring. A pure function of a (verified) keyring — no I/O, no clock.

use std::collections::BTreeSet;

use openom_protocol::v1::Keyring;
use openom_roles::{ROLE_MAINTAINER, ROLE_OWNER};

/// The `did:key`s of members whose CURRENT role grants direct cross-author edit authority — Maintainer
/// or above (Owner, Co-owner, Maintainer). This is exactly the set `openom_crdt::materialize` treats as
/// authorized to Remove / Supersede / Revoke any claim; feed it in on unlock and on every governing
/// keyring change.
///
/// `keyring` MUST be the caller's verified, watermarked head — authority is only as trustworthy as the
/// keyring it is read from, so never derive this from an unverified network keyring. A member whose
/// `author_public_key` is not a 32-byte Ed25519 key is skipped (it could not have authored an entry
/// anyway), so the function is total and never panics on malformed input.
pub fn moderators(keyring: &Keyring) -> BTreeSet<String> {
    // Roles are power-descending: Owner(1) < Co-owner(2) < Maintainer(3) < Editor(4) < Viewer(5). Ranks
    // 1..=3 moderate; 0 (unspecified) and 4/5 do not.
    let moderator_rank = i32::from(ROLE_OWNER)..=i32::from(ROLE_MAINTAINER);
    keyring
        .members
        .iter()
        .filter(|m| moderator_rank.contains(&m.role))
        .filter_map(|m| <[u8; 32]>::try_from(m.author_public_key.as_slice()).ok())
        .map(|pk| openom_did::encode_ed25519(&pk))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_protocol::v1::{Member, MemberRole};

    fn member(id: &str, role: MemberRole, pk: [u8; 32]) -> Member {
        Member {
            member_id: id.into(),
            role: role as i32,
            author_public_key: pk.to_vec(),
            ..Default::default()
        }
    }

    fn keyring(members: Vec<Member>) -> Keyring {
        Keyring {
            members,
            ..Default::default()
        }
    }

    #[test]
    fn only_maintainer_and_above_are_moderators() {
        let (owner, coowner, admin, editor, viewer) =
            ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]);
        let kr = keyring(vec![
            member("o", MemberRole::Owner, owner),
            member("co", MemberRole::CoOwner, coowner),
            member("m", MemberRole::Admin, admin), // "Admin" == Maintainer (role 3)
            member("e", MemberRole::Editor, editor),
            member("v", MemberRole::Viewer, viewer),
        ]);
        let mods = moderators(&kr);
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
        let kr = keyring(vec![Member {
            member_id: "u".into(),
            role: 0, // MemberRole::Unspecified
            author_public_key: [7u8; 32].to_vec(),
            ..Default::default()
        }]);
        assert!(moderators(&kr).is_empty());
    }

    #[test]
    fn a_malformed_author_key_is_skipped_not_panicking() {
        let kr = keyring(vec![Member {
            member_id: "x".into(),
            role: MemberRole::Owner as i32,
            author_public_key: vec![1, 2, 3], // not 32 bytes
            ..Default::default()
        }]);
        assert!(moderators(&kr).is_empty());
    }
}
