#![doc = include_str!("../README.md")]

use openom_protocol::v1::{Kind, MemberRole};

/// Role values (== `MemberRole`), power descending: lower is stronger.
pub const ROLE_OWNER: i16 = MemberRole::Owner as i16; // 1
pub const ROLE_CO_OWNER: i16 = MemberRole::CoOwner as i16; // 2
pub const ROLE_MAINTAINER: i16 = MemberRole::Admin as i16; // 3 — UI: "Maintainer"
pub const ROLE_EDITOR: i16 = MemberRole::Editor as i16; // 4
pub const ROLE_VIEWER: i16 = MemberRole::Viewer as i16; // 5

/// The capability a request (server) or entry (client) needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read any of the tree's channels. Viewer+.
    Read,
    /// Submit a proposal. Editor+.
    Propose,
    /// Stage media bytes (upload/confirm). Editor+.
    StageMedia,
    /// Write authoritative state — append a delta, replace the snapshot, attach/detach media. Maintainer+.
    Commit,
    /// Administer ordinary members. Maintainer+. (Signer ops are gated at the endpoint as Owner/Co-owner.)
    Administer,
}

impl Access {
    /// The weakest (highest-numbered) role allowed to exercise this capability.
    pub fn min_role(self) -> i16 {
        match self {
            Access::Read => ROLE_VIEWER,
            Access::Propose | Access::StageMedia => ROLE_EDITOR,
            Access::Commit | Access::Administer => ROLE_MAINTAINER,
        }
    }
}

/// The weakest role allowed to AUTHOR an entry of `kind` — the client-side verify mapping, mirroring the
/// server's endpoint matrix. Snapshot & Delta are commits (Maintainer+); Proposal and Media are Editor+.
/// `None` for a kind that can't be role-gated (unspecified).
pub fn required_role_for_kind(kind: Kind) -> Option<i16> {
    match kind {
        Kind::Snapshot | Kind::Delta => Some(ROLE_MAINTAINER),
        Kind::Proposal | Kind::Media => Some(ROLE_EDITOR),
        Kind::Unspecified => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_min_roles_match_the_matrix() {
        assert_eq!(Access::Read.min_role(), ROLE_VIEWER);
        assert_eq!(Access::Propose.min_role(), ROLE_EDITOR);
        assert_eq!(Access::StageMedia.min_role(), ROLE_EDITOR);
        assert_eq!(Access::Commit.min_role(), ROLE_MAINTAINER);
        assert_eq!(Access::Administer.min_role(), ROLE_MAINTAINER);
    }

    #[test]
    fn kind_required_roles_match_the_matrix() {
        assert_eq!(required_role_for_kind(Kind::Delta), Some(ROLE_MAINTAINER));
        assert_eq!(
            required_role_for_kind(Kind::Snapshot),
            Some(ROLE_MAINTAINER)
        );
        assert_eq!(required_role_for_kind(Kind::Proposal), Some(ROLE_EDITOR));
        assert_eq!(required_role_for_kind(Kind::Media), Some(ROLE_EDITOR));
        assert_eq!(required_role_for_kind(Kind::Unspecified), None);
    }

    #[test]
    fn roles_are_power_descending() {
        assert!(ROLE_OWNER < ROLE_CO_OWNER);
        assert!(ROLE_CO_OWNER < ROLE_MAINTAINER);
        assert!(ROLE_MAINTAINER < ROLE_EDITOR);
        assert!(ROLE_EDITOR < ROLE_VIEWER);
    }
}
