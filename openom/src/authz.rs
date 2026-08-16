//! Tree authorization — the ONE place "may this member do this to this tree?" is decided.
//!
//! The authoritative membership/role lives in the client-verified signed keyring; `tree_access` is a
//! DERIVED, advisory server ACL — defense-in-depth + cost-control, never the security boundary (a
//! malicious server can edit a row but can't forge a signature or decrypt). Handlers resolve the owner
//! they already need and call [`authorize`]; this is the single point B3 widens from single-owner to
//! role-based, and the only place the endpoint→capability→role policy lives.
//!
//! Roles are numeric, power descending (owner strongest), so a gate is `member_role <= required`.

use uuid::Uuid;

use crate::trees::ApiError;

// Role values — mirror the keyring `MemberRole` enum (design.sharing §2.2). Lower = more powerful.
pub const ROLE_OWNER: i16 = 1;
pub const ROLE_CO_OWNER: i16 = 2;
pub const ROLE_MAINTAINER: i16 = 3; // keyring ADMIN
pub const ROLE_EDITOR: i16 = 4;
pub const ROLE_VIEWER: i16 = 5;

/// The capability a request needs. Each maps to the weakest role that may perform it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read any of the tree's channels (snapshot, log, media, proposals, keyring). Viewer+.
    Read,
    /// Submit a proposal for review. Editor+.
    Propose,
    /// Stage media bytes (upload/confirm) — e.g. to reference from a proposal. Editor+.
    StageMedia,
    /// Write authoritative state: append a delta, replace the snapshot, attach/detach media. Maintainer+.
    Commit,
    /// Administer ordinary members (add/remove/role). Maintainer+. (Signer ops — keyring PUT, co-owner
    /// changes — are gated at the endpoint as Owner/Co-owner, not here.)
    Administer,
}

impl Access {
    /// The weakest (highest-numbered) role allowed to exercise this capability.
    fn min_role(self) -> i16 {
        match self {
            Access::Read => ROLE_VIEWER,
            Access::Propose | Access::StageMedia => ROLE_EDITOR,
            Access::Commit | Access::Administer => ROLE_MAINTAINER,
        }
    }
}

/// Authorize `member` for `need` access to the tree `tree_id` owned by `owner`. `Ok(())` if permitted,
/// [`ApiError::Forbidden`] otherwise.
///
/// The owner always has full access (fast path, no query). Otherwise the member's role is looked up in
/// the derived `tree_access` ACL; a member with no row is refused. B3 slice 2 populates that ACL from the
/// keyring — call sites don't change.
pub async fn authorize(
    db: &sqlx::PgPool,
    tree_id: Uuid,
    owner: Uuid,
    member: Uuid,
    need: Access,
) -> Result<(), ApiError> {
    if member == owner {
        return Ok(()); // owner is role 1 — full access
    }
    let role: Option<i16> =
        sqlx::query_scalar("SELECT role FROM tree_access WHERE tree_id = $1 AND member_id = $2")
            .bind(tree_id)
            .bind(member)
            .fetch_optional(db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    match role {
        Some(r) if r <= need.min_role() => Ok(()),
        _ => Err(ApiError::Forbidden), // not a member, or role too weak for this capability
    }
}
