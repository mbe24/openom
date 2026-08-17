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

// The capability→role policy is domain logic shared with the client (verify_entry enforces the same
// mapping): it lives in `openom-roles`. This module keeps only the server-side ACL query.
pub use openom_roles::Access;

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
