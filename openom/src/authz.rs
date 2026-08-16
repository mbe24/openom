//! Tree authorization — the ONE place "may this member do this to this tree?" is decided.
//!
//! V1 is single-owner: the tree owner has full access and no one else has any. Every handler
//! resolves the owner it already needs (for owner-pays metering, CAS, etc.) and then calls
//! [`authorize`] instead of inlining `owner != member → Forbidden`. That indirection is the point:
//! B3 (sharing) widens this to role-based access via a `tree_access` lookup by changing *this
//! function only* — the call sites already ask the right question ("can this member Read/Write this
//! tree?") and won't move.
//!
//! It's async and takes the pool + tree id now, though V1 needs neither, precisely so the B3 change
//! is confined here: the signature the handlers call is already the one a role lookup will use.

use uuid::Uuid;

use crate::trees::ApiError;

/// The capability a request needs. V1 treats both the same (owner-only); B3 will distinguish them
/// (e.g. a viewer role gets `Read` but not `Write`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// Authorize `member` for `need` access to the tree `tree_id` owned by `owner`. Returns `Ok(())`
/// when permitted, [`ApiError::Forbidden`] otherwise.
///
/// V1: the owner has full access; everyone else is refused. `db`/`tree_id`/`need` are unused today
/// but are the inputs a B3 `tree_access` role lookup will need, so keeping them in the signature now
/// means B3 doesn't ripple out to the call sites.
pub async fn authorize(
    _db: &sqlx::PgPool,
    _tree_id: Uuid,
    owner: Uuid,
    member: Uuid,
    _need: Access,
) -> Result<(), ApiError> {
    if owner == member {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
