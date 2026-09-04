//! Authentication.
//!
//! In production, routes are guarded by a provider-neutral JWT (Supabase HS256, or Clerk/Auth0/OIDC
//! RS256 via JWKS — see [`crate::jwks`]), validated locally with no DB round-trip; `sub` is the member
//! id. In `AUTH=dev` the real crypto is bypassed: a request is accepted and mapped to a member (a
//! bearer that parses as a UUID impersonates that member), so the app above this line is identical in
//! both modes.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{request::Parts, StatusCode};
use uuid::Uuid;

use crate::AppState;

/// The authenticated caller. Just the account id for now.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    pub member_id: Uuid,
}

impl FromRequestParts<AppState> for Identity {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        if state.config.auth_is_dev() {
            // Fake auth: no signature check. A bearer token that parses as a UUID lets a test
            // impersonate a specific member; otherwise the default one.
            let id = bearer
                .and_then(|t| Uuid::parse_str(t.trim()).ok())
                .unwrap_or(state.config.local_member_id);
            // OPE-335: a fresh dev UUID has no `accounts` row, so its first `PUT /trees` would 403
            // (FK + per-owner quota gate). Provision it idempotently here — the one place every
            // dev-authed path passes through — so every dev account works.
            crate::provision_dev_account(&state.db, id).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "dev account provisioning failed",
                )
            })?;
            return Ok(Identity { member_id: id });
        }

        let token = bearer.ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let verifier = state.jwt_verifier.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "jwt verifier not configured",
        ))?;
        let member_id = verifier
            .verify(token)
            .await
            .map_err(|msg| (StatusCode::UNAUTHORIZED, msg))?;
        Ok(Identity { member_id })
    }
}
