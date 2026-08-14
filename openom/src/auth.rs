//! Authentication.
//!
//! In production, routes are guarded by Supabase-issued JWTs, validated locally
//! in-memory (HS256, no DB round-trip). In `RUN_MODE=local` the real crypto is
//! bypassed: a request is accepted and mapped to a local test member, so the app
//! code above this line is identical in both modes.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{request::Parts, StatusCode};
use jsonwebtoken::{decode, Algorithm, Validation};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;

/// The authenticated caller. Just the account id for now.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    pub member_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct Claims {
    /// Subject — the Supabase account id (a UUID).
    sub: String,
}

impl FromRequestParts<AppState> for Identity {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        if state.config.is_local() {
            // Fake auth: no signature check. A bearer token that parses as a UUID
            // lets a test impersonate a specific member; otherwise the default one.
            let id = bearer
                .and_then(|t| Uuid::parse_str(t.trim()).ok())
                .unwrap_or(state.config.local_member_id);
            return Ok(Identity { member_id: id });
        }

        let token = bearer.ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let key = state
            .jwt_key
            .as_ref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "jwt secret not configured"))?;
        // Signature + expiry are enforced; audience varies across Supabase setups,
        // so it is not checked here (hardened when we lock the deployment down).
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;
        let data = decode::<Claims>(token, key, &validation)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?;
        let member_id = Uuid::parse_str(&data.claims.sub)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "sub is not a uuid"))?;
        Ok(Identity { member_id })
    }
}
