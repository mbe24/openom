//! Authentication.
//!
//! In production, routes are guarded by Supabase-issued JWTs, validated locally
//! in-memory (HS256, no DB round-trip). In `RUN_MODE=local` the real crypto is
//! bypassed: a request is accepted and mapped to a local test member, so the app
//! code above this line is identical in both modes.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{request::Parts, StatusCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
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

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
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
        let key = state.jwt_key.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "jwt secret not configured",
        ))?;
        let member_id = validate_token(token, key, state.config.jwt_audience.as_deref())
            .map_err(|msg| (StatusCode::UNAUTHORIZED, msg))?;
        Ok(Identity { member_id })
    }
}

/// Validate a Supabase HS256 token and return the member id (`sub`). Signature and
/// expiry are always enforced; `audience`, when `Some`, additionally requires the
/// token's `aud` to match — `None` skips the audience check (the pre-hardening
/// behaviour, still used locally and for non-standard deployments). Pure over its
/// inputs so it's unit-testable without an AppState.
fn validate_token(
    token: &str,
    key: &DecodingKey,
    audience: Option<&str>,
) -> Result<Uuid, &'static str> {
    let mut validation = Validation::new(Algorithm::HS256);
    match audience {
        Some(aud) => validation.set_audience(&[aud]), // keeps validate_aud on, pins the expected aud
        None => validation.validate_aud = false,
    }
    let data = decode::<Claims>(token, key, &validation).map_err(|_| "invalid token")?;
    Uuid::parse_str(&data.claims.sub).map_err(|_| "sub is not a uuid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        aud: String,
        exp: usize,
    }

    fn token(secret: &[u8], sub: &str, aud: &str) -> String {
        let claims = TestClaims {
            sub: sub.into(),
            aud: aud.into(),
            exp: 4_102_444_800,
        }; // ~year 2100
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    const SECRET: &[u8] = b"test-secret";
    const MEMBER: &str = "00000000-0000-0000-0000-0000000000ab";

    #[test]
    fn accepts_matching_audience() {
        let key = DecodingKey::from_secret(SECRET);
        let t = token(SECRET, MEMBER, "authenticated");
        let id = validate_token(&t, &key, Some("authenticated")).expect("valid aud accepted");
        assert_eq!(id, Uuid::parse_str(MEMBER).unwrap());
    }

    #[test]
    fn rejects_wrong_audience() {
        let key = DecodingKey::from_secret(SECRET);
        let t = token(SECRET, MEMBER, "some-other-service");
        assert!(
            validate_token(&t, &key, Some("authenticated")).is_err(),
            "mismatched aud rejected"
        );
    }

    #[test]
    fn skips_audience_when_unset() {
        let key = DecodingKey::from_secret(SECRET);
        // A token whose aud we'd otherwise reject still passes when the check is off.
        let t = token(SECRET, MEMBER, "anything-goes");
        assert!(
            validate_token(&t, &key, None).is_ok(),
            "aud not checked when None"
        );
    }

    #[test]
    fn rejects_wrong_signature() {
        let key = DecodingKey::from_secret(b"a-different-secret");
        let t = token(SECRET, MEMBER, "authenticated");
        assert!(
            validate_token(&t, &key, Some("authenticated")).is_err(),
            "bad signature rejected"
        );
    }
}
