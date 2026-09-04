//! Provider-neutral JWT verification (OPE-340).
//!
//! One `JwtVerifier` the auth extractor calls, with two arms chosen by config:
//! - `Hs256` — a static shared secret (Supabase, or a local dev secret). In-memory, no I/O.
//! - `Jwks`  — public keys fetched from a JWKS URL (Clerk / Auth0 / OIDC / self-hosted), cached by
//!   `kid`, refreshed on an unknown kid, single-flighted (a burst of unknown-kid requests fetches
//!   once), and FAIL-CLOSED: a token whose signing key can't be resolved is rejected, never accepted.
//!
//! The signing algorithm is bound to the RESOLVED KEY (from the JWK), not taken from the token header
//! — so a token can't downgrade/confuse the algorithm (an RSA kid is only ever verified as RS*). The
//! issuer is a deployment choice (config), never baked in; `exp` is always required, and `aud` is
//! required whenever an audience is pinned. Both arms extract the same `sub` (a UUID) as the member id.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Claims {
    /// Subject — the account id (a UUID). The only claim we read; everything else is validated.
    sub: String,
}

/// The provider-neutral verifier. Built once from config; shared across requests (the JWKS cache has
/// interior mutability, so cloning `AppState` shares one cache).
pub enum JwtVerifier {
    Hs256 {
        key: DecodingKey,
        validation: Validation,
    },
    Jwks {
        cache: JwksCache,
        audience: Option<String>,
        issuer: Option<String>,
    },
}

impl JwtVerifier {
    /// HS256 with a shared secret (Supabase / a local dev secret).
    pub fn hs256(secret: &str, audience: Option<&str>, issuer: Option<&str>) -> Self {
        Self::Hs256 {
            key: DecodingKey::from_secret(secret.as_bytes()),
            validation: validation(Algorithm::HS256, audience, issuer),
        }
    }

    /// RS256 / ES256 (and RS384/512, PS*, ES384, EdDSA) with public keys fetched from a JWKS URL.
    pub fn jwks(url: String, audience: Option<&str>, issuer: Option<&str>) -> Self {
        Self::Jwks {
            cache: JwksCache::new(url),
            audience: audience.map(String::from),
            issuer: issuer.map(String::from),
        }
    }

    /// Verify a bearer token and return its `sub` as the member id. Async because the JWKS arm may
    /// need to fetch keys.
    pub async fn verify(&self, token: &str) -> Result<Uuid, &'static str> {
        match self {
            Self::Hs256 { key, validation } => decode_sub(token, key, validation),
            Self::Jwks { cache, audience, issuer } => {
                let header = decode_header(token).map_err(|_| "invalid token header")?;
                let kid = header.kid.ok_or("token has no kid (JWKS verification requires one)")?;
                // The algorithm comes from the resolved KEY, not the header — no alg confusion.
                let (key, alg) = cache.key(&kid).await?;
                let validation = validation(alg, audience.as_deref(), issuer.as_deref());
                decode_sub(token, &key, &validation)
            }
        }
    }
}

/// A `Validation` for one algorithm family: exp always required; aud required (present AND matching)
/// when pinned; issuer checked when configured.
fn validation(alg: Algorithm, audience: Option<&str>, issuer: Option<&str>) -> Validation {
    let mut v = Validation::new(alg);
    match audience {
        Some(aud) => {
            v.set_audience(&[aud]);
            v.set_required_spec_claims(&["exp", "aud"]); // both MUST be present, not merely valid-if-present
        }
        None => v.validate_aud = false,
    }
    if let Some(iss) = issuer {
        v.set_issuer(&[iss]);
    }
    v
}

fn decode_sub(token: &str, key: &DecodingKey, validation: &Validation) -> Result<Uuid, &'static str> {
    let data = decode::<Claims>(token, key, validation).map_err(|_| "invalid token")?;
    Uuid::parse_str(&data.claims.sub).map_err(|_| "sub is not a uuid")
}

/// A JWKS key cache: `kid → (DecodingKey, Algorithm)`, populated by fetching the JWKS URL. A miss
/// triggers ONE refresh, single-flighted behind a mutex; a fetch failure is FAIL-CLOSED (the token is
/// rejected, never accepted on an unresolved key).
pub struct JwksCache {
    url: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, (Arc<DecodingKey>, Algorithm)>>,
    refresh: Mutex<()>,
}

impl JwksCache {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            keys: RwLock::new(HashMap::new()),
            refresh: Mutex::new(()),
        }
    }

    async fn key(&self, kid: &str) -> Result<(Arc<DecodingKey>, Algorithm), &'static str> {
        if let Some(k) = self.keys.read().await.get(kid).cloned() {
            return Ok(k);
        }
        // Unknown kid — the issuer may have rotated its signing keys. Refresh once, single-flighted:
        // hold the mutex so a burst of unknown-kid requests collapses into one fetch.
        let _g = self.refresh.lock().await;
        if let Some(k) = self.keys.read().await.get(kid).cloned() {
            return Ok(k); // another task refreshed while we waited for the lock
        }
        let fetched = self.fetch().await?; // fail-closed: a fetch error propagates as a rejection
        let key = fetched.get(kid).cloned();
        *self.keys.write().await = fetched;
        key.ok_or("no JWKS key matches the token's kid")
    }

    async fn fetch(&self) -> Result<HashMap<String, (Arc<DecodingKey>, Algorithm)>, &'static str> {
        let set: JwkSet = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|_| "JWKS fetch failed")?
            .json()
            .await
            .map_err(|_| "JWKS parse failed")?;
        Ok(jwks_to_keys(&set))
    }

    #[cfg(test)]
    fn with_keys(keys: HashMap<String, (Arc<DecodingKey>, Algorithm)>) -> Self {
        Self {
            url: String::new(),
            client: reqwest::Client::new(),
            keys: RwLock::new(keys),
            refresh: Mutex::new(()),
        }
    }
}

/// Parse a JWK set into `(DecodingKey, Algorithm)` by `kid`. Keys without a kid, of an unsupported
/// type, or whose components don't build are skipped.
fn jwks_to_keys(set: &JwkSet) -> HashMap<String, (Arc<DecodingKey>, Algorithm)> {
    let mut map = HashMap::new();
    for jwk in &set.keys {
        if let (Some(kid), Some(alg), Ok(key)) =
            (jwk.common.key_id.clone(), alg_of(jwk), DecodingKey::from_jwk(jwk))
        {
            map.insert(kid, (Arc::new(key), alg));
        }
    }
    map
}

/// The signing algorithm for a JWK: its explicit `alg` when present + supported, else the family
/// default from the key type (RSA → RS256, EC → ES256 — the overwhelmingly common choices).
fn alg_of(jwk: &Jwk) -> Option<Algorithm> {
    match jwk.common.key_algorithm {
        Some(KeyAlgorithm::RS256) => return Some(Algorithm::RS256),
        Some(KeyAlgorithm::RS384) => return Some(Algorithm::RS384),
        Some(KeyAlgorithm::RS512) => return Some(Algorithm::RS512),
        Some(KeyAlgorithm::PS256) => return Some(Algorithm::PS256),
        Some(KeyAlgorithm::PS384) => return Some(Algorithm::PS384),
        Some(KeyAlgorithm::PS512) => return Some(Algorithm::PS512),
        Some(KeyAlgorithm::ES256) => return Some(Algorithm::ES256),
        Some(KeyAlgorithm::ES384) => return Some(Algorithm::ES384),
        Some(KeyAlgorithm::EdDSA) => return Some(Algorithm::EdDSA),
        _ => {}
    }
    match jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(_) => Some(Algorithm::ES256),
        _ => None,
    }
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

    const HS_SECRET: &[u8] = b"test-secret";
    const MEMBER: &str = "00000000-0000-0000-0000-0000000000ab";

    fn hs_token(secret: &[u8], sub: &str, aud: &str) -> String {
        let claims = TestClaims { sub: sub.into(), aud: aud.into(), exp: 4_102_444_800 };
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    #[tokio::test]
    async fn hs256_accepts_a_matching_audience() {
        let v = JwtVerifier::hs256("test-secret", Some("authenticated"), None);
        let id = v.verify(&hs_token(HS_SECRET, MEMBER, "authenticated")).await.expect("valid aud accepted");
        assert_eq!(id, Uuid::parse_str(MEMBER).unwrap());
    }

    #[tokio::test]
    async fn hs256_rejects_wrong_audience_signature_and_missing_aud() {
        let v = JwtVerifier::hs256("test-secret", Some("authenticated"), None);
        assert!(v.verify(&hs_token(HS_SECRET, MEMBER, "some-other-service")).await.is_err(), "wrong aud");
        assert!(v.verify(&hs_token(b"a-different-secret", MEMBER, "authenticated")).await.is_err(), "bad sig");
        let no_aud = encode(&Header::new(Algorithm::HS256),
            &serde_json::json!({ "sub": MEMBER, "exp": 4_102_444_800usize }),
            &EncodingKey::from_secret(HS_SECRET)).unwrap();
        assert!(v.verify(&no_aud).await.is_err(), "missing aud rejected when pinned");
    }

    #[tokio::test]
    async fn hs256_enforces_issuer_when_configured() {
        let v = JwtVerifier::hs256("test-secret", None, Some("https://issuer.example"));
        let good = encode(&Header::new(Algorithm::HS256),
            &serde_json::json!({ "sub": MEMBER, "iss": "https://issuer.example", "exp": 4_102_444_800usize }),
            &EncodingKey::from_secret(HS_SECRET)).unwrap();
        assert!(v.verify(&good).await.is_ok(), "matching iss accepted");
        let bad = encode(&Header::new(Algorithm::HS256),
            &serde_json::json!({ "sub": MEMBER, "iss": "https://evil.example", "exp": 4_102_444_800usize }),
            &EncodingKey::from_secret(HS_SECRET)).unwrap();
        assert!(v.verify(&bad).await.is_err(), "wrong iss rejected");
    }

    // RS256 vectors: a real 2048-bit RSA token + its public JWK (generated once, offline).
    const RS_SUB: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const RS_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ.eyJzdWIiOiIzZjI1MDRlMC00Zjg5LTQxZDMtOWEwYy0wMzA1ZTgyYzMzMDEiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZSIsImV4cCI6NDEwMjQ0NDgwMH0.JAmws1un4sTJwv60M_FjwAycydM_UzemeDDvqnDFMHSHgiToWkdlF0-7nyM6tYAM6wLmOINbSe_jR5gu_tk566MCdr86LwOmMTmUCqP8uDztKWttRIKbWy6YabzInNDELmaBBFjCK9NJ1N_jnsWHHSwVFQn37b0ypooIzzPeNJK27iDGmwSh96uywhM9wmG94w5INKMj95U3UQ86dqeyLf1_K92Te04TnAbeaCPj69XIFjgsApkmTpHxLTpvDDW2EuXzxBalFAlkdTLNzNQmBInLhgnVL3qYaj5pnLGSbZRcH76g4kysT3unoh9j_HOwsSpJZVXWhsJ3SUjIuhKsLA";
    const RS_JWKS: &str = r#"{"keys":[{"kty":"RSA","n":"3H9ju-JokApVR7BOmSRVoTK-_mYdRfI3bfLGMMcGyMvO_UGd2jDBGa8kjAwGekWM-k7DWCvryFIeCLIm8Yossv6HVRiVhttBzi_HKmxdMq2bLV6_O_w4CAfEjEY41dytnb5GFsepwkyxyVkZsq-A9ppZH9Sik7IiJztU17K4sV18e-R3DtZErh-6JRwVBTthAnckVe873MA28CFSHyk8Lz9U92K3VLBLzY06yN2Y_5LFsddgC42yL4qki-Jc-gOLMoQrljNXmNJN50UvrUUMdhidO5pgAnWM7ReBq7koyVA1WSOKJXIV22cKGAuQzXJu90hLzjE0DTZ352mH41Ynvw","e":"AQAB","kid":"test-key-1","alg":"RS256","use":"sig"}]}"#;

    fn jwks_verifier(audience: Option<&str>, issuer: Option<&str>) -> JwtVerifier {
        let set: JwkSet = serde_json::from_str(RS_JWKS).unwrap();
        JwtVerifier::Jwks {
            cache: JwksCache::with_keys(jwks_to_keys(&set)),
            audience: audience.map(String::from),
            issuer: issuer.map(String::from),
        }
    }

    #[tokio::test]
    async fn jwks_rs256_accepts_a_token_signed_by_a_cached_key() {
        let v = jwks_verifier(Some("authenticated"), Some("https://issuer.example"));
        let id = v.verify(RS_JWT).await.expect("valid RS256 token accepted");
        assert_eq!(id, Uuid::parse_str(RS_SUB).unwrap());
    }

    #[tokio::test]
    async fn jwks_rejects_wrong_audience() {
        let v = jwks_verifier(Some("some-other-service"), None);
        assert!(v.verify(RS_JWT).await.is_err(), "mismatched aud rejected on the JWKS path");
    }

    #[tokio::test]
    async fn jwks_is_fail_closed_when_the_key_cannot_be_resolved() {
        // Empty cache + an unreachable JWKS URL: an unknown kid triggers a fetch that fails → REJECT.
        let v = JwtVerifier::Jwks {
            cache: JwksCache::new("http://127.0.0.1:1/nonexistent".into()),
            audience: None,
            issuer: None,
        };
        assert!(v.verify(RS_JWT).await.is_err(), "unresolved signing key must be rejected, never accepted");
    }
}
