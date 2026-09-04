//! Runtime configuration.
//!
//! Three INDEPENDENT axes, so a deployment can mix them (the point of the split):
//! - `STORAGE` — `local` (MinIO) vs `cloud` (R2). Also gates the dev-key refusal.
//! - `AUTH` — `dev` (fake auth: a bearer that parses as a UUID = that member) vs `jwt`
//!   (a real verified token; the `aud` default keys on this).
//! - deployment target — local HTTP server (+ pretty logs, dev routes) vs Lambda (+ JSON
//!   logs, no dev routes). Tracks `RUN_MODE` (Local vs Production).
//!
//! `RUN_MODE` is a convenience PRESET: `local` → {storage=local, auth=dev, LocalServer};
//! `production` → {storage=cloud, auth=jwt, Lambda}. `STORAGE` / `AUTH` override their axis
//! independently — e.g. `RUN_MODE=local` + `AUTH=jwt` + `AUTH_JWT_SECRET=…` is "local Supabase"
//! (real JWT verification over local MinIO). Everything is read from the environment.

use std::env;
use uuid::Uuid;

/// Deployment-target preset. Local = HTTP server + pretty logs + dev routes;
/// Production = Lambda + JSON logs + no dev routes. Also the default source for the
/// storage/auth axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Local,
    Production,
}

/// Where encrypted tree bytes live. `Cloud` additionally refuses the reserved dev key_id
/// (§16) so a dev key can never seal real user data at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Local,
    Cloud,
}

/// How a request is authenticated. `Dev` = fake auth (a UUID bearer is that member, no
/// signature). `Jwt` = the real provider-neutral verifier (Supabase/Clerk/self-hosted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Dev,
    Jwt,
}

/// The JWT verifier algorithm (when `AUTH=jwt`). `Hs256` = a shared secret (Supabase / dev).
/// `Rs256` = asymmetric keys (RS256/ES256) fetched from a JWKS URL (Clerk / Auth0 / OIDC /
/// self-hosted). The issuer is never baked in — it's a deployment config choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlg {
    Hs256,
    Rs256,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Deployment target preset (Local server vs Lambda). See the module docs.
    pub run_mode: RunMode,
    /// Storage axis (independent of `run_mode`; defaults from it, `STORAGE` overrides).
    pub storage: StorageMode,
    /// Auth axis (independent of `run_mode`; defaults from it, `AUTH` overrides).
    pub auth: AuthMode,
    /// Address the local HTTP server binds. Ignored under Lambda.
    pub http_addr: String,
    /// Postgres connection string (Neon in prod, a local container in dev).
    pub database_url: String,
    /// S3-compatible endpoint the *server* uses for proxy ops (R2 in prod, MinIO in dev).
    pub s3_endpoint: String,
    /// Endpoint baked into presigned URLs handed to clients — must be client-reachable.
    pub s3_public_endpoint: String,
    /// Bucket that holds the encrypted tree envelopes.
    pub s3_bucket: String,
    /// S3 region.
    pub s3_region: String,
    /// S3 access key id.
    pub s3_access_key: String,
    /// S3 secret access key.
    pub s3_secret_key: String,
    /// The JWT verifier algorithm when `AUTH=jwt`. `AUTH_JWT_ALG` (`HS256`|`RS256`); default `HS256`
    /// (Supabase/dev back-compat).
    pub jwt_alg: JwtAlg,
    /// JWT verifier shared secret (HS256 — Supabase/dev). `AUTH_JWT_SECRET`, alias
    /// `SUPABASE_JWT_SECRET`. Required when `AUTH=jwt` and `AUTH_JWT_ALG=HS256`.
    pub jwt_secret: Option<String>,
    /// JWKS URL for the asymmetric arm (RS256/ES256 — Clerk/Auth0/OIDC/self-hosted). `AUTH_JWKS_URL`.
    /// Required when `AUTH=jwt` and `AUTH_JWT_ALG=RS256`.
    pub jwks_url: Option<String>,
    /// Expected JWT `iss` claim. `Some` → the token's issuer must match; `None` → skip. `AUTH_JWT_ISS`.
    /// A deployment choice — never baked into code.
    pub jwt_issuer: Option<String>,
    /// Expected JWT `aud` claim. `Some` → the token's audience must match; `None` → skip.
    /// Defaults to `"authenticated"` (Supabase) when `AUTH=jwt`; `AUTH_JWT_AUD` (alias
    /// `SUPABASE_JWT_AUD`) overrides, and an explicit empty value opts out.
    pub jwt_audience: Option<String>,
    /// The account fake-auth maps a bearer-less local request to (`AUTH=dev`).
    pub local_member_id: Uuid,

    /// Export spans over OTLP (opt-in, `OPENOM_OTEL=1`).
    pub otel_enabled: bool,
    /// OTLP/HTTP base endpoint.
    pub otlp_endpoint: String,
    /// Extra OTLP headers as `k1=v1,k2=v2` — a secret, never logged.
    pub otlp_headers: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let run_mode = match env::var("RUN_MODE").unwrap_or_default().as_str() {
            "production" | "prod" => RunMode::Production,
            _ => RunMode::Local,
        };
        // Each axis defaults from the RUN_MODE preset, then its own env overrides it.
        let storage = match env::var("STORAGE").ok().as_deref() {
            Some("cloud") => StorageMode::Cloud,
            Some("local") => StorageMode::Local,
            _ => match run_mode {
                RunMode::Production => StorageMode::Cloud,
                RunMode::Local => StorageMode::Local,
            },
        };
        let auth = match env::var("AUTH").ok().as_deref() {
            Some("jwt") => AuthMode::Jwt,
            Some("dev") => AuthMode::Dev,
            _ => match run_mode {
                RunMode::Production => AuthMode::Jwt,
                RunMode::Local => AuthMode::Dev,
            },
        };
        let s3_endpoint =
            env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into());
        let s3_public_endpoint =
            env::var("S3_PUBLIC_ENDPOINT").unwrap_or_else(|_| s3_endpoint.clone());
        let config = Self {
            run_mode,
            storage,
            auth,
            http_addr: env::var("OPENOM_HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:6060".into()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://openom:openom@localhost:5432/openom".into()),
            s3_endpoint,
            s3_public_endpoint,
            s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| "openom-trees".into()),
            s3_region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            s3_access_key: env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "openom".into()),
            s3_secret_key: env::var("S3_SECRET_KEY").unwrap_or_else(|_| "openompw123".into()),
            jwt_alg: match env::var("AUTH_JWT_ALG").ok().as_deref() {
                Some("RS256") | Some("rs256") | Some("ES256") | Some("es256") => JwtAlg::Rs256,
                _ => JwtAlg::Hs256,
            },
            jwt_secret: env::var("AUTH_JWT_SECRET")
                .or_else(|_| env::var("SUPABASE_JWT_SECRET"))
                .ok(),
            jwks_url: env::var("AUTH_JWKS_URL").ok().filter(|s| !s.trim().is_empty()),
            jwt_issuer: env::var("AUTH_JWT_ISS").ok().filter(|s| !s.trim().is_empty()),
            jwt_audience: match env::var("AUTH_JWT_AUD").or_else(|_| env::var("SUPABASE_JWT_AUD")) {
                Ok(v) if v.trim().is_empty() => None, // explicit opt-out
                Ok(v) => Some(v),
                // Default the audience check ON for the real-JWT axis (Supabase's "authenticated").
                // Keyed on AUTH, not RUN_MODE, so local-Supabase (RUN_MODE=local, AUTH=jwt) is hardened.
                Err(_) if auth == AuthMode::Jwt => Some("authenticated".into()),
                Err(_) => None,
            },
            local_member_id: env::var("OPENOM_LOCAL_MEMBER_ID")
                .ok()
                .and_then(|s| Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| {
                    Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
                }),
            otel_enabled: matches!(env::var("OPENOM_OTEL").as_deref(), Ok("1") | Ok("true")),
            otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4318".into()),
            otlp_headers: env::var("OTEL_EXPORTER_OTLP_HEADERS").ok(),
        };
        config.validate();
        config
    }

    /// True on the local storage axis (MinIO). Gates bucket bootstrap; its inverse gates
    /// the dev-key refusal.
    pub fn storage_is_local(&self) -> bool {
        self.storage == StorageMode::Local
    }
    /// True on the cloud storage axis (R2) — refuse the reserved dev key_id at rest (§16).
    pub fn storage_is_cloud(&self) -> bool {
        self.storage == StorageMode::Cloud
    }
    /// True on the fake-auth axis (a UUID bearer is that member; no signature).
    pub fn auth_is_dev(&self) -> bool {
        self.auth == AuthMode::Dev
    }
    /// True on the real-JWT axis.
    pub fn auth_is_jwt(&self) -> bool {
        self.auth == AuthMode::Jwt
    }
    /// The deployment runs under Lambda (JSON logs, no dev routes). Local server otherwise.
    pub fn is_lambda(&self) -> bool {
        self.run_mode == RunMode::Production
    }
    /// Dev-only routes (`/dev/gc`, later `/dev/token`) are registered only on the local
    /// server deployment — never under Lambda.
    pub fn dev_routes_enabled(&self) -> bool {
        self.run_mode == RunMode::Local
    }

    /// Refuse illegal axis combinations at startup (fail fast, never at request time).
    fn validate(&self) {
        // Fake auth over real user data must be unrepresentable.
        assert!(
            !(self.auth == AuthMode::Dev && self.storage == StorageMode::Cloud),
            "config: AUTH=dev with STORAGE=cloud is refused — fake auth must never guard real user data"
        );
        // The real-JWT axis needs verifier material for its algorithm: HS256 a shared secret, RS256 a
        // JWKS URL. Fail fast at startup rather than 500 on the first request.
        if self.auth == AuthMode::Jwt {
            match self.jwt_alg {
                JwtAlg::Hs256 => assert!(
                    self.jwt_secret.is_some(),
                    "config: AUTH=jwt AUTH_JWT_ALG=HS256 requires AUTH_JWT_SECRET (a shared secret)"
                ),
                JwtAlg::Rs256 => assert!(
                    self.jwks_url.is_some(),
                    "config: AUTH=jwt AUTH_JWT_ALG=RS256 requires AUTH_JWKS_URL (the issuer's JWKS endpoint)"
                ),
            }
        }
    }
}
