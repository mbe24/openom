//! Runtime configuration.
//!
//! `RUN_MODE=local` decouples the server from every cloud dependency: MinIO for
//! storage, a local Postgres, fake auth. Everything is read from the environment,
//! so the same binary serves both modes — only the endpoints and the behaviour of
//! a few middlewares differ.

use std::env;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Fully offline: MinIO, local Postgres, fake auth, pretty logs.
    Local,
    /// Cloud: R2, Neon, Supabase, JSON logs.
    Production,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub run_mode: RunMode,
    /// Address the local HTTP server binds. Ignored under Lambda in production.
    pub http_addr: String,
    /// Postgres connection string (Neon in prod, a local container in dev).
    pub database_url: String,
    /// S3-compatible endpoint the *server* uses for proxy ops (R2 in prod, MinIO in
    /// dev). In-cluster hostname (e.g. `http://minio:9000`).
    pub s3_endpoint: String,
    /// Endpoint baked into *presigned URLs handed to clients* — must be
    /// client-reachable. Same as `s3_endpoint` for R2; for local MinIO it's the
    /// host-published address (`http://localhost:9000`), since the SigV4 signature
    /// binds the host and can't be rewritten after signing.
    pub s3_public_endpoint: String,
    /// Bucket that holds the encrypted tree envelopes.
    pub s3_bucket: String,
    /// S3 region. MinIO ignores it but still requires a value in the signature;
    /// R2 uses "auto".
    pub s3_region: String,
    /// S3 access key id (MinIO root user in dev, R2 token id in prod).
    pub s3_access_key: String,
    /// S3 secret access key.
    pub s3_secret_key: String,
    /// Supabase JWT secret (HS256). Required in production, unused locally.
    pub jwt_secret: Option<String>,
    /// Expected JWT `aud` claim. `Some` → the token's audience must match (hardening);
    /// `None` → the audience check is skipped. Defaults to Supabase's `"authenticated"`
    /// in production and off locally; `SUPABASE_JWT_AUD` overrides, and an explicit empty
    /// value opts out (for a deployment whose tokens carry a non-standard audience).
    pub jwt_audience: Option<String>,
    /// The account fake-auth maps anonymous local requests to.
    pub local_member_id: Uuid,

    /// Export spans over OTLP (opt-in). Off by default so a plain local run stays
    /// cheap and needs no collector; `OPENOM_OTEL=1` turns it on.
    pub otel_enabled: bool,
    /// OTLP/HTTP base endpoint (grafana/otel-lgtm in dev, Better Stack in prod).
    /// The traces path (`/v1/traces`) is appended if absent.
    pub otlp_endpoint: String,
    /// Extra OTLP headers as `k1=v1,k2=v2` (e.g. a Better Stack source token). The
    /// value is a secret — never logged.
    pub otlp_headers: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let run_mode = match env::var("RUN_MODE").unwrap_or_default().as_str() {
            "production" | "prod" => RunMode::Production,
            _ => RunMode::Local,
        };
        let s3_endpoint =
            env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into());
        let s3_public_endpoint =
            env::var("S3_PUBLIC_ENDPOINT").unwrap_or_else(|_| s3_endpoint.clone());
        Self {
            run_mode,
            http_addr: env::var("OPENOM_HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:6060".into()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://openom:openom@localhost:5432/openom".into()),
            s3_endpoint,
            s3_public_endpoint,
            s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| "openom-trees".into()),
            s3_region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            s3_access_key: env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "openom".into()),
            s3_secret_key: env::var("S3_SECRET_KEY").unwrap_or_else(|_| "openompw123".into()),
            jwt_secret: env::var("SUPABASE_JWT_SECRET").ok(),
            jwt_audience: match env::var("SUPABASE_JWT_AUD") {
                Ok(v) if v.trim().is_empty() => None, // explicit opt-out
                Ok(v) => Some(v),
                Err(_) if run_mode == RunMode::Production => Some("authenticated".into()),
                Err(_) => None,
            },
            local_member_id: env::var("OPENOM_LOCAL_MEMBER_ID")
                .ok()
                .and_then(|s| Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
            otel_enabled: matches!(env::var("OPENOM_OTEL").as_deref(), Ok("1") | Ok("true")),
            otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4318".into()),
            otlp_headers: env::var("OTEL_EXPORTER_OTLP_HEADERS").ok(),
        }
    }

    pub fn is_local(&self) -> bool {
        self.run_mode == RunMode::Local
    }
}
