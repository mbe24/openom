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
    /// S3-compatible endpoint (Cloudflare R2 in prod, MinIO in dev).
    #[allow(dead_code)] // used once the blob-store subsystem lands
    pub s3_endpoint: String,
    /// Bucket that holds the encrypted tree envelopes.
    #[allow(dead_code)]
    pub s3_bucket: String,
    /// Supabase JWT secret (HS256). Required in production, unused locally.
    pub jwt_secret: Option<String>,
    /// The account fake-auth maps anonymous local requests to.
    pub local_member_id: Uuid,
}

impl Config {
    pub fn from_env() -> Self {
        let run_mode = match env::var("RUN_MODE").unwrap_or_default().as_str() {
            "production" | "prod" => RunMode::Production,
            _ => RunMode::Local,
        };
        Self {
            run_mode,
            http_addr: env::var("OPENOM_HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:6060".into()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://openom:openom@localhost:5432/openom".into()),
            s3_endpoint: env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into()),
            s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| "openom-trees".into()),
            jwt_secret: env::var("SUPABASE_JWT_SECRET").ok(),
            local_member_id: env::var("OPENOM_LOCAL_MEMBER_ID")
                .ok()
                .and_then(|s| Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
        }
    }

    pub fn is_local(&self) -> bool {
        self.run_mode == RunMode::Local
    }
}
