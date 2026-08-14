//! openom server — Axum, a zero-knowledge blob store.
//!
//! One binary, two run modes (see [`config`]): under `RUN_MODE=local` it serves a
//! plain HTTP listener against a local MinIO + Postgres stack; in production the
//! same Axum app runs on AWS Lambda through `lambda_http`. Storage and the tree
//! PUT/GET routes land on top of this skeleton in the following steps.

mod auth;
mod config;

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use config::Config;
use jsonwebtoken::DecodingKey;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    db: PgPool,
    config: Arc<Config>,
    /// HS256 key for verifying Supabase JWTs (production). None locally.
    jwt_key: Option<DecodingKey>,
}

/// Liveness: the process is up.
async fn health() -> &'static str {
    "openom ok"
}

/// Readiness: dependencies are reachable. V1 checks Postgres; storage and auth
/// join this as those subsystems land.
async fn ready(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "ready"),
        Err(err) => {
            tracing::warn!(%err, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "db unreachable")
        }
    }
}

/// Echoes the authenticated caller — proves the auth wiring end to end.
async fn whoami(id: auth::Identity) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "member_id": id.member_id }))
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/whoami", get(whoami))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    let config = Config::from_env();
    init_tracing(config.is_local());

    tracing::info!(
        run_mode = ?config.run_mode,
        envelope_version = openom_protocol::ENVELOPE_VERSION,
        ciphers = openom_crypto::cipher_suite(),
        "openom starting"
    );

    // Lazy pool: the server process starts even if Postgres is briefly slow; the
    // migration below is the first thing that actually needs a connection.
    let db = PgPoolOptions::new().connect_lazy(&config.database_url)?;

    // Migrations are idempotent and advisory-locked, so running them on every
    // start is safe (already-applied ones are a quick no-op).
    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("migrations applied");

    // Locally there is no Supabase to create accounts, so seed the fake-auth
    // member — otherwise its future tree writes would fail the owner_id foreign key.
    if config.is_local() {
        sqlx::query("INSERT INTO accounts (id) VALUES ($1) ON CONFLICT (id) DO NOTHING")
            .bind(config.local_member_id)
            .execute(&db)
            .await?;
        tracing::info!(member_id = %config.local_member_id, "seeded local account");
    }

    let jwt_key = config
        .jwt_secret
        .as_ref()
        .map(|s| DecodingKey::from_secret(s.as_bytes()));
    let state = AppState { db, config: Arc::new(config.clone()), jwt_key };
    let router = app(state);

    if config.is_local() {
        let addr = config.http_addr.clone();
        tracing::info!(%addr, "serving locally over plain HTTP");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, router).await?;
        Ok(())
    } else {
        lambda_http::run(router).await
    }
}

/// Pretty, coloured logs locally; JSON for the aggregator in production.
fn init_tracing(local: bool) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = fmt().with_env_filter(filter);
    if local {
        builder.init();
    } else {
        builder.json().init();
    }
}
