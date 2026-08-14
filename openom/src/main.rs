//! openom server — Axum, a zero-knowledge blob store.
//!
//! One binary, two run modes (see [`config`]): under `RUN_MODE=local` it serves a
//! plain HTTP listener against a local MinIO + Postgres stack; in production the
//! same Axum app runs on AWS Lambda through `lambda_http`. Auth, storage and the
//! tree PUT/GET routes land on top of this skeleton in the following steps.

mod config;

use axum::{extract::State, http::StatusCode, routing::get, Router};
use config::Config;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    #[allow(dead_code)] // used once storage/routes land
    config: Arc<Config>,
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

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
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

    // Lazy pool: the server starts even if Postgres is briefly unavailable (e.g.
    // the DB container is still coming up); /ready reports the live state.
    let db = PgPoolOptions::new().connect_lazy(&config.database_url)?;
    let state = AppState { db, config: Arc::new(config.clone()) };
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
