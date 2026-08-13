//! openom server — Axum on AWS Lambda ("Monolith-on-FaaS").
//!
//! This is the wiring skeleton: it depends on the shared crates
//! (`openom-protocol`, `openom-crypto`) and the server stack (`axum`,
//! `lambda_http`, `tokio`, `tracing`) and references each, so a broken dependency
//! fails the build. Real routes, auth, storage (R2/MinIO) and persistence
//! (Neon/Postgres) land in the following steps.

use axum::{routing::get, Router};
use lambda_http::{run, Error};

/// Liveness probe. Returns 200 with a fixed body.
async fn health() -> &'static str {
    "openom ok"
}

/// The single Axum app the Lambda serves.
fn app() -> Router {
    Router::new().route("/health", get(health))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Terminal-friendly for now; JSON + a SaaS aggregator arrive with observability.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Touch the shared crates so their wiring is verified at compile time.
    tracing::info!(
        schema_version = openom_protocol::SCHEMA_VERSION,
        ciphers = openom_crypto::cipher_suite(),
        "openom starting"
    );

    run(app()).await
}
