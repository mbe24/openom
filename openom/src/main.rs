//! openom server — Axum, a zero-knowledge blob store.
//!
//! One binary, two run modes (see [`config`]): under `RUN_MODE=local` it serves a
//! plain HTTP listener against a local MinIO + Postgres stack; in production the
//! same Axum app runs on AWS Lambda through `lambda_http`. Storage and the tree
//! PUT/GET routes land on top of this skeleton in the following steps.

mod auth;
mod config;
mod storage;
mod telemetry;
mod trees;

use axum::extract::DefaultBodyLimit;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;
use config::Config;
use jsonwebtoken::DecodingKey;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use storage::S3Store;

#[derive(Clone)]
pub struct AppState {
    db: PgPool,
    config: Arc<Config>,
    /// HS256 key for verifying Supabase JWTs (production). None locally.
    jwt_key: Option<DecodingKey>,
    /// Blob store (MinIO in dev, R2 in prod).
    storage: S3Store,
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
        .route("/trees/{tree_id}", get(trees::get_tree).put(trees::put_tree))
        // Cap the tree PUT body at the proxy ceiling (§9.9); larger uploads (media)
        // take the presigned path, never this proxy.
        .layer(DefaultBodyLimit::max(trees::MAX_OBJECT_BYTES))
        // One root span per request. DefaultMakeSpan records method + matched route +
        // version only — no PII, no query strings (SERVER-DATA-FORMAT §7 discipline).
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().level(Level::INFO)))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    let config = Config::from_env();
    let otel = init_tracing(&config);

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
    // Give it a generous tree limit: the dev account is a convenience, not a
    // free-tier user, and shouldn't trip entitlement caps during development.
    if config.is_local() {
        // Generous entitlements: the dev account is a convenience, not a free-tier
        // user, so grant media + streaming + big caps (§17) — dev shouldn't trip
        // entitlement gates. 5 GiB/blob, 1 TiB pool, 10 GiB tree reserve.
        sqlx::query(
            "INSERT INTO accounts
                 (id, max_trees, allow_media, allow_streaming_media,
                  max_blob_bytes, max_blob_count, max_storage_bytes, max_tree_bytes)
             VALUES ($1, 1000000, true, true, 5368709120, 1000000, 1099511627776, 10737418240)
             ON CONFLICT (id) DO UPDATE SET
                 max_trees = EXCLUDED.max_trees,
                 allow_media = EXCLUDED.allow_media,
                 allow_streaming_media = EXCLUDED.allow_streaming_media,
                 max_blob_bytes = EXCLUDED.max_blob_bytes,
                 max_blob_count = EXCLUDED.max_blob_count,
                 max_storage_bytes = EXCLUDED.max_storage_bytes,
                 max_tree_bytes = EXCLUDED.max_tree_bytes",
        )
        .bind(config.local_member_id)
        .execute(&db)
        .await?;
        tracing::info!(member_id = %config.local_member_id, "seeded local account");
    }

    let jwt_key = config
        .jwt_secret
        .as_ref()
        .map(|s| DecodingKey::from_secret(s.as_bytes()));

    let storage = S3Store::from_config(&config)?;
    // Dev bootstrap: MinIO starts empty, so create the bucket up front. In prod the
    // bucket is provisioned out of band and this is a cheap already-exists no-op.
    if config.is_local() {
        if let Err(err) = storage.ensure_bucket().await {
            tracing::warn!(%err, "could not ensure local bucket (MinIO not up yet?)");
        }
    }

    let state = AppState { db, config: Arc::new(config.clone()), jwt_key, storage };
    let router = app(state);

    if config.is_local() {
        let addr = config.http_addr.clone();
        tracing::info!(%addr, "serving locally over plain HTTP");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, router).await?;
        Ok(())
    } else {
        // On Lambda the batch processor's flush timer stops when the sandbox freezes
        // between invocations, so spans would be lost. Flush explicitly after each
        // response instead (invisible to app code — the seam stays in one place).
        let router = match otel.clone() {
            Some(provider) => router.layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let provider = provider.clone();
                    async move {
                        let response = next.run(req).await;
                        let _ = provider.force_flush();
                        response
                    }
                },
            )),
            None => router,
        };
        lambda_http::run(router).await
    }
}

/// Build the subscriber: an `EnvFilter`, a `fmt` layer (pretty local / JSON prod),
/// and — only when `OPENOM_OTEL` is set — a `tracing-opentelemetry` layer exporting
/// over OTLP. App code speaks plain `tracing` macros and never knows which backend
/// is attached; this composition root is the only place the choice is made. Returns
/// the tracer provider (when enabled) so the caller can flush it on Lambda.
fn init_tracing(config: &Config) -> Option<SdkTracerProvider> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter, Layer};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let provider = telemetry::build_tracer_provider(config);
    let otel_layer = provider.as_ref().map(|p| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(p.tracer("openom"))
    });

    let fmt_layer = if config.is_local() {
        fmt::layer().boxed()
    } else {
        fmt::layer().json().boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    provider
}
