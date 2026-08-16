//! openom server library — the Axum app, shared state, and startup wiring.
//!
//! Exposed as a library (alongside the `openom` binary) so integration tests can
//! build [`AppState`] and drive [`app`] in-process via `tower`'s `oneshot`, exercising
//! the real routing + extractor + handler + DB + storage stack without a socket. The
//! binary ([`main`](../main.rs)) is a thin shell: tracing + serve/Lambda selection.

pub mod auth;
pub mod config;
pub mod log;
pub mod media;
pub mod prof;
pub mod storage;
pub mod telemetry;
pub mod trees;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::DecodingKey;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use config::Config;
use storage::S3Store;

/// Shared handler state. Fields stay private to the crate — handlers in child modules
/// reach them directly; nothing outside constructs it except [`build_state`].
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

/// Readiness: dependencies are reachable. V1 checks Postgres.
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

/// Build the router. `/dev/gc` is local-only (prod drives the sweep from a scheduled
/// trigger). This is the single source of truth for routes, shared by the binary and
/// the integration tests.
pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/whoami", get(whoami))
        .route("/trees/{tree_id}", get(trees::get_tree).put(trees::put_tree))
        // Delta-log: append a sealed delta / pull the ordered tail (sync + change history, §B1).
        .route("/trees/{tree_id}/log", post(log::append_log).get(log::get_log))
        // Media: entitlement-gated presigned upload/download (§12, §17). Bytes never
        // traverse the server, so the body limit below doesn't apply to them.
        .route("/trees/{tree_id}/media/intent", post(media::intent))
        .route("/trees/{tree_id}/media/{blob_id}", get(media::get_media))
        .route("/trees/{tree_id}/media/{blob_id}/confirm", post(media::confirm))
        // Presence-based GC (§9.11): the client drives refcount as it references /
        // dereferences a blob in its tree doc.
        .route("/trees/{tree_id}/media/{blob_id}/attach", post(media::attach))
        .route("/trees/{tree_id}/media/{blob_id}/detach", post(media::detach));
    if state.config.is_local() {
        router = router.route("/dev/gc", post(media::sweep_dev));
    }
    router
        // Cap the tree PUT body at the proxy ceiling (§9.9); larger uploads (media)
        // take the presigned path, never this proxy.
        .layer(DefaultBodyLimit::max(trees::MAX_OBJECT_BYTES))
        // One root span per request. DefaultMakeSpan records method + matched route +
        // version only — no PII, no query strings (SERVER-DATA-FORMAT §7 discipline).
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().level(Level::INFO)))
        .with_state(state)
}

/// Wire up the shared state: a lazy Postgres pool, run migrations, seed the local
/// dev account, and connect the blob store. Idempotent — safe to call at every
/// startup and at the top of each integration test.
pub async fn build_state(config: &Config) -> Result<AppState, BuildError> {
    // Lazy pool: the process starts even if Postgres is briefly slow; the migration
    // below is the first thing that actually needs a connection.
    let db = PgPoolOptions::new().connect_lazy(&config.database_url)?;

    // Migrations are idempotent and advisory-locked, so running them on every start
    // is safe (already-applied ones are a quick no-op).
    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("migrations applied");

    if config.is_local() {
        seed_local_account(&db, config.local_member_id).await?;
    }

    let jwt_key = config
        .jwt_secret
        .as_ref()
        .map(|s| DecodingKey::from_secret(s.as_bytes()));

    let storage = S3Store::from_config(config)?;
    // Dev bootstrap: MinIO starts empty, so create the bucket up front. In prod the
    // bucket is provisioned out of band and this is a cheap already-exists no-op.
    if config.is_local() {
        if let Err(err) = storage.ensure_bucket().await {
            tracing::warn!(%err, "could not ensure local bucket (MinIO not up yet?)");
        }
    }

    Ok(AppState { db, config: Arc::new(config.clone()), jwt_key, storage })
}

/// Seed the fake-auth member locally (no Supabase to create accounts). Generous
/// entitlements: the dev account is a convenience, not a free-tier user, so it grants
/// media + streaming + big caps (§17) and shouldn't trip entitlement gates.
async fn seed_local_account(db: &PgPool, member_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO accounts
             (id, max_trees, allow_media, allow_streaming_media,
              max_blob_bytes, max_blob_count, max_storage_bytes, max_tree_bytes,
              log_rate, log_burst, log_tokens)
         VALUES ($1, 1000000, true, true, 5368709120, 1000000, 1099511627776, 10737418240,
                 100000, 100000, 100000)
         ON CONFLICT (id) DO UPDATE SET
             max_trees = EXCLUDED.max_trees,
             allow_media = EXCLUDED.allow_media,
             allow_streaming_media = EXCLUDED.allow_streaming_media,
             max_blob_bytes = EXCLUDED.max_blob_bytes,
             max_blob_count = EXCLUDED.max_blob_count,
             max_storage_bytes = EXCLUDED.max_storage_bytes,
             max_tree_bytes = EXCLUDED.max_tree_bytes,
             log_rate = EXCLUDED.log_rate,
             log_burst = EXCLUDED.log_burst",
    )
    .bind(member_id)
    .execute(db)
    .await?;
    tracing::info!(%member_id, "seeded local account");
    Ok(())
}

/// Startup failure (pool, migration, or storage config).
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("storage: {0}")]
    Storage(#[from] storage::StorageError),
}
