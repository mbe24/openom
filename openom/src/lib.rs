//! openom server library — the Axum app, shared state, and startup wiring.
//!
//! Exposed as a library (alongside the `openom` binary) so integration tests can
//! build [`AppState`] and drive [`app`] in-process via `tower`'s `oneshot`, exercising
//! the real routing + extractor + handler + DB + storage stack without a socket. The
//! binary ([`main`](../main.rs)) is a thin shell: tracing + serve/Lambda selection.

pub mod access;
pub mod auth;
pub mod authz;
pub mod config;
pub mod jwks;
pub mod keyring;
pub mod log;
pub mod media;
pub mod prof;
pub mod proposals;
pub mod storage;
pub mod telemetry;
pub mod trees;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
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
    /// The provider-neutral JWT verifier (HS256 secret or RS256/ES256 JWKS) under `AUTH=jwt`; `None`
    /// under `AUTH=dev`. `Arc` so cloning `AppState` shares one JWKS cache.
    jwt_verifier: Option<Arc<jwks::JwtVerifier>>,
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
        .route(
            "/trees/{tree_id}",
            get(trees::get_tree).put(trees::put_tree),
        )
        // Delta-log: append a sealed delta / pull the ordered tail (sync + change history, §B1).
        .route(
            "/trees/{tree_id}/log",
            post(log::append_log).get(log::get_log),
        )
        // Proposals: the transient, off-history approval channel for review-changes (§B2).
        .route(
            "/trees/{tree_id}/proposals",
            post(proposals::create_proposal).get(proposals::list_proposals),
        )
        .route(
            "/trees/{tree_id}/proposals/{proposal_id}",
            delete(proposals::delete_proposal),
        )
        // Keyring: the authoritative signed membership/role chain; PUT verifies + derives the ACL (§B3).
        .route(
            "/trees/{tree_id}/keyring",
            put(keyring::put_keyring).get(keyring::get_keyring),
        )
        // Advisory membership: PUT a client-asserted engine-neutral summary (OPE-278), GET the derived
        // member list + the summary's generation/basis (sharing UI + the client's pre-push staleness check).
        .route(
            "/trees/{tree_id}/access",
            get(access::get_access).put(access::put_access),
        )
        // Media: entitlement-gated presigned upload/download (§12, §17). Bytes never
        // traverse the server, so the body limit below doesn't apply to them.
        .route("/trees/{tree_id}/media/intent", post(media::intent))
        .route("/trees/{tree_id}/media/{blob_id}", get(media::get_media))
        .route(
            "/trees/{tree_id}/media/{blob_id}/confirm",
            post(media::confirm),
        )
        // Presence-based GC (§9.11): the client drives refcount as it references /
        // dereferences a blob in its tree doc.
        .route(
            "/trees/{tree_id}/media/{blob_id}/attach",
            post(media::attach),
        )
        .route(
            "/trees/{tree_id}/media/{blob_id}/detach",
            post(media::detach),
        );
    if state.config.dev_routes_enabled() {
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

    if config.auth_is_dev() {
        provision_dev_account(&db, config.local_member_id).await?;
    }

    // Build the JWT verifier once (its algorithm + key material are validated at config load).
    let jwt_verifier = config.auth_is_jwt().then(|| {
        let aud = config.jwt_audience.as_deref();
        let iss = config.jwt_issuer.as_deref();
        Arc::new(match config.jwt_alg {
            config::JwtAlg::Hs256 => jwks::JwtVerifier::hs256(
                config.jwt_secret.as_deref().expect("validate(): HS256 requires a secret"),
                aud,
                iss,
            ),
            config::JwtAlg::Rs256 => jwks::JwtVerifier::jwks(
                config.jwks_url.clone().expect("validate(): RS256 requires a JWKS URL"),
                aud,
                iss,
            ),
        })
    });

    let storage = S3Store::from_config(config)?;
    // Dev bootstrap: MinIO starts empty, so create the bucket up front. In prod the
    // bucket is provisioned out of band and this is a cheap already-exists no-op.
    if config.storage_is_local() {
        if let Err(err) = storage.ensure_bucket().await {
            tracing::warn!(%err, "could not ensure local bucket (MinIO not up yet?)");
        }
    }

    Ok(AppState {
        db,
        config: Arc::new(config.clone()),
        jwt_verifier,
        storage,
    })
}

/// Provision a fake-auth (`AUTH=dev`) member's `accounts` row (no Supabase to create
/// accounts). Idempotent — called at startup for the default member AND lazily at
/// `Identity` resolution for every dev UUID (OPE-335: without a row, the FK + quota gate
/// make the account's first `PUT /trees` a 403). Generous entitlements: a dev account is
/// a convenience, not a free-tier user, so it grants media + streaming + big caps (§17)
/// and shouldn't trip entitlement gates.
/// NOTE: production (`AUTH=jwt`) has the same gap — nothing provisions an `accounts` row
/// for a fresh Supabase/Clerk `sub`. That is a separate, deliberate decision (free-tier
/// defaults + a self-serve provisioning policy), deferred; the columns all have defaults.
pub(crate) async fn provision_dev_account(db: &PgPool, member_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO accounts
             (id, max_trees, allow_media, allow_streaming_media,
              max_blob_bytes, max_blob_count, max_storage_bytes, max_tree_bytes,
              log_rate, log_burst, log_tokens,
              max_proposal_bytes, max_open_proposals_per_tree, max_proposals_per_member_day)
         VALUES ($1, 1000000, true, true, 5368709120, 1000000, 1099511627776, 10737418240,
                 100000, 100000, 100000,
                 1048576, 100000, 100000)
         ON CONFLICT (id) DO UPDATE SET
             max_trees = EXCLUDED.max_trees,
             allow_media = EXCLUDED.allow_media,
             allow_streaming_media = EXCLUDED.allow_streaming_media,
             max_blob_bytes = EXCLUDED.max_blob_bytes,
             max_blob_count = EXCLUDED.max_blob_count,
             max_storage_bytes = EXCLUDED.max_storage_bytes,
             max_tree_bytes = EXCLUDED.max_tree_bytes,
             log_rate = EXCLUDED.log_rate,
             log_burst = EXCLUDED.log_burst,
             max_proposal_bytes = EXCLUDED.max_proposal_bytes,
             max_open_proposals_per_tree = EXCLUDED.max_open_proposals_per_tree,
             max_proposals_per_member_day = EXCLUDED.max_proposals_per_member_day",
    )
    .bind(member_id)
    .execute(db)
    .await?;
    tracing::debug!(%member_id, "provisioned dev account");
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
