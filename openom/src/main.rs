//! openom server binary — a thin shell over the `openom` library: initialize
//! tracing, build shared state, and serve (local HTTP or Lambda). The app, routes,
//! state, and startup wiring live in `lib.rs` so they're testable in-process.

use openom::config::Config;
use openom::{app, build_state, telemetry};
use opentelemetry_sdk::trace::SdkTracerProvider;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    let config = Config::from_env();
    let otel = init_tracing(&config);

    tracing::info!(
        run_mode = ?config.run_mode,
        storage = ?config.storage,
        auth = ?config.auth,
        envelope_version = openom_protocol::ENVELOPE_VERSION,
        ciphers = openom_crypto::cipher_suite(),
        "openom starting"
    );

    let state = build_state(&config).await?;
    let router = app(state);

    if !config.is_lambda() {
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
/// over OTLP. App code speaks plain `tracing` macros and never knows which backend is
/// attached; this composition root is the only place the choice is made. Returns the
/// tracer provider (when enabled) so the caller can flush it on Lambda.
fn init_tracing(config: &Config) -> Option<SdkTracerProvider> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter, Layer};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let provider = telemetry::build_tracer_provider(config);
    let otel_layer = provider.as_ref().map(|p| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(p.tracer("openom"))
    });

    let fmt_layer = if !config.is_lambda() {
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
