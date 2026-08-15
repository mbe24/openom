//! OTLP export wiring.
//!
//! The `tracing` macros stay the *only* instrumentation API the app ever touches —
//! this module just turns their spans into OTLP when `OPENOM_OTEL` is set, pointed
//! at grafana/otel-lgtm (dev) or Better Stack (prod) by config. Everything here is
//! inert unless [`build_tracer_provider`] returns `Some`, so a plain local run pays
//! nothing. Export is HTTP/protobuf over reqwest+rustls — no gRPC/tonic, no OpenSSL.

use std::collections::HashMap;

use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

use crate::config::Config;

/// Build a batch-exporting tracer provider, or `None` when telemetry is off (or the
/// exporter can't be constructed — telemetry must never take the server down). The
/// caller attaches it as a `tracing` layer and holds it to `force_flush` on Lambda.
pub fn build_tracer_provider(config: &Config) -> Option<SdkTracerProvider> {
    if !config.otel_enabled {
        return None;
    }
    let mut builder = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(traces_endpoint(&config.otlp_endpoint));
    if let Some(raw) = &config.otlp_headers {
        builder = builder.with_headers(parse_headers(raw));
    }
    match builder.build() {
        Ok(exporter) => Some(
            SdkTracerProvider::builder()
                // Batch, not per-span: on Lambda a per-invocation force_flush drains
                // it before the sandbox freezes (main.rs); locally the batch timer
                // flushes on its own.
                .with_batch_exporter(exporter)
                .with_resource(Resource::builder().with_service_name("openom").build())
                .build(),
        ),
        Err(err) => {
            // tracing isn't initialized yet at this point, so go straight to stderr.
            eprintln!("openom: OTLP exporter init failed ({err}); continuing without span export");
            None
        }
    }
}

/// OTLP/HTTP wants the signal path; accept either a base (`…:4318`) or a full
/// traces endpoint and normalize to `…/v1/traces`.
fn traces_endpoint(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

/// Parse `k1=v1,k2=v2` OTLP headers (e.g. a Better Stack source token). Values are
/// secret and never logged.
fn parse_headers(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}
