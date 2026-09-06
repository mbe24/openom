//! Opt-in scope profiling, gated by the `profiling` cargo feature (off in release → zero cost).
//!
//! Drop a `let _p = prof::span("log.append");` at the top of a hot scope; when the feature is on it
//! logs the elapsed microseconds on scope exit (target `openom::profile`, so it can be filtered or
//! routed to its own OTLP stream). When off, `Span` is a zero-sized no-op the optimiser erases.

/// Start a timing span for the current scope. Bind it to a `_p` so it lives to the scope's end.
#[inline]
#[must_use]
pub fn span(label: &'static str) -> Span {
    Span::new(label)
}

#[cfg(feature = "profiling")]
pub struct Span {
    label: &'static str,
    start: std::time::Instant,
}

#[cfg(feature = "profiling")]
impl Span {
    #[inline]
    fn new(label: &'static str) -> Self {
        Span {
            label,
            start: std::time::Instant::now(),
        }
    }
}

#[cfg(feature = "profiling")]
impl Drop for Span {
    fn drop(&mut self) {
        // A span over ~584k years is impossible; saturate rather than truncate the u128 micros.
        let micros = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        tracing::debug!(target: "openom::profile", label = self.label, micros, "prof");
    }
}

#[cfg(not(feature = "profiling"))]
pub struct Span;

#[cfg(not(feature = "profiling"))]
impl Span {
    #[inline]
    fn new(_label: &'static str) -> Self {
        Span
    }
}
