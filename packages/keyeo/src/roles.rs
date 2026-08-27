//! Role model — pluggable trait.
//! The library provides the trait only. Role implementations are domain-specific
//! and defined by the caller (test, flowcontrol, etc.).
use std::fmt::Debug;

/// A role that can be compared for strength. `Serialize` is required because a role appears in an
/// op's signed, content-addressed bytes (via the `CanonicalBytes` seam — see `canonical`).
pub trait Role: Clone + Debug + Eq + std::hash::Hash + Send + Sync + serde::Serialize {
    fn grants_at_least(&self, other: &Self) -> bool;
}
