//! Shared protocol — the wire format used identically by the server and the Tauri
//! client (through `openom-store`).
//!
//! The Rust types in [`v1`] are generated from `proto/openom/v1/openom.proto` with
//! `buf generate` (the neoeinstein-prost plugin) and checked into `src/generated/`.
//! There is **no build script and no `protoc`**, so nothing executes during
//! `cargo build` — which is what lets the crate build on a host whose policy blocks
//! build-script execution. Regenerate with `cd proto && buf generate` after editing
//! the `.proto`.

/// Generated types for `package openom.v1` — `Envelope`, `Header`, `Keyring`,
/// `KeyEpoch`, `KeyWrap`, `KdfParams`, and the `Kind` / `Format` / `Aead` /
/// `Compression` / `WrapMethod` enums.
pub mod v1 {
    include!("generated/openom/v1/openom.v1.rs");
}

/// Canonical, length-prefixed AAD encoding of a `Header` (data-format spec §5) — the
/// byte string a Rust and a WASM/JS build must produce identically.
pub mod aad;

/// The `Envelope.version` this build reads and writes (data-format spec §3). An
/// envelope carrying a higher version is opened read-only rather than misread.
pub const ENVELOPE_VERSION: u32 = 1;

/// Re-exported so callers can `decode`/`encode` the generated messages without
/// taking their own direct `prost` dependency (the server decodes uploaded
/// envelopes to validate them; see `openom` `trees` module).
pub use prost::Message;
