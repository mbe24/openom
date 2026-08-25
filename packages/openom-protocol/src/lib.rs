#![doc = include_str!("../README.md")]

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

/// The `Keyring.layout_version` this build reads and writes (data-format spec §4). A
/// keyring carrying a higher layout is opened read-only rather than misread — the
/// keyring's own version axis, independent of `ENVELOPE_VERSION`.
pub const KEYRING_LAYOUT_VERSION: u32 = 1;

/// Re-exported so callers can `decode`/`encode` the generated messages without
/// taking their own direct `prost` dependency (the server decodes uploaded
/// envelopes to validate them; see `openom` `trees` module).
pub use prost::Message;
