//! Shared protocol — the protobuf data model used identically by the server and
//! the Tauri client (through `openom-store`).
//!
//! The Rust types are generated from `proto/openom.proto` with `buf generate`
//! (the neoeinstein-prost plugin) into `src/generated/`, **not** by a build
//! script — so this crate has no build-time `protoc`/`protox` dependency and
//! nothing executes during `cargo build`. Once the schema exists, the generated
//! module is `include!`d here. Until then this placeholder keeps the crate and
//! its `prost` wiring compiling.

/// Bumped whenever the wire schema changes; travels with every update.
pub const SCHEMA_VERSION: u32 = 1;

/// Placeholder message that exercises the `prost` dependency until the code
/// generated from `openom.proto` replaces it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Placeholder {
    #[prost(string, tag = "1")]
    pub note: ::prost::alloc::string::String,
}
