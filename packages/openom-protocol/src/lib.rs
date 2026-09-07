#![doc = include_str!("../README.md")]
// The crate doc is the README (via include_str!). clippy's too_long_first_doc_paragraph flags its first
// paragraph but emits a location-less warning it cannot map to a source span, so it survives splitting every
// candidate README paragraph — a clippy limitation on included markdown. Allowed here (the crate's own source
// doc paragraphs are all within the limit); see scripts/nursery.mjs.
#![allow(clippy::too_long_first_doc_paragraph)]

/// Generated types for `package openom.v1` — `Envelope`, `Header`, `KeyringUpdate`, and the
/// `Kind` / `Format` / `Aead` / `Compression` / `MemberRole` enums. (The keyring wire moved to
/// `openom-keyring-chain` in OPE-300; the keyring KEY MATERIAL — `KdfParams` / `WrapMethod` / epochs /
/// wraps — moved to `keyeo-crypto` + `keyeo_crypto::codec`, OPE-377.)
// prost-generated code — not ours to hand-lint, so pedantic + nursery are off for the generated module only.
#[allow(clippy::pedantic, clippy::nursery)]
pub mod v1 {
    include!("generated/openom/v1/openom.v1.rs");
}

/// Identity newtypes (`TreeId` / `ReplicaId` / `MemberId`) so the vault surface can't confuse one
/// opaque id byte-string for another at a call site. Wrap the proto's own fields; no wire change.
pub mod ids;

/// The `Envelope.version` this build reads and writes (data-format spec §3). An
/// envelope carrying a higher version is opened read-only rather than misread.
pub const ENVELOPE_VERSION: u32 = 1;

/// The `Keyring.layout_version` this build reads and writes (data-format spec §4).
///
/// A
/// keyring carrying a higher layout is opened read-only rather than misread — the
/// keyring's own version axis, independent of `ENVELOPE_VERSION`.
pub const KEYRING_LAYOUT_VERSION: u32 = 1;

/// Re-exported so callers can `decode`/`encode` the generated messages without
/// taking their own direct `prost` dependency (the server decodes uploaded
/// envelopes to validate them; see `openom` `trees` module).
pub use prost::Message;
