//! The **commute format bridge** — import/export structured documents as mergeable [`commute`] cells.
//!
//! It is a REUSABILITY layer (openom's own editing goes through typed ops, not this). Two seams:
//!
//! - a [`Codec`] turns a serialized format ⇄ a neutral [`ValueTree`] (mechanical; one impl per
//!   format — JSON now, XML/YAML later behind the same trait);
//! - a `Mapping` (next slice) turns a [`ValueTree`] ⇄ commute cells, carrying **identity** and a
//!   per-field **merge policy** — the substance, and where "no silent last-writer-wins" is enforced.
//!
//! This slice lands the IR + the JSON codec. The JSON codec is hand-rolled (no serde) so it
//! **rejects duplicate object keys and floating-point numbers** — a document CRDT that silently
//! last-writer-wins a duplicate key, or archives a non-canonical float, is exactly what we avoid.

#![forbid(unsafe_code)]

/// A neutral, format-agnostic value — the pivot every [`Codec`] and mapping shares. `#[non_exhaustive]`
/// so an XML-shaped `Element` variant can be added later without a breaking change. The map is an
/// **ordered, duplicate-capable** `Vec<(String, _)>`: order is preserved for deterministic emit, and
/// a codec decides its own duplicate-key policy (JSON rejects them). **No float variant** — values
/// become a canonical, float-free archive encoding downstream.
#[non_exhaustive]
#[derive(Clone, PartialEq, Debug)]
pub enum ValueTree {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Str(String),
    Bytes(Vec<u8>),
    Seq(Vec<ValueTree>),
    Map(Vec<(String, ValueTree)>),
}

/// A serialized format ⇄ [`ValueTree`]. Mechanical, no CRDT knowledge.
pub trait Codec {
    fn parse(&self, bytes: &[u8]) -> Result<ValueTree, CodecError>;
    fn emit(&self, value: &ValueTree) -> Result<Vec<u8>, CodecError>;
}

/// Why a codec rejected its input (or output). Never a panic — arbitrary bytes fail cleanly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("malformed input at byte {pos}: {what}")]
    Malformed { pos: usize, what: &'static str },
    #[error("duplicate object key {0:?}")]
    DuplicateKey(String),
    #[error("floating-point numbers are not representable (no canonical archive form)")]
    FloatNotRepresentable,
    #[error("number out of the i64/u64 range")]
    NumberOutOfRange,
    #[error("nesting deeper than the configured limit")]
    TooDeep,
    #[error("value cannot be represented in this format: {0}")]
    Unrepresentable(&'static str),
}

#[cfg(feature = "json")]
mod json;
#[cfg(feature = "json")]
pub use json::JsonCodec;

#[cfg(test)]
mod tests;
