//! The canonical-bytes seam — the single definition of "the bytes" a signature and a content-addressed
//! id bind to.
//!
//! **Design "A":** [`CanonicalBytes`] is the seam. **Default "B":** a postcard encoding of anything
//! `serde::Serialize`, a compact, deterministic binary format that is byte-identical across native and
//! wasm Rust builds. (The old `format!("{:?}")` encoding was never guaranteed stable across builds, so it
//! could never back a content hash.) To adopt a non-postcard layout for a specific type later, implement
//! the trait by hand — a versioned change, since every id/signature over that type moves.
//!
//! This crate owns the generic seam only; the concrete `canonical_encode` block-layout functions and the
//! by-hand impls for the engine's own payload types live in the engine crate (they name engine types),
//! and go through [`Postcard`] for their `Serialize` sub-fields.

use serde::Serialize;

/// The canonical-bytes seam. The default ("B") is a deterministic postcard encoding for anything
/// `Serialize` — used for primitive `Id`/`Role`/`OpId` values via [`Postcard`]. Types that embed non-serde
/// crypto byte-arrays implement it by hand (in the engine crate).
pub trait CanonicalBytes {
    fn write_canonical(&self, out: &mut Vec<u8>);
}

/// A newtype so the postcard default doesn't blanket-cover *every* `Serialize` type — which would
/// collide (coherence) with the by-hand impls. Wrap a `Serialize` value to get its postcard bytes.
pub struct Postcard<'a, T: Serialize>(pub &'a T);

impl<T: Serialize> CanonicalBytes for Postcard<'_, T> {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(
            &postcard::to_allocvec(self.0)
                .expect("postcard serialization of canonical op content is infallible"),
        );
    }
}
