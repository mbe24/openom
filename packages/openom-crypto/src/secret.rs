//! Typed secret key material (OPE-211).
//!
//! Each key *role* is a distinct newtype over a zeroizing 32-byte buffer, so the compiler rejects
//! passing one role's key where another's is expected — a KEK where a DEK goes, a member's HPKE
//! secret where the recovery-root secret is escrow-wrapped. This is one level of abstraction: the
//! role newtype *is* the secrecy guard, not a `Secret<Role>` wrapper stacked on top.
//!
//! The guard has three parts, all of which `Key32` (a bare `Zeroizing<[u8; 32]>`) lacks:
//! - **No `Deref`** — the raw bytes are reachable only through the explicit [`expose`](Dek::expose),
//!   so every raw-key access is greppable for a security audit and a key can't silently coerce into a
//!   `&[u8]` argument.
//! - **No `Serialize`** — a key can't be accidentally serialized into a wire message or store.
//! - **A hand-written `Debug`** printing `Role(..)` — `{:?}` on a key never prints its bytes (unlike
//!   `Zeroizing`, whose derived `Debug` forwards to the inner array).
//!
//! These types deliberately do **not** reach the sealer: inside `openom-sealer`'s `Sealer` a key is
//! unambiguously "the DEK", with no other role to confuse it with, so `vault.rs` converts a [`Dek`]
//! to raw bytes ([`into_inner`](Dek::into_inner)) at the one point it hands DEKs to the sealer.

use zeroize::Zeroizing;

use crate::KEY_LEN;

macro_rules! secret_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Zeroizing<[u8; KEY_LEN]>);

        impl $name {
            /// Wrap raw 32-byte key material. The bytes zeroize on drop.
            pub fn new(bytes: [u8; KEY_LEN]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// Borrow the raw key bytes — the single, explicit exposure point (grep `.expose()` to
            /// audit every place raw key material is read).
            pub fn expose(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Consume the newtype into its zeroizing buffer — the deliberate escape hatch used only
            /// at the sealer boundary, where a key stops being role-typed and becomes "the DEK".
            pub fn into_inner(self) -> Zeroizing<[u8; KEY_LEN]> {
                self.0
            }
        }

        impl From<Zeroizing<[u8; KEY_LEN]>> for $name {
            fn from(z: Zeroizing<[u8; KEY_LEN]>) -> Self {
                Self(z)
            }
        }

        // Hand-written so `{:?}` can never print the key bytes.
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

secret_key!(
    /// A per-tree, per-epoch **data-encryption key**: the symmetric key that seals entries. Produced
    /// by `generate_dek` / `unwrap_dek` / `hpke_unwrap_dek`; consumed by the wrap functions and (via
    /// `into_inner`) the sealer.
    Dek
);
secret_key!(
    /// A **key-encryption key**, derived from a passphrase or recovery code (`derive_kek`). Wraps a
    /// [`Dek`] or an [`RrkSecret`]; never itself wrapped or sealed.
    Kek
);
secret_key!(
    /// The **recovery-root-key private scalar** (X25519). Unlike an [`HpkePrivate`] it is not derived
    /// from a passphrase: it is escrow-wrapped at rest (`wrap_rrk_secret`) and, once recovered, opens
    /// the owner's epoch DEK wraps. Distinct from [`HpkePrivate`] so it can never be swapped in as a
    /// symmetric-wrap payload, nor a member secret be wrapped in its place.
    RrkSecret
);
secret_key!(
    /// A **member's X25519 HPKE private scalar**, derived from their passphrase root (`derive_root`).
    /// Opens a DEK wrapped to them when they are a member of another tree; never escrow-wrapped
    /// itself (it re-derives from the passphrase). Distinct from [`RrkSecret`].
    HpkePrivate
);
