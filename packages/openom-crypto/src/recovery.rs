//! The recovery-code wrap's `KdfParams` (minimal Argon2id cost).
//!
//! The recovery code itself (generation, parsing, checksum) and its Argon2id cost constants live in
//! `keyeo_crypto::recovery` (openom-free) and are re-exported unchanged. This module owns only
//! [`recovery_kdf_params`], which builds keyeo's `KdfParams` from those costs — a recovery wrap is otherwise
//! an ordinary keyeo `kek_wrap` under the recovery-code method with the KEK derived from the code's entropy
//! via [`crate::derive_kek`].

use keyeo_crypto::{
    KdfParams, RECOVERY_ARGON2_ITERATIONS, RECOVERY_ARGON2_MEMORY_KIB, RECOVERY_ARGON2_PARALLELISM,
};

/// `KdfParams` for a recovery-code wrap (minimal cost) with the given `salt`.
pub fn recovery_kdf_params(salt: Vec<u8>) -> KdfParams {
    KdfParams {
        salt,
        memory_kib: RECOVERY_ARGON2_MEMORY_KIB,
        iterations: RECOVERY_ARGON2_ITERATIONS,
        parallelism: RECOVERY_ARGON2_PARALLELISM,
    }
}
