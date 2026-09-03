//! Proto-edge recovery wrapper: the wire `KdfParams` for a recovery-code wrap.
//!
//! The recovery code itself (generation, parsing, checksum) and its Argon2id cost constants live in
//! `keyeo_crypto::recovery` (openom-free) and are re-exported unchanged. This module owns only
//! [`recovery_kdf_params`], which builds the wire `openom_protocol::v1::KdfParams` from those costs — a
//! recovery wrap is otherwise an ordinary [`crate::wrap_dek`] under
//! `WRAP_METHOD_RECOVERY_CODE_ARGON2ID` with the KEK derived from the code's entropy via
//! [`crate::derive_kek`].

use keyeo_crypto::{RECOVERY_ARGON2_ITERATIONS, RECOVERY_ARGON2_MEMORY_KIB,
    RECOVERY_ARGON2_PARALLELISM};
use openom_protocol::v1::KdfParams;

/// `KdfParams` for a recovery-code wrap (minimal cost) with the given `salt`.
pub fn recovery_kdf_params(salt: Vec<u8>) -> KdfParams {
    KdfParams {
        salt,
        memory_kib: RECOVERY_ARGON2_MEMORY_KIB,
        iterations: RECOVERY_ARGON2_ITERATIONS,
        parallelism: RECOVERY_ARGON2_PARALLELISM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_kek, unwrap_dek, wrap_dek, WrapContext};
    use keyeo_crypto::{generate_dek, generate_recovery_code, generate_salt, parse_recovery_code};
    use openom_protocol::v1::WrapMethod;

    #[test]
    fn recovery_wrap_opens_the_dek() {
        // The recovery code is a genuine second door to the same DEK (§4).
        let dek = generate_dek().unwrap();
        let salt = generate_salt().unwrap().to_vec();
        let code = generate_recovery_code().unwrap();
        let params = recovery_kdf_params(salt);
        let ctx = WrapContext {
            tree_id: b"tree-uuid-16byte",
            key_id: b"epoch-0-key",
            member_id: "acct-1",
            wrap_method: WrapMethod::RecoveryCodeArgon2id as i32,
        };

        // Wrap under the recovery-code-derived KEK.
        let entropy = parse_recovery_code(&code).unwrap();
        let kek = derive_kek(entropy.as_slice(), &params).unwrap();
        let w = wrap_dek(&kek, &dek, &ctx).unwrap();

        // Later, from the code alone, recover the DEK.
        let entropy2 = parse_recovery_code(&code).unwrap();
        let kek2 = derive_kek(entropy2.as_slice(), &params).unwrap();
        let recovered = unwrap_dek(&kek2, &w.nonce, &w.wrapped_dek, &ctx).unwrap();
        assert_eq!(recovered.expose(), dek.expose());
    }
}
