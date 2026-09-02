//! Fuzz surface for the vault: it decodes untrusted keyring bytes from a partly-trusted server, so
//! `unlock`/`recover` on ARBITRARY bytes must never panic — only ever return an error. (Random bytes never
//! form a keyring that finds a wrap for this member, so these return before any Argon2id runs — cheap.)

use openom_crypto::{Passphrase, RecoveryCode};
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_vault::vault::{recover, unlock};
use proptest::prelude::*;

proptest! {
    #[test]
    fn unlock_on_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let r = unlock(
            &bytes,
            &Passphrase::new(b"pass".to_vec()),
            &TreeId::new(b"tree-uuid-16byte".as_slice()),
            &MemberId::new("acct-1"),
            &ReplicaId::new(b"replica-0".as_slice()),
        );
        prop_assert!(r.is_err());
    }

    #[test]
    fn recover_on_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let r = recover(
            &bytes,
            &RecoveryCode::new("some-code"),
            &Passphrase::new(b"pass".to_vec()),
            &TreeId::new(b"tree-uuid-16byte".as_slice()),
            &MemberId::new("acct-1"),
            &ReplicaId::new(b"replica-0".as_slice()),
            0,
            &[],
            &[],
        );
        prop_assert!(r.is_err());
    }
}
