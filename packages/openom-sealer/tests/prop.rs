//! Property + fuzz-style tests for the sealer core. Beyond the plain round-trip, these pin
//! the scope/kind guards (a blob for another tree or of another kind is refused before the
//! AEAD) and the fuzz surface: opening arbitrary bytes never panics — it returns an error.

use openom_crypto::{Passphrase, RecoveryCode};
use openom_protocol::ids::{KeyId, MemberId, ReplicaId, TreeId};
use openom_protocol::v1::{Compression, Format};
use openom_sealer::vault::{recover, unlock};
use openom_sealer::{EntryKind, SealContext, Sealer, SealerError};
use proptest::prelude::*;

fn sealer(tree: &[u8]) -> Sealer {
    Sealer::from_unwrapped(
        1,
        openom_crypto::generate_dek().unwrap().into_inner(),
        TreeId::new(tree),
        KeyId::new(b"epoch-0".to_vec()),
        ReplicaId::new(b"replica-0".to_vec()),
    )
}

fn ctx(kind: EntryKind, counter: u64) -> SealContext {
    SealContext {
        kind,
        format: Format::OpenomJson,
        compression: Compression::None,
        replica_counter: counter,
        prev_ciphertext_hash: Vec::new(),
        covers_through_seq: 0,
        blob_id: Vec::new(),
    }
}

fn kind() -> impl Strategy<Value = EntryKind> {
    prop_oneof![
        Just(EntryKind::Snapshot),
        Just(EntryKind::Delta),
        Just(EntryKind::Media),
    ]
}

proptest! {
    #[test]
    fn seal_open_round_trips(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        counter in any::<u64>(),
        kind in kind(),
    ) {
        let s = sealer(b"tree-uuid-16byte");
        let out = s.seal_entry(&ctx(kind, counter), &plaintext).unwrap();
        prop_assert_eq!(s.open_entry(kind, &out.envelope).unwrap(), plaintext);
    }

    #[test]
    fn opening_arbitrary_bytes_errors_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        kind in kind(),
    ) {
        let s = sealer(b"tree-uuid-16byte");
        // Random bytes are never a valid sealed entry for this scope — an error, not a panic.
        prop_assert!(s.open_entry(kind, &bytes).is_err());
    }

    #[test]
    fn another_trees_blob_is_rejected(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let a = sealer(b"tree-uuid-16byte");
        let b = sealer(b"other-tree-16byt");
        let out = a.seal_entry(&ctx(EntryKind::Snapshot, 0), &plaintext).unwrap();
        prop_assert!(matches!(
            b.open_entry(EntryKind::Snapshot, &out.envelope),
            Err(SealerError::WrongScope)
        ));
    }

    #[test]
    fn the_wrong_kind_is_rejected(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let s = sealer(b"tree-uuid-16byte");
        let out = s.seal_entry(&ctx(EntryKind::Snapshot, 0), &plaintext).unwrap();
        prop_assert!(matches!(
            s.open_entry(EntryKind::Delta, &out.envelope),
            Err(SealerError::WrongKind)
        ));
    }

    // The vault decodes untrusted keyring bytes from a partly-trusted server; that must never
    // panic — only ever Err. (Random bytes never form a keyring that finds a wrap for this
    // member, so these return before any Argon2id runs — the fuzz stays cheap.)
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
        );
        prop_assert!(r.is_err());
    }
}
