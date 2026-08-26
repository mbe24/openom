//! Landed-entry author verification — the client-side write boundary (§B3 launch gate).
//!
//! On a shared tree, before folding a peer's entry (delta / snapshot / proposal / media) into local
//! state, the client verifies it was authored by a member who held the required capability **in the
//! keyring revision that governed the entry when it was authored**. This is what makes roles a real
//! guarantee rather than a server promise (the server is not the security boundary, §0): a curious or
//! hostile server can serve any bytes, but it can't forge a member's Ed25519 author signature.
//!
//! The capability→role mapping mirrors the server's authz seam (both enforce; they must agree). B+
//! epoch-consistency closes the "seal under the current key, stamp an old revision" forge; the
//! retained-old-key variant is the documented residual left for the full-A log-frontier slice.

use ed25519_dalek::{Signature, VerifyingKey};
use openom_protocol::aad::author_signing_bytes;
use openom_protocol::v1::{Header, Keyring, Kind};
use openom_roles::{required_role_for_kind, SIGNER_FOUNDER};
use sha2::{Digest, Sha256};

/// Why a landed entry's author attribution was refused. One variant per check, so the client can react
/// (retry vs alarm) and each gets a negative test.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    #[error("entry carries no author_signature (unattributed) on a tree that requires signatures")]
    Unattributed,
    #[error("entry kind cannot be role-gated")]
    UnsupportedKind,
    #[error("the sealing epoch (key_id) is not the newest at the governing keyring revision")]
    EpochMismatch,
    #[error("author_member_id is not a member at the governing keyring revision")]
    UnknownAuthor,
    #[error("the author's public key is missing or malformed")]
    BadAuthorKey,
    #[error("author_signature does not verify over the entry")]
    BadSignature,
    #[error("the author's role does not grant this entry's capability")]
    InsufficientRole,
}

/// Verify a landed entry's author attribution against `governing` — the keyring at
/// `header.keyring_revision`, which the caller fetches and chain-verifies (the foundation's keyring
/// sync). `plaintext` is the AEAD-opened payload (verification runs after open — the AEAD tag has already
/// authenticated the header, including `author_signature`, against this exact ciphertext). `Ok(())` iff a
/// member with sufficient role for `header.kind` validly signed the entry at the governing revision.
///
/// The caller decides separately whether an *unattributed* entry (empty `author_signature`) is acceptable
/// — that's a per-epoch property of the verified keyring, not something this function can judge from the
/// entry alone (a hostile server must never be able to downgrade to "unattributed").
pub fn verify_entry(
    version: u32,
    header: &Header,
    plaintext: &[u8],
    governing: &Keyring,
) -> Result<(), EntryError> {
    if header.author_signature.is_empty() {
        return Err(EntryError::Unattributed);
    }
    let kind = Kind::try_from(header.kind).map_err(|_| EntryError::UnsupportedKind)?;
    let required = required_role_for_kind(kind).ok_or(EntryError::UnsupportedKind)?;

    // B+ epoch-consistency: the sealing epoch must be the newest at the governing revision. Closes the
    // "seal under the CURRENT key, stamp an OLD revision" forge (the current key belongs to a newer epoch
    // than any old revision, so it won't match that revision's newest epoch).
    let newest = governing
        .epochs
        .iter()
        .max_by_key(|e| e.epoch)
        .ok_or(EntryError::EpochMismatch)?;
    if newest.key_id != header.key_id {
        return Err(EntryError::EpochMismatch);
    }

    // The claimed author must be a member at the governing revision; verify against THAT key + role.
    let member = governing
        .members
        .iter()
        .find(|m| m.member_id == header.author_member_id)
        .ok_or(EntryError::UnknownAuthor)?;
    let key_bytes: [u8; 32] = member
        .author_public_key
        .as_slice()
        .try_into()
        .map_err(|_| EntryError::BadAuthorKey)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| EntryError::BadAuthorKey)?;
    let sig_bytes: [u8; 64] = header
        .author_signature
        .as_slice()
        .try_into()
        .map_err(|_| EntryError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let plaintext_hash = Sha256::digest(plaintext);
    let msg = author_signing_bytes(version, header, plaintext_hash.as_slice());
    // verify_strict, not verify: reject small-order / torsion author keys — defense in depth matching
    // the claim signing path, since a member's author key comes from the (shared, attacker-influenced)
    // keyring.
    key.verify_strict(&msg, &signature)
        .map_err(|_| EntryError::BadSignature)?;

    // Role (numeric, lower = stronger): the author's role must be at least as strong as required.
    if member.role > required as i32 {
        return Err(EntryError::InsufficientRole);
    }
    Ok(())
}

/// Whether the epoch identified by `key_id` is **attributed** — its DEK was wrapped to someone besides
/// the sole founder (a co-owner or an ordinary member), i.e. the tree is shared under this epoch. Entries
/// under an attributed epoch MUST carry a valid `author_signature` (see [`verify_entry`]); entries under
/// an unattributed epoch — a solo owner's own epoch, wrapped only to the founder — may be unattributed
/// (V1's communal-DEK history stays valid). The decision is derived from the VERIFIED keyring, never from
/// an entry's own (server-visible, forgeable) emptiness — so a keyless hostile server can't downgrade an
/// attributed epoch to "looks unattributed, skip the check" (the §B3 downgrade attack). `key_id` is
/// AAD-bound, so a forger can't lie about which epoch they sealed under either.
pub fn epoch_is_attributed(keyring: &Keyring, key_id: &[u8]) -> bool {
    let founder = keyring
        .authorized_signers
        .iter()
        .find(|s| s.role == SIGNER_FOUNDER)
        .map(|s| &s.member_id);
    keyring
        .epochs
        .iter()
        .filter(|e| e.key_id == key_id)
        .any(|e| e.wraps.iter().any(|w| Some(&w.member_id) != founder))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity, SigningKey};
    use ed25519_dalek::Signer;
    use openom_protocol::v1::{KeyEpoch, Member, MemberRole, SignerRole};

    const KID: &[u8] = b"epoch-key-0";
    const VERSION: u32 = 1;

    fn member(id: &str, role: MemberRole, author: &SigningKey) -> Member {
        Member {
            member_id: id.into(),
            role: role as i32,
            author_public_key: author.verifying_key().to_bytes().to_vec(),
            hpke_public_key: vec![9; 32],
        }
    }

    /// A governing keyring whose newest epoch uses KID and whose members are as given.
    fn governing(members: Vec<Member>) -> Keyring {
        Keyring {
            tree_id: vec![1; 16],
            revision: 3,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![],
            members,
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: KID.to_vec(),
                epoch: 0,
                wraps: vec![],
            }],
        }
    }

    /// A header authored by `author_id` under KID, stamped at the governing revision, signed by `key`.
    fn signed(kind: Kind, author_id: &str, key: &SigningKey, plaintext: &[u8]) -> Header {
        let mut h = Header {
            kind: kind as i32,
            aead: openom_protocol::v1::Aead::Xchacha20Poly1305 as i32,
            key_id: KID.to_vec(),
            tree_id: vec![1; 16],
            replica_id: vec![2; 4],
            replica_counter: 1,
            author_member_id: author_id.into(),
            keyring_revision: 3,
            ..Default::default()
        };
        let msg = author_signing_bytes(VERSION, &h, Sha256::digest(plaintext).as_slice());
        h.author_signature = key.sign(&msg).to_bytes().to_vec();
        h
    }

    #[test]
    fn accepts_a_maintainer_commit() {
        let k = generate_identity().unwrap();
        let kr = governing(vec![member("m1", MemberRole::Admin, &k)]);
        let h = signed(Kind::Delta, "m1", &k, b"payload");
        assert_eq!(verify_entry(VERSION, &h, b"payload", &kr), Ok(()));
    }

    #[test]
    fn rejects_an_editor_commit_but_accepts_their_proposal() {
        let k = generate_identity().unwrap();
        let kr = governing(vec![member("e1", MemberRole::Editor, &k)]);
        assert_eq!(
            verify_entry(VERSION, &signed(Kind::Delta, "e1", &k, b"x"), b"x", &kr),
            Err(EntryError::InsufficientRole)
        );
        assert_eq!(
            verify_entry(VERSION, &signed(Kind::Proposal, "e1", &k, b"x"), b"x", &kr),
            Ok(())
        );
    }

    #[test]
    fn rejects_tampered_plaintext() {
        let k = generate_identity().unwrap();
        let kr = governing(vec![member("m1", MemberRole::Admin, &k)]);
        let h = signed(Kind::Delta, "m1", &k, b"original");
        assert_eq!(
            verify_entry(VERSION, &h, b"tampered", &kr),
            Err(EntryError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_signer() {
        let real = generate_identity().unwrap();
        let mallory = generate_identity().unwrap();
        // Keyring says m1's key is `real`, but the entry was signed by `mallory` claiming to be m1.
        let kr = governing(vec![member("m1", MemberRole::Admin, &real)]);
        let h = signed(Kind::Delta, "m1", &mallory, b"x");
        assert_eq!(
            verify_entry(VERSION, &h, b"x", &kr),
            Err(EntryError::BadSignature)
        );
    }

    #[test]
    fn rejects_unknown_author() {
        let k = generate_identity().unwrap();
        let kr = governing(vec![member("m1", MemberRole::Admin, &k)]);
        let h = signed(Kind::Delta, "ghost", &k, b"x");
        assert_eq!(
            verify_entry(VERSION, &h, b"x", &kr),
            Err(EntryError::UnknownAuthor)
        );
    }

    #[test]
    fn rejects_epoch_mismatch_seal_under_current_key_stamp_old_revision() {
        // The B+ core: a demoted member seals under a *different* (current) key but stamps this old
        // governing revision, whose newest epoch is KID. The mismatch is caught before any role lookup.
        let k = generate_identity().unwrap();
        let kr = governing(vec![member("m1", MemberRole::Admin, &k)]);
        let mut h = signed(Kind::Delta, "m1", &k, b"x");
        h.key_id = b"a-newer-epoch-key".to_vec();
        h.author_signature = k
            .sign(&author_signing_bytes(
                VERSION,
                &h,
                Sha256::digest(b"x").as_slice(),
            ))
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify_entry(VERSION, &h, b"x", &kr),
            Err(EntryError::EpochMismatch)
        );
    }

    #[test]
    fn rejects_unattributed() {
        let kr = governing(vec![]);
        let h = Header {
            kind: Kind::Delta as i32,
            key_id: KID.to_vec(),
            ..Default::default()
        };
        assert_eq!(
            verify_entry(VERSION, &h, b"x", &kr),
            Err(EntryError::Unattributed)
        );
    }

    #[test]
    fn seal_envelope_round_trips_through_verify_entry() {
        // The cross-crate round-trip: openom-crypto seals + signs the entry, this crate verifies it.
        // (Lives here, not in openom-crypto, because verify_entry moved out and openom-keyring is the only
        // crate that can depend on both directions.)
        use openom_crypto::{
            generate_dek, open_envelope, seal_envelope, AuthorContext, SealParams,
        };
        use openom_protocol::v1::{Aead, Compression, Format};

        let dek = generate_dek().unwrap();
        let author = generate_identity().unwrap();
        let params = SealParams {
            version: VERSION,
            kind: Kind::Delta,
            format: Format::OpenomTreelog,
            aead: Aead::Xchacha20Poly1305,
            compression: Compression::None,
            key_id: KID,
            tree_id: b"tree-uuid-16byte",
            replica_id: b"r",
            replica_counter: 1,
            prev_ciphertext_hash: b"",
            covers_through_seq: 0,
            blob_id: b"",
            author: Some(AuthorContext {
                signing_key: &author,
                member_id: "m1",
                keyring_revision: 3,
            }),
        };
        let env = seal_envelope(dek.expose(), &params, b"a change").unwrap();
        let header = env.header.as_ref().unwrap();
        assert!(!header.author_signature.is_empty(), "signed");
        assert_eq!(header.author_member_id, "m1");
        assert_eq!(header.keyring_revision, 3);

        // A governing keyring at rev 3 whose newest epoch is KID and where m1 is a Maintainer.
        let kr = governing(vec![member("m1", MemberRole::Admin, &author)]);
        let plaintext = open_envelope(dek.expose(), &env).unwrap();
        assert_eq!(
            verify_entry(VERSION, header, &plaintext, &kr),
            Ok(()),
            "the sealed entry verifies"
        );
        // A different plaintext against the same signature → rejected (content binding).
        assert_eq!(
            verify_entry(VERSION, header, b"tampered", &kr),
            Err(EntryError::BadSignature)
        );
    }

    #[test]
    fn epoch_attribution_tracks_who_the_dek_is_wrapped_to() {
        use openom_protocol::v1::{AuthorizedSigner, KeyWrap};
        let wrap = |id: &str| KeyWrap {
            member_id: id.into(),
            wrap_method: 0,
            nonce: vec![],
            wrapped_dek: vec![1],
            kdf_params: None,
            ephemeral_public_key: vec![],
        };
        let founder = AuthorizedSigner {
            public_key: vec![0; 32],
            member_id: "owner".into(),
            role: SignerRole::Founder as i32,
        };
        let mk = |wraps: Vec<KeyWrap>| Keyring {
            tree_id: vec![],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![founder.clone()],
            members: vec![],
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: KID.to_vec(),
                epoch: 0,
                wraps,
            }],
        };
        // Solo owner: the epoch's DEK is wrapped only to the founder → unattributed (V1 history stays valid).
        assert!(!epoch_is_attributed(&mk(vec![wrap("owner")]), KID));
        // Shared: a wrap to any non-founder member → attributed (entries must be signed).
        assert!(epoch_is_attributed(
            &mk(vec![wrap("owner"), wrap("editor-1")]),
            KID
        ));
        // An unknown key_id has no matching epoch → not attributed.
        assert!(!epoch_is_attributed(
            &mk(vec![wrap("owner"), wrap("editor-1")]),
            b"no-such-key"
        ));
    }
}
