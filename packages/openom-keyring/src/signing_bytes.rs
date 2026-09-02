//! The chain keyring's canonical, domain-separated signing bytes (data-format spec §4) — the exact byte
//! string an authorized signer's Ed25519 key signs over a `Keyring`. This is the CHAIN engine's own wire
//! concern, so it lives here (openom-keyring), not in the shared wire-types crate (OPE-279). Same
//! branchless, length-prefixed, fixed-width discipline as the envelope AAD (see `openom_crypto::aad`), so a
//! Rust and a JS/WASM verifier agree byte-for-byte.

use openom_protocol::v1::{AuthorizedSigner, KeyEpoch, KeyWrap, Keyring, Member, RecoveryKey};

/// The canonical, domain-separated byte string an authorized signer's Ed25519 key
/// signs over the keyring (§4): every keyring field **except `signatures`**, length- and
/// count-prefixed so a signature can't be replayed onto a different keyring or another
/// structure. The `openom:keyring` tag separates this from the header/wrap AAD;
/// `layout_version` is first (after the tag) and is the sole version axis — a
/// fail-closed forward selector, like `Envelope.version` — so any future keyring layout
/// is byte-disjoint from this one. Covered: `revision`/`prev_keyring_hash` (anti-rollback
/// and history chain), the `authorized_signers` trust set, the `members` role/key manifest,
/// and the epochs/wraps. `signatures` is excluded, so every signer signs identical bytes
/// and their signatures collect independently.
#[deny(unused_variables)]
pub fn keyring_signing_bytes(keyring: &Keyring) -> Vec<u8> {
    // Exhaustive destructure (no `..`) + deny(unused): adding a Keyring/RecoveryKey/etc. field is a
    // compile error here until it is signed or explicitly excluded. This is the guard that would have
    // prevented the recovery_verifying_key signing-omission (OPE-277 crypto review). Byte order UNCHANGED.
    let Keyring {
        tree_id,
        epochs,
        revision,
        layout_version,
        prev_keyring_hash,
        authorized_signers,
        members,
        // `signatures` EXCLUDED by design: every signer signs identical bytes, so their signatures
        // collect independently — the one field that must NOT be in its own signed bytes.
        signatures: _,
        recovery_keys,
        governance_kind,
        governance_threshold,
    } = keyring;

    let mut out = Vec::with_capacity(256);
    put_bytes(&mut out, b"openom:keyring");
    put_u32(&mut out, *layout_version);
    put_bytes(&mut out, tree_id);
    put_u32(&mut out, *revision);
    put_bytes(&mut out, prev_keyring_hash);

    put_u32(&mut out, authorized_signers.len() as u32);
    for s in authorized_signers {
        let AuthorizedSigner { public_key, member_id, role } = s;
        put_bytes(&mut out, public_key);
        put_bytes(&mut out, member_id.as_bytes());
        put_u32(&mut out, *role as u32);
    }

    put_u32(&mut out, members.len() as u32);
    for m in members {
        let Member { member_id, role, author_public_key, hpke_public_key } = m;
        put_bytes(&mut out, member_id.as_bytes());
        put_u32(&mut out, *role as u32);
        put_bytes(&mut out, author_public_key);
        put_bytes(&mut out, hpke_public_key);
    }

    put_u32(&mut out, epochs.len() as u32);
    for ep in epochs {
        let KeyEpoch { key_id, epoch, wraps } = ep;
        put_bytes(&mut out, key_id);
        put_u32(&mut out, *epoch);
        put_u32(&mut out, wraps.len() as u32);
        for w in wraps {
            put_wrap(&mut out, w);
        }
    }

    put_u32(&mut out, recovery_keys.len() as u32);
    for rk in recovery_keys {
        // The RVK (recovery_verifying_key) MUST be signed — the omission the crypto review caught. The
        // destructure now makes forgetting it a compile error.
        let RecoveryKey { public_key, member_id, wraps, recovery_verifying_key } = rk;
        put_bytes(&mut out, public_key);
        put_bytes(&mut out, member_id.as_bytes());
        put_u32(&mut out, wraps.len() as u32);
        for w in wraps {
            put_wrap(&mut out, w);
        }
        put_bytes(&mut out, recovery_verifying_key);
    }
    // Governance rule — signed, so it's tamper-evident and a change to it is authorized like a set change.
    put_u32(&mut out, *governance_kind);
    put_u32(&mut out, *governance_threshold);
    out
}

/// Encode one `KeyWrap` into the keyring signing bytes: `member_id, wrap_method, nonce,
/// wrapped_dek`, then a branchless `kdf_params` (presence flag + four fields, zeros when
/// absent), then `ephemeral_public_key`. Shared by the epoch wraps and the recovery-key
/// wraps so the two never drift.
#[deny(unused_variables)]
fn put_wrap(out: &mut Vec<u8>, w: &KeyWrap) {
    // Exhaustive destructure (no `..`) + deny(unused): a new KeyWrap/KdfParams field can't slip out of
    // the signed/AAD wrap encoding by accident. Byte order UNCHANGED.
    //
    // `recipient_public_key` is DELIBERATELY excluded: it is a dag-only, unauthenticated coverage HINT
    // (OPE-290), not part of the chain's signed wrap encoding. The chain never reads it, and on the dag the
    // sealing payload is already integrity-protected by the op's content address — so signing it here would
    // buy nothing and would falsely imply it is authenticated (a wrap's real addressing is enforced by HPKE,
    // not this field). Keeping it out also leaves the signing byte order unchanged.
    let KeyWrap {
        member_id,
        wrap_method,
        nonce,
        wrapped_dek,
        kdf_params,
        ephemeral_public_key,
        recipient_public_key: _,
    } = w;
    put_bytes(out, member_id.as_bytes());
    put_u32(out, *wrap_method as u32);
    put_bytes(out, nonce);
    put_bytes(out, wrapped_dek);
    match kdf_params {
        Some(k) => {
            let openom_protocol::v1::KdfParams { salt, memory_kib, iterations, parallelism } = k;
            put_u32(out, 1);
            put_bytes(out, salt);
            put_u32(out, *memory_kib);
            put_u32(out, *iterations);
            put_u32(out, *parallelism);
        }
        None => {
            put_u32(out, 0);
            put_bytes(out, &[]);
            put_u32(out, 0);
            put_u32(out, 0);
            put_u32(out, 0);
        }
    }
    put_bytes(out, ephemeral_public_key);
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
/// 4-byte big-endian length prefix, then the bytes — the framing that defeats the
/// `"ab"+"c" == "a"+"bc"` forgery class (§5).
#[inline]
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_signing_bytes_binds_each_wrap_field() {
        // put_wrap encodes each KeyWrap field into the signed bytes; a changed wrap field must change
        // them (kills put_wrap being stubbed to a no-op, which would leave every wrap unbound).
        let kr = |member: &str, nonce: Vec<u8>, method: i32| Keyring {
            tree_id: vec![],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![],
            members: vec![],
            signatures: vec![],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![],
                epoch: 0,
                wraps: vec![KeyWrap {
                    member_id: member.into(),
                    wrap_method: method,
                    nonce,
                    wrapped_dek: vec![9; 48],
                    kdf_params: None,
                    ephemeral_public_key: vec![],
                    recipient_public_key: vec![],
                }],
            }],
            ..Default::default()
        };
        let base = keyring_signing_bytes(&kr("acct", vec![7; 24], 1));
        assert_ne!(base, keyring_signing_bytes(&kr("other", vec![7; 24], 1)), "wrap member_id bound");
        assert_ne!(base, keyring_signing_bytes(&kr("acct", vec![8; 24], 1)), "wrap nonce bound");
        assert_ne!(base, keyring_signing_bytes(&kr("acct", vec![7; 24], 2)), "wrap method bound");
    }

    #[test]
    fn keyring_signing_bytes_covers_and_ignores_signatures() {
        use openom_protocol::v1::{KdfParams, KeyringSignature};
        let mut kr = Keyring {
            tree_id: vec![0x11; 16],
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            authorized_signers: vec![AuthorizedSigner {
                public_key: vec![0xAB; 32],
                member_id: "acct".into(),
                role: 1, // FOUNDER
            }],
            members: vec![Member {
                member_id: "acct".into(),
                role: 1, // OWNER
                author_public_key: vec![],
                hpke_public_key: vec![],
            }],
            // must NOT affect the signed bytes
            signatures: vec![KeyringSignature {
                signer_public_key: vec![0xAB; 32],
                signature: vec![0xFF; 64],
            }],
            recovery_keys: vec![],
            epochs: vec![KeyEpoch {
                key_id: vec![1, 2, 3],
                epoch: 0,
                wraps: vec![KeyWrap {
                    member_id: "acct".into(),
                    wrap_method: 1,
                    nonce: vec![7; 24],
                    wrapped_dek: vec![9; 48],
                    kdf_params: Some(KdfParams {
                        salt: vec![5; 16],
                        memory_kib: 19456,
                        iterations: 2,
                        parallelism: 1,
                    }),
                    ephemeral_public_key: vec![],
                    recipient_public_key: vec![],
                }],
            }],
            ..Default::default()
        };
        let a = keyring_signing_bytes(&kr);
        kr.signatures[0].signature = vec![0x00; 64];
        kr.signatures.push(KeyringSignature {
            signer_public_key: vec![1; 32],
            signature: vec![2; 64],
        });
        assert_eq!(a, keyring_signing_bytes(&kr), "signatures are excluded from signed bytes");
        kr.revision = 2;
        assert_ne!(a, keyring_signing_bytes(&kr), "revision is covered (anti-rollback)");

        // The signer set, the member/role manifest, and the history-chain link are covered.
        let mut set_change = kr.clone();
        set_change.revision = 1;
        set_change.authorized_signers[0].role = 2; // FOUNDER -> CO_OWNER
        assert_ne!(a, keyring_signing_bytes(&set_change), "authorized_signers are covered");
        let mut role_change = kr.clone();
        role_change.revision = 1;
        role_change.members[0].role = 4; // OWNER -> EDITOR
        assert_ne!(a, keyring_signing_bytes(&role_change), "members are covered");
        let mut chained = kr.clone();
        chained.revision = 1;
        chained.prev_keyring_hash = vec![0x77; 32];
        assert_ne!(a, keyring_signing_bytes(&chained), "prev_keyring_hash is covered");

        // The recovery verifying key (RVK) is covered — an untrusted server must not be able to
        // substitute OR blank it undetectably, or the reset-authorization gate that trusts it is defeated
        // (OPE-277 crypto review).
        let mut with_rvk = kr.clone();
        with_rvk.revision = 1;
        with_rvk.recovery_keys = vec![RecoveryKey {
            public_key: vec![0x22; 32],
            member_id: "acct".into(),
            wraps: vec![],
            recovery_verifying_key: vec![0xAA; 32],
        }];
        let with = keyring_signing_bytes(&with_rvk);
        let mut swapped = with_rvk.clone();
        swapped.recovery_keys[0].recovery_verifying_key = vec![0xBB; 32];
        assert_ne!(with, keyring_signing_bytes(&swapped), "recovery_verifying_key substitution is covered");
        let mut blanked = with_rvk.clone();
        blanked.recovery_keys[0].recovery_verifying_key = vec![];
        assert_ne!(with, keyring_signing_bytes(&blanked), "recovery_verifying_key blanking is covered");
    }

    #[test]
    fn keyring_signing_bytes_layout_version_disjoint() {
        let mut kr = Keyring {
            tree_id: vec![1; 16],
            revision: 1,
            layout_version: 1,
            ..Default::default()
        };
        let v1 = keyring_signing_bytes(&kr);
        kr.layout_version = 2;
        assert_ne!(v1, keyring_signing_bytes(&kr), "layout_version must make signing bytes disjoint");
    }
}
