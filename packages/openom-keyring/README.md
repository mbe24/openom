# openom-keyring

> Keyring chain verification, landed-entry authorship, and keyring signing — the multi-member membership mechanism an E2EE tree's clients trust.

**Status:** built · access-control/membership mechanism, load-bearing · §B3 launch gate
**Last updated:** 2026-08-25

## What it is — and is not

The signed `Keyring` is the authoritative membership + role manifest for a tree, and this crate is
where enforcing it lives, in three parts: **`chain`** decides whether a candidate keyring served by
the network is a legitimate successor of the one the client already trusts (anti-rollback,
anti-fork, founder-or-unanimity on signer-set changes, wrap-completeness); **`entry`** decides
whether a landed delta/snapshot/proposal was authored by a member who held the required capability
*at the keyring revision that governed it*; **`keyring`** does the signing and signature-set
verification both of those rest on. The throughline is that **the server is not the security
boundary** — it can serve any bytes it likes, but it can't forge an Ed25519 signature — so every
guarantee here is a client-side check over signed wire data, never a promise taken on trust from
the transport.

It is **not** the wire format (that's `openom-protocol`, whose `Keyring`/`Header` types and
canonical signing-byte encoders it consumes) and not the key-wrapping crypto that seals a DEK to a
member (`openom-crypto`, used elsewhere) — this crate only answers "is this keyring a legitimate
successor" and "did an authorized member sign this." It does not persist trust state: the caller
owns the anchor store and rebuilds it via `KeyringAnchor::from_keyring`. And it does not decide on
its own whether an unattributed entry is acceptable — `epoch_is_attributed` derives that from the
*verified* keyring, and the caller applies it; an entry can never assert its own attribution, or a
keyless hostile server could downgrade an attributed epoch to skip the check.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **KEYRING-1** | A candidate keyring must advance the revision by exactly one and chain onto the anchor's hash — a skip, replay, or rewritten history is rejected, not just a wrong-signature. | A withheld hop or forked history becomes evidence, never silent acceptance. | `chain::tests::rollback_fork_and_gap_are_distinct_errors`, `chain::tests::bootstrap_and_walk` |
| **KEYRING-2** | Founder-or-unanimity: an ordinary revision needs any prior authorized signer; a signer-set change needs the *prior* founder's signature or unanimity of the *prior* set — never the candidate's own claimed set — with a narrow self-removal carve-out (a lone co-owner may remove only themselves). | Stops a rogue signer from adding itself and self-authorizing, or a mutineer bundling a self-removal with someone else's. | `chain::tests::founder_gated_set_changes`, `chain::tests::rogue_signer_injection_is_rejected`, `chain::tests::co_owner_can_remove_themselves_but_not_bundle_others`, `chain::tests::founder_key_rotation_needs_the_old_key`, `chain::tests::verify_transition_matches_the_oracle` (differential proptest oracle) |
| **KEYRING-3** | Structural well-formedness: exactly one founder, and every authorized signer must be a member whose `author_public_key` matches the signer key — no ghost signers. | A signature-valid-but-structurally-broken keyring (two founders, an unaffiliated signer) can't slip through. | `chain::tests::a_signer_who_is_not_a_member_is_structural_reject`, `chain::tests::wrap_incompleteness_and_double_founder_are_rejected` |
| **KEYRING-4** | Wrap-completeness: in the newest epoch, the founder must be reachable via a recovery-root wrap and every other member via their own HPKE wrap, or the transition is refused. | Blocks a signature-valid revision that rotates the epoch key but wraps it to only a subset — a silent lock-out. | `chain::tests::wrap_incompleteness_and_double_founder_are_rejected` |
| **KEYRING-5** | First-sight trust has exactly two roots: `bootstrap_from_genesis` (the founder's own key over a revision-1 keyring) or `bootstrap_from_oob` (an out-of-band pinned `(revision, hash)`) — never an unauthenticated first keyring. | Closes the §10 first-sight gap without inventing a third, weaker trust path. | `chain::tests::bootstrap_and_walk` |
| **KEYRING-6** | `verify_reset` is deliberately **not** a chain transition: it accepts a keyring that is structurally sound, wrap-complete, and self-signed by one of its own current signers, with no link to a prior anchor — so a recovery reset under a fresh founder identity succeeds where `verify_transition` on the same bytes would reject it as unendorsed. | The recovery/provision writer's self-check has to differ from the reader's chain check by design, not by accident. | `chain::tests::verify_reset_accepts_a_genesis_and_a_reset_but_not_an_unsigned_one` |
| **KEYRING-7** | `verify_entry` accepts only if: the author is a member at the *governing* revision, their signature verifies over the content-bound message, the sealing epoch is the governing revision's newest epoch (closing the "seal under the current key, stamp an old revision" forge), and their role meets the entry kind's required role. | Makes roles a real cryptographic guarantee rather than a server-enforced promise. | `entry::tests::accepts_a_maintainer_commit`, `entry::tests::rejects_an_editor_commit_but_accepts_their_proposal`, `entry::tests::rejects_tampered_plaintext`, `entry::tests::rejects_wrong_signer`, `entry::tests::rejects_unknown_author`, `entry::tests::rejects_epoch_mismatch_seal_under_current_key_stamp_old_revision`, `entry::tests::seal_envelope_round_trips_through_verify_entry` |
| **KEYRING-8** | An entry with an empty `author_signature` is rejected by `verify_entry`; whether an epoch tolerates that at all (`epoch_is_attributed`) is derived from the verified keyring's key-wrap membership, never from the entry's own claim. | An entry can't assert its own unattributed status — only the DEK's wrap targets in the verified keyring can. | `entry::tests::rejects_unattributed`, `entry::tests::epoch_attribution_tracks_who_the_dek_is_wrapped_to` |
| **KEYRING-9** | A keyring's signatures cover its full content (revision, signer set, members, wraps) but exclude the `signatures` field itself: any tampering after signing — role, wrapped key, revision — invalidates every signature, and the chain hash tracks content the same way. | The signature and the chain hash are exactly as tamper-evident as the fields they cover, no more and no less. | `keyring::tests::tampering_after_signing_is_detected`, `keyring::tests::keyring_hash_changes_with_content_and_ignores_signatures` |

Run: `node scripts/cargo.mjs test -p openom-keyring` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Usage

```rust
use openom_keyring::{bootstrap_from_genesis, keyring_hash, sign_keyring, verify_transition, SigningKey};
use openom_protocol::v1::{
    AuthorizedSigner, KeyEpoch, Keyring, KeyWrap, Member, MemberRole, SignerRole, WrapMethod,
};

// In production an identity is passphrase-derived (openom_crypto::derive_root); a fixed seed keeps this
// example deterministic.
let founder = SigningKey::from_seed(&[7u8; 32]);
let founder_key = founder.verifying_key().to_bytes().to_vec();
let wrap = |id: &str, method: WrapMethod| KeyWrap {
    member_id: id.into(),
    wrap_method: method as i32,
    nonce: vec![],
    wrapped_dek: vec![1],
    kdf_params: None,
    ephemeral_public_key: vec![],
};

// A one-founder genesis keyring (revision 1), signed by the founder.
let mut genesis = Keyring {
    tree_id: b"tree-uuid-16byte".to_vec(),
    revision: 1,
    layout_version: 1,
    prev_keyring_hash: vec![],
    authorized_signers: vec![AuthorizedSigner {
        public_key: founder_key.clone(),
        member_id: "owner".into(),
        role: SignerRole::Founder as i32,
    }],
    members: vec![Member {
        member_id: "owner".into(),
        role: MemberRole::Owner as i32,
        author_public_key: founder_key,
        hpke_public_key: vec![9; 32],
    }],
    signatures: vec![],
    recovery_keys: vec![],
    epochs: vec![KeyEpoch {
        key_id: vec![0],
        epoch: 0,
        wraps: vec![wrap("owner", WrapMethod::RrkHpke)],
    }],
};
sign_keyring(&mut genesis, &founder);

// First sight: the founder bootstraps trust from their own key, no prior anchor needed.
let anchor = bootstrap_from_genesis(&genesis, &founder.verifying_key()).unwrap();
assert_eq!(anchor.revision, 1);

// A successor revision: bump, chain the hash, add a member, re-sign, verify against the anchor.
let mut next = genesis.clone();
next.revision = 2;
next.prev_keyring_hash = keyring_hash(&genesis).to_vec();
next.members.push(Member {
    member_id: "bob".into(),
    role: MemberRole::Editor as i32,
    author_public_key: vec![7; 32],
    hpke_public_key: vec![9; 32],
});
next.epochs[0].wraps.push(wrap("bob", WrapMethod::X25519Hpke));
next.signatures.clear();
sign_keyring(&mut next, &founder);

let anchor = verify_transition(&anchor, &next).unwrap();
assert_eq!(anchor.revision, 2);
```

Entry points: `bootstrap_from_genesis` / `bootstrap_from_oob` (first-sight trust),
`verify_transition` / `verify_walk` (chain a candidate, or a contiguous run, onto an anchor),
`verify_reset` (the recovery/provision writer's self-check), `verify_entry` /
`epoch_is_attributed` (landed-entry authorship), and `sign_keyring` / `verify_keyring` /
`verify_keyring_any` / `verify_keyring_all` / `keyring_hash` (the signing layer underneath all of it;
`generate_identity` is a `test-util`-gated random-identity helper, not a production path).

## Position

Sits in the access-control/identity layer, above the substrate (`openom-protocol` for wire types,
`openom-crypto` for the shared error type, `openom-roles` for the capability→role policy) and below
whatever holds keyring sync + trust storage (client sync, `openom-vault-host`) and the server's own
authz seam, which must enforce the identical capability mapping. Full dependency graph: see
`packages/README.md`.
