# openom-keyring-chain

> openom's linear signed-chain keyring binding — keyring chain verification and signing on the generic
> `keyeo-linear` engine. The multi-member membership mechanism an E2EE tree's clients trust.

**Status:** built · access-control/membership mechanism, load-bearing · §B3 launch gate
**Last updated:** 2026-09-04

## What it is — and is not

The signed `Keyring` is the authoritative membership + role manifest for a tree, and this crate is the
**chain** binding of it: it decides whether a candidate keyring served by the network is a legitimate
successor of the one the client already trusts (anti-rollback, anti-fork, founder-or-unanimity on
signer-set changes, wrap-completeness), and it does the signing + signature-set verification that rests
on. Since OPE-300 the transition/walk/reset/bootstrap/governance/quorum LOGIC lives in the generic,
domain-neutral **`keyeo-linear`** engine (over `<Id, Role, Sig>`); this crate is the thin openom binding
that picks concrete types (`String` ids, an ordinal `ChainRole`, Ed25519), owns the openom **keyring
wire** (`wire.rs` — hand-written `prost` messages), and classes the engine's errors into the chain's own
taxonomy. The throughline: **the server is not the security boundary** — it can serve any bytes, but it
can't forge an Ed25519 signature — so every guarantee is a client-side check over signed wire data.

It is **openom-domain-specific but openom-dependency-free** (like `openom-keyring-dag`): it depends on the
generic `keyeo-linear`/`keyeo-core` engines, `openom-keyring-api` (the engine seam), `edsign`, and the
substrate crates (`prost`/`sha2`/`blobstore`), but on **no `openom-*` crate**. The keyring wire, formerly
in `openom-protocol`, now lives here in `wire.rs` (`Keyring` / `Member` / `KeyEpoch` / `KeyWrap` /
`RecoveryKey` / `KeyringSignature` + a wire-identical `KdfParams`).

Landed-entry authorship (`verify_entry` / `epoch_is_attributed`) is a *consumer* of the keyring and now
lives in `openom-vault` (OPE-300), not here.

## Usage

```rust
use openom_keyring_chain::{bootstrap_from_genesis, keyring_hash, sign_keyring, verify_transition, SigningKey};
use openom_keyring_chain::wire::{KeyEpoch, Keyring, KeyWrap, Member, WRAP_RRK_HPKE, WRAP_X25519_HPKE, MEMBER_OWNER};

// In production an identity is passphrase-derived; a fixed seed keeps this example deterministic.
let founder = SigningKey::from_seed(&[7u8; 32]);
let founder_key = founder.verifying_key().to_bytes().to_vec();
let wrap = |id: &str, method: i32| KeyWrap {
    member_id: id.into(),
    wrap_method: method,
    nonce: vec![],
    wrapped_dek: vec![1],
    kdf_params: None,
    ephemeral_public_key: vec![],
    recipient_public_key: vec![],
};

// A one-founder genesis keyring (revision 1), signed by the founder.
let mut genesis = Keyring {
    tree_id: b"tree-uuid-16byte".to_vec(),
    revision: 1,
    layout_version: 1,
    prev_keyring_hash: vec![],
    // The signer set is DERIVED from members: the OWNER-role member is the founder signer (OPE-309).
    members: vec![Member {
        member_id: "owner".into(),
        role: MEMBER_OWNER,
        author_public_key: founder_key,
        hpke_public_key: vec![9; 32],
    }],
    signatures: vec![],
    recovery_keys: vec![],
    epochs: vec![KeyEpoch { key_id: vec![0], epoch: 0, wraps: vec![wrap("owner", WRAP_RRK_HPKE)] }],
    ..Default::default()
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
    role: 4, // Editor
    author_public_key: vec![7; 32],
    hpke_public_key: vec![9; 32],
});
next.epochs[0].wraps.push(wrap("bob", WRAP_X25519_HPKE));
next.signatures.clear();
sign_keyring(&mut next, &founder);

let anchor = verify_transition(&anchor, &next).unwrap();
assert_eq!(anchor.revision, 2);
```

Entry points: `bootstrap_from_genesis` / `bootstrap_from_oob` (first-sight trust), `verify_transition` /
`verify_walk` (chain a candidate, or a contiguous run, onto an anchor), `verify_reset` (the
recovery/provision writer's self-check), and `sign_keyring` / `verify_keyring` / `verify_keyring_any` /
`keyring_hash` (the signing layer underneath; `generate_identity` is a `test-util`-gated helper). The
`ChainVerifier` (in `verifier`) is the keyless server-side `KeyringVerifier` seam; `blob_sync` is the
`blobstore` transport.

Run: `node scripts/cargo.mjs test -p openom-keyring-chain` (from the repo root; on Windows cargo runs under
WSL2/Docker).

## Position

Sits in the access-control/identity layer, on the generic `keyeo-linear` engine and the `openom-keyring-api`
seam, and below whatever holds keyring sync + trust storage (`openom-vault` / `openom-vault-host`, client
sync) and the server's own authz seam, which must enforce the identical capability mapping. Full dependency
graph: see `packages/README.md`.
