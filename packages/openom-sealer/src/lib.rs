#![doc = include_str!("../README.md")]

use openom_crypto::{open_envelope, seal_envelope, CryptoError, Key32};
use openom_protocol::ids::{KeyId, ReplicaId, TreeId};
use openom_protocol::v1::{Aead, Compression, Envelope, Format, Header, Kind};
use openom_protocol::Message;

pub mod vault;
mod vault_core;

pub mod lifecycle;
pub use lifecycle::{ChainVault, KeyringLifecycle, VaultContext};

#[cfg(feature = "wasm")]
pub mod wasm;

/// The kind of log entry being sealed — the sealer's view of `Kind` (§3), without the
/// proto's `Unspecified` zero value that must never reach the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A full tree snapshot.
    Snapshot,
    /// An incremental delta over a prior snapshot (V2 payload; the envelope is ready now).
    Delta,
    /// An encrypted media blob (photo/document), uploaded out-of-band and referenced by
    /// `blob_id`.
    Media,
    /// A staged bundle of edits awaiting approval — sealed under the tree DEK but kept in a
    /// separate proposals channel, never on the append/log path.
    Proposal,
}

impl EntryKind {
    fn to_proto(self) -> Kind {
        match self {
            EntryKind::Snapshot => Kind::Snapshot,
            EntryKind::Delta => Kind::Delta,
            EntryKind::Media => Kind::Media,
            EntryKind::Proposal => Kind::Proposal,
        }
    }

    fn from_proto(k: i32) -> Option<Self> {
        match Kind::try_from(k).ok()? {
            Kind::Snapshot => Some(EntryKind::Snapshot),
            Kind::Delta => Some(EntryKind::Delta),
            Kind::Media => Some(EntryKind::Media),
            Kind::Proposal => Some(EntryKind::Proposal),
            Kind::Unspecified => None,
        }
    }
}

/// The per-entry chain state the caller supplies for a single [`Sealer::seal_entry`].
///
/// Everything here is owned by the caller (JS/Tauri), not the sealer — see the module
/// docs. `format`/`compression` describe how the *caller* already prepared the plaintext
/// (the sealer seals bytes as-given and only records the labels; zstd stays out of this
/// crate). `blob_id` is meaningful for [`EntryKind::Media`] and empty otherwise.
pub struct SealContext {
    pub kind: EntryKind,
    pub format: Format,
    pub compression: Compression,
    /// Monotonic per-replica sequence (§8). The caller advances it; the sealer records it.
    pub replica_counter: u64,
    /// `ciphertext_hash` of the previous entry in this replica's chain — empty for the
    /// first. Returned by the prior [`seal_entry`]; the caller threads it through.
    pub prev_ciphertext_hash: Vec<u8>,
    /// The snapshot coordinate this entry covers through (§10 watermark input).
    pub covers_through_seq: u64,
    /// KIND_MEDIA only; empty otherwise.
    pub blob_id: Vec<u8>,
}

impl SealContext {
    /// A snapshot at the chain head — the common case. `format` defaults to openom-json,
    /// uncompressed; adjust the fields for compressed payloads or media.
    pub fn snapshot(
        replica_counter: u64,
        prev_ciphertext_hash: Vec<u8>,
        covers_through_seq: u64,
    ) -> Self {
        SealContext {
            kind: EntryKind::Snapshot,
            format: Format::OpenomJson,
            compression: Compression::None,
            replica_counter,
            prev_ciphertext_hash,
            covers_through_seq,
            blob_id: Vec::new(),
        }
    }
}

/// The result of sealing one entry: the complete, wire-ready envelope bytes to upload,
/// and the `ciphertext_hash` the caller persists as the next entry's `prev`.
pub struct SealOutcome {
    /// The prost-encoded [`Envelope`], ready for `RemoteStore.put`.
    pub envelope: Vec<u8>,
    /// `SHA-256(ciphertext)` of this envelope — the chain link for the next `seal_entry`,
    /// and the id under which the server addresses this blob.
    pub ciphertext_hash: Vec<u8>,
}

/// A crypto/format failure. The `Crypto(Open)` case is intentionally opaque (bad key,
/// tag, nonce, or tampered header all look alike); the scope/kind cases fail *before*
/// the AEAD so a misrouted blob gets a precise error instead of a generic auth failure.
#[derive(Debug, thiserror::Error)]
pub enum SealerError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// The bytes weren't a valid `Envelope` (`prost` decode failed).
    #[error("malformed envelope: {0}")]
    Decode(String),
    /// The envelope carried no header.
    #[error("envelope has no header")]
    NoHeader,
    /// The envelope's `tree_id`/`key_id` doesn't match this sealer's scope — a blob for a
    /// different tree, or sealed under a different key epoch.
    #[error("envelope is out of scope for this sealer (tree_id/key_id mismatch)")]
    WrongScope,
    /// The envelope's `key_id` names an epoch the caller holds no key for — an expected
    /// access boundary (e.g. a member reading content from before they joined), distinct
    /// from a tampered/misrouted blob.
    #[error("no key for this envelope's epoch")]
    EpochUnreachable,
    /// The envelope's `kind` isn't the one the caller expected to open.
    #[error("unexpected entry kind")]
    WrongKind,
    /// The keyring bytes wouldn't decode, are too large, or are structurally invalid.
    #[error("malformed keyring: {0}")]
    BadKeyring(String),
    /// A keyring's Argon2id `kdf_params` are outside the range this build will run — a
    /// hostile keyring could otherwise OOM/CPU-burn the client before any verification.
    #[error("keyring KDF params out of range")]
    BadKdfParams,
    /// No wrap in the keyring matches the expected `(member_id, wrap_method)`.
    #[error("keyring has no matching wrap")]
    MissingWrap,
    /// A member with this id is already in the keyring (add is not idempotent — the caller
    /// should update or remove first).
    #[error("member already present in the keyring")]
    MemberExists,
    /// No member with the given id is in the keyring (e.g. asked to remove a non-member).
    #[error("member not found in the keyring")]
    MemberNotFound,
    /// The owner/founder cannot be removed — they are the keyring's root of trust. Transfer
    /// ownership instead (a future flow).
    #[error("the owner cannot be removed")]
    CannotRemoveOwner,
    /// The caller isn't authorized for this administrative action — e.g. a member who isn't a
    /// co-owner trying to add/remove members, or a co-owner trying to change the signer set
    /// (founder-only).
    #[error("not authorized for this action")]
    NotAuthorized,
    /// The keyring is for a different tree than the caller expected (the caller supplies the
    /// trusted `tree_id`; it is never read from the untrusted keyring for the AEAD context).
    #[error("keyring is for a different tree")]
    TreeMismatch,
    /// The served keyring revision is below the client's watermark — a rollback/replay.
    #[error("keyring revision rolled back: floor {have}, served {got}")]
    RevisionRollback { have: u32, got: u32 },
    /// The next revision would overflow `u32` (a poisoned/absurd served revision).
    #[error("keyring revision overflow")]
    RevisionOverflow,
    /// The opaque anti-rollback watermark floor handed to a lifecycle call wasn't a valid encoding for
    /// this engine (for the chain, a non-empty value that isn't a 4-byte revision). The floor is a
    /// client-local cursor, so this is local corruption, not an attack — but it's refused rather than
    /// silently dropped, since dropping the floor would drop rollback protection.
    #[error("malformed anti-rollback watermark")]
    MalformedWatermark,
}

/// A stateful sealing session bound to one `(tree_id, key_id, replica_id)` scope, holding
/// the unlocked DEK. Constructed from an already-unwrapped DEK (unlock/provision, which
/// perform the Argon2id KEK derivation + keyring verification, build this).
pub struct Sealer {
    version: u32,
    dek: Key32,
    aead: Aead,
    tree_id: Vec<u8>,
    key_id: Vec<u8>,
    replica_id: Vec<u8>,
    /// The member's author identity for signing + attributing entries on a shared tree (§B3 launch
    /// gate), owned for the session and borrowed into each seal. Set at unlock via
    /// [`Sealer::with_author`]; `governing_ref` is the opaque, engine-encoded reference to the member's
    /// watermarked keyring head at unlock (a keyring change re-unlocks and refreshes it — for the chain,
    /// the head revision). `None` → unattributed entries (V1 communal-DEK).
    author: Option<openom_crypto::AuthorIdentity>,
}

impl Sealer {
    /// Build a sealer from an already-unwrapped DEK and its scope. The default AEAD is
    /// XChaCha20-Poly1305 (§6); use [`with_aead`](Self::with_aead) to seal snapshots under
    /// AES-256-GCM. `version` is normally [`openom_protocol::ENVELOPE_VERSION`].
    pub fn from_unwrapped(
        version: u32,
        dek: Key32,
        tree_id: TreeId,
        key_id: KeyId,
        replica_id: ReplicaId,
    ) -> Self {
        Sealer {
            version,
            dek,
            aead: Aead::Xchacha20Poly1305,
            tree_id: tree_id.into_bytes(),
            key_id: key_id.into_bytes(),
            replica_id: replica_id.into_bytes(),
            author: None,
        }
    }

    /// Attach the member's author identity so entries this sealer seals are SIGNED + attributed
    /// (shared trees). Builder-style; set at unlock from the verified keyring's member identity + the
    /// watermarked keyring head. Omit for unattributed (single-owner V1) trees.
    pub fn with_author(
        mut self,
        signing_key: openom_keyring::SigningKey,
        member_id: String,
        governing_ref: Vec<u8>,
    ) -> Self {
        self.set_author(signing_key, member_id, governing_ref);
        self
    }

    /// Mutating form of [`with_author`](Self::with_author), for setting the author on a sealer already
    /// inside a collection (see [`SealerSet::with_author`]).
    pub fn set_author(
        &mut self,
        signing_key: openom_keyring::SigningKey,
        member_id: String,
        governing_ref: Vec<u8>,
    ) {
        self.author = Some(openom_crypto::AuthorIdentity {
            signing_key,
            member_id,
            governing_ref,
        });
    }

    /// A local-development sealer using the reserved dev key (§16): real ciphertext,
    /// well-known DEK, tagged with `DEV_KEY_ID` — which the server refuses under
    /// `RUN_MODE=production`. This is what lets the web app run the full seal/open path
    /// with no server and no unlock flow, for fast UI iteration.
    pub fn dev(tree_id: TreeId, replica_id: ReplicaId) -> Self {
        Self::from_unwrapped(
            openom_protocol::ENVELOPE_VERSION,
            openom_crypto::dev_dek(),
            tree_id,
            KeyId::new(openom_crypto::DEV_KEY_ID.to_vec()),
            replica_id,
        )
    }

    /// Override the AEAD (default XChaCha20-Poly1305). Builder-style.
    pub fn with_aead(mut self, aead: Aead) -> Self {
        self.aead = aead;
        self
    }

    /// The tree this sealer is scoped to.
    pub fn tree_id(&self) -> &[u8] {
        &self.tree_id
    }

    /// The key epoch (`key_id`) this sealer is scoped to.
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// Seal `plaintext` into a wire-ready envelope under this sealer's DEK and scope,
    /// using the caller-supplied chain state in `ctx`. Returns the encoded bytes plus the
    /// `ciphertext_hash` to thread into the next call.
    pub fn seal_entry(
        &self,
        ctx: &SealContext,
        plaintext: &[u8],
    ) -> Result<SealOutcome, SealerError> {
        let params = openom_crypto::SealParams {
            version: self.version,
            kind: ctx.kind.to_proto(),
            format: ctx.format,
            aead: self.aead,
            compression: ctx.compression,
            key_id: &self.key_id,
            tree_id: &self.tree_id,
            replica_id: &self.replica_id,
            replica_counter: ctx.replica_counter,
            prev_ciphertext_hash: &ctx.prev_ciphertext_hash,
            covers_through_seq: ctx.covers_through_seq,
            blob_id: &ctx.blob_id,
            // Sign + attribute the entry when this sealer carries an author identity (shared trees).
            // The sealer owns the identity for the session; SealParams borrows it like every field.
            author: self.author.as_ref(),
        };
        let envelope = seal_envelope(&self.dek, &params, plaintext)?;
        // seal_envelope always sets ciphertext_hash after sealing; the header is present.
        let ciphertext_hash = envelope
            .header
            .as_ref()
            .ok_or(SealerError::NoHeader)?
            .ciphertext_hash
            .clone();
        Ok(SealOutcome {
            envelope: envelope.encode_to_vec(),
            ciphertext_hash,
        })
    }

    /// Decode `envelope_bytes`, verify it belongs to this sealer's `(tree_id, key_id)`
    /// scope and is the `expect` kind, then AEAD-open it. Returns the plaintext.
    pub fn open_entry(
        &self,
        expect: EntryKind,
        envelope_bytes: &[u8],
    ) -> Result<Vec<u8>, SealerError> {
        let envelope =
            Envelope::decode(envelope_bytes).map_err(|e| SealerError::Decode(e.to_string()))?;
        let header = envelope.header.as_ref().ok_or(SealerError::NoHeader)?;
        self.check_scope(header)?;
        if EntryKind::from_proto(header.kind) != Some(expect) {
            return Err(SealerError::WrongKind);
        }
        Ok(open_envelope(&self.dek, &envelope)?)
    }

    fn check_scope(&self, header: &Header) -> Result<(), SealerError> {
        if header.tree_id != self.tree_id || header.key_id != self.key_id {
            return Err(SealerError::WrongScope);
        }
        Ok(())
    }
}

/// A reader/writer over **all epochs** a caller can reach: one [`Sealer`] per epoch (they
/// share `tree_id`/`replica_id`), routing an open to the sealer whose `key_id` matches the
/// envelope, and always sealing new entries under the single **write epoch** (the latest).
///
/// This is what lets a client read content sealed before a key rotation (old-epoch
/// snapshots and, under leave-and-lazy media, old photos) while writing only under the
/// current key. The per-replica chain state (§8a) is orthogonal to `key_id` and spans
/// epochs — a rotation switches which epoch a *write* targets, never the replica's counter
/// or `prev` chain.
pub struct SealerSet {
    tree_id: Vec<u8>,
    write_key_id: Vec<u8>,
    sealers: Vec<Sealer>,
}

impl SealerSet {
    /// Build a set from `(key_id, dek)` per reachable epoch. `write_key_id` must be one of
    /// them (the latest epoch) — new entries seal under it.
    pub fn new(
        tree_id: TreeId,
        replica_id: ReplicaId,
        epochs: Vec<(Vec<u8>, Key32)>,
        write_key_id: KeyId,
    ) -> Self {
        let tree_id = tree_id.into_bytes();
        let replica_id = replica_id.into_bytes();
        let write_key_id = write_key_id.into_bytes();
        let sealers = epochs
            .into_iter()
            .map(|(key_id, dek)| {
                Sealer::from_unwrapped(
                    openom_protocol::ENVELOPE_VERSION,
                    dek,
                    TreeId::new(tree_id.clone()),
                    KeyId::new(key_id),
                    ReplicaId::new(replica_id.clone()),
                )
            })
            .collect();
        SealerSet {
            tree_id,
            write_key_id,
            sealers,
        }
    }

    /// Attach the member's author identity to the WRITE-epoch sealer, so new entries are signed +
    /// attributed (§B3 shared trees). Old-epoch sealers only open (never seal new entries), so they need
    /// no author. Set at unlock, gated on the write epoch being attributed (shared).
    pub fn with_author(
        mut self,
        signing_key: openom_keyring::SigningKey,
        member_id: String,
        governing_ref: Vec<u8>,
    ) -> Self {
        let write = self.write_key_id.clone();
        if let Some(w) = self.sealers.iter_mut().find(|s| s.key_id == write) {
            w.set_author(signing_key, member_id, governing_ref);
        }
        self
    }

    /// A single-epoch set — the local-development / demo path (one dev sealer).
    pub fn single(sealer: Sealer) -> Self {
        SealerSet {
            tree_id: sealer.tree_id.clone(),
            write_key_id: sealer.key_id.clone(),
            sealers: vec![sealer],
        }
    }

    /// The tree this set is scoped to.
    pub fn tree_id(&self) -> &[u8] {
        &self.tree_id
    }

    /// Seal a new entry under the **write** (latest) epoch.
    pub fn seal_entry(
        &self,
        ctx: &SealContext,
        plaintext: &[u8],
    ) -> Result<SealOutcome, SealerError> {
        self.sealers
            .iter()
            .find(|s| s.key_id == self.write_key_id)
            .ok_or(SealerError::EpochUnreachable)?
            .seal_entry(ctx, plaintext)
    }

    /// Open an envelope by routing to the sealer for its epoch. A `tree_id` mismatch is a
    /// misrouted blob (`WrongScope`); a `key_id` the set doesn't hold is an access boundary
    /// (`EpochUnreachable`).
    pub fn open_entry(
        &self,
        expect: EntryKind,
        envelope_bytes: &[u8],
    ) -> Result<Vec<u8>, SealerError> {
        let envelope =
            Envelope::decode(envelope_bytes).map_err(|e| SealerError::Decode(e.to_string()))?;
        let header = envelope.header.as_ref().ok_or(SealerError::NoHeader)?;
        if header.tree_id != self.tree_id {
            return Err(SealerError::WrongScope);
        }
        self.sealers
            .iter()
            .find(|s| s.key_id == header.key_id)
            .ok_or(SealerError::EpochUnreachable)?
            .open_entry(expect, envelope_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer() -> Sealer {
        Sealer::from_unwrapped(
            1,
            openom_crypto::generate_dek().unwrap().into_inner(),
            TreeId::new(b"tree-uuid-16byte".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
            ReplicaId::new(b"replica-0".to_vec()),
        )
    }

    #[test]
    fn round_trips_a_snapshot() {
        let s = sealer();
        let ctx = SealContext::snapshot(1, Vec::new(), 0);
        let out = s.seal_entry(&ctx, b"the family tree").unwrap();
        assert!(!out.ciphertext_hash.is_empty());
        assert_eq!(
            s.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(),
            b"the family tree"
        );
    }

    #[test]
    fn round_trips_a_delta_and_a_proposal() {
        // An op-based payload flows through the header as a delta and as a proposal — the seal path
        // for the engine's sync deltas + proposal bundles.
        let s = sealer();
        let delta = SealContext {
            kind: EntryKind::Delta,
            format: Format::OpenomOps,
            ..SealContext::snapshot(1, Vec::new(), 0)
        };
        let out = s.seal_entry(&delta, b"op-delta-bytes").unwrap();
        let env = Envelope::decode(out.envelope.as_slice()).unwrap();
        assert_eq!(env.header.unwrap().format, Format::OpenomOps as i32);
        assert_eq!(
            s.open_entry(EntryKind::Delta, &out.envelope).unwrap(),
            b"op-delta-bytes"
        );

        let proposal = SealContext {
            kind: EntryKind::Proposal,
            format: Format::OpenomOps,
            ..SealContext::snapshot(2, out.ciphertext_hash.clone(), 0)
        };
        let pout = s.seal_entry(&proposal, b"proposal-op-bundle").unwrap();
        assert_eq!(
            s.open_entry(EntryKind::Proposal, &pout.envelope).unwrap(),
            b"proposal-op-bundle"
        );
        // A proposal must not open as a delta (domain separation via the kind AAD binding).
        assert!(matches!(
            s.open_entry(EntryKind::Delta, &pout.envelope),
            Err(SealerError::WrongKind)
        ));
    }

    #[test]
    fn with_author_signs_and_attributes_the_entry() {
        let author = openom_keyring::generate_identity().unwrap();
        let s = sealer().with_author(author, "m1".into(), openom_keyring::encode_governing_ref(3));
        let delta = SealContext {
            kind: EntryKind::Delta,
            format: Format::OpenomOps,
            ..SealContext::snapshot(1, Vec::new(), 0)
        };
        let out = s.seal_entry(&delta, b"a change").unwrap();
        let h = Envelope::decode(out.envelope.as_slice())
            .unwrap()
            .header
            .unwrap();
        assert!(
            !h.author_signature.is_empty(),
            "an author-bearing sealer signs the entry"
        );
        assert_eq!(h.author_member_id, "m1");
        assert_eq!(h.governing_ref, openom_keyring::encode_governing_ref(3));
        // Default (no author) → unattributed, V1 communal-DEK behaviour.
        let plain = sealer().seal_entry(&delta, b"a change").unwrap().envelope;
        let h2 = Envelope::decode(plain.as_slice()).unwrap().header.unwrap();
        assert!(
            h2.author_signature.is_empty()
                && h2.author_member_id.is_empty()
                && h2.governing_ref.is_empty()
        );
    }

    #[test]
    fn returns_the_chain_hash_for_the_next_entry() {
        let s = sealer();
        let first = s
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"a")
            .unwrap();
        let second = s
            .seal_entry(
                &SealContext::snapshot(2, first.ciphertext_hash.clone(), 1),
                b"b",
            )
            .unwrap();
        // The second envelope's header records the first's hash as its prev.
        let env = Envelope::decode(second.envelope.as_slice()).unwrap();
        assert_eq!(
            env.header.unwrap().prev_ciphertext_hash,
            first.ciphertext_hash
        );
    }

    #[test]
    fn rejects_a_blob_from_another_tree() {
        let a = sealer();
        let b = Sealer::from_unwrapped(
            1,
            openom_crypto::generate_dek().unwrap().into_inner(),
            TreeId::new(b"other-tree-16byt".to_vec()),
            KeyId::new(b"epoch-0".to_vec()),
            ReplicaId::new(b"replica-9".to_vec()),
        );
        let out = a
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"secret")
            .unwrap();
        assert!(matches!(
            b.open_entry(EntryKind::Snapshot, &out.envelope),
            Err(SealerError::WrongScope)
        ));
    }

    #[test]
    fn rejects_the_wrong_kind() {
        let s = sealer();
        let out = s
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"x")
            .unwrap();
        assert!(matches!(
            s.open_entry(EntryKind::Media, &out.envelope),
            Err(SealerError::WrongKind)
        ));
    }

    #[test]
    fn dev_sealer_tags_the_reserved_key_id() {
        let s = Sealer::dev(
            TreeId::new(b"tree-uuid-16byte".to_vec()),
            ReplicaId::new(b"replica-0".to_vec()),
        );
        let out = s
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"local dev")
            .unwrap();
        let env = Envelope::decode(out.envelope.as_slice()).unwrap();
        assert_eq!(env.header.unwrap().key_id, openom_crypto::DEV_KEY_ID);
        assert_eq!(
            s.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(),
            b"local dev"
        );
    }

    #[test]
    fn corrupted_ciphertext_fails_to_open() {
        let s = sealer();
        let mut out = s
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"payload")
            .unwrap();
        // Flip a byte deep in the encoded envelope (the ciphertext lives near the end).
        let n = out.envelope.len();
        out.envelope[n - 1] ^= 0xFF;
        assert!(s.open_entry(EntryKind::Snapshot, &out.envelope).is_err());
    }

    #[test]
    fn seals_under_aes_gcm_when_selected() {
        let s = sealer().with_aead(Aead::Aes256Gcm);
        let out = s
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"aes path")
            .unwrap();
        let env = Envelope::decode(out.envelope.as_slice()).unwrap();
        assert_eq!(env.header.as_ref().unwrap().aead, Aead::Aes256Gcm as i32);
        assert_eq!(
            s.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(),
            b"aes path"
        );
    }
}
