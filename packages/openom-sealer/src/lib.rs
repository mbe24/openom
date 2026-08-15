//! openom **sealer** — the client-side session that holds the *unlocked* DEK and turns
//! plaintext into wire-ready [`Envelope`] bytes (and back). It is the one stateful,
//! key-holding component in the system; the server stays keyless (§16). The same core
//! runs natively inside Tauri and, compiled to wasm32 with the `wasm` feature, inside
//! the browser through the [`wasm`] veneer — one implementation, two bindings, so a web
//! and a native client can never disagree on how a blob was sealed.
//!
//! ## What lives here vs. in the caller
//! The sealer is deliberately *not* the source of truth for the log chain. Per the §3
//! crash-retry model, the caller (JS `SealedStore` / the Tauri command) owns the chain
//! state — `replica_counter`, `prev_ciphertext_hash`, `covers_through_seq` — and passes
//! it in as a [`SealContext`]. [`Sealer::seal_entry`] returns the freshly-minted
//! `ciphertext_hash`, which the caller persists as the next entry's `prev`.
//!
//! ## Retry means re-UPLOAD, never re-SEAL
//! Each `seal_entry` mints a **fresh random nonce**, so re-sealing the *same* logical
//! entry yields a *different* `ciphertext_hash` under the *same* `(replica_id, counter)`
//! slot — and if the first upload had actually landed (a lost ack), that is a self-
//! inflicted chain fork. So a transient upload failure must retry the **already-sealed
//! bytes verbatim** (the caller persists them locally before upload; that local commit is
//! the write-ahead point). `seal_entry` is called exactly once per logical entry, and a
//! fresh seal (new nonce) is reserved for genuinely new content, which always takes a new
//! counter. The purity here is what makes that discipline possible, not a license to
//! re-seal on retry.
//!
//! ## Scope binding
//! A sealer is bound to exactly one `(tree_id, key_id, replica_id)`. On open it verifies
//! the envelope's header matches that scope and the expected [`EntryKind`] before
//! decrypting — a blob for another tree, or sealed under a superseded key epoch, is
//! rejected structurally rather than handed to the AEAD and failing opaquely.

use openom_crypto::{open_envelope, seal_envelope, CryptoError, Key32};
use openom_protocol::v1::{Aead, Compression, Envelope, Format, Header, Kind};
use openom_protocol::Message;

pub mod vault;

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
}

impl EntryKind {
    fn to_proto(self) -> Kind {
        match self {
            EntryKind::Snapshot => Kind::Snapshot,
            EntryKind::Delta => Kind::Delta,
            EntryKind::Media => Kind::Media,
        }
    }

    fn from_proto(k: i32) -> Option<Self> {
        match Kind::try_from(k).ok()? {
            Kind::Snapshot => Some(EntryKind::Snapshot),
            Kind::Delta => Some(EntryKind::Delta),
            Kind::Media => Some(EntryKind::Media),
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
    pub fn snapshot(replica_counter: u64, prev_ciphertext_hash: Vec<u8>, covers_through_seq: u64) -> Self {
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
}

impl Sealer {
    /// Build a sealer from an already-unwrapped DEK and its scope. The default AEAD is
    /// XChaCha20-Poly1305 (§6); use [`with_aead`](Self::with_aead) to seal snapshots under
    /// AES-256-GCM. `version` is normally [`openom_protocol::ENVELOPE_VERSION`].
    pub fn from_unwrapped(
        version: u32,
        dek: Key32,
        tree_id: Vec<u8>,
        key_id: Vec<u8>,
        replica_id: Vec<u8>,
    ) -> Self {
        Sealer {
            version,
            dek,
            aead: Aead::Xchacha20Poly1305,
            tree_id,
            key_id,
            replica_id,
        }
    }

    /// A local-development sealer using the reserved dev key (§16): real ciphertext,
    /// well-known DEK, tagged with `DEV_KEY_ID` — which the server refuses under
    /// `RUN_MODE=production`. This is what lets the web app run the full seal/open path
    /// with no server and no unlock flow, for fast UI iteration.
    pub fn dev(tree_id: Vec<u8>, replica_id: Vec<u8>) -> Self {
        Self::from_unwrapped(
            openom_protocol::ENVELOPE_VERSION,
            openom_crypto::dev_dek(),
            tree_id,
            openom_crypto::DEV_KEY_ID.to_vec(),
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

    /// Seal `plaintext` into a wire-ready envelope under this sealer's DEK and scope,
    /// using the caller-supplied chain state in `ctx`. Returns the encoded bytes plus the
    /// `ciphertext_hash` to thread into the next call.
    pub fn seal_entry(&self, ctx: &SealContext, plaintext: &[u8]) -> Result<SealOutcome, SealerError> {
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
    pub fn open_entry(&self, expect: EntryKind, envelope_bytes: &[u8]) -> Result<Vec<u8>, SealerError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer() -> Sealer {
        Sealer::from_unwrapped(
            1,
            openom_crypto::generate_dek().unwrap(),
            b"tree-uuid-16byte".to_vec(),
            b"epoch-0".to_vec(),
            b"replica-0".to_vec(),
        )
    }

    #[test]
    fn round_trips_a_snapshot() {
        let s = sealer();
        let ctx = SealContext::snapshot(1, Vec::new(), 0);
        let out = s.seal_entry(&ctx, b"the family tree").unwrap();
        assert!(!out.ciphertext_hash.is_empty());
        assert_eq!(s.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(), b"the family tree");
    }

    #[test]
    fn returns_the_chain_hash_for_the_next_entry() {
        let s = sealer();
        let first = s.seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"a").unwrap();
        let second = s
            .seal_entry(&SealContext::snapshot(2, first.ciphertext_hash.clone(), 1), b"b")
            .unwrap();
        // The second envelope's header records the first's hash as its prev.
        let env = Envelope::decode(second.envelope.as_slice()).unwrap();
        assert_eq!(env.header.unwrap().prev_ciphertext_hash, first.ciphertext_hash);
    }

    #[test]
    fn rejects_a_blob_from_another_tree() {
        let a = sealer();
        let b = Sealer::from_unwrapped(
            1,
            openom_crypto::generate_dek().unwrap(),
            b"other-tree-16byt".to_vec(),
            b"epoch-0".to_vec(),
            b"replica-9".to_vec(),
        );
        let out = a.seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"secret").unwrap();
        assert!(matches!(
            b.open_entry(EntryKind::Snapshot, &out.envelope),
            Err(SealerError::WrongScope)
        ));
    }

    #[test]
    fn rejects_the_wrong_kind() {
        let s = sealer();
        let out = s.seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"x").unwrap();
        assert!(matches!(
            s.open_entry(EntryKind::Media, &out.envelope),
            Err(SealerError::WrongKind)
        ));
    }

    #[test]
    fn dev_sealer_tags_the_reserved_key_id() {
        let s = Sealer::dev(b"tree-uuid-16byte".to_vec(), b"replica-0".to_vec());
        let out = s.seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"local dev").unwrap();
        let env = Envelope::decode(out.envelope.as_slice()).unwrap();
        assert_eq!(env.header.unwrap().key_id, openom_crypto::DEV_KEY_ID);
        assert_eq!(s.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(), b"local dev");
    }

    #[test]
    fn corrupted_ciphertext_fails_to_open() {
        let s = sealer();
        let mut out = s.seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"payload").unwrap();
        // Flip a byte deep in the encoded envelope (the ciphertext lives near the end).
        let n = out.envelope.len();
        out.envelope[n - 1] ^= 0xFF;
        assert!(s.open_entry(EntryKind::Snapshot, &out.envelope).is_err());
    }

    #[test]
    fn seals_under_aes_gcm_when_selected() {
        let s = sealer().with_aead(Aead::Aes256Gcm);
        let out = s.seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"aes path").unwrap();
        let env = Envelope::decode(out.envelope.as_slice()).unwrap();
        assert_eq!(env.header.as_ref().unwrap().aead, Aead::Aes256Gcm as i32);
        assert_eq!(s.open_entry(EntryKind::Snapshot, &out.envelope).unwrap(), b"aes path");
    }
}
