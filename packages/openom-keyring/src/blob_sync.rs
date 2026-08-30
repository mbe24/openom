//! Fit the linear chain keyring to the `blobstore` seam (OPE-265).
//!
//! The keyring is one small, low-contention register, so **per-object CAS is its sequencer**: the current
//! keyring lives at a single CAS'd `keyring/head`, with an append-only `keyring/rev/{n}` history so a
//! lagging replica can [`verify_walk`](crate::verify_walk) up to the head. This works on a managed
//! backend and a dumb BYO one alike.
//!
//! This is the storage transport only. The crypto that *produces* keyrings —
//! provision / recover / change-passphrase, in openom-sealer's vault — is a pure `bytes -> bytes`
//! lifecycle (it takes the current keyring bytes and returns the next), so every operation publishes its
//! output through here unchanged. Recovery is the one that isn't a plain transition: a reset re-founds
//! the identity, so [`verify_transition`](crate::verify_transition) rejects it — it surfaces on pull as
//! [`PullError::ResetPending`] (the client's out-of-band re-verify ceremony) and is adopted via
//! [`KeyringChainBlobSync::accept_reset`], never silently walked.

use blobstore::{BlobError, BlobStore, Etag, Precondition};
use openom_protocol::v1::Keyring;
use openom_protocol::Message;

use crate::{keyring_hash, verify_reset, verify_walk, ChainError, KeyringAnchor};

const HEAD: &str = "keyring/head";

fn rev_key(n: u32) -> String {
    format!("keyring/rev/{n}")
}

/// A transport failure (as opposed to a governance decision — see [`PullError`]).
#[derive(Debug)]
pub enum SyncError {
    Store(BlobError),
    Decode(String),
    Chain(String),
    Malformed(&'static str),
    /// The head advanced under us during a publish — pull, re-produce the keyring, and publish again.
    Conflict,
}

impl From<BlobError> for SyncError {
    fn from(e: BlobError) -> Self {
        SyncError::Store(e)
    }
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Store(e) => write!(f, "blob store: {e}"),
            SyncError::Decode(e) => write!(f, "keyring decode: {e}"),
            SyncError::Chain(e) => write!(f, "chain rejected: {e}"),
            SyncError::Malformed(m) => write!(f, "malformed keyring transport state: {m}"),
            SyncError::Conflict => write!(f, "head advanced concurrently; retry"),
        }
    }
}
impl std::error::Error for SyncError {}

/// Pulling can surface a decision the transport can't make itself.
#[derive(Debug)]
pub enum PullError {
    Sync(SyncError),
    /// The served head is OLDER than what we've accepted — a rollback / stale-serve attack.
    Rollback { have: u32, served: u32 },
    /// The head is a recovery RESET (a new, deliberately-unendorsed founder). The client must confirm it
    /// out of band (surface the hash + revision), then call [`KeyringChainBlobSync::accept_reset`].
    ResetPending,
}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PullError::Sync(e) => write!(f, "{e}"),
            PullError::Rollback { have, served } => {
                write!(f, "rollback: have revision {have}, store served {served}")
            }
            PullError::ResetPending => write!(f, "head is a recovery reset; awaiting out-of-band confirm"),
        }
    }
}
impl std::error::Error for PullError {}

/// One replica's Blob transport for a chain keyring: publishes locally-produced keyrings and pulls
/// remote advances, holding the trusted [`KeyringAnchor`] and the head etag for CAS.
pub struct KeyringChainBlobSync<S: BlobStore> {
    store: S,
    anchor: Option<KeyringAnchor>,
    head_etag: Option<Etag>,
}

impl<S: BlobStore> KeyringChainBlobSync<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            anchor: None,
            head_etag: None,
        }
    }

    /// The revision this replica currently trusts (its anti-rollback watermark), if bootstrapped.
    pub fn revision(&self) -> Option<u32> {
        self.anchor.as_ref().map(|a| a.revision)
    }

    /// Publish a locally-produced keyring (the vault's output bytes). Writes its immutable `rev/{n}` blob
    /// and CAS-advances the head; adopts it as the local anchor (own production is trusted). Returns
    /// [`SyncError::Conflict`] if another replica advanced the head first (pull + re-produce + retry).
    pub fn publish(&mut self, keyring_bytes: &[u8]) -> Result<(), SyncError> {
        let keyring = decode(keyring_bytes)?;
        match self
            .store
            .put(&rev_key(keyring.revision), keyring_bytes, Precondition::IfAbsent)
        {
            Ok(_) | Err(BlobError::PreconditionFailed) => {} // immutable + idempotent
            Err(e) => return Err(SyncError::Store(e)),
        }
        // First publish (no head yet): create-only. Otherwise CAS onto the etag we last saw.
        let pre = match &self.head_etag {
            Some(e) => Precondition::IfMatch(e.clone()),
            None => Precondition::IfAbsent,
        };
        let etag = self.store.put(HEAD, keyring_bytes, pre).map_err(|e| match e {
            BlobError::PreconditionFailed => SyncError::Conflict,
            e => SyncError::Store(e),
        })?;
        self.head_etag = Some(etag);
        self.anchor = Some(KeyringAnchor::from_keyring(&keyring));
        Ok(())
    }

    /// First-sight trust from the head (genesis, or an out-of-band-pinned head): [`verify_reset`] accepts
    /// it on its own terms. Sets the anchor. Returns the keyring bytes, or `None` if there is no head.
    pub fn bootstrap(&mut self) -> Result<Option<Vec<u8>>, SyncError> {
        let Some((bytes, etag)) = self.store.get(HEAD)? else {
            return Ok(None);
        };
        let keyring = decode(&bytes)?;
        self.anchor = Some(verify_reset(&keyring).map_err(chain_err)?);
        self.head_etag = Some(etag);
        Ok(Some(bytes))
    }

    /// Pull the head and verify it advances the anchor ([`verify_walk`] over any skipped revisions).
    /// Returns the new keyring bytes if it advanced, `None` if unchanged. Rejects a rollback; surfaces a
    /// recovery reset as [`PullError::ResetPending`].
    pub fn pull(&mut self) -> Result<Option<Vec<u8>>, PullError> {
        let Some(anchor) = self.anchor.clone() else {
            return self.bootstrap().map_err(PullError::Sync);
        };
        let Some((bytes, etag)) = self.store.get(HEAD).map_err(|e| PullError::Sync(e.into()))? else {
            return Ok(None);
        };
        let head = decode(&bytes).map_err(PullError::Sync)?;
        if head.revision < anchor.revision {
            return Err(PullError::Rollback {
                have: anchor.revision,
                served: head.revision,
            });
        }
        if head.revision == anchor.revision {
            if keyring_hash(&head) != anchor.keyring_hash {
                return Err(PullError::Sync(SyncError::Malformed(
                    "store served a different keyring at the same revision",
                )));
            }
            self.head_etag = Some(etag);
            return Ok(None);
        }
        // Gather the skipped revisions from history, then the head, and walk them.
        let mut hops = Vec::new();
        for n in (anchor.revision + 1)..head.revision {
            let (rb, _) = self
                .store
                .get(&rev_key(n))
                .map_err(|e| PullError::Sync(e.into()))?
                .ok_or(PullError::Sync(SyncError::Malformed("missing revision in history")))?;
            hops.push(decode(&rb).map_err(PullError::Sync)?);
        }
        hops.push(head);
        match verify_walk(&anchor, &hops) {
            Ok(new_anchor) => {
                self.anchor = Some(new_anchor);
                self.head_etag = Some(etag);
                Ok(Some(bytes))
            }
            // An unendorsed set change on the walk is a recovery reset — needs the OOB ceremony.
            Err(ChainError::UnendorsedSetChange) => Err(PullError::ResetPending),
            Err(e) => Err(PullError::Sync(SyncError::Chain(format!("{e:?}")))),
        }
    }

    /// Adopt the head as a recovery reset, AFTER the client's out-of-band confirmation: run
    /// [`verify_reset`] and set the anchor. Refuses a reset whose revision is behind the watermark.
    /// Returns the keyring bytes.
    pub fn accept_reset(&mut self) -> Result<Vec<u8>, SyncError> {
        let Some((bytes, etag)) = self.store.get(HEAD)? else {
            return Err(SyncError::Malformed("no head to accept"));
        };
        let keyring = decode(&bytes)?;
        if let Some(a) = &self.anchor {
            if keyring.revision < a.revision {
                return Err(SyncError::Malformed("reset revision is behind the watermark"));
            }
        }
        self.anchor = Some(verify_reset(&keyring).map_err(chain_err)?);
        self.head_etag = Some(etag);
        Ok(bytes)
    }
}

fn decode(bytes: &[u8]) -> Result<Keyring, SyncError> {
    Keyring::decode(bytes).map_err(|e| SyncError::Decode(e.to_string()))
}

fn chain_err(e: ChainError) -> SyncError {
    SyncError::Chain(format!("{e:?}"))
}
