#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};

use openom_claim::envelope::Record;
use openom_claim::{ClaimError, ContentAddressed};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `type` URI every [`Op`] envelope carries — the discriminator that routes an item to [`Op`]
/// rather than a [`Record`], and part of the op's hash preimage (domain separation inside the hash).
pub const OP_TYPE: &str = "openom.org/core/op/v1";

/// Domain-separation prefix for operation signatures, distinct from `openom-claim`'s
/// `openom-claim-v1` so a claim signature and an op signature can never be mistaken for one another.
/// Reserved for the deferred op-signing step (see the module docs).
pub const SIGN_DOMAIN: &[u8] = b"openom-op-v1";

/// One element of the operations channel: an **add** (the bare [`Record`]) or an [`Op`].
///
/// "Every change is an operation" is modeled at the *channel*, not the envelope: an add is the record
/// itself (its own id/author/timestamp is the whole story), while remove/supersede/revoke — which
/// have no record to be — carry an [`Op`] envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ChannelItem {
    /// Add a record. The op id *is* the record id; the author *is* the record's author.
    Assert(Record),
    /// A remove / supersede / revoke operation.
    Op(Op),
}

impl<'de> Deserialize<'de> for ChannelItem {
    /// Routes through [`ChannelItem::try_from`], the one verifying ingest door (dispatch on `type`;
    /// verify the op's / embedded record's content hash).
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        ChannelItem::try_from(v).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<Value> for ChannelItem {
    type Error = CrdtError;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        let type_uri = v
            .get("type")
            .and_then(Value::as_str)
            .ok_or(CrdtError::MissingType)?;
        if type_uri == OP_TYPE {
            Ok(ChannelItem::Op(Op::try_from(v)?))
        } else {
            Ok(ChannelItem::Assert(Record::try_from(v)?))
        }
    }
}

impl ChannelItem {
    /// The item's id: the record id for an [`Assert`](ChannelItem::Assert), the op id for an [`Op`].
    pub fn id(&self) -> &str {
        match self {
            ChannelItem::Assert(r) => r.id(),
            ChannelItem::Op(op) => &op.id,
        }
    }

    /// The item's author (`createdBy`).
    pub fn created_by(&self) -> &str {
        match self {
            ChannelItem::Assert(r) => r.created_by(),
            ChannelItem::Op(op) => &op.created_by,
        }
    }
}

/// The envelope for a remove / supersede / revoke operation. `id` is the content hash of the
/// envelope (excluding `id`, `signature`, and — for a supersede — the embedded record's `signature`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Op {
    /// `"sha256:…"` content hash — see [`ContentAddressed`].
    pub id: String,
    /// Always [`OP_TYPE`].
    #[serde(rename = "type")]
    pub type_uri: String,
    /// Advisory timestamp (epoch ms). Provenance only — never a convergence tiebreak. Per-device
    /// monotonic, so a byte-identical resend of the same logical op collapses by id (see the
    /// revoke/re-remove note on [`OpKind::Revoke`]).
    pub created_at: i64,
    /// The operation's author. Must equal the transport-authenticated entry author, and — for a
    /// [`Supersede`](OpKind::Supersede) — the replacement record's author.
    pub created_by: String,
    /// Ed25519 signature over `SIGN_DOMAIN ‖ content_hash`; present only in `signed_claims` trees.
    /// Signing/verifying is deferred (see the module docs); the field is reserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Which operation this is, and its operands.
    #[serde(flatten)]
    pub kind: OpKind,
}

/// The operation kinds. `op` is the JSON discriminator (`"remove"` / `"supersede"` / `"revoke"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum OpKind {
    /// Remove a record by id (same-author, observed-remove). Not an un-send — an appended delete-op
    /// that honest replicas fold out of the live set; undoable by [`Revoke`](OpKind::Revoke) up to the
    /// GC horizon.
    Remove {
        /// The **record** id being removed.
        target: String,
    },
    /// Edit: atomically remove `prior` and assert `replacement`, carrying an edit-lineage edge
    /// (same-author on both). Atomic so a remove and an assert never arrive in separate deltas and
    /// transiently show a deletion where the user made an edit. Kept distinct from a plain
    /// remove+assert for exactly that atomicity and the lineage.
    Supersede {
        /// The **record** id being replaced.
        prior: String,
        /// The new record (its id is content-verified on ingest). Boxed so a remove/revoke op does
        /// not carry the record-sized variant as slack; serde treats `Box<Record>` as the record.
        replacement: Box<Record>,
    },
    /// Undo a [`Remove`](OpKind::Remove) (same-author as that remove), restoring the *original*
    /// record id — so attestations and citations bound to it survive the undo, which a fresh
    /// re-assert (new id) could not. One level: a revoke is not itself revocable; a re-remove is a
    /// new remove of the same record.
    Revoke {
        /// The **operation** id of the remove being undone.
        removal: String,
    },
}

impl Op {
    /// Build an operation, computing its content-hash id. `signature` starts empty — signing is a
    /// separate, deferred step (see the module docs).
    pub fn new(
        created_at: i64,
        created_by: impl Into<String>,
        kind: OpKind,
    ) -> Result<Self, CrdtError> {
        let mut op = Op {
            id: String::new(),
            type_uri: OP_TYPE.to_owned(),
            created_at,
            created_by: created_by.into(),
            signature: None,
            kind,
        };
        op.id = op.content_id()?;
        Ok(op)
    }
}

impl ContentAddressed for Op {
    /// The op's hash preimage, with the embedded record's `signature` stripped so that signing the
    /// replacement of a [`Supersede`](OpKind::Supersede) does not shift the enclosing op id (JCS
    /// field-exclusion is top-level-only, so the nested strip is done here). The op's own top-level
    /// `id`/`signature` are excluded downstream by the shared `claim_id` seam.
    fn hash_envelope(&self) -> Result<Value, ClaimError> {
        let mut v = serde_json::to_value(self)?;
        if let Some(obj) = v.get_mut("replacement").and_then(Value::as_object_mut) {
            obj.remove("signature");
        }
        Ok(v)
    }
}

impl<'de> Deserialize<'de> for Op {
    /// Routes through [`Op::try_from`] so the op's content hash and any embedded record's hash are
    /// verified on deserialize — there is no id-skipping structural path.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Op::try_from(v).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<Value> for Op {
    type Error = CrdtError;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        // A distinct local shape carries the structural derive, so this path never recurses through
        // Op's own (verifying) Deserialize. Its embedded Record is still parsed by Record's verifying
        // Deserialize, so a forged replacement id is rejected here too.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            id: String,
            #[serde(rename = "type")]
            type_uri: String,
            created_at: i64,
            created_by: String,
            #[serde(default)]
            signature: Option<String>,
            #[serde(flatten)]
            kind: OpKind,
        }

        let raw = Raw::deserialize(&v).map_err(CrdtError::Malformed)?;
        if raw.type_uri != OP_TYPE {
            return Err(CrdtError::WrongType(raw.type_uri));
        }
        let op = Op {
            id: raw.id,
            type_uri: raw.type_uri,
            created_at: raw.created_at,
            created_by: raw.created_by,
            signature: raw.signature,
            kind: raw.kind,
        };
        if op.id != op.content_id()? {
            return Err(CrdtError::IdMismatch);
        }
        Ok(op)
    }
}

/// Ingesting an operation from untrusted JSON failed.
#[derive(Debug, thiserror::Error)]
pub enum CrdtError {
    /// No `type` discriminator on the envelope.
    #[error("missing type discriminator")]
    MissingType,
    /// The `type` is not [`OP_TYPE`].
    #[error("not an operation envelope: type is {0}")]
    WrongType(String),
    /// The JSON did not match the operation shape.
    #[error("malformed operation: {0}")]
    Malformed(serde_json::Error),
    /// The stated `id` does not match the content hash.
    #[error("operation id does not match its content hash")]
    IdMismatch,
    /// An embedded record failed to ingest, or hashing failed.
    #[error(transparent)]
    Claim(#[from] ClaimError),
}

/// Materialize the live record set from an operations-channel item set — the fold that produces the
/// snapshot `openom-projection` reads.
///
/// Authority is **role-based**: a Remove/Supersede/Revoke governs its target only when its author is in
/// `moderators` — the did:keys currently at Maintainer or above (derived from the latest keyring; a
/// solo tree passes its own did, so the owner moderates their own tree). An op by a non-moderator (for
/// example a since-demoted member's stale op) is a deterministic no-op, so demoting a member and
/// re-folding the SAME item set resurfaces whatever their ops had hidden — authority is always judged
/// against the *current* roles, never as-of-authoring. A Supersede's replacement must still be authored
/// in the acting author's own name (an impersonating replacement is a forgery, dropped) — a moderator
/// may overrule another's claim, never forge one in their name.
///
/// `live = (asserted ∪ authorized-supersede-replacements) − { ids named by an authorized, un-revoked
/// Remove or Supersede }`. Every step is set membership over the *set* of items for a FIXED
/// `moderators`, so the result is independent of order and duplication — the convergence guarantee (a
/// set CRDT parameterized by the convergent, hash-chained keyring register).
///
/// The returned records are cloned once here (the compaction/snapshot fold, not the read hot path).
/// Output is ordered by id.
pub fn materialize(items: &[ChannelItem], moderators: &BTreeSet<String>) -> Vec<Record> {
    // 1. Every asserted record by id (bare Asserts + Supersede replacements in the acting author's own
    //    name — a replacement attributed to someone else is a forgery, dropped, else the projection
    //    would tally a corroborating author out of thin air). First writer of an id wins (a collision
    //    is a byte-identical duplicate, so idempotent).
    let mut records: BTreeMap<&str, &Record> = BTreeMap::new();
    for item in items {
        match item {
            ChannelItem::Assert(r) => {
                records.entry(r.id()).or_insert(r);
            }
            ChannelItem::Op(op) => {
                if let OpKind::Supersede { replacement, .. } = &op.kind {
                    if op.created_by == replacement.created_by() {
                        records
                            .entry(replacement.id())
                            .or_insert(replacement.as_ref());
                    }
                }
            }
        }
    }

    // 2. Remove ops suppressed by a Revoke from a moderator (a role holder may undo any removal).
    let mut revoked: BTreeSet<&str> = BTreeSet::new();
    for item in items {
        if let ChannelItem::Op(op) = item {
            if let OpKind::Revoke { removal } = &op.kind {
                if moderators.contains(op.created_by.as_str()) {
                    revoked.insert(removal.as_str());
                }
            }
        }
    }

    // 3. Dead record ids: an un-revoked Remove or a Supersede BY A MODERATOR kills its named target. An
    //    op by a non-moderator is skipped entirely — a deterministic no-op on every replica.
    let mut dead: BTreeSet<&str> = BTreeSet::new();
    for item in items {
        let ChannelItem::Op(op) = item else { continue };
        if !moderators.contains(op.created_by.as_str()) {
            continue;
        }
        let target = match &op.kind {
            OpKind::Remove { target } if !revoked.contains(op.id.as_str()) => target.as_str(),
            OpKind::Supersede { prior, .. } => prior.as_str(),
            OpKind::Remove { .. } | OpKind::Revoke { .. } => continue,
        };
        dead.insert(target);
    }

    // 4. Live = asserted records whose id is not dead.
    records
        .into_iter()
        .filter(|(id, _)| !dead.contains(id))
        .map(|(_, r)| r.clone())
        .collect()
}

/// Serialize a batch of [`ChannelItem`]s to / from the sealed payload bytes — the single op-batch
/// codec, shared by every transport (`openom-sync`'s `SyncClient`, the `openom-tree` engine) so
/// they emit byte-identical bytes and a future CBOR swap (OPE-199, `ldclabs/cbor2`) touches exactly one
/// place. V1 is plain `serde_json`; a decoded item's content-hash id is re-verified by `ChannelItem`'s
/// deserializer (the parse-don't-validate ingest boundary).
pub mod codec {
    use crate::ChannelItem;

    /// Encode a batch of channel items to the sealed payload bytes.
    pub fn encode(items: &[ChannelItem]) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(items)
    }

    /// Decode a sealed payload back to channel items (each id re-verified on decode).
    pub fn decode(bytes: &[u8]) -> Result<Vec<ChannelItem>, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests;
