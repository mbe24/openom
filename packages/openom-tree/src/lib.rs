#![doc = include_str!("../README.md")]

use std::collections::BTreeMap;

use openom_claim::envelope::{Anchor, Claim, Record};
use openom_crdt::{codec, materialize, ChannelItem, Op, OpKind};
use openom_projection::{project, Policy, Projection};
use serde_json::Value;

/// An edit or ingest failed.
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    /// Building or hashing a claim/record failed.
    #[error(transparent)]
    Claim(#[from] openom_claim::ClaimError),
    /// Minting or ingesting an operation failed.
    #[error(transparent)]
    Crdt(#[from] openom_crdt::CrdtError),
    /// Encoding/decoding an op batch failed.
    #[error("codec: {0}")]
    Codec(#[from] serde_json::Error),
}

/// The app-facing family-tree engine: the in-memory record set + the local author id. It composes the
/// `openom-crdt` fold and the `openom-projection` read model. Edits mint an operation, apply it to the
/// local set optimistically, and **return the encoded op-batch bytes** for the transport to seal +
/// append. It is **key-less** — it never touches the DEK.
pub struct Tree {
    /// The author stamped on every op this replica mints (a `did:key`; OPE-191 supplies it).
    created_by: String,
    /// The accumulated op set, keyed by content id (idempotent under re-delivery). The durable log
    /// lives in the transport; this is rebuilt by [`merge`](Tree::merge)-ing it back.
    items: BTreeMap<String, ChannelItem>,
}

impl Tree {
    /// A fresh engine for author `created_by` (the vault-derived `did:key`).
    pub fn new(created_by: impl Into<String>) -> Self {
        Tree {
            created_by: created_by.into(),
            items: BTreeMap::new(),
        }
    }

    /// The author this replica stamps on its ops.
    pub fn author(&self) -> &str {
        &self.created_by
    }

    // --- edits: mint an op, apply it optimistically, return the batch bytes to seal --------------

    /// Assert a new claim about `target`, authored by this replica.
    pub fn assert_claim(
        &mut self,
        target: &str,
        predicate: &str,
        value: Value,
        created_at: i64,
    ) -> Result<Vec<u8>, TreeError> {
        let mut c = Claim::new(
            target,
            predicate,
            value,
            self.created_by.as_str(),
            created_at,
        );
        c.compute_id()?;
        self.emit(ChannelItem::Assert(Record::Claim(c)))
    }

    /// Assert an identity anchor (Person / Event / Place / Tree) with the given id, authored by this
    /// replica. Anchor ids are opaque (a caller-minted UUID) — the engine does not generate them.
    pub fn assert_anchor(
        &mut self,
        id: &str,
        type_uri: &str,
        created_at: i64,
    ) -> Result<Vec<u8>, TreeError> {
        let anchor = Anchor {
            id: id.to_owned(),
            type_uri: type_uri.to_owned(),
            created_at,
            created_by: self.created_by.clone(),
        };
        self.emit(ChannelItem::Assert(Record::Anchor(anchor)))
    }

    /// Remove one of this author's own records by id (same-author observed-remove). Undoable by
    /// [`revoke`](Tree::revoke) up to the compaction (GC) horizon.
    pub fn remove(&mut self, target: &str, created_at: i64) -> Result<Vec<u8>, TreeError> {
        let op = Op::new(
            created_at,
            self.created_by.as_str(),
            OpKind::Remove {
                target: target.to_owned(),
            },
        )?;
        self.emit(ChannelItem::Op(op))
    }

    /// Edit: atomically supersede the `prior` record with a fresh claim value, authored by this
    /// replica.
    pub fn supersede_claim(
        &mut self,
        prior: &str,
        target: &str,
        predicate: &str,
        value: Value,
        created_at: i64,
    ) -> Result<Vec<u8>, TreeError> {
        let mut c = Claim::new(
            target,
            predicate,
            value,
            self.created_by.as_str(),
            created_at,
        );
        c.compute_id()?;
        let op = Op::new(
            created_at,
            self.created_by.as_str(),
            OpKind::Supersede {
                prior: prior.to_owned(),
                replacement: Box::new(Record::Claim(c)),
            },
        )?;
        self.emit(ChannelItem::Op(op))
    }

    /// Undo a same-author `Remove` by its operation id — restores the original record (before the GC
    /// horizon).
    pub fn revoke(&mut self, removal_op_id: &str, created_at: i64) -> Result<Vec<u8>, TreeError> {
        let op = Op::new(
            created_at,
            self.created_by.as_str(),
            OpKind::Revoke {
                removal: removal_op_id.to_owned(),
            },
        )?;
        self.emit(ChannelItem::Op(op))
    }

    /// Encode the minted item as a one-item batch, track it locally, and return the bytes. (A caller
    /// batching several edits into one entry can `merge` the concatenated set instead — pre-release.)
    fn emit(&mut self, item: ChannelItem) -> Result<Vec<u8>, TreeError> {
        let bytes = codec::encode(std::slice::from_ref(&item))?;
        self.items.insert(item.id().to_owned(), item);
        Ok(bytes)
    }

    // --- ingest / snapshot ----------------------------------------------------------------------

    /// Merge a peer's (or our own replayed) op batch into the set. Returns how many items were
    /// ingested. Idempotent — re-ingesting the same items re-inserts by id.
    pub fn merge(&mut self, bytes: &[u8]) -> Result<usize, TreeError> {
        let items = codec::decode(bytes)?;
        let n = items.len();
        for item in items {
            self.items.insert(item.id().to_owned(), item);
        }
        Ok(n)
    }

    /// The live record set as a snapshot batch (the fold's output, emitted as `Assert`s — removed and
    /// superseded records fold out). A fresh engine can [`load_snapshot`](Tree::load_snapshot) it and
    /// then `merge` only the tail.
    pub fn snapshot(&self) -> Result<Vec<u8>, TreeError> {
        let live: Vec<ChannelItem> = self
            .materialized()
            .into_iter()
            .map(ChannelItem::Assert)
            .collect();
        Ok(codec::encode(&live)?)
    }

    /// Load a snapshot batch into the set (idempotent; combine with further `merge`d tail ops).
    pub fn load_snapshot(&mut self, bytes: &[u8]) -> Result<(), TreeError> {
        for item in codec::decode(bytes)? {
            self.items.insert(item.id().to_owned(), item);
        }
        Ok(())
    }

    // --- read -----------------------------------------------------------------------------------

    /// The materialized read model (people, unions, events, …) over the live record set.
    pub fn project(&self) -> Projection {
        project(&self.materialized(), &Policy::default())
    }

    /// The read model as a JSON string — for the wasm boundary and any JSON consumer.
    pub fn project_json(&self) -> Result<String, TreeError> {
        Ok(serde_json::to_string(&self.project())?)
    }

    /// The live claims about `target` under `predicate` (after the fold), each as its JSON record — a
    /// granular reader for the editor (e.g. which name claims exist on a person, to supersede one).
    pub fn live_claims_of(&self, target: &str, predicate: &str) -> Vec<Value> {
        self.materialized()
            .iter()
            .filter_map(|r| match r {
                Record::Claim(c)
                    if c.target_id.as_str() == target && c.predicate.as_str() == predicate =>
                {
                    Some(c.to_value())
                }
                _ => None,
            })
            .collect()
    }

    /// The canonical person id an anchor resolves to (its cluster's minimum-anchor id), or `None` if
    /// the anchor is not part of any projected person.
    pub fn resolve_id(&self, anchor: &str) -> Option<String> {
        self.project().people.into_iter().find_map(|p| {
            let hit = p.id.as_str() == anchor || p.also.iter().any(|a| a.as_str() == anchor);
            hit.then_some(p.id)
        })
    }

    /// The live record set — the `openom-crdt` fold over the accumulated ops.
    fn materialized(&self) -> Vec<Record> {
        let items: Vec<ChannelItem> = self.items.values().cloned().collect();
        materialize(&items)
    }
}

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(test)]
mod tests;
