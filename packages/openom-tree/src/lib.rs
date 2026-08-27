#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};

use openom_claim::envelope::{Anchor, Claim, Record, PREDICATE_EXISTENCE};
use openom_claim::Hlc;
use openom_crdt::{codec, materialize, ChannelItem, Op, OpKind};
use openom_projection::{project, Policy, Projection};
use serde_json::Value;

/// Logical ticks per physical millisecond before the counter carries into the next millisecond —
/// matches the wire form's three-digit logical field (see [`Hlc`]).
const LOGICAL_PER_MILLI: u32 = 1000;

/// The engine-owned Hybrid Logical Clock. Every mint stamps `created_at` through [`next`](HlcClock::next),
/// so no caller can supply a non-monotonic or colliding timestamp; every ingest advances it through
/// [`observe`](HlcClock::observe) (the HLC receive rule), so after hydrating a set the next local mint is
/// past every timestamp already present. Together these make the id-collision bug — where a fast
/// create→undo→redo (even across a reload or a second device) reproduced a still-tombstoned id —
/// structurally impossible: a re-assert always draws a fresh, unused `created_at`. The caller passes only
/// a physical wall-clock reading (`Date::now()` on the web); the clock sanitizes it.
#[derive(Default)]
struct HlcClock {
    last_millis: i64,
    logical: u32,
}

impl HlcClock {
    /// The next strictly-greater timestamp given a physical reading. If the wall clock advanced, take it
    /// with a reset logical counter; otherwise (a tie or a backwards reading) bump the logical counter,
    /// carrying into `millis` if it would exceed the three-digit field — so the result is always both
    /// strictly monotonic and canonically representable.
    fn next(&mut self, now_millis: i64) -> Hlc {
        if now_millis > self.last_millis {
            self.last_millis = now_millis;
            self.logical = 0;
        } else {
            self.logical += 1;
            while self.logical >= LOGICAL_PER_MILLI {
                self.last_millis += 1;
                self.logical -= LOGICAL_PER_MILLI;
            }
        }
        Hlc::new(self.last_millis, self.logical)
    }

    /// The receive rule: advance so the clock is at least as high as a timestamp just ingested (from a
    /// peer's op or a snapshot). A subsequent [`next`](HlcClock::next) is then strictly greater than
    /// everything seen, so a re-mint can never collide with an existing id.
    fn observe(&mut self, at: Hlc) {
        if (at.millis(), at.logical()) > (self.last_millis, self.logical) {
            self.last_millis = at.millis();
            self.logical = at.logical();
        }
    }
}

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
    /// The `did:key`s CURRENTLY authorized to moderate (Maintainer or above) — the only authors whose
    /// Remove/Supersede/Revoke ops the fold honors. Defaults to `{ created_by }`: a solo tree's owner
    /// moderates their own tree. A shared tree calls [`set_moderators`](Tree::set_moderators) with the
    /// keyring's Maintainer+ set on unlock and on every keyring-head change (so a role change re-folds).
    moderators: BTreeSet<String>,
    /// Items minted in the current intention, accumulated by [`emit`](Tree::emit) and encoded into one
    /// op-batch by [`flush`](Tree::flush): one settled edit = one sealed entry, so a peer never sees a
    /// half-formed record set (e.g. an event anchor with no type). Applied to `items` immediately.
    pending: Vec<ChannelItem>,
    /// The engine-owned monotonic clock that stamps `created_at` on every mint (see [`HlcClock`]).
    clock: HlcClock,
}

impl Tree {
    /// A fresh engine for author `created_by` (the vault-derived `did:key`).
    pub fn new(created_by: impl Into<String>) -> Self {
        let created_by = created_by.into();
        Tree {
            moderators: BTreeSet::from([created_by.clone()]),
            created_by,
            items: BTreeMap::new(),
            pending: Vec::new(),
            clock: HlcClock::default(),
        }
    }

    /// The author this replica stamps on its ops.
    pub fn author(&self) -> &str {
        &self.created_by
    }

    /// Replace the moderator set (the `did:key`s currently at Maintainer+). Call on unlock and whenever
    /// the governing keyring changes — the very next read re-folds against the new roles, so a demotion
    /// resurfaces what the demoted member's ops had hidden and a promotion applies their authority.
    pub fn set_moderators(&mut self, moderators: BTreeSet<String>) {
        self.moderators = moderators;
    }

    // --- edits: mint an op, apply it optimistically, return the batch bytes to seal --------------

    /// Assert a new claim about `target`, authored by this replica. `now_millis` is a physical
    /// wall-clock reading (epoch ms); the engine-owned clock turns it into the monotonic `createdAt`.
    pub fn assert_claim(
        &mut self,
        target: &str,
        predicate: &str,
        value: Value,
        now_millis: i64,
    ) -> Result<Vec<u8>, TreeError> {
        let at = self.clock.next(now_millis);
        let mut c = Claim::new(target, predicate, value, self.created_by.as_str(), at);
        c.compute_id()?;
        self.emit(vec![ChannelItem::Assert(Record::Claim(c))])
    }

    /// Assert an identity anchor (Person / Event / Place / Tree) with the given id, authored by this
    /// replica. Anchor ids are opaque (a caller-minted UUID) — the engine does not generate them.
    ///
    /// The anchor is born with its **existence claim** (`PREDICATE_EXISTENCE`, value `{}`) in the same
    /// batch — the single root proposition "this individual is real". It is the citation host for
    /// evidence of existence and the target other authors `attest`/refute; they never mint a second
    /// existence claim. The anchor and its existence claim share this call's one clock tick.
    ///
    /// Crash-retry idempotency is a **byte-replay** property, not a re-mint one: the engine's clock
    /// always advances, so calling `assert_anchor` again would mint a *different* `createdAt` (hence a
    /// different existence-claim id). A retry instead replays the persisted op-batch bytes through
    /// [`merge`](Tree::merge), which re-inserts by id — idempotent by construction.
    pub fn assert_anchor(
        &mut self,
        id: &str,
        type_uri: &str,
        now_millis: i64,
    ) -> Result<Vec<u8>, TreeError> {
        let at = self.clock.next(now_millis);
        let anchor = Anchor {
            id: id.to_owned(),
            type_uri: type_uri.to_owned(),
            created_at: at,
            created_by: self.created_by.clone(),
        };
        let mut existence = Claim::new(
            id,
            PREDICATE_EXISTENCE,
            Value::Object(serde_json::Map::new()),
            self.created_by.as_str(),
            at,
        );
        existence.compute_id()?;
        self.emit(vec![
            ChannelItem::Assert(Record::Anchor(anchor)),
            ChannelItem::Assert(Record::Claim(existence)),
        ])
    }

    /// Remove one of this author's own records by id (same-author observed-remove). Undoable by
    /// [`revoke`](Tree::revoke) up to the compaction (GC) horizon. Returns the Remove op's own id so
    /// the caller can later revoke it — the minted op only reaches the store on the next [`flush`], but
    /// its content id is known now.
    pub fn remove(&mut self, target: &str, now_millis: i64) -> Result<String, TreeError> {
        let op = Op::new(
            self.clock.next(now_millis),
            self.created_by.as_str(),
            OpKind::Remove {
                target: target.to_owned(),
            },
        )?;
        let item = ChannelItem::Op(op);
        let id = item.id().to_owned();
        self.emit(vec![item])?;
        Ok(id)
    }

    /// Edit: atomically supersede the `prior` record with a fresh claim value, authored by this
    /// replica.
    pub fn supersede_claim(
        &mut self,
        prior: &str,
        target: &str,
        predicate: &str,
        value: Value,
        now_millis: i64,
    ) -> Result<Vec<u8>, TreeError> {
        // The replacement claim and the enclosing op are one atomic edit — they share one clock tick.
        let at = self.clock.next(now_millis);
        let mut c = Claim::new(target, predicate, value, self.created_by.as_str(), at);
        c.compute_id()?;
        let op = Op::new(
            at,
            self.created_by.as_str(),
            OpKind::Supersede {
                prior: prior.to_owned(),
                replacement: Box::new(Record::Claim(c)),
            },
        )?;
        self.emit(vec![ChannelItem::Op(op)])
    }

    /// Undo a same-author `Remove` by its operation id — restores the original record (before the GC
    /// horizon).
    pub fn revoke(&mut self, removal_op_id: &str, now_millis: i64) -> Result<Vec<u8>, TreeError> {
        let op = Op::new(
            self.clock.next(now_millis),
            self.created_by.as_str(),
            OpKind::Revoke {
                removal: removal_op_id.to_owned(),
            },
        )?;
        self.emit(vec![ChannelItem::Op(op)])
    }

    /// Accumulate the minted item(s) into the current intention's batch and apply them to the live set
    /// immediately (so a later read in the same intention sees them). The encoded op-batch is produced
    /// once by [`flush`](Tree::flush), not here — so a whole edit (e.g. `addMarriage` with its event) is
    /// one sealed entry rather than a train of single-op entries a peer could observe half-formed.
    /// Returns no bytes (an empty vec, so the mint methods keep their signature) — [`flush`](Tree::flush)
    /// is the sole producer of the encoded batch.
    fn emit(&mut self, items: Vec<ChannelItem>) -> Result<Vec<u8>, TreeError> {
        for item in items {
            self.pending.push(item.clone());
            self.items.insert(item.id().to_owned(), item);
        }
        Ok(Vec::new())
    }

    /// Encode everything minted since the last flush as ONE op-batch and clear the buffer (empty bytes
    /// if nothing was minted). The single emit point: the caller flushes once per settled intention.
    pub fn flush(&mut self) -> Result<Vec<u8>, TreeError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        let batch = codec::encode(&self.pending)?;
        self.pending.clear();
        Ok(batch)
    }

    // --- ingest / snapshot ----------------------------------------------------------------------

    /// Merge a peer's (or our own replayed) op batch into the set. Returns how many items were
    /// ingested. Idempotent — re-ingesting the same items re-inserts by id.
    pub fn merge(&mut self, bytes: &[u8]) -> Result<usize, TreeError> {
        let items = codec::decode(bytes)?;
        let n = items.len();
        for item in items {
            self.clock.observe(item.created_at());
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
            self.clock.observe(item.created_at());
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

    /// Every live claim about `target`, whatever its predicate (after the fold) — the predicate-less
    /// reader a generic renderer uses to enumerate a subject's claims, **including** ones under
    /// predicates this build doesn't recognize (whose projection counterpart is `Person.other` /
    /// `Projection.unclassified`). So a newer app version's data is editable here with no code change.
    pub fn live_claims_of_any(&self, target: &str) -> Vec<Value> {
        self.materialized()
            .iter()
            .filter_map(|r| match r {
                Record::Claim(c) if c.target_id.as_str() == target => Some(c.to_value()),
                _ => None,
            })
            .collect()
    }

    /// Every live record (anchors + claims), each as its JSON — the granular set the app's undo/redo
    /// diff reads to compute what a commit added vs. removed (keyed by content-hash id).
    pub fn live_records(&self) -> Result<Vec<Value>, TreeError> {
        Ok(self
            .materialized()
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?)
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
        materialize(&items, &self.moderators)
    }
}

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(test)]
mod tests;
