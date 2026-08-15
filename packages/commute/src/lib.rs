//! `commute` — a small, self-contained **operation-based CRDT**.
//!
//! `commute` is deliberately NOT a JSON/document CRDT. It merges a keyed collection of **typed
//! cells** — each with its own convergent merge rule — via **self-contained operations**: every op
//! names its own target and carries everything needed to apply it, referencing no other op. That is
//! the defining property, and it buys three things at once:
//!
//! - **order-independence** — ops commute, so replicas that have seen the same set of ops agree,
//!   regardless of delivery order (proven by the convergence property test);
//! - **idempotence** — re-delivering an op is a no-op, so at-least-once sync is safe;
//! - **discardable proposals** — because nothing depends on a given op, a rejected op leaves no
//!   dangling references (the property that makes an approval/reject gate clean; see `openom-treelog`).
//!
//! Ordering is a **Lamport clock** `(lamport, replica)`, never wall-clock time — so merge decisions
//! are deterministic and immune to device clock skew. The **engine owns the clock**: a caller hands
//! in an unstamped [`OpIntent`] and [`Doc::apply_local`] stamps it. Leaf [`Value`]s are opaque and
//! contain **no floats** (values become a canonical archive encoding downstream; floats have no
//! canonical form).
//!
//! This first slice provides two cell kinds — an **LWW register** and a **tombstoned OR-set** — plus
//! the Lamport kernel and merge. Richer cells (sourced-claim sets, keyed-ordered collections), the
//! canonical byte codec, and snapshot/compaction land in later slices behind the same op model.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub mod codec;
pub use codec::DecodeError;

/// A replica's stable identity — the tiebreaker in the Lamport order. Opaque 16 bytes.
pub type ReplicaId = [u8; 16];

/// Per-replica high-water mark (max lamport seen from each replica) — a document's version. Used to
/// request "everything after what I already have" for coarse, log-based sync.
pub type VersionVector = BTreeMap<ReplicaId, u64>;
/// An opaque cell address. The domain layer chooses the addressing scheme (e.g. entity+field).
pub type CellId = Vec<u8>;
/// An element's stable identity within a set — the CRDT merge key (never positional).
pub type ElemId = Vec<u8>;

/// A Lamport timestamp. `Ord` is lexicographic `(lamport, replica)` — a **total** order over all
/// ops, so two concurrent writes always have a deterministic, skew-free winner. Distinct ops never
/// share a stamp (a replica never reuses a lamport value), so equality means "the same op".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Stamp {
    pub lamport: u64,
    pub replica: ReplicaId,
}

/// An opaque leaf value stored in a cell. Closed set, **no floats** (they have no canonical archive
/// form). `commute` never merges *inside* a value — a value is an indivisible leaf.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Value {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    Bytes(Vec<u8>),
    Text(String),
}

/// An **unstamped** operation — what a caller (or a format bridge) produces. The engine assigns the
/// Lamport stamp at [`Doc::apply_local`], so callers never fabricate stamps.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OpIntent {
    /// Set an LWW register cell to `value` (last writer by Lamport stamp wins).
    SetRegister { cell: CellId, value: Value },
    /// Add (or update) element `elem` in a set cell, carrying an opaque `value` payload.
    AddElement { cell: CellId, elem: ElemId, value: Value },
    /// Tombstone element `elem` in a set cell. Later stamp wins between an element's add and remove.
    RemoveElement { cell: CellId, elem: ElemId },
}

/// A **stamped** operation — the unit that is sealed and synced. Self-contained: applying it needs
/// nothing but itself.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Op {
    pub stamp: Stamp,
    pub intent: OpIntent,
}

/// One element of a set cell: the winning add (max stamp + its value) and the winning tombstone
/// (max stamp). The element is live iff it has an add that out-stamps its tombstone.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct SetEntry {
    add: Option<(Stamp, Value)>,
    tomb: Option<Stamp>,
}

impl SetEntry {
    fn live(&self) -> bool {
        match (&self.add, &self.tomb) {
            (Some((a, _)), Some(t)) => a > t,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// A commute document: a set of typed cells plus this replica's Lamport clock. All merge state is
/// held in `BTreeMap`s, so iteration order is deterministic (the basis for a canonical checkpoint).
#[derive(Clone, Debug)]
pub struct Doc {
    replica: ReplicaId,
    lamport: u64,
    vv: VersionVector,
    registers: BTreeMap<CellId, (Stamp, Value)>,
    sets: BTreeMap<CellId, BTreeMap<ElemId, SetEntry>>,
}

impl Doc {
    /// A fresh, empty document for `replica`.
    pub fn new(replica: ReplicaId) -> Self {
        Doc { replica, lamport: 0, vv: VersionVector::new(), registers: BTreeMap::new(), sets: BTreeMap::new() }
    }

    /// Reconstruct a document from a snapshot (or any op run) produced by [`Doc::snapshot`].
    pub fn from_snapshot(replica: ReplicaId, bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Doc::new(replica);
        d.merge_bytes(bytes)?;
        Ok(d)
    }

    /// Apply a **local** edit: the engine stamps `intent` with `(lamport+1, replica)`, integrates
    /// it, and returns the stamped [`Op`] for the caller to seal/sync. The clock owner is here — a
    /// caller can never mint a stamp itself.
    pub fn apply_local(&mut self, intent: OpIntent) -> Op {
        self.lamport += 1;
        let op = Op { stamp: Stamp { lamport: self.lamport, replica: self.replica }, intent };
        self.integrate(&op);
        op
    }

    /// Integrate a stamped [`Op`] from anywhere — **idempotent and commutative**. Advances the
    /// Lamport clock past the op's stamp (the merge half of the Lamport rule).
    pub fn merge_op(&mut self, op: &Op) {
        if op.stamp.lamport > self.lamport {
            self.lamport = op.stamp.lamport;
        }
        self.integrate(op);
    }

    /// The order-independent core: every cell keeps only max-stamped state, so applying ops in any
    /// order (or twice) converges to the same result.
    fn integrate(&mut self, op: &Op) {
        let hw = self.vv.entry(op.stamp.replica).or_insert(0);
        if op.stamp.lamport > *hw {
            *hw = op.stamp.lamport;
        }
        match &op.intent {
            OpIntent::SetRegister { cell, value } => match self.registers.get(cell) {
                Some((s, _)) if *s >= op.stamp => {}
                _ => {
                    self.registers.insert(cell.clone(), (op.stamp, value.clone()));
                }
            },
            OpIntent::AddElement { cell, elem, value } => {
                let e = self.sets.entry(cell.clone()).or_default().entry(elem.clone()).or_default();
                match &e.add {
                    Some((s, _)) if *s >= op.stamp => {}
                    _ => e.add = Some((op.stamp, value.clone())),
                }
            }
            OpIntent::RemoveElement { cell, elem } => {
                let e = self.sets.entry(cell.clone()).or_default().entry(elem.clone()).or_default();
                if e.tomb.map_or(true, |t| op.stamp > t) {
                    e.tomb = Some(op.stamp);
                }
            }
        }
    }

    /// The current value of an LWW register cell, if set.
    pub fn register(&self, cell: &[u8]) -> Option<&Value> {
        self.registers.get(cell).map(|(_, v)| v)
    }

    /// The live elements of a set cell (tombstoned elements excluded), in deterministic id order.
    pub fn set_elements(&self, cell: &[u8]) -> Vec<(&ElemId, &Value)> {
        self.sets
            .get(cell)
            .into_iter()
            .flatten()
            .filter(|(_, e)| e.live())
            .filter_map(|(id, e)| e.add.as_ref().map(|(_, v)| (id, v)))
            .collect()
    }

    /// This document's version — the high-water mark per replica. Hand it to a peer's
    /// [`Doc::delta_since`] to fetch only what this replica is missing.
    pub fn version(&self) -> VersionVector {
        self.vv.clone()
    }

    fn covered(vv: &VersionVector, s: &Stamp) -> bool {
        vv.get(&s.replica).is_some_and(|&l| l >= s.lamport)
    }

    /// Reconstruct the ops whose state is newer than `vv`, in canonical order (registers then sets,
    /// each in id order). Because every cell keeps only its max-stamped state, this is a compacted
    /// delta — the state *is* the log. With an empty `vv` it is the full snapshot.
    fn ops_since(&self, vv: &VersionVector) -> Vec<Op> {
        let mut ops = Vec::new();
        for (cell, (s, v)) in &self.registers {
            if !Self::covered(vv, s) {
                ops.push(Op { stamp: *s, intent: OpIntent::SetRegister { cell: cell.clone(), value: v.clone() } });
            }
        }
        for (cell, elems) in &self.sets {
            for (elem, e) in elems {
                if let Some((s, v)) = &e.add {
                    if !Self::covered(vv, s) {
                        ops.push(Op { stamp: *s, intent: OpIntent::AddElement { cell: cell.clone(), elem: elem.clone(), value: v.clone() } });
                    }
                }
                if let Some(s) = &e.tomb {
                    if !Self::covered(vv, s) {
                        ops.push(Op { stamp: *s, intent: OpIntent::RemoveElement { cell: cell.clone(), elem: elem.clone() } });
                    }
                }
            }
        }
        ops
    }

    /// The full state as canonical bytes — for first sync or after a peer compacted. Two converged
    /// replicas produce byte-identical snapshots.
    pub fn snapshot(&self) -> Vec<u8> {
        codec::encode_ops(&self.ops_since(&VersionVector::new()))
    }

    /// Just the state newer than `vv`, as canonical bytes — the coarse "everything after" delta.
    pub fn delta_since(&self, vv: &VersionVector) -> Vec<u8> {
        codec::encode_ops(&self.ops_since(vv))
    }

    /// Integrate a snapshot or delta produced by [`Doc::snapshot`]/[`Doc::delta_since`]. Idempotent
    /// and commutative like [`Doc::merge_op`]. On a decode error nothing is applied.
    pub fn merge_bytes(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        let ops = codec::decode_ops(bytes)?;
        for op in &ops {
            self.integrate(op);
            if op.stamp.lamport > self.lamport {
                self.lamport = op.stamp.lamport;
            }
        }
        Ok(())
    }

    /// A **canonical, replica-independent** projection of the merge state. Two replicas that have
    /// integrated the same set of ops produce EQUAL checkpoints — this is the convergence oracle
    /// (a later slice replaces it with canonical-CBOR byte equality). The local replica id and
    /// Lamport counter are deliberately excluded, since they legitimately differ between replicas.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint { registers: self.registers.clone(), sets: self.sets.clone() }
    }
}

/// The comparable, order-independent state of a [`Doc`] (see [`Doc::checkpoint`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    registers: BTreeMap<CellId, (Stamp, Value)>,
    sets: BTreeMap<CellId, BTreeMap<ElemId, SetEntry>>,
}

#[cfg(test)]
mod tests;
