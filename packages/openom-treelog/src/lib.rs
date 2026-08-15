//! `openom-treelog` — the family-tree domain layer, composed over the [`commute`] op-based CRDT.
//!
//! `commute` provides typed convergent *cells* (LWW registers, tombstoned OR-sets) and self-contained
//! ops; this crate maps the genealogy model onto them. The design choice that matters most here is how
//! a **fact** is represented. A birth date is NOT an overwritable scalar — two relatives who record
//! different dates must both be *kept*, as competing **sourced claims** for a human to adjudicate;
//! silent last-writer-wins is genealogically wrong. So a fact is:
//!
//! - an OR-set of [`Claim`]s (each `AddClaim` names a caller-minted [`ClaimId`], so a crash-retry is
//!   idempotent and never mints a duplicate), plus
//! - an LWW register holding the *preferred* claim pointer.
//!
//! Person/family existence and relationships (child, spouse) are OR-sets of ids. Everything inherits
//! `commute`'s convergence: any concurrent edits, in any order, converge — and competing facts are
//! retained, not clobbered.
//!
//! This first slice covers persons and their sourced facts. Relationships, media, `MoveChild`,
//! batched actions, and the proposal/approval flow build on the same op model in later slices.

#![forbid(unsafe_code)]

use commute::{CellId, Doc, Op, OpIntent, ReplicaId, Value};

/// A caller-minted person id (opaque; the merge key for a person).
pub type PersonId = Vec<u8>;
/// A caller-minted family id (opaque; the merge key for a family/union).
pub type FamilyId = Vec<u8>;
/// A fact key on a person, e.g. `"birth.date"`, `"name.given"`. Part of a fact's cell address.
pub type FieldKey = String;
/// A caller-minted claim id (opaque; the merge key for one claim within a fact).
pub type ClaimId = Vec<u8>;

/// How a child belongs to a family. A child can legitimately belong to more than one family (a birth
/// family and an adoptive one), so this is per child-link, not per person.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Pedigree {
    #[default]
    Birth,
    Adopted,
    Foster,
    Step,
    Unknown,
}

impl Pedigree {
    fn tag(self) -> i64 {
        match self {
            Pedigree::Birth => 0,
            Pedigree::Adopted => 1,
            Pedigree::Foster => 2,
            Pedigree::Step => 3,
            Pedigree::Unknown => 4,
        }
    }
    fn from_tag(t: i64) -> Pedigree {
        match t {
            1 => Pedigree::Adopted,
            2 => Pedigree::Foster,
            3 => Pedigree::Step,
            4 => Pedigree::Unknown,
            _ => Pedigree::Birth,
        }
    }
}

// Cell-kind tags — the first byte of every [`CellId`], keeping the address spaces disjoint.
const KIND_PERSONS: u8 = 1; // the set of live person ids
const KIND_FACT_CLAIMS: u8 = 2; // per (person, field): the OR-set of claims
const KIND_FACT_PREFERRED: u8 = 3; // per (person, field): the preferred-claim register
const KIND_FAMILIES: u8 = 4; // the set of live family ids
const KIND_CHILDREN: u8 = 5; // per family: the OR-set of child person ids (value = pedigree)
const KIND_SPOUSES: u8 = 6; // per family: the OR-set of spouse/partner person ids

/// Build a length-prefixed, kind-tagged cell address from its parts (collision-free across kinds).
fn cell(kind: u8, parts: &[&[u8]]) -> CellId {
    let mut c = vec![kind];
    for p in parts {
        c.extend_from_slice(&(p.len() as u32).to_be_bytes());
        c.extend_from_slice(p);
    }
    c
}

fn persons_cell() -> CellId {
    cell(KIND_PERSONS, &[])
}
fn fact_claims_cell(person: &[u8], field: &str) -> CellId {
    cell(KIND_FACT_CLAIMS, &[person, field.as_bytes()])
}
fn fact_preferred_cell(person: &[u8], field: &str) -> CellId {
    cell(KIND_FACT_PREFERRED, &[person, field.as_bytes()])
}
fn families_cell() -> CellId {
    cell(KIND_FAMILIES, &[])
}
fn children_cell(family: &[u8]) -> CellId {
    cell(KIND_CHILDREN, &[family])
}
fn spouses_cell(family: &[u8]) -> CellId {
    cell(KIND_SPOUSES, &[family])
}

/// A single sourced assertion about a fact — the value plus its provenance. Distinct claims stay
/// distinct even with equal values (two sources recording "1903" is genuine corroboration).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Claim {
    pub id: ClaimId,
    pub value: String,
    pub source: Option<String>,
}

/// A fact's full state: every retained claim, plus which one is currently preferred for display.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Fact {
    /// All live claims, in deterministic id order. More than one ⇒ a conflict awaiting adjudication.
    pub claims: Vec<Claim>,
    /// The preferred claim: the explicitly-set pointer if it still names a live claim, else a
    /// deterministic fallback (the greatest claim id) so every replica displays the same one.
    pub preferred: Option<Claim>,
}

/// A typed family-tree edit. Each maps to exactly one self-contained `commute` op (batched actions
/// come later). `AddClaim` carries its own `claim` id — every op names the ids it creates, so a
/// retried op is idempotent.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TreeOp {
    AddPerson { id: PersonId },
    RemovePerson { id: PersonId },
    AddClaim { person: PersonId, field: FieldKey, claim: ClaimId, value: String, source: Option<String> },
    SetPreferredClaim { person: PersonId, field: FieldKey, claim: ClaimId },
    RetractClaim { person: PersonId, field: FieldKey, claim: ClaimId },
    AddFamily { id: FamilyId },
    RemoveFamily { id: FamilyId },
    LinkChild { family: FamilyId, person: PersonId, pedi: Pedigree },
    UnlinkChild { family: FamilyId, person: PersonId },
    /// Re-parent a child atomically: drop the `from` link and add the `to` link. First-class so the
    /// intent survives in a proposal bundle ("moved child Y from F1 to F2"), not an inferred pair.
    MoveChild { person: PersonId, from: FamilyId, to: FamilyId, pedi: Pedigree },
    LinkSpouse { family: FamilyId, person: PersonId },
    UnlinkSpouse { family: FamilyId, person: PersonId },
}

impl TreeOp {
    /// The one-or-more self-contained `commute` intents this edit expands to. Most are a single
    /// intent; `MoveChild` is two (an unlink then a link) applied as one atomic action.
    fn into_intents(self) -> Vec<OpIntent> {
        match self {
            TreeOp::AddPerson { id } => vec![OpIntent::AddElement { cell: persons_cell(), elem: id, value: Value::Null }],
            TreeOp::RemovePerson { id } => vec![OpIntent::RemoveElement { cell: persons_cell(), elem: id }],
            TreeOp::AddClaim { person, field, claim, value, source } => vec![OpIntent::AddElement {
                cell: fact_claims_cell(&person, &field),
                elem: claim,
                value: Value::Bytes(encode_claim(&value, source.as_deref())),
            }],
            TreeOp::SetPreferredClaim { person, field, claim } => {
                vec![OpIntent::SetRegister { cell: fact_preferred_cell(&person, &field), value: Value::Bytes(claim) }]
            }
            TreeOp::RetractClaim { person, field, claim } => {
                vec![OpIntent::RemoveElement { cell: fact_claims_cell(&person, &field), elem: claim }]
            }
            TreeOp::AddFamily { id } => vec![OpIntent::AddElement { cell: families_cell(), elem: id, value: Value::Null }],
            TreeOp::RemoveFamily { id } => vec![OpIntent::RemoveElement { cell: families_cell(), elem: id }],
            TreeOp::LinkChild { family, person, pedi } => {
                vec![OpIntent::AddElement { cell: children_cell(&family), elem: person, value: Value::I64(pedi.tag()) }]
            }
            TreeOp::UnlinkChild { family, person } => {
                vec![OpIntent::RemoveElement { cell: children_cell(&family), elem: person }]
            }
            TreeOp::MoveChild { person, from, to, pedi } => vec![
                OpIntent::RemoveElement { cell: children_cell(&from), elem: person.clone() },
                OpIntent::AddElement { cell: children_cell(&to), elem: person, value: Value::I64(pedi.tag()) },
            ],
            TreeOp::LinkSpouse { family, person } => {
                vec![OpIntent::AddElement { cell: spouses_cell(&family), elem: person, value: Value::Null }]
            }
            TreeOp::UnlinkSpouse { family, person } => {
                vec![OpIntent::RemoveElement { cell: spouses_cell(&family), elem: person }]
            }
        }
    }
}

/// A family tree — a [`commute::Doc`] with the genealogy read/write model on top.
#[derive(Clone, Debug)]
pub struct Tree {
    doc: Doc,
}

impl Tree {
    /// A fresh, empty tree for `replica`.
    pub fn new(replica: ReplicaId) -> Self {
        Tree { doc: Doc::new(replica) }
    }

    /// Rebuild from a `commute` snapshot.
    pub fn from_snapshot(replica: ReplicaId, bytes: &[u8]) -> Result<Self, commute::DecodeError> {
        Ok(Tree { doc: Doc::from_snapshot(replica, bytes)? })
    }

    /// Apply a local edit; returns the stamped `commute` op(s) to seal and sync (usually one, two
    /// for `MoveChild`).
    pub fn apply(&mut self, op: TreeOp) -> Vec<Op> {
        op.into_intents().into_iter().map(|i| self.doc.apply_local(i)).collect()
    }

    /// Apply several edits as **one atomic action** — the natural unit for a user action that spans
    /// records (e.g. "add a marriage" = a family + links). The returned ops are sealed/persisted
    /// together by the caller, so a crash never lands half an action.
    pub fn apply_batch(&mut self, ops: Vec<TreeOp>) -> Vec<Op> {
        ops.into_iter().flat_map(TreeOp::into_intents).map(|i| self.doc.apply_local(i)).collect()
    }

    /// The underlying document — for sync (`snapshot`/`delta_since`/`merge_bytes`/`version`).
    pub fn doc(&self) -> &Doc {
        &self.doc
    }
    /// Mutable access for integrating remote ops/deltas.
    pub fn doc_mut(&mut self) -> &mut Doc {
        &mut self.doc
    }

    /// The live person ids, in deterministic order.
    pub fn persons(&self) -> Vec<PersonId> {
        self.doc.set_elements(&persons_cell()).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// Whether a person currently exists (added and not tombstoned).
    pub fn has_person(&self, id: &[u8]) -> bool {
        self.doc.set_elements(&persons_cell()).iter().any(|(e, _)| e.as_slice() == id)
    }

    /// The live family ids, in deterministic order.
    pub fn families(&self) -> Vec<FamilyId> {
        self.doc.set_elements(&families_cell()).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// The children of a family, each with its pedigree, in deterministic person-id order.
    pub fn children_of(&self, family: &[u8]) -> Vec<(PersonId, Pedigree)> {
        self.doc
            .set_elements(&children_cell(family))
            .into_iter()
            .map(|(id, v)| {
                let pedi = match v {
                    Value::I64(t) => Pedigree::from_tag(*t),
                    _ => Pedigree::Unknown,
                };
                (id.clone(), pedi)
            })
            .collect()
    }

    /// The spouses/partners of a family, in deterministic person-id order.
    pub fn spouses_of(&self, family: &[u8]) -> Vec<PersonId> {
        self.doc.set_elements(&spouses_cell(family)).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// A person's fact: every retained claim + the preferred one. Empty if the fact has no claims.
    pub fn fact(&self, person: &[u8], field: &str) -> Fact {
        let mut claims: Vec<Claim> = self
            .doc
            .set_elements(&fact_claims_cell(person, field))
            .into_iter()
            .filter_map(|(id, v)| match v {
                Value::Bytes(b) => decode_claim(b).map(|(value, source)| Claim { id: id.clone(), value, source }),
                _ => None,
            })
            .collect();
        claims.sort_by(|a, b| a.id.cmp(&b.id));

        // Preferred: the explicit pointer if it still names a live claim; else the greatest id.
        let pointer = match self.doc.register(&fact_preferred_cell(person, field)) {
            Some(Value::Bytes(id)) => Some(id.clone()),
            _ => None,
        };
        let preferred = pointer
            .and_then(|id| claims.iter().find(|c| c.id == id).cloned())
            .or_else(|| claims.last().cloned());

        Fact { claims, preferred }
    }
}

// ---- claim payload encoding (stored opaquely inside a commute Value::Bytes) --------------------

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn encode_claim(value: &str, source: Option<&str>) -> Vec<u8> {
    let mut o = Vec::new();
    put_str(&mut o, value);
    match source {
        Some(s) => {
            o.push(1);
            put_str(&mut o, s);
        }
        None => o.push(0),
    }
    o
}

fn take_str(b: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 4 > b.len() {
        return None;
    }
    let n = u32::from_be_bytes(b[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if *pos + n > b.len() {
        return None;
    }
    let s = String::from_utf8(b[*pos..*pos + n].to_vec()).ok()?;
    *pos += n;
    Some(s)
}

/// Decode a claim payload. Returns `None` on malformed bytes (defensive — the payload is opaque to
/// `commute` and could in principle be corrupt).
fn decode_claim(b: &[u8]) -> Option<(String, Option<String>)> {
    let mut pos = 0;
    let value = take_str(b, &mut pos)?;
    let has_source = *b.get(pos)?;
    pos += 1;
    let source = match has_source {
        0 => None,
        1 => Some(take_str(b, &mut pos)?),
        _ => return None,
    };
    Some((value, source))
}

#[cfg(test)]
mod tests;
