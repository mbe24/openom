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

mod wire;
pub use wire::ProposalError;

#[cfg(feature = "wasm")]
mod wasm;

/// A caller-minted person id (opaque; the merge key for a person).
pub type PersonId = Vec<u8>;
/// A caller-minted family id (opaque; the merge key for a family/union).
pub type FamilyId = Vec<u8>;
/// A fact key on a person, e.g. `"birth.date"`, `"name.given"`. Part of a fact's cell address.
pub type FieldKey = String;
/// A caller-minted claim id (opaque; the merge key for one claim within a fact).
pub type ClaimId = Vec<u8>;
/// Any fact-bearing entity id: a person, a family, or (later) a sub-entity such as a name, event, or
/// source record. Facts are addressed purely by `(kind, subject_bytes, field)` — nothing in the cell
/// machinery is person-specific — so a family id is a valid fact subject (that is how family-level
/// facts like a marriage date/place are stored). Person and family ids share this 16-byte keyspace;
/// the collision surface is the same as two person ids colliding, which the design already accepts.
pub type SubjectId = Vec<u8>;
/// An opaque reference to an encrypted media blob (its remote id / ciphertext hash) — the merge key
/// for one attachment.
pub type MediaRef = Vec<u8>;
/// A caller-minted name-entity id (a person's name, with its own leaf facts: given/family/type/…).
pub type NameId = Vec<u8>;
/// A caller-minted event-entity id (a life event, with leaf facts: type/date/place).
pub type EventId = Vec<u8>;
/// A caller-minted source-record id (a citation source, with leaf facts: title/detail).
pub type SourceId = Vec<u8>;
/// A caller-minted media-link id (one attachment of a media record to a subject, with leaf facts:
/// role/order/caption/crop). Its OR-set element value is the media-record id it points at.
pub type MediaLinkId = Vec<u8>;

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

// Cell-kind tags — the first byte of every [`CellId`], keeping the address spaces disjoint. Facts
// (2/3) are keyed by *subject*, which is any entity id — a person, a family, or a sub-entity (a name,
// event, source, or media record/link). Sub-entities carry their own leaf facts through 2/3.
const KIND_PERSONS: u8 = 1; // the set of live person ids
const KIND_FACT_CLAIMS: u8 = 2; // per (subject, field): the OR-set of claims
const KIND_FACT_PREFERRED: u8 = 3; // per (subject, field): the preferred-claim register (also name.primary)
const KIND_FAMILIES: u8 = 4; // the set of live family ids
const KIND_CHILDREN: u8 = 5; // per family: the OR-set of child person ids (value = pedigree)
const KIND_SPOUSES: u8 = 6; // per family: the OR-set of spouse/partner person ids
const KIND_MEDIA: u8 = 7; // per subject: the OR-set of media-LINK ids (value = media-record id)
const KIND_NAMES: u8 = 8; // per subject: the OR-set of name-entity ids
const KIND_EVENTS: u8 = 9; // per subject: the OR-set of event-entity ids
const KIND_SOURCES: u8 = 10; // doc-level: the OR-set of source-record ids
const KIND_CITES: u8 = 11; // per (subject, field): OR-set of source ids (value = claim id | none)
const KIND_MEDIA_RECORDS: u8 = 12; // doc-level: the OR-set of media-record ids

/// The register field holding a person's preferred (display) name-entity id — a reserved fact field
/// on [`KIND_FACT_PREFERRED`], never a claim set, so it shares no address with a real fact.
const FIELD_NAME_PRIMARY: &str = "name.primary";

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
fn fact_claims_cell(subject: &[u8], field: &str) -> CellId {
    cell(KIND_FACT_CLAIMS, &[subject, field.as_bytes()])
}
fn fact_preferred_cell(subject: &[u8], field: &str) -> CellId {
    cell(KIND_FACT_PREFERRED, &[subject, field.as_bytes()])
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
fn names_cell(subject: &[u8]) -> CellId {
    cell(KIND_NAMES, &[subject])
}
fn events_cell(subject: &[u8]) -> CellId {
    cell(KIND_EVENTS, &[subject])
}
fn sources_cell() -> CellId {
    cell(KIND_SOURCES, &[])
}
fn cites_cell(subject: &[u8], field: &str) -> CellId {
    cell(KIND_CITES, &[subject, field.as_bytes()])
}
fn media_records_cell() -> CellId {
    cell(KIND_MEDIA_RECORDS, &[])
}
fn media_cell(subject: &[u8]) -> CellId {
    cell(KIND_MEDIA, &[subject])
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

/// A staged bundle of edits drafted against a base version, awaiting approval. The op bundle is
/// self-contained (each op names its own target), so approving it is apply-all and rejecting it is a
/// clean discard — nothing dangles.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proposal {
    /// The proposer's version when they drafted this — lets [`Tree::review`] flag facts that moved
    /// since (staleness / concurrent edits the approver must adjudicate).
    pub base: commute::VersionVector,
    pub ops: Vec<TreeOp>,
}

impl Proposal {
    /// Encode this proposal to the canonical bytes sealed as a `KIND_PROPOSAL` bundle.
    pub fn encode(&self) -> Vec<u8> {
        wire::encode(self)
    }

    /// Decode a proposal bundle. Never panics on arbitrary/corrupt input.
    pub fn decode(bytes: &[u8]) -> Result<Proposal, ProposalError> {
        wire::decode(bytes)
    }
}

/// One human-renderable change a proposal would make, described against the CURRENT head (so the
/// approver sees "add 1903 — current preferred is 1901", not a base-relative diff).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Change {
    PersonAdded(PersonId),
    PersonRemoved(PersonId),
    ClaimAdded { subject: SubjectId, field: FieldKey, value: String, source: Option<String>, current_preferred: Option<String> },
    PreferredChanged { subject: SubjectId, field: FieldKey, claim: ClaimId },
    ClaimRetracted { subject: SubjectId, field: FieldKey, claim: ClaimId },
    FamilyAdded(FamilyId),
    FamilyRemoved(FamilyId),
    ChildLinked { family: FamilyId, person: PersonId, pedi: Pedigree },
    ChildUnlinked { family: FamilyId, person: PersonId },
    ChildMoved { person: PersonId, from: FamilyId, to: FamilyId, pedi: Pedigree },
    SpouseLinked { family: FamilyId, person: PersonId },
    SpouseUnlinked { family: FamilyId, person: PersonId },
    NameAdded { subject: SubjectId, name: NameId },
    NameRemoved { subject: SubjectId, name: NameId },
    PrimaryNameSet { subject: SubjectId, name: NameId },
    EventAdded { subject: SubjectId, event: EventId },
    EventRemoved { subject: SubjectId, event: EventId },
    SourceAdded { source: SourceId },
    SourceRemoved { source: SourceId },
    Cited { subject: SubjectId, field: FieldKey, source: SourceId, claim: Option<ClaimId> },
    Uncited { subject: SubjectId, field: FieldKey, source: SourceId },
    MediaRecordAdded { media: MediaRef },
    MediaRecordRemoved { media: MediaRef },
    MediaLinked { subject: SubjectId, link: MediaLinkId, media: MediaRef },
    MediaUnlinked { subject: SubjectId, link: MediaLinkId },
}

/// A fact the proposal edits that ALSO moved since the proposal's base — the approver decides
/// whether to apply anyway (in the claim model that usually means "keep both").
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Conflict {
    pub subject: SubjectId,
    pub field: FieldKey,
}

/// The approver's view of a proposal: the changes it makes and the facts it collides with.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Review {
    pub changes: Vec<Change>,
    pub conflicts: Vec<Conflict>,
}

/// A typed family-tree edit. Each maps to exactly one self-contained `commute` op (batched actions
/// come later). `AddClaim` carries its own `claim` id — every op names the ids it creates, so a
/// retried op is idempotent.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TreeOp {
    AddPerson { id: PersonId },
    RemovePerson { id: PersonId },
    AddClaim { subject: SubjectId, field: FieldKey, claim: ClaimId, value: String, source: Option<String> },
    SetPreferredClaim { subject: SubjectId, field: FieldKey, claim: ClaimId },
    RetractClaim { subject: SubjectId, field: FieldKey, claim: ClaimId },
    AddFamily { id: FamilyId },
    RemoveFamily { id: FamilyId },
    LinkChild { family: FamilyId, person: PersonId, pedi: Pedigree },
    UnlinkChild { family: FamilyId, person: PersonId },
    /// Re-parent a child atomically: drop the `from` link and add the `to` link. First-class so the
    /// intent survives in a proposal bundle ("moved child Y from F1 to F2"), not an inferred pair.
    MoveChild { person: PersonId, from: FamilyId, to: FamilyId, pedi: Pedigree },
    LinkSpouse { family: FamilyId, person: PersonId },
    UnlinkSpouse { family: FamilyId, person: PersonId },
    // ---- sub-entities: names / events (own id + leaf facts via AddClaim on that id) ----
    /// Add a name-entity to a subject's name set. Its parts (given/family/type/…) are `AddClaim`s on
    /// `name`. `SetPrimaryName` chooses which drives the display name.
    AddName { subject: SubjectId, name: NameId },
    RemoveName { subject: SubjectId, name: NameId },
    /// Point a subject's preferred-name register at `name` (an LWW register, not a claim set — display
    /// preference is not a competing genealogical claim).
    SetPrimaryName { subject: SubjectId, name: NameId },
    /// Add an event-entity to a subject's event set. Its `type`/`date`/`place` are `AddClaim`s on `event`.
    AddEvent { subject: SubjectId, event: EventId },
    RemoveEvent { subject: SubjectId, event: EventId },
    // ---- sources + citations ----
    /// Add a shared source-record (doc-level). Its `title`/`detail` are `AddClaim`s on `source`.
    AddSource { source: SourceId },
    RemoveSource { source: SourceId },
    /// Cite a source for a fact. `claim` names the specific competing claim the source supports, or
    /// `None` to cite the field generally.
    Cite { subject: SubjectId, field: FieldKey, source: SourceId, claim: Option<ClaimId> },
    Uncite { subject: SubjectId, field: FieldKey, source: SourceId },
    // ---- media: shared records + per-subject links ----
    /// Add a shared media-record (doc-level). Its `mime`/`hash`/`w`/`h`/`kind` are `AddClaim`s on `media`.
    AddMediaRecord { media: MediaRef },
    RemoveMediaRecord { media: MediaRef },
    /// Attach a media-record to a subject via a link-entity (element value = the media-record id). The
    /// link's `role`/`order`/`caption`/`crop` are `AddClaim`s on `link`. `RemoveMediaLink` tombstones
    /// it, so a re-delivered attach never resurrects a detached link.
    AddMediaLink { subject: SubjectId, link: MediaLinkId, media: MediaRef },
    RemoveMediaLink { subject: SubjectId, link: MediaLinkId },
}

impl TreeOp {
    /// The one-or-more self-contained `commute` intents this edit expands to. Most are a single
    /// intent; `MoveChild` is two (an unlink then a link) applied as one atomic action.
    fn into_intents(self) -> Vec<OpIntent> {
        match self {
            TreeOp::AddPerson { id } => vec![OpIntent::AddElement { cell: persons_cell(), elem: id, value: Value::Null }],
            TreeOp::RemovePerson { id } => vec![OpIntent::RemoveElement { cell: persons_cell(), elem: id }],
            TreeOp::AddClaim { subject, field, claim, value, source } => vec![OpIntent::AddElement {
                cell: fact_claims_cell(&subject, &field),
                elem: claim,
                value: Value::Bytes(encode_claim(&value, source.as_deref())),
            }],
            TreeOp::SetPreferredClaim { subject, field, claim } => {
                vec![OpIntent::SetRegister { cell: fact_preferred_cell(&subject, &field), value: Value::Bytes(claim) }]
            }
            TreeOp::RetractClaim { subject, field, claim } => {
                vec![OpIntent::RemoveElement { cell: fact_claims_cell(&subject, &field), elem: claim }]
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
            TreeOp::AddName { subject, name } => {
                vec![OpIntent::AddElement { cell: names_cell(&subject), elem: name, value: Value::Null }]
            }
            TreeOp::RemoveName { subject, name } => {
                vec![OpIntent::RemoveElement { cell: names_cell(&subject), elem: name }]
            }
            TreeOp::SetPrimaryName { subject, name } => {
                vec![OpIntent::SetRegister { cell: fact_preferred_cell(&subject, FIELD_NAME_PRIMARY), value: Value::Bytes(name) }]
            }
            TreeOp::AddEvent { subject, event } => {
                vec![OpIntent::AddElement { cell: events_cell(&subject), elem: event, value: Value::Null }]
            }
            TreeOp::RemoveEvent { subject, event } => {
                vec![OpIntent::RemoveElement { cell: events_cell(&subject), elem: event }]
            }
            TreeOp::AddSource { source } => {
                vec![OpIntent::AddElement { cell: sources_cell(), elem: source, value: Value::Null }]
            }
            TreeOp::RemoveSource { source } => {
                vec![OpIntent::RemoveElement { cell: sources_cell(), elem: source }]
            }
            TreeOp::Cite { subject, field, source, claim } => vec![OpIntent::AddElement {
                cell: cites_cell(&subject, &field),
                elem: source,
                value: match claim {
                    Some(c) => Value::Bytes(c),
                    None => Value::Null,
                },
            }],
            TreeOp::Uncite { subject, field, source } => {
                vec![OpIntent::RemoveElement { cell: cites_cell(&subject, &field), elem: source }]
            }
            TreeOp::AddMediaRecord { media } => {
                vec![OpIntent::AddElement { cell: media_records_cell(), elem: media, value: Value::Null }]
            }
            TreeOp::RemoveMediaRecord { media } => {
                vec![OpIntent::RemoveElement { cell: media_records_cell(), elem: media }]
            }
            TreeOp::AddMediaLink { subject, link, media } => {
                vec![OpIntent::AddElement { cell: media_cell(&subject), elem: link, value: Value::Bytes(media) }]
            }
            TreeOp::RemoveMediaLink { subject, link } => {
                vec![OpIntent::RemoveElement { cell: media_cell(&subject), elem: link }]
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

    /// Capture the current version — a proposer stamps their [`Proposal`] with this as its `base`.
    pub fn version_cursor(&self) -> commute::VersionVector {
        self.doc.version()
    }

    /// Describe what `proposal` would do, against the current head, flagging any fact it edits that
    /// also moved since the proposal's `base`. Read-only — no state changes.
    pub fn review(&self, proposal: &Proposal) -> Review {
        let changed = self.doc.changed_cells_since(&proposal.base);
        let mut review = Review::default();
        for op in &proposal.ops {
            if let Some((subject, field)) = fact_target(op) {
                let touched = changed.contains(&fact_claims_cell(&subject, &field)) || changed.contains(&fact_preferred_cell(&subject, &field));
                if touched {
                    let c = Conflict { subject, field };
                    if !review.conflicts.contains(&c) {
                        review.conflicts.push(c);
                    }
                }
            }
            review.changes.push(self.describe(op));
        }
        review
    }

    /// Apply an approved proposal as the committing (approver) replica; returns the sealed ops.
    /// Rejecting a proposal needs no method — just drop it; because its ops are self-contained,
    /// nothing in the tree ever depended on it.
    pub fn commit_proposal(&mut self, proposal: &Proposal) -> Vec<Op> {
        self.apply_batch(proposal.ops.clone())
    }

    fn describe(&self, op: &TreeOp) -> Change {
        match op.clone() {
            TreeOp::AddPerson { id } => Change::PersonAdded(id),
            TreeOp::RemovePerson { id } => Change::PersonRemoved(id),
            TreeOp::AddClaim { subject, field, value, source, .. } => {
                let current_preferred = self.fact(&subject, &field).preferred.map(|c| c.value);
                Change::ClaimAdded { subject, field, value, source, current_preferred }
            }
            TreeOp::SetPreferredClaim { subject, field, claim } => Change::PreferredChanged { subject, field, claim },
            TreeOp::RetractClaim { subject, field, claim } => Change::ClaimRetracted { subject, field, claim },
            TreeOp::AddFamily { id } => Change::FamilyAdded(id),
            TreeOp::RemoveFamily { id } => Change::FamilyRemoved(id),
            TreeOp::LinkChild { family, person, pedi } => Change::ChildLinked { family, person, pedi },
            TreeOp::UnlinkChild { family, person } => Change::ChildUnlinked { family, person },
            TreeOp::MoveChild { person, from, to, pedi } => Change::ChildMoved { person, from, to, pedi },
            TreeOp::LinkSpouse { family, person } => Change::SpouseLinked { family, person },
            TreeOp::UnlinkSpouse { family, person } => Change::SpouseUnlinked { family, person },
            TreeOp::AddName { subject, name } => Change::NameAdded { subject, name },
            TreeOp::RemoveName { subject, name } => Change::NameRemoved { subject, name },
            TreeOp::SetPrimaryName { subject, name } => Change::PrimaryNameSet { subject, name },
            TreeOp::AddEvent { subject, event } => Change::EventAdded { subject, event },
            TreeOp::RemoveEvent { subject, event } => Change::EventRemoved { subject, event },
            TreeOp::AddSource { source } => Change::SourceAdded { source },
            TreeOp::RemoveSource { source } => Change::SourceRemoved { source },
            TreeOp::Cite { subject, field, source, claim } => Change::Cited { subject, field, source, claim },
            TreeOp::Uncite { subject, field, source } => Change::Uncited { subject, field, source },
            TreeOp::AddMediaRecord { media } => Change::MediaRecordAdded { media },
            TreeOp::RemoveMediaRecord { media } => Change::MediaRecordRemoved { media },
            TreeOp::AddMediaLink { subject, link, media } => Change::MediaLinked { subject, link, media },
            TreeOp::RemoveMediaLink { subject, link } => Change::MediaUnlinked { subject, link },
        }
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

    /// The media LINKS attached to a subject, each as `(link id, media-record id)`, in deterministic
    /// order. The link's own facts (role/order/caption/crop) and the record's facts (mime/hash/…) are
    /// read via [`Tree::fact`] on the respective id.
    pub fn media_of(&self, subject: &[u8]) -> Vec<(MediaLinkId, MediaRef)> {
        self.doc
            .set_elements(&media_cell(subject))
            .into_iter()
            .filter_map(|(id, v)| match v {
                Value::Bytes(rec) => Some((id.clone(), rec.clone())),
                _ => None,
            })
            .collect()
    }

    /// The live media-record ids (doc-level), in deterministic order.
    pub fn media_records(&self) -> Vec<MediaRef> {
        self.doc.set_elements(&media_records_cell()).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// A subject's name-entity ids, in deterministic (id) order.
    pub fn names_of(&self, subject: &[u8]) -> Vec<NameId> {
        self.doc.set_elements(&names_cell(subject)).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// A subject's preferred (display) name entity: the register pointer if it still names a live name,
    /// else the greatest live name id (deterministic across replicas), else `None` if there are none.
    /// A read adapter may prefer a `birth`-type name over the greatest id; that policy lives above.
    pub fn primary_name(&self, subject: &[u8]) -> Option<NameId> {
        let names = self.names_of(subject);
        let pointer = match self.doc.register(&fact_preferred_cell(subject, FIELD_NAME_PRIMARY)) {
            Some(Value::Bytes(id)) => Some(id.clone()),
            _ => None,
        };
        pointer.filter(|p| names.iter().any(|n| n == p)).or_else(|| names.last().cloned())
    }

    /// A subject's event-entity ids, in deterministic (id) order. Ordering by date is a read-adapter
    /// concern (the leaf `date` fact), not the engine's.
    pub fn events_of(&self, subject: &[u8]) -> Vec<EventId> {
        self.doc.set_elements(&events_cell(subject)).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// The fact field keys that currently have at least one live claim on `subject` (e.g. `"sex"`,
    /// `"note"`, `"custom.occupation"`). Lets a read adapter reconstruct open-ended field sets — such
    /// as user-defined custom fields — without a side registry, so a value never disappears from the
    /// read model just because its field was dropped from a schema.
    pub fn fields_of(&self, subject: &[u8]) -> Vec<FieldKey> {
        // Every fact-claims cell for this subject shares the prefix `KIND ‖ len(subject) ‖ subject`;
        // the remainder is `len(field) ‖ field` (the second part `cell()` length-prefixes).
        let mut prefix = vec![KIND_FACT_CLAIMS];
        prefix.extend_from_slice(&(subject.len() as u32).to_be_bytes());
        prefix.extend_from_slice(subject);
        let mut out = Vec::new();
        for c in self.doc.set_cell_ids_with_prefix(&prefix) {
            let rest = &c[prefix.len()..];
            if rest.len() < 4 {
                continue;
            }
            let n = u32::from_be_bytes(rest[0..4].try_into().expect("4")) as usize;
            if rest.len() < 4 + n {
                continue;
            }
            if let Ok(field) = String::from_utf8(rest[4..4 + n].to_vec()) {
                out.push(field);
            }
        }
        out
    }

    /// The live source-record ids (doc-level), in deterministic order.
    pub fn sources(&self) -> Vec<SourceId> {
        self.doc.set_elements(&sources_cell()).into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// The sources citing a fact, each as `(source id, the specific claim it supports or None for the
    /// field in general)`, in deterministic order.
    pub fn cites_of(&self, subject: &[u8], field: &str) -> Vec<(SourceId, Option<ClaimId>)> {
        self.doc
            .set_elements(&cites_cell(subject, field))
            .into_iter()
            .map(|(id, v)| {
                let claim = match v {
                    Value::Bytes(c) => Some(c.clone()),
                    _ => None,
                };
                (id.clone(), claim)
            })
            .collect()
    }

    /// A person's fact: every retained claim + the preferred one. Empty if the fact has no claims.
    pub fn fact(&self, subject: &[u8], field: &str) -> Fact {
        let mut claims: Vec<Claim> = self
            .doc
            .set_elements(&fact_claims_cell(subject, field))
            .into_iter()
            .filter_map(|(id, v)| match v {
                Value::Bytes(b) => decode_claim(b).map(|(value, source)| Claim { id: id.clone(), value, source }),
                _ => None,
            })
            .collect();
        claims.sort_by(|a, b| a.id.cmp(&b.id));

        // Preferred: the explicit pointer if it still names a live claim; else the greatest id.
        let pointer = match self.doc.register(&fact_preferred_cell(subject, field)) {
            Some(Value::Bytes(id)) => Some(id.clone()),
            _ => None,
        };
        let preferred = pointer
            .and_then(|id| claims.iter().find(|c| c.id == id).cloned())
            .or_else(|| claims.last().cloned());

        Fact { claims, preferred }
    }
}

/// The (subject, field) a fact op targets, for conflict detection. `None` for non-fact ops.
fn fact_target(op: &TreeOp) -> Option<(SubjectId, FieldKey)> {
    match op {
        TreeOp::AddClaim { subject, field, .. }
        | TreeOp::SetPreferredClaim { subject, field, .. }
        | TreeOp::RetractClaim { subject, field, .. } => Some((subject.clone(), field.clone())),
        _ => None,
    }
}

// ---- claim payload encoding (stored opaquely inside a commute Value::Bytes) --------------------

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Claim payload layout version. v1 = `len(value)‖value‖0/1‖[len(source)‖source]`, preceded by this
/// byte. The leading version lets a future typed-leaf value land without a migration; a payload whose
/// version this build doesn't know surfaces as an opaque (unreadable-but-present) claim rather than
/// silently vanishing from the read model — these bytes are permanent sealed-archive substrate.
const CLAIM_V1: u8 = 1;

fn encode_claim(value: &str, source: Option<&str>) -> Vec<u8> {
    let mut o = vec![CLAIM_V1];
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
    let version = *b.get(pos)?;
    pos += 1;
    if version != CLAIM_V1 {
        // A newer payload format this build can't parse: keep the claim present but unrenderable,
        // never silently absent (the same discipline as refusing unknown ops rather than skipping
        // them). The claim id is retained by the OR-set; only its value is opaque here.
        return Some((format!("(unreadable claim: payload v{version})"), None));
    }
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
