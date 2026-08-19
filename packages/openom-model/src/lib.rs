//! openom canonical data model — the flat, tabular, id-keyed representation of a family tree.
//!
//! Design: `plan/design.data-model.md`. Flat tables (no deep nesting), each entity carrying an
//! **opaque, random, stable id** (see [`id`]). A family tree is a **DAG, not a tree** (a person has
//! two parents), so relationships are `edges`, not nesting. Ids are intrinsic stored fields, so
//! **editing a fact never changes an id and never breaks an edge**, and folding deltas into a
//! snapshot (compaction) preserves them.
//!
//! Out of scope here (tracked separately): RFC-8785 canonicalization + per-entity hashing
//! (OPE-96/OPE-97), generous JSON-Schema bounds (OPE-96), and embedding the name model
//! (`design.data-name-mode.md`, OPE-98) — `names` is referenced by [`NameId`] but not yet a table.

mod id;
pub use id::*;

pub mod name;
pub use name::{Name, NameError, Part, Position};

#[cfg(feature = "validation")]
pub mod schema;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// A node is a person or a family (the GEDCOM INDI / FAM split). Attributes (names, events, custom
/// fields) live in their own tables keyed by this node's id — nothing is nested on the node.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NodeKind {
    Person,
    Family,
}

/// Relationship carried by an edge. Extended additively over time (never renumber/reuse — see the
/// schema-evolution rules).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RelationshipType {
    ParentChild,
    Spouse,
    Partner,
}

/// Kind of a life event. Extended additively.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EventType {
    Birth,
    Death,
    Marriage,
    Divorce,
    Baptism,
    Burial,
    Immigration,
    Other,
}

/// A person or family. Minimal by design — the id is the durable graph key.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    /// RESERVED SEAM (OPE-99): an opaque subtree-scope tag for future subtree-scoped visibility
    /// (`design.subtree-scope.md`). `None` = unscoped (the whole-tree default). No feature reads it
    /// today; it exists so adding scoping later is not a schema break.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// A directed relationship edge (`from` → `to`; e.g. parent → child). Two node ids + a type.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub relationship: RelationshipType,
    pub from: NodeId,
    pub to: NodeId,
}

/// An event: a type, a primary node, an optional secondary node (e.g. the other spouse in a
/// marriage), an optional Unix timestamp, and an optional attached media id.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub event_type: EventType,
    pub primary: NodeId,
    // Optionals are skipped when absent so canonical bytes match "absent == default" — the
    // hash-stability rule (an entity without an optional hashes identically to an explicit-none one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<MediaId>,
}

/// A shared source record (provenance; attestations and GEDCOM sources reference these).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Source {
    pub id: SourceId,
    pub citation: String,
}

/// A shared media record — stores the **content hash**, never the binary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Media {
    pub id: MediaId,
    pub content_sha256: [u8; 32],
}

/// Merge class of a field's value. RESERVED SEAM (OPE-150). `Lww` (default) = whole-value
/// last-writer-wins; `Text` marks a free-text field (e.g. a biography) for a future sequence/text
/// CRDT — the algorithm behind it is deferred (OPE-151). Present now so marking a field text-merged
/// later is not a schema break.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MergeClass {
    #[default]
    Lww,
    Text,
}

/// A user-created custom-field definition.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FieldDef {
    pub id: FieldDefId,
    pub name: String,
    #[serde(default)]
    pub merge: MergeClass,
}

/// A value for a custom field, attached to a node.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FieldValue {
    pub id: FieldValueId,
    pub node: NodeId,
    pub def: FieldDefId,
    pub value: String,
}

/// A link from a node in this tree to a node in ANOTHER tree — RESERVED SEAM (OPE-99) for future
/// tree federation. The record type exists so federation isn't a schema break; no federation
/// behaviour (unifying projection, cross-tree resolution) is built.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CrossTreeLink {
    pub id: LinkId,
    pub local: NodeId,
    pub remote_tree: TreeId,
    pub remote_node: NodeId,
}

/// Errors from mutations that would violate structural integrity.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ModelError {
    #[error("edge references node {0} which is not in the model")]
    DanglingNode(NodeId),
    #[error("an edge cannot connect a node to itself")]
    SelfLoop,
    #[error("no event with id {0}")]
    NoSuchEvent(EventId),
}

/// The whole tree, as flat id-keyed tables. `BTreeMap` gives a deterministic iteration order
/// (a convenience for the future canonicalization step). Node ids are namespaced by `tree` for
/// cross-tree references (`(tree, node)`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Model {
    pub tree: TreeId,
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<EdgeId, Edge>,
    pub events: BTreeMap<EventId, Event>,
    pub sources: BTreeMap<SourceId, Source>,
    pub media: BTreeMap<MediaId, Media>,
    pub field_defs: BTreeMap<FieldDefId, FieldDef>,
    pub field_values: BTreeMap<FieldValueId, FieldValue>,
    /// RESERVED SEAM (OPE-99): links from this tree's nodes to nodes in other trees.
    pub cross_tree_links: BTreeMap<LinkId, CrossTreeLink>,
}

impl Model {
    /// An empty tree.
    pub fn new(tree: TreeId) -> Self {
        Self {
            tree,
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            events: BTreeMap::new(),
            sources: BTreeMap::new(),
            media: BTreeMap::new(),
            field_defs: BTreeMap::new(),
            field_values: BTreeMap::new(),
            cross_tree_links: BTreeMap::new(),
        }
    }

    /// Reserve a cross-tree link (OPE-99 seam). Validates the local node exists; the remote endpoint
    /// is opaque — no federation behaviour is performed.
    pub fn add_cross_tree_link(
        &mut self,
        local: NodeId,
        remote_tree: TreeId,
        remote_node: NodeId,
        src: &mut impl IdSource,
    ) -> Result<LinkId, ModelError> {
        if !self.nodes.contains_key(&local) {
            return Err(ModelError::DanglingNode(local));
        }
        let id = LinkId::generate(src);
        self.cross_tree_links
            .insert(id, CrossTreeLink { id, local, remote_tree, remote_node });
        Ok(id)
    }

    /// Create a node, minting a fresh opaque id.
    pub fn create_node(&mut self, kind: NodeKind, src: &mut impl IdSource) -> NodeId {
        let id = NodeId::generate(src);
        self.nodes.insert(id, Node { id, kind, scope: None });
        id
    }

    /// Add a relationship edge. Rejects self-loops and edges to absent nodes.
    pub fn add_edge(
        &mut self,
        relationship: RelationshipType,
        from: NodeId,
        to: NodeId,
        src: &mut impl IdSource,
    ) -> Result<EdgeId, ModelError> {
        if from == to {
            return Err(ModelError::SelfLoop);
        }
        if !self.nodes.contains_key(&from) {
            return Err(ModelError::DanglingNode(from));
        }
        if !self.nodes.contains_key(&to) {
            return Err(ModelError::DanglingNode(to));
        }
        let id = EdgeId::generate(src);
        self.edges.insert(id, Edge { id, relationship, from, to });
        Ok(id)
    }

    /// Record an event on a node.
    pub fn add_event(
        &mut self,
        event_type: EventType,
        primary: NodeId,
        timestamp: Option<i64>,
        src: &mut impl IdSource,
    ) -> Result<EventId, ModelError> {
        if !self.nodes.contains_key(&primary) {
            return Err(ModelError::DanglingNode(primary));
        }
        let id = EventId::generate(src);
        self.events.insert(
            id,
            Event { id, event_type, primary, secondary: None, timestamp, image: None },
        );
        Ok(id)
    }

    /// Correct an event's timestamp **in place** — the event's id (and any reference to it) is
    /// unchanged. This is the whole point of opaque, non-derived ids: facts are mutable, identity
    /// is not.
    pub fn correct_event_timestamp(
        &mut self,
        event: EventId,
        timestamp: Option<i64>,
    ) -> Result<(), ModelError> {
        let e = self.events.get_mut(&event).ok_or(ModelError::NoSuchEvent(event))?;
        e.timestamp = timestamp;
        Ok(())
    }
}

/// Canonical bytes of any serializable value — RFC 8785 (JCS)-equivalent for our data. Routing
/// through `serde_json::Value` (whose objects are a sorted `BTreeMap`) and serializing compactly
/// yields sorted keys, no whitespace, and canonical integers. This equals JCS here because the model
/// is float-free (JCS's ES6 number rule only bites on floats) and its keys are ASCII (byte order ==
/// UTF-16 order). If arbitrary/float data ever needs canonicalizing, swap in a full JCS impl here.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::to_value(value)?)
}

/// Canonical bytes of the whole model.
pub fn canonicalize(model: &Model) -> Result<Vec<u8>, serde_json::Error> {
    canonical_json(model)
}

/// The **per-entity canonical content hash** — the value an attestation binds to. SHA-256 over the
/// entity's canonical bytes ([`canonical_json`]). It is:
/// - **deterministic + identical across clients** — a pure function of the canonical form;
/// - **stable through compaction** — it depends only on the entity's own fields, never on log
///   position (byte-preservation through GC is enforced separately);
/// - **high-entropy** — the entity's opaque, random id is part of the hashed bytes, so a low-entropy
///   fact ("born 1901") can't be confirmed by guessing its fields.
///
/// Editing a fact changes its hash *by design*: an attestation on the old value then reads as
/// "attested an earlier value".
pub fn content_hash<T: Serialize>(value: &T) -> Result<[u8; 32], serde_json::Error> {
    Ok(Sha256::digest(canonical_json(value)?).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> SeededIdSource {
        SeededIdSource::new(0xC0FFEE)
    }

    #[test]
    fn edit_preserves_id_and_edges() {
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));

        let parent = m.create_node(NodeKind::Person, &mut src);
        let child = m.create_node(NodeKind::Person, &mut src);
        let edge = m.add_edge(RelationshipType::ParentChild, parent, child, &mut src).unwrap();
        let birth = m.add_event(EventType::Birth, child, Some(1900), &mut src).unwrap();

        // Correct a wrong birth year — a real edit.
        m.correct_event_timestamp(birth, Some(1901)).unwrap();

        // The id never moved, the corrected value is there, and the edge still resolves.
        assert_eq!(m.events[&birth].timestamp, Some(1901));
        assert_eq!(m.events[&birth].id, birth);
        let e = &m.edges[&edge];
        assert_eq!(e.from, parent);
        assert_eq!(e.to, child);
        assert!(m.nodes.contains_key(&e.from) && m.nodes.contains_key(&e.to));
    }

    #[test]
    fn edge_validation() {
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));
        let a = m.create_node(NodeKind::Person, &mut src);

        // Self-loop (the "own parent" paradox).
        assert_eq!(
            m.add_edge(RelationshipType::ParentChild, a, a, &mut src),
            Err(ModelError::SelfLoop)
        );

        // Edge to a node that isn't in the model.
        let ghost = NodeId::generate(&mut src);
        assert_eq!(
            m.add_edge(RelationshipType::Spouse, a, ghost, &mut src),
            Err(ModelError::DanglingNode(ghost))
        );
    }

    #[test]
    fn round_trip_preserves_ids_and_structure() {
        // A serialize → deserialize round-trip stands in for a compaction/snapshot fold: the
        // stored ids and the whole structure come back byte-for-byte-equivalent.
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));
        let p = m.create_node(NodeKind::Person, &mut src);
        let f = m.create_node(NodeKind::Family, &mut src);
        m.add_edge(RelationshipType::ParentChild, f, p, &mut src).unwrap();
        m.add_event(EventType::Birth, p, Some(2000), &mut src).unwrap();

        let json = serde_json::to_string(&m).unwrap();
        let back: Model = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn reserved_seams_scope_link_merge() {
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));
        let a = m.create_node(NodeKind::Person, &mut src);

        // OPE-99: an opaque subtree-scope tag on a node.
        m.nodes.get_mut(&a).unwrap().scope = Some("branch:paternal".into());
        assert_eq!(m.nodes[&a].scope.as_deref(), Some("branch:paternal"));

        // OPE-99: a cross-tree link record (federation seam).
        let other_tree = TreeId::generate(&mut src);
        let other_node = NodeId::generate(&mut src);
        let link = m.add_cross_tree_link(a, other_tree, other_node, &mut src).unwrap();
        assert_eq!(m.cross_tree_links[&link].remote_node, other_node);

        // OPE-150: the field merge-class marker — default Lww, Text opt-in.
        assert_eq!(MergeClass::default(), MergeClass::Lww);
        let def = FieldDef {
            id: FieldDefId::generate(&mut src),
            name: "biography".into(),
            merge: MergeClass::Text,
        };
        assert_eq!(def.merge, MergeClass::Text);

        // Round-trip still holds with the new reserved fields.
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(m, serde_json::from_str::<Model>(&json).unwrap());
    }

    #[test]
    fn canonicalize_is_deterministic_and_sorted() {
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));
        let p = m.create_node(NodeKind::Person, &mut src);
        m.add_event(EventType::Birth, p, Some(1990), &mut src).unwrap();

        // Stable across a serialize → parse round-trip: same materialized state → identical bytes.
        let a = canonicalize(&m).unwrap();
        let reparsed: Model = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(a, canonicalize(&reparsed).unwrap());

        // Object keys are emitted in sorted (JCS) order: `cross_tree_links` precedes `tree`.
        let s = String::from_utf8(a).unwrap();
        assert!(s.find("cross_tree_links").unwrap() < s.find("\"tree\"").unwrap());
    }

    #[test]
    fn content_hash_binds_to_the_fact_not_the_tree() {
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));
        let a = m.create_node(NodeKind::Person, &mut src);
        let b = m.create_node(NodeKind::Person, &mut src);
        let ea = m.add_event(EventType::Birth, a, Some(1901), &mut src).unwrap();
        let eb = m.add_event(EventType::Death, b, Some(1980), &mut src).unwrap();

        let h = content_hash(&m.events[&ea]).unwrap();

        // Editing ANOTHER fact leaves this fact's hash untouched (binds to the fact, not the tree).
        m.correct_event_timestamp(eb, Some(1981)).unwrap();
        assert_eq!(content_hash(&m.events[&ea]).unwrap(), h);

        // Editing THIS fact changes its hash — the "attested an earlier value" behaviour.
        m.correct_event_timestamp(ea, Some(1902)).unwrap();
        assert_ne!(content_hash(&m.events[&ea]).unwrap(), h);
    }

    #[test]
    fn content_hash_is_deterministic_and_high_entropy() {
        let mut src = seeded();
        let mut m = Model::new(TreeId::generate(&mut src));
        let p = m.create_node(NodeKind::Person, &mut src);
        let e = m.add_event(EventType::Birth, p, Some(2000), &mut src).unwrap();

        // Pure function of the canonical bytes: a re-parse hashes identically (cross-client stable).
        let ev = m.events[&e].clone();
        let reparsed: Event = serde_json::from_slice(&serde_json::to_vec(&ev).unwrap()).unwrap();
        assert_eq!(content_hash(&reparsed).unwrap(), content_hash(&ev).unwrap());

        // Two facts with identical fields but different random ids hash differently — the id is the
        // high-entropy component, so the fields alone can't be confirmed by guessing.
        let e1 = m.add_event(EventType::Birth, p, Some(1901), &mut src).unwrap();
        let e2 = m.add_event(EventType::Birth, p, Some(1901), &mut src).unwrap();
        assert_ne!(content_hash(&m.events[&e1]).unwrap(), content_hash(&m.events[&e2]).unwrap());
    }
}
