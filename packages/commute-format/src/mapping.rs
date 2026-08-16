//! The **Mapping** — a [`ValueTree`] ⇄ `commute` cells, carrying identity and merge policy. This is
//! where "no silent last-writer-wins" is enforced: a scalar field auto-maps to an LWW register
//! (safe — keys are stable), but a **collection with no declared policy is a hard error**, never a
//! silent whole-list overwrite. Policy comes from a **static, declared** [`MappingSpec`], not from
//! the shape of any one document (so two documents that differ only in a field's incidental shape
//! can't make replicas disagree). `import` emits **unstamped** op intents; the engine stamps them.
//!
//! This slice covers a top-level object with scalar fields + declared **Keyed** array fields + a
//! whole-value **Atomic** policy; element values are stored opaquely (element-level identity, opaque
//! leaf). KeyedOrdered, a scalar-set (ValueIdentity) policy, Replace-mode retraction, and recursive
//! per-field merge within elements are follow-ups on this seam.

use crate::{Codec, CodecError, ValueTree};
use commute::{CellId, OpIntent, Value};
use std::collections::HashSet;

/// How one top-level field maps onto cells. A field not listed is auto-mapped only if it's a
/// scalar; a collection field must be declared here or [`import`] refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldPolicy {
    /// The value is a scalar → an LWW register cell keyed by the field name.
    Scalar,
    /// The value is an array of objects → an OR-set keyed by the field name; each element is
    /// identified by its `key_field` and stored as an opaque leaf.
    Keyed { key_field: String },
    /// The whole value (any shape) → one atomic LWW register (opaque leaf). Explicit opt-in.
    Atomic,
}

/// A static, declared mapping schema. Fields absent here auto-map when scalar; a collection absent
/// here is a hard error.
#[derive(Clone, Debug, Default)]
pub struct MappingSpec {
    pub fields: Vec<(String, FieldPolicy)>,
}

impl MappingSpec {
    fn policy(&self, field: &str) -> Option<&FieldPolicy> {
        self.fields.iter().find(|(f, _)| f == field).map(|(_, p)| p)
    }
}

/// Why an import couldn't be mapped. Never silently succeeds where a policy is missing/ambiguous.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapError {
    #[error("the document root must be an object")]
    NotAnObject,
    #[error("field {0:?} is a collection with no declared policy")]
    UndeclaredCollection(String),
    #[error("field {0:?} is declared Scalar but its value is a collection")]
    ExpectedScalar(String),
    #[error("field {0:?} is declared Keyed but its value is not an array")]
    NotAnArray(String),
    #[error("a Keyed element in field {0:?} is not an object")]
    ElementNotAnObject(String),
    #[error("a Keyed element in field {field:?} is missing its key field {key:?}")]
    MissingKey { field: String, key: String },
    #[error("the key field of an element in {field:?} is not a scalar")]
    BadKeyType { field: String },
    #[error("two elements in field {field:?} share the key {key:?}")]
    DuplicateKey { field: String, key: String },
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// The result of mapping a document: the unstamped intents to apply, and a human-readable summary.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportPlan {
    pub intents: Vec<OpIntent>,
    pub summary: Vec<String>,
}

fn cell(field: &str) -> CellId {
    field.as_bytes().to_vec()
}

/// Project a commute document back into a [`ValueTree`] — the reverse of [`import`]. Register cells
/// become scalar fields (or the decoded sub-tree if they hold an opaque/atomic leaf); set cells
/// become arrays of their decoded elements. Field order is the document's canonical (cell) order,
/// so `export ∘ import` round-trips modulo key ordering. Needs no spec: the cell's stored shape
/// (scalar vs opaque bytes vs set) says how to reverse it.
pub fn export(doc: &commute::Doc, codec: &dyn Codec) -> Result<ValueTree, MapError> {
    let mut fields: Vec<(String, ValueTree)> = Vec::new();
    for (cell, value) in doc.register_cells() {
        let field = String::from_utf8(cell).map_err(|_| MapError::NotAnObject)?;
        let tree = match value {
            Value::Bytes(b) => codec.parse(&b)?, // an atomic/opaque leaf → its sub-tree
            v => value_to_tree(&v),
        };
        fields.push((field, tree));
    }
    for cell in doc.set_cell_ids() {
        let field = String::from_utf8(cell.clone()).map_err(|_| MapError::NotAnObject)?;
        let mut arr = Vec::new();
        for (_, v) in doc.set_elements(&cell) {
            match v {
                Value::Bytes(b) => arr.push(codec.parse(b)?),
                other => arr.push(value_to_tree(other)),
            }
        }
        fields.push((field, ValueTree::Seq(arr)));
    }
    Ok(ValueTree::Map(fields))
}

/// A ValueTree for a commute scalar leaf.
fn value_to_tree(v: &Value) -> ValueTree {
    match v {
        Value::Null => ValueTree::Null,
        Value::Bool(b) => ValueTree::Bool(*b),
        Value::I64(n) => ValueTree::Int(*n),
        Value::U64(n) => ValueTree::Uint(*n),
        Value::Text(s) => ValueTree::Str(s.clone()),
        Value::Bytes(b) => ValueTree::Bytes(b.clone()),
    }
}

/// A commute leaf value for a scalar ValueTree, or `None` if it isn't a scalar.
fn scalar(v: &ValueTree) -> Option<Value> {
    Some(match v {
        ValueTree::Null => Value::Null,
        ValueTree::Bool(b) => Value::Bool(*b),
        ValueTree::Int(n) => Value::I64(*n),
        ValueTree::Uint(n) => Value::U64(*n),
        ValueTree::Str(s) => Value::Text(s.clone()),
        _ => return None,
    })
}

/// A scalar rendered as an id/string (for a key field).
fn key_string(v: &ValueTree) -> Option<String> {
    Some(match v {
        ValueTree::Str(s) => s.clone(),
        ValueTree::Int(n) => n.to_string(),
        ValueTree::Uint(n) => n.to_string(),
        ValueTree::Bool(b) => b.to_string(),
        _ => return None,
    })
}

/// Map a parsed document into unstamped op intents, per the spec. `codec` re-encodes opaque element
/// / atomic values as leaf bytes (round-trips against the same codec on export).
pub fn import(doc: &ValueTree, spec: &MappingSpec, codec: &dyn Codec) -> Result<ImportPlan, MapError> {
    let ValueTree::Map(fields) = doc else {
        return Err(MapError::NotAnObject);
    };
    let mut plan = ImportPlan::default();

    for (field, value) in fields {
        match spec.policy(field) {
            Some(FieldPolicy::Scalar) | None if scalar(value).is_some() => {
                let v = scalar(value).expect("checked scalar");
                plan.intents.push(OpIntent::SetRegister { cell: cell(field), value: v });
                plan.summary.push(format!("set {field}"));
            }
            // A collection (Seq/Map) with no declared policy — refuse, never silently LWW.
            None => return Err(MapError::UndeclaredCollection(field.clone())),
            Some(FieldPolicy::Scalar) => return Err(MapError::ExpectedScalar(field.clone())),
            Some(FieldPolicy::Atomic) => {
                let bytes = codec.emit(value)?;
                plan.intents.push(OpIntent::SetRegister { cell: cell(field), value: Value::Bytes(bytes) });
                plan.summary.push(format!("set {field} (atomic)"));
            }
            Some(FieldPolicy::Keyed { key_field }) => {
                let ValueTree::Seq(elems) = value else {
                    return Err(MapError::NotAnArray(field.clone()));
                };
                let mut seen: HashSet<String> = HashSet::new();
                for elem in elems {
                    let ValueTree::Map(props) = elem else {
                        return Err(MapError::ElementNotAnObject(field.clone()));
                    };
                    let key_val = props.iter().find(|(k, _)| k == key_field).map(|(_, v)| v);
                    let key_val = key_val.ok_or_else(|| MapError::MissingKey { field: field.clone(), key: key_field.clone() })?;
                    let key = key_string(key_val).ok_or_else(|| MapError::BadKeyType { field: field.clone() })?;
                    if !seen.insert(key.clone()) {
                        return Err(MapError::DuplicateKey { field: field.clone(), key });
                    }
                    let bytes = codec.emit(elem)?;
                    plan.intents.push(OpIntent::AddElement { cell: cell(field), elem: key.into_bytes(), value: Value::Bytes(bytes) });
                }
                plan.summary.push(format!("upsert {} element(s) in {field}", elems.len()));
            }
        }
    }
    Ok(plan)
}
