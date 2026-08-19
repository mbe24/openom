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
    /// Like `Keyed`, but each element also carries an `order_field` used to sort the collection
    /// deterministically on export (identity from `key_field`, display order from `order_field`).
    KeyedOrdered {
        key_field: String,
        order_field: String,
    },
    /// An array of scalars → an OR-set keyed by the scalar value itself (tags, aliases). Concurrent
    /// adds/removes of distinct values converge; a repeated value in one document collapses (it's a
    /// set). The alternative for a scalar collection would be the lossy whole-list Atomic.
    ValueIdentity,
    /// The whole value (any shape) → one atomic LWW register (opaque leaf). Explicit opt-in.
    Atomic,
}

/// A static, declared mapping schema. Fields absent here auto-map when scalar; a collection absent
/// here is a hard error.
#[derive(Clone, Debug, Default)]
pub struct MappingSpec {
    pub fields: Vec<(String, FieldPolicy)>,
}

/// How an import treats elements/fields that the current state has but the document omits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportMode {
    /// Additive: only add/update what the document names; never remove anything (safe default).
    Merge,
    /// Authoritative for collections: a collection element present now but absent from the document
    /// is retracted (tombstoned). Registers are still upsert-only (a commute register has no
    /// tombstone). Requires the current document to diff against.
    Replace,
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
/// become arrays of their decoded elements — in element-id order, except a `KeyedOrdered` field is
/// sorted by its declared `order_field`. `export ∘ import` round-trips modulo key ordering. The spec
/// is consulted only for that ordering; the cell's stored shape says how to reverse everything else.
pub fn export(
    doc: &commute::Doc,
    spec: &MappingSpec,
    codec: &dyn Codec,
) -> Result<ValueTree, MapError> {
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
        if let Some(FieldPolicy::KeyedOrdered { order_field, .. }) = spec.policy(&field) {
            arr.sort_by_key(|a| order_rank(a, order_field));
        }
        fields.push((field, ValueTree::Seq(arr)));
    }
    Ok(ValueTree::Map(fields))
}

/// A total, deterministic sort key for a KeyedOrdered element by its `order_field`: numbers first
/// (numerically), then strings (lexically), then anything unorderable — so export order is stable.
fn order_rank(elem: &ValueTree, order_field: &str) -> (u8, i128, String) {
    let v = match elem {
        ValueTree::Map(props) => props.iter().find(|(k, _)| k == order_field).map(|(_, v)| v),
        _ => None,
    };
    match v {
        Some(ValueTree::Int(n)) => (0, *n as i128, String::new()),
        Some(ValueTree::Uint(n)) => (0, *n as i128, String::new()),
        Some(ValueTree::Str(s)) => (1, 0, s.clone()),
        _ => (2, 0, String::new()),
    }
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

/// Map a parsed document into unstamped op intents (Merge mode — additive only). `codec` re-encodes
/// opaque element / atomic values as leaf bytes (round-trips against the same codec on export).
pub fn import(
    doc: &ValueTree,
    spec: &MappingSpec,
    codec: &dyn Codec,
) -> Result<ImportPlan, MapError> {
    import_mode(doc, spec, codec, ImportMode::Merge, None)
}

/// Map a document into intents under an explicit [`ImportMode`]. In [`ImportMode::Replace`], `current`
/// (the document being imported into) is required: any collection element it has that the incoming
/// document omits is retracted (tombstoned).
pub fn import_mode(
    doc: &ValueTree,
    spec: &MappingSpec,
    codec: &dyn Codec,
    mode: ImportMode,
    current: Option<&commute::Doc>,
) -> Result<ImportPlan, MapError> {
    let ValueTree::Map(fields) = doc else {
        return Err(MapError::NotAnObject);
    };
    let mut plan = ImportPlan::default();
    // The element keys the document names, per collection field — the basis for Replace retraction.
    let mut present: Vec<(String, HashSet<Vec<u8>>)> = Vec::new();

    for (field, value) in fields {
        match spec.policy(field) {
            Some(FieldPolicy::Scalar) | None if scalar(value).is_some() => {
                plan.intents.push(OpIntent::SetRegister {
                    cell: cell(field),
                    value: scalar(value).expect("checked scalar"),
                });
                plan.summary.push(format!("set {field}"));
            }
            // A collection (Seq/Map) with no declared policy — refuse, never silently LWW.
            None => return Err(MapError::UndeclaredCollection(field.clone())),
            Some(FieldPolicy::Scalar) => return Err(MapError::ExpectedScalar(field.clone())),
            Some(FieldPolicy::Atomic) => {
                let bytes = codec.emit(value)?;
                plan.intents.push(OpIntent::SetRegister {
                    cell: cell(field),
                    value: Value::Bytes(bytes),
                });
                plan.summary.push(format!("set {field} (atomic)"));
            }
            Some(FieldPolicy::ValueIdentity) => {
                let ValueTree::Seq(elems) = value else {
                    return Err(MapError::NotAnArray(field.clone()));
                };
                let mut keys: HashSet<Vec<u8>> = HashSet::new();
                for elem in elems {
                    let key = key_string(elem).ok_or_else(|| MapError::BadKeyType {
                        field: field.clone(),
                    })?;
                    let v = scalar(elem).expect("key_string implies scalar");
                    if keys.insert(key.clone().into_bytes()) {
                        plan.intents.push(OpIntent::AddElement {
                            cell: cell(field),
                            elem: key.into_bytes(),
                            value: v,
                        });
                    }
                }
                plan.summary
                    .push(format!("upsert {} value(s) in {field}", keys.len()));
                present.push((field.clone(), keys));
            }
            Some(FieldPolicy::Keyed { key_field }) => {
                let keys = keyed_elements(field, value, key_field, None, codec, &mut plan)?;
                present.push((field.clone(), keys));
            }
            Some(FieldPolicy::KeyedOrdered {
                key_field,
                order_field,
            }) => {
                let keys =
                    keyed_elements(field, value, key_field, Some(order_field), codec, &mut plan)?;
                present.push((field.clone(), keys));
            }
        }
    }

    // Replace: retract any current collection element the document didn't mention.
    if mode == ImportMode::Replace {
        let cur = current.ok_or(MapError::NotAnObject)?; // Replace needs the current state
        for (field, keys) in &present {
            for (id, _) in cur.set_elements(field.as_bytes()) {
                if !keys.contains(id.as_slice()) {
                    plan.intents.push(OpIntent::RemoveElement {
                        cell: cell(field),
                        elem: id.clone(),
                    });
                    plan.summary.push(format!("retract 1 element from {field}"));
                }
            }
        }
    }
    Ok(plan)
}

/// Shared Keyed / KeyedOrdered element mapping: each element is an object identified by `key_field`
/// (and, for KeyedOrdered, must also carry `order_field`), stored as an opaque leaf. Returns the set
/// of element keys seen. Duplicate keys are an error.
fn keyed_elements(
    field: &str,
    value: &ValueTree,
    key_field: &str,
    order_field: Option<&str>,
    codec: &dyn Codec,
    plan: &mut ImportPlan,
) -> Result<HashSet<Vec<u8>>, MapError> {
    let ValueTree::Seq(elems) = value else {
        return Err(MapError::NotAnArray(field.to_string()));
    };
    let mut keys: HashSet<Vec<u8>> = HashSet::new();
    for elem in elems {
        let ValueTree::Map(props) = elem else {
            return Err(MapError::ElementNotAnObject(field.to_string()));
        };
        let get = |name: &str| props.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        let key_val = get(key_field).ok_or_else(|| MapError::MissingKey {
            field: field.to_string(),
            key: key_field.to_string(),
        })?;
        let key = key_string(key_val).ok_or_else(|| MapError::BadKeyType {
            field: field.to_string(),
        })?;
        if let Some(of) = order_field {
            // KeyedOrdered requires the order field so the collection can be sorted on export.
            if get(of).is_none() {
                return Err(MapError::MissingKey {
                    field: field.to_string(),
                    key: of.to_string(),
                });
            }
        }
        if !keys.insert(key.clone().into_bytes()) {
            return Err(MapError::DuplicateKey {
                field: field.to_string(),
                key,
            });
        }
        let bytes = codec.emit(elem)?;
        plan.intents.push(OpIntent::AddElement {
            cell: cell(field),
            elem: key.into_bytes(),
            value: Value::Bytes(bytes),
        });
    }
    plan.summary
        .push(format!("upsert {} element(s) in {field}", elems.len()));
    Ok(keys)
}
