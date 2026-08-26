#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};

pub use openom_claim::envelope::Record;
use openom_claim::envelope::{Citations, Claim};
use serde_json::Value;

const TYPE_PERSON: &str = "openom.org/core/person/v1";
const TYPE_EVENT: &str = "openom.org/core/event/v1";
const P_NAME: &str = "openom.org/core/name/v1";
const P_EVENT_TYPE: &str = "openom.org/core/event_type/v1";
const P_DATE: &str = "openom.org/core/date/v1";
const P_EVENT_PLACE: &str = "openom.org/core/event_place/v1";
const P_PARTICIPANT: &str = "openom.org/core/participant/v1";
const P_SEX: &str = "openom.org/core/sex/v1";
const P_BIOGRAPHY: &str = "openom.org/core/biography/v1";
const P_SAME_AS: &str = "openom.org/core/same_as/v1";
const P_DIFFERENT_FROM: &str = "openom.org/core/different_from/v1";
const P_REATTRIBUTE: &str = "openom.org/core/reattribute_to/v1";
const P_PREFERRED: &str = "openom.org/core/preferred/v1";
const P_PARENT: &str = "openom.org/core/parent/v1";
const P_PARTNERSHIP: &str = "openom.org/core/partnership/v1";
const P_CUSTOM_FIELD: &str = "openom.org/core/custom/field/v1"; // definition (on the tree)
const P_CUSTOM_VALUE: &str = "openom.org/core/custom/value/v1"; // a value (on a person)
const P_ATTEST: &str = "openom.org/core/attest/v1";
const P_SOURCE: &str = "openom.org/core/source/v1"; // a self-subject source (cite-sink), §10.2
const P_PLACE_POINT: &str = "openom.org/core/place_point/v1"; // {latitude, longitude, precision?}
const P_PLACE_NAME: &str = "openom.org/core/place_name/v1"; // {name, validRange} — time-bounded, §10.3
const P_PART_OF: &str = "openom.org/core/part_of/v1"; // {parentPlaceId} — modern nesting
const P_MEDIA_LINK: &str = "openom.org/core/media_link/v1"; // {mediaHash, coverage?} — blob ↔ anchor
const DEFAULT_KIND: &str = "biological";
const DEFAULT_ROLE: &str = "partner";

/// Read-time policy knobs.
pub struct Policy {
    /// Minimum score to merge a `same_as` pair.
    pub same_as_threshold: i64,
    /// Minimum score for a `different_from` to act as a hard cut; a weaker or refuted one does not
    /// block a merge.
    pub different_from_threshold: i64,
    /// Minimum score for a `reattribute_to` to re-home a claim's subject to a new anchor.
    pub reattribute_threshold: i64,
    /// Minimum score for a `preferred` selection to take effect.
    pub preferred_threshold: i64,
    /// Minimum score for a parent-child or partnership edge to be admitted.
    pub relationship_threshold: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            same_as_threshold: 1,
            different_from_threshold: 1,
            reattribute_threshold: 1,
            preferred_threshold: 1,
            relationship_threshold: 1,
        }
    }
}

/// One rendering of a person's name, retargeted to the canonical person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameView {
    pub claim_id: String,
    pub parts: Value,
    /// Equivalence-class label — the minimum `claim_id` among names joined (directly or transitively)
    /// by `equivalent_to`. Names sharing it are the *same* name differently rendered (§6); a name with
    /// no equivalents is its own class.
    pub equiv_class: String,
}

/// A projected person: one real individual, possibly assembled from several merged anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// Canonical id — the minimum anchor id in the cluster.
    pub id: String,
    /// The other anchor ids merged into this person (sorted; empty if none).
    pub also: Vec<String>,
    /// Name claims about this person (sorted by claim id).
    pub names: Vec<NameView>,
    /// The claim id of the preferred name, if a `preferred` selection resolved to one of `names`.
    pub preferred_name: Option<String>,
    /// Resolved sex, if asserted (the value with the most distinct authors; ties broken lexically).
    pub sex: Option<String>,
    /// Resolved biography text, if asserted (most-corroborated `core/biography/v1` plain text).
    pub biography: Option<String>,
    /// Resolved custom fields (sorted by `field_id`): each field's canonical label/type from its
    /// `custom/field/v1` definition + this person's most-corroborated `custom/value/v1`.
    pub custom_fields: Vec<CustomField>,
    /// Citations backing facts about this person: every claim directly targeting this person (after
    /// `reattribute_to`) that carries an inline `citation`, with its `sourceId` resolved to the
    /// referenced `core/source/v1` claim (§10.2). Sorted by (source id, citing claim id). Citations
    /// borne by an event a person merely participates in are not yet folded in (a documented seam).
    pub sources: Vec<Citation>,
    /// Media linked to this person (§10.2) — portraits and other blobs, via `media_link/v1` claims
    /// targeting the person, each carrying the full media shape (mime/size/role/caption/crop). Sorted
    /// by claim id; a link with `role == "portrait"` is the portrait (a disputable `preferred`
    /// portrait slot is a later refinement).
    pub media: Vec<MediaLink>,
}

/// A content-addressed blob linked to an anchor via a `media_link/v1` claim (§10.2). Carries the full
/// media shape so an engine's media surface (attach / portrait / crop) round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaLink {
    pub claim_id: String,
    /// The content hash of the blob (out-of-band, fetched from object storage).
    pub media_hash: String,
    /// A coverage/locator within the blob (e.g. `{page, entry}`) for partial media, if given.
    pub coverage: Option<Value>,
    /// MIME type of the blob, if given (e.g. `image/jpeg`).
    pub mime: Option<String>,
    /// Pixel width / height of the blob, if given.
    pub width: Option<i64>,
    pub height: Option<i64>,
    /// Coarse kind (e.g. `image`, `document`), if given — usually derivable from `mime`.
    pub kind: Option<String>,
    /// The link's role — `portrait` marks this as the person's portrait, otherwise a document/other.
    pub role: Option<String>,
    /// Display order among a person's media, if given.
    pub order: Option<i64>,
    /// Caption text, if given.
    pub caption: Option<String>,
    /// A crop rectangle (a native object, e.g. `{x, y, w, h}`) for the portrait, if given.
    pub crop: Option<Value>,
}

/// Build a [`MediaLink`] view from a `media_link/v1` claim's value, carrying the full media shape
/// (§10.2). `role == "portrait"` is the portrait selection (a disputable `preferred` portrait slot is
/// a later refinement).
fn media_link_view(claim_id: String, value: &Value) -> MediaLink {
    let s = |k: &str| value.get(k).and_then(Value::as_str).map(str::to_owned);
    let i = |k: &str| value.get(k).and_then(Value::as_i64);
    MediaLink {
        claim_id,
        media_hash: s("mediaHash").unwrap_or_default(),
        coverage: value.get("coverage").cloned(),
        mime: s("mime"),
        width: i("width"),
        height: i("height"),
        kind: s("kind"),
        role: s("role"),
        order: i("order"),
        caption: s("caption"),
        crop: value.get("crop").cloned(),
    }
}

/// A source referenced by a citation, resolved from its `core/source/v1` claim. Every field is
/// `None` when the `source_id` does not resolve to a known source claim (dangling reference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub source_id: String,
    pub title: Option<String>,
    pub repository: Option<String>,
    pub uri: Option<String>,
    /// `primary` | `secondary` | `original` | `derivative`.
    pub quality: Option<String>,
}

/// One citation surfaced on a person's sources panel: the fact it backs, where in the source, and the
/// resolved source itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Citation {
    /// The id of the claim this citation is attached to.
    pub claim_id: String,
    /// The predicate of that claim, so the panel can say *what* is cited.
    pub predicate: String,
    /// A locator within the source (e.g. `{page, entry}`), verbatim, if given.
    pub locator: Option<Value>,
    /// A verbatim extract from the source, if given.
    pub extract: Option<String>,
    /// The referenced source, resolved from `citation.sourceId`.
    pub source: SourceRef,
}

/// A resolved custom field on a person. `label`/`field_type` come from the field's `custom/field/v1`
/// definition (most-corroborated); a value whose `field_id` has no definition degrades to
/// `label = field_id`, `field_type = "text"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomField {
    pub field_id: String,
    pub label: String,
    pub field_type: String,
    pub value: Value,
}

/// A `same_as` edge that was not applied because a `different_from` cut it — surfaced, never merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub cut_pair: [String; 2],
}

/// A directional parent→child edge (stored once, read from either end) between canonical persons.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParentChild {
    pub parent: String,
    pub child: String,
    /// A `core/relations/v1` term: `biological` | `adoptive` | `step` | `foster` | `guardian`.
    pub kind: String,
}

/// A symmetric partnership between two canonical persons.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Partnership {
    pub pair: [String; 2],
    /// A `core/roles/v1` term: `spouse` | `partner`.
    pub role: String,
}

/// One participant in an event: the canonical person and the role they played.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Participant {
    pub person: String,
    /// A `core/roles/v1` term: `child` | `parent` | `spouse` | `witness` | `officiant` | …
    pub role: String,
}

/// A projected event (birth, death, marriage, …) — a hyper-edge assembled from the claims targeting
/// one Event anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventView {
    pub id: String,
    /// The event type, if asserted (most-corroborated value).
    pub event_type: Option<String>,
    /// The raw EDTF date, if asserted (most-corroborated).
    pub date_edtf: Option<String>,
    /// Sortable year bounds parsed from the EDTF (`None` if it doesn't parse or an end is open).
    pub date_min_year: Option<i32>,
    pub date_max_year: Option<i32>,
    /// The place anchor id, if asserted (most-corroborated).
    pub place_id: Option<String>,
    /// Participants (persons canonicalized), sorted.
    pub participants: Vec<Participant>,
    /// The resolved place, if a `place_id` is asserted: its name rendered for this event's date, its
    /// point, and its parent. `None` if the event has no place.
    pub place: Option<PlaceView>,
}

/// A resolved place for an event (§10.3): its time-appropriate name plus its point and parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceView {
    /// The place anchor id (referenced verbatim; place `same_as` dedup is a documented seam).
    pub id: String,
    /// The `place_name` whose `validRange` covers the event date; falls back to the most-corroborated
    /// name if none covers (or the event has no date). `None` if the place has no name claim.
    pub name: Option<String>,
    /// The most-corroborated `place_point` value `{ latitude, longitude, precision? }`, if asserted.
    pub point: Option<Value>,
    /// The parent place anchor id from `part_of` (most-corroborated), if any.
    pub part_of: Option<String>,
}

/// A family/union — a parent-set (the spouses) and the children sharing exactly that parent-set,
/// with a stable id and its marriage event if one is recorded. Derived from the atomic parent-child +
/// partnership edges so the GUI has an addressable "family": marriage facts attach here, and full vs.
/// half siblings fall out of the parent-set grouping (a shared parent-set = full siblings; a partially
/// shared one = a different union = half siblings). The id is stable across replicas (a function of
/// the canonical parent-set), so it survives merges and re-projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Union {
    /// Stable id: `"union:" + the sorted canonical parent ids joined by '+'`.
    pub id: String,
    /// The parents (0 is impossible, 1 = single-parent family, 2 = a couple), sorted.
    pub parents: Vec<String>,
    /// The children sharing exactly this parent-set, sorted.
    pub children: Vec<String>,
    /// The id of a recorded marriage/divorce event whose spouses are exactly these parents, if any.
    pub marriage_event: Option<String>,
}

/// The materialized read model: people, relationships, family unions, events, and identity conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub people: Vec<Person>,
    pub parent_child: Vec<ParentChild>,
    pub partnerships: Vec<Partnership>,
    pub unions: Vec<Union>,
    pub events: Vec<EventView>,
    pub conflicts: Vec<Conflict>,
}

/// Project a record set into the read model. Pure: the result depends only on the set of records and
/// the policy, never on their order.
pub fn project(records: &[Record], policy: &Policy) -> Projection {
    // The store guarantees unique content-hash ids, but be robust to a duplicated slice: keep the
    // first record per id, so projecting `recs` and `recs ++ recs` give the same result (set input).
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    let deduped: Vec<&Record> = records
        .iter()
        .filter(|r| seen_ids.insert(r.id().to_string()))
        .collect();

    // --- classify -------------------------------------------------------------------------------
    // Anchors, and person-scoped claims. Deletion and edit-supersession are operations applied
    // upstream (the ops→snapshot layer, §8.2); the projection consumes the already-live claim set.
    let mut anchors: BTreeSet<String> = BTreeSet::new();
    let mut same_as: BTreeMap<[String; 2], PairInfo> = BTreeMap::new();
    let mut different_from: BTreeMap<[String; 2], PairInfo> = BTreeMap::new();
    let mut attests: BTreeMap<String, Votes> = BTreeMap::new(); // target (claim id | fingerprint) -> votes
    let mut name_claims: Vec<(String, String, Value)> = Vec::new(); // (targetId, claimId, parts)
    let mut sex_claims: Vec<(String, String, String, String)> = Vec::new(); // (targetId, claimId, value, author)
    let mut biography_claims: Vec<(String, String, String, String)> = Vec::new(); // (targetId, claimId, text, author)
    let mut field_label: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // fieldId -> label -> authors
    let mut field_type: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // fieldId -> type -> authors
    let mut custom_values: Vec<(String, String, String, Value, String)> = Vec::new(); // (target, claimId, fieldId, value, author)
    let mut reattribute: BTreeMap<String, BTreeMap<String, PairInfo>> = BTreeMap::new(); // re-homed claim id -> personId -> info
    let mut preferred: BTreeMap<(String, String, String), PairInfo> = BTreeMap::new(); // (person, for, claim content-ref) -> info
    let mut parent_child: BTreeMap<(String, String, String), PairInfo> = BTreeMap::new(); // (child, parent, kind) -> info
    let mut partnership: BTreeMap<([String; 2], String), PairInfo> = BTreeMap::new(); // (canonical pair, role) -> info
    let mut event_anchors: BTreeSet<String> = BTreeSet::new();
    let mut event_type: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // eventId -> type -> authors
    let mut event_date: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // eventId -> edtf -> authors
    let mut event_place: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // eventId -> placeId -> authors
    let mut participants: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new(); // eventId -> {(personId, role)}
    let mut sources: BTreeMap<String, Value> = BTreeMap::new(); // source claim id -> its value
    let mut citations: Vec<(String, String, String, Value)> = Vec::new(); // (targetId, citing claimId, predicate, citation)
    #[allow(clippy::type_complexity)]
    let mut place_point: BTreeMap<String, BTreeMap<String, (BTreeSet<String>, Value)>> =
        BTreeMap::new(); // placeId -> canonical(point) -> (authors, pointValue)
    let mut place_name: BTreeMap<String, BTreeMap<(String, String), BTreeSet<String>>> =
        BTreeMap::new(); // placeId -> (validRange, name) -> authors
    let mut part_of: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // placeId -> parentId -> authors
    let mut media_links: Vec<(String, String, Value)> = Vec::new(); // (target, claimId, value)

    for &r in &deduped {
        let c: &Claim = match r {
            Record::Anchor(a) => {
                match a.type_uri.as_str() {
                    TYPE_PERSON => {
                        anchors.insert(a.id.clone());
                    }
                    TYPE_EVENT => {
                        event_anchors.insert(a.id.clone());
                    }
                    _ => {}
                }
                continue;
            }
            Record::Claim(c) => c,
        };
        let pred = c.predicate.as_str();
        let id = c.id.as_str();
        // Any claim (whatever its predicate) may carry an inline citation backing the fact it asserts.
        // Today only a single-object citation is captured; an array citation is a documented seam.
        if let Some(Citations::One(cit)) = &c.citation {
            if let Ok(cit_val) = serde_json::to_value(cit) {
                citations.push((
                    c.target_id.clone(),
                    id.to_string(),
                    pred.to_string(),
                    cit_val,
                ));
            }
        }
        match pred {
            P_SOURCE => {
                sources.insert(id.to_string(), c.value.clone());
            }
            P_PLACE_POINT => {
                if let (Some(t), Some(v), Some(a)) = (
                    Some(c.target_id.as_str()),
                    Some(&c.value),
                    Some(c.created_by.as_str()),
                ) {
                    place_point
                        .entry(t.to_string())
                        .or_default()
                        .entry(v.to_string())
                        .or_insert_with(|| (BTreeSet::new(), v.clone()))
                        .0
                        .insert(a.to_string());
                }
            }
            P_PLACE_NAME => {
                if let (Some(t), Some(name), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("name").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    let range = c
                        .value
                        .get("validRange")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    place_name
                        .entry(t.to_string())
                        .or_default()
                        .entry((range.to_string(), name.to_string()))
                        .or_default()
                        .insert(a.to_string());
                }
            }
            P_PART_OF => tally(&mut part_of, c, "parentPlaceId"),
            P_MEDIA_LINK => {
                // Keep the whole value so the media view round-trips mime/width/height/role/order/
                // caption/crop/kind (§10.2); require only `mediaHash` (the blob this links).
                if c.value.get("mediaHash").and_then(Value::as_str).is_some() {
                    media_links.push((c.target_id.clone(), id.to_string(), c.value.clone()));
                }
            }
            P_SAME_AS => collect_pair(&mut same_as, c, id),
            P_DIFFERENT_FROM => collect_pair(&mut different_from, c, id),
            P_ATTEST => {
                if let (Some(t), Some(verdict), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("verdict").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    let v = attests.entry(t.to_string()).or_default();
                    match verdict {
                        "support" => {
                            v.support.insert(a.to_string());
                        }
                        "reject" => {
                            v.reject.insert(a.to_string());
                        }
                        _ => {}
                    }
                }
            }
            P_PREFERRED => {
                if let (Some(person), Some(for_pred), Some(claim_ref), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("for").and_then(Value::as_str),
                    c.value.get("claimId").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    let info = preferred
                        .entry((
                            person.to_string(),
                            for_pred.to_string(),
                            claim_ref.to_string(),
                        ))
                        .or_default();
                    info.authors.insert(a.to_string());
                    info.claim_ids.insert(id.to_string());
                    if info.fingerprint.is_none() {
                        info.fingerprint = fingerprint_str(c);
                    }
                }
            }
            P_PARENT => {
                if let (Some(child), Some(parent), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("parentPersonId").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    let kind = c
                        .value
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or(DEFAULT_KIND);
                    let info = parent_child
                        .entry((child.to_string(), parent.to_string(), kind.to_string()))
                        .or_default();
                    info.authors.insert(a.to_string());
                    info.claim_ids.insert(id.to_string());
                    if info.fingerprint.is_none() {
                        info.fingerprint = fingerprint_str(c);
                    }
                }
            }
            P_PARTNERSHIP => {
                if let (Some(p), Some(a)) = (pair(c), Some(c.created_by.as_str())) {
                    let role = c
                        .value
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or(DEFAULT_ROLE);
                    let info = partnership.entry((p, role.to_string())).or_default();
                    info.authors.insert(a.to_string());
                    info.claim_ids.insert(id.to_string());
                    if info.fingerprint.is_none() {
                        info.fingerprint = fingerprint_str(c);
                    }
                }
            }
            P_EVENT_TYPE => tally(&mut event_type, c, "type"),
            P_DATE => tally(&mut event_date, c, "edtf"),
            P_EVENT_PLACE => tally(&mut event_place, c, "placeId"),
            P_PARTICIPANT => {
                if let (Some(evt), Some(person), Some(role)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("personId").and_then(Value::as_str),
                    c.value.get("role").and_then(Value::as_str),
                ) {
                    participants
                        .entry(evt.to_string())
                        .or_default()
                        .insert((person.to_string(), role.to_string()));
                }
            }
            P_NAME => {
                if let (Some(t), Some(v)) = (Some(c.target_id.as_str()), Some(&c.value)) {
                    name_claims.push((t.to_string(), id.to_string(), v.clone()));
                }
            }
            P_SEX => {
                if let (Some(t), Some(sex), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("sex").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    sex_claims.push((
                        t.to_string(),
                        id.to_string(),
                        sex.to_string(),
                        a.to_string(),
                    ));
                }
            }
            P_BIOGRAPHY => {
                if let (Some(t), Some(text), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("text").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    biography_claims.push((
                        t.to_string(),
                        id.to_string(),
                        text.to_string(),
                        a.to_string(),
                    ));
                }
            }
            P_CUSTOM_FIELD => {
                if let (Some(fid), Some(a)) = (
                    c.value.get("fieldId").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    let val = &c.value;
                    if let Some(label) = val.get("label").and_then(Value::as_str) {
                        field_label
                            .entry(fid.to_string())
                            .or_default()
                            .entry(label.to_string())
                            .or_default()
                            .insert(a.to_string());
                    }
                    if let Some(ty) = val.get("type").and_then(Value::as_str) {
                        field_type
                            .entry(fid.to_string())
                            .or_default()
                            .entry(ty.to_string())
                            .or_default()
                            .insert(a.to_string());
                    }
                }
            }
            P_CUSTOM_VALUE => {
                if let (Some(t), Some(fid), Some(val), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("fieldId").and_then(Value::as_str),
                    c.value.get("value"),
                    Some(c.created_by.as_str()),
                ) {
                    custom_values.push((
                        t.to_string(),
                        id.to_string(),
                        fid.to_string(),
                        val.clone(),
                        a.to_string(),
                    ));
                }
            }
            P_REATTRIBUTE => {
                if let (Some(target), Some(person), Some(a)) = (
                    Some(c.target_id.as_str()),
                    c.value.get("personId").and_then(Value::as_str),
                    Some(c.created_by.as_str()),
                ) {
                    let info = reattribute
                        .entry(target.to_string())
                        .or_default()
                        .entry(person.to_string())
                        .or_default();
                    info.authors.insert(a.to_string());
                    info.claim_ids.insert(id.to_string());
                    if info.fingerprint.is_none() {
                        info.fingerprint = fingerprint_str(c);
                    }
                }
            }
            _ => {}
        }
    }

    // --- nodes = every id that participates as a person -----------------------------------------
    let mut nodes: BTreeSet<String> = anchors.clone();
    for p in same_as.keys().chain(different_from.keys()) {
        nodes.insert(p[0].clone());
        nodes.insert(p[1].clone());
    }
    for (t, _, _) in &name_claims {
        nodes.insert(t.clone());
    }
    for (t, _, _, _) in &sex_claims {
        nodes.insert(t.clone());
    }
    for (t, _, _, _) in &biography_claims {
        nodes.insert(t.clone());
    }
    for (t, _, _, _, _) in &custom_values {
        nodes.insert(t.clone());
    }
    for (t, _, _) in &media_links {
        nodes.insert(t.clone());
    }
    for options in reattribute.values() {
        for person in options.keys() {
            nodes.insert(person.clone());
        }
    }
    for (child, parent, _) in parent_child.keys() {
        nodes.insert(child.clone());
        nodes.insert(parent.clone());
    }
    for (pair, _) in partnership.keys() {
        nodes.insert(pair[0].clone());
        nodes.insert(pair[1].clone());
    }

    // --- edges + cuts, each gated by its attestation-weighted score -----------------------------
    let edges: Vec<Edge> = same_as
        .iter()
        .filter_map(|(pair, info)| {
            let s = score(info, &attests);
            (s >= policy.same_as_threshold).then(|| Edge {
                a: pair[0].clone(),
                b: pair[1].clone(),
                score: s,
            })
        })
        .collect();
    let cuts: Vec<[String; 2]> = different_from
        .iter()
        .filter(|(_, info)| score(info, &attests) >= policy.different_from_threshold)
        .map(|(pair, _)| pair.clone())
        .collect();

    let Clustering { rep, skipped } = cluster(&nodes, edges, &cuts);

    // --- assemble people ------------------------------------------------------------------------
    // Group nodes by cluster key (the min-node rep), then pick each cluster's canonical PERSON id =
    // its minimum *anchor* member. A cluster with no anchor (e.g. a dangling `same_as` endpoint that
    // sorts below the real anchors) is not a person and is dropped.
    let mut by_key: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (node, key) in &rep {
        by_key.entry(key.clone()).or_default().insert(node.clone());
    }
    let mut canonical: BTreeMap<String, String> = BTreeMap::new(); // cluster key -> min anchor
    for (key, members) in &by_key {
        if let Some(anchor) = members.iter().find(|m| anchors.contains(*m)) {
            canonical.insert(key.clone(), anchor.clone());
        }
    }
    let canon_of =
        |id: &str| -> Option<String> { rep.get(id).and_then(|key| canonical.get(key)).cloned() };

    // Resolve reattribute_to: per re-homed claim, the winning net-positive personId (highest score,
    // ties by personId). eff_target then re-homes a claim's subject *before* it is grouped.
    let rehome: BTreeMap<String, String> = reattribute
        .iter()
        .filter_map(|(claim, options)| {
            options
                .iter()
                .filter(|(_, info)| score(info, &attests) >= policy.reattribute_threshold)
                .max_by(|a, b| {
                    score(a.1, &attests)
                        .cmp(&score(b.1, &attests))
                        .then(b.0.cmp(a.0))
                })
                .map(|(person, _)| (claim.clone(), person.clone()))
        })
        .collect();
    let eff_target = |claim_id: &str, orig: &str| -> String {
        rehome
            .get(claim_id)
            .cloned()
            .unwrap_or_else(|| orig.to_string())
    };

    // Pre-group names + sex by canonical person (applying reattribute_to via eff_target).
    let mut names_by_person: BTreeMap<String, Vec<NameView>> = BTreeMap::new();
    for (target, cid, parts) in &name_claims {
        if let Some(canon) = canon_of(&eff_target(cid, target)) {
            names_by_person.entry(canon).or_default().push(NameView {
                claim_id: cid.clone(),
                parts: parts.clone(),
                equiv_class: String::new(),
            });
        }
    }
    for views in names_by_person.values_mut() {
        views.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
        let classes = equiv_classes(views);
        for v in views.iter_mut() {
            v.equiv_class = classes
                .get(&v.claim_id)
                .cloned()
                .unwrap_or_else(|| v.claim_id.clone());
        }
    }

    let mut sex_by_person: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for (target, cid, val, author) in &sex_claims {
        if let Some(canon) = canon_of(&eff_target(cid, target)) {
            sex_by_person
                .entry(canon)
                .or_default()
                .entry(val.clone())
                .or_default()
                .insert(author.clone());
        }
    }

    let mut biography_by_person: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> =
        BTreeMap::new();
    for (target, cid, text, author) in &biography_claims {
        if let Some(canon) = canon_of(&eff_target(cid, target)) {
            biography_by_person
                .entry(canon)
                .or_default()
                .entry(text.clone())
                .or_default()
                .insert(author.clone());
        }
    }

    // Custom fields: per (person, fieldId) resolve the most-corroborated value; label/type from the
    // field's most-corroborated definition (dangling fieldId → label = fieldId, type = "text").
    #[allow(clippy::type_complexity)]
    let mut custom_by_person: BTreeMap<
        String,
        BTreeMap<String, BTreeMap<String, (BTreeSet<String>, Value)>>,
    > = BTreeMap::new();
    for (target, cid, fid, val, author) in &custom_values {
        if let Some(canon) = canon_of(&eff_target(cid, target)) {
            custom_by_person
                .entry(canon)
                .or_default()
                .entry(fid.clone())
                .or_default()
                .entry(val.to_string())
                .or_insert_with(|| (BTreeSet::new(), val.clone()))
                .0
                .insert(author.clone());
        }
    }
    let mut customs_of: BTreeMap<String, Vec<CustomField>> = BTreeMap::new();
    for (person, by_field) in &custom_by_person {
        let mut fields: Vec<CustomField> = by_field
            .iter()
            .filter_map(|(fid, by_value)| {
                by_value
                    .iter()
                    .max_by(|a, b| a.1 .0.len().cmp(&b.1 .0.len()).then(b.0.cmp(a.0)))
                    .map(|(_, (_, val))| CustomField {
                        field_id: fid.clone(),
                        label: field_label
                            .get(fid)
                            .and_then(most_corroborated)
                            .unwrap_or_else(|| fid.clone()),
                        field_type: field_type
                            .get(fid)
                            .and_then(most_corroborated)
                            .unwrap_or_else(|| "text".to_string()),
                        value: val.clone(),
                    })
            })
            .collect();
        fields.sort_by(|a, b| a.field_id.cmp(&b.field_id));
        customs_of.insert(person.clone(), fields);
    }

    // Sources: attach each citing claim to the canonical person its (effective) target resolves to,
    // resolving the `sourceId` to the source claim's description. An unresolved source id surfaces the
    // reference with empty source fields rather than dropping the citation.
    let mut sources_by_person: BTreeMap<String, Vec<Citation>> = BTreeMap::new();
    for (target, cid, pred, cit) in &citations {
        let Some(canon) = canon_of(&eff_target(cid, target)) else {
            continue;
        };
        let source_id = cit
            .get("sourceId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let src = sources.get(&source_id);
        let field = |k: &str| {
            src.and_then(|s| s.get(k))
                .and_then(Value::as_str)
                .map(String::from)
        };
        sources_by_person.entry(canon).or_default().push(Citation {
            claim_id: cid.clone(),
            predicate: pred.clone(),
            locator: cit.get("locator").cloned(),
            extract: cit.get("extract").and_then(Value::as_str).map(String::from),
            source: SourceRef {
                source_id: source_id.clone(),
                title: field("title"),
                repository: field("repository"),
                uri: field("uri"),
                quality: field("quality"),
            },
        });
    }
    for cits in sources_by_person.values_mut() {
        cits.sort_by(|a, b| {
            a.source
                .source_id
                .cmp(&b.source.source_id)
                .then(a.claim_id.cmp(&b.claim_id))
        });
        cits.dedup();
    }

    // Media: attach each `media_link` to the canonical person its (effective) target resolves to.
    // Links targeting events or sources don't resolve to a person and are dropped here (a seam).
    let mut media_by_person: BTreeMap<String, Vec<MediaLink>> = BTreeMap::new();
    for (target, cid, value) in &media_links {
        if let Some(canon) = canon_of(&eff_target(cid, target)) {
            media_by_person
                .entry(canon)
                .or_default()
                .push(media_link_view(cid.clone(), value));
        }
    }
    for links in media_by_person.values_mut() {
        links.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
        links.dedup();
    }

    // Resolve `preferred` for the name slot: per person, the highest-scored net-positive `preferred`
    // whose referent resolves to one of the person's names wins (ties by content-ref).
    let mut name_ref_to_id: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new(); // person -> ref -> claimId
    for (person, views) in &names_by_person {
        let map = views
            .iter()
            .filter_map(|v| name_ref(&v.parts).map(|r| (r, v.claim_id.clone())))
            .collect();
        name_ref_to_id.insert(person.clone(), map);
    }
    let mut by_slot: BTreeMap<(String, String), Vec<(&String, &PairInfo)>> = BTreeMap::new();
    for ((person, for_pred, claim_ref), info) in &preferred {
        if let Some(canon) = canon_of(person) {
            by_slot
                .entry((canon, for_pred.clone()))
                .or_default()
                .push((claim_ref, info));
        }
    }
    let mut preferred_name_of: BTreeMap<String, String> = BTreeMap::new();
    for ((person, for_pred), options) in &by_slot {
        if for_pred != P_NAME {
            continue; // other slots (birthdate, portrait…) use the same mechanism — a later increment
        }
        let refs = name_ref_to_id.get(person);
        let winner = options
            .iter()
            .filter(|(claim_ref, info)| {
                score(info, &attests) >= policy.preferred_threshold
                    && refs.is_some_and(|m| m.contains_key(*claim_ref))
            })
            .max_by(|a, b| {
                score(a.1, &attests)
                    .cmp(&score(b.1, &attests))
                    .then(b.0.cmp(a.0))
            });
        if let Some(name_id) = winner.and_then(|(r, _)| refs.and_then(|m| m.get(*r))) {
            preferred_name_of.insert(person.clone(), name_id.clone());
        }
    }

    let mut people = Vec::new();
    for (key, members) in &by_key {
        let Some(canon) = canonical.get(key) else {
            continue;
        };

        let mut also: Vec<String> = Vec::new();
        for m in members {
            if anchors.contains(m) && m != canon {
                also.push(m.clone());
            }
        }

        let names = names_by_person.remove(canon).unwrap_or_default();
        let sex = sex_by_person.get(canon).and_then(|tally| {
            tally
                .iter()
                .max_by(|x, y| x.1.len().cmp(&y.1.len()).then(y.0.cmp(x.0)))
                .map(|(val, _)| val.clone())
        });

        let preferred_name = preferred_name_of.get(canon).cloned();
        let biography = biography_by_person.get(canon).and_then(most_corroborated);
        let custom_fields = customs_of.remove(canon).unwrap_or_default();
        let sources = sources_by_person.remove(canon).unwrap_or_default();
        let media = media_by_person.remove(canon).unwrap_or_default();
        people.push(Person {
            id: canon.clone(),
            also,
            names,
            preferred_name,
            sex,
            biography,
            custom_fields,
            sources,
            media,
        });
    }
    people.sort_by(|a, b| a.id.cmp(&b.id));

    // Relationships between canonical persons (attestation-weighted; endpoints canonicalized through
    // the same_as clusters; an edge with a dangling endpoint or that collapses to a self-loop is
    // dropped; duplicates that coincide after canonicalization are merged).
    let mut parent_child_edges: Vec<ParentChild> = parent_child
        .iter()
        .filter(|(_, info)| score(info, &attests) >= policy.relationship_threshold)
        .filter_map(|((child, parent, kind), _)| {
            let (c, p) = (canon_of(child)?, canon_of(parent)?);
            (c != p).then(|| ParentChild {
                parent: p,
                child: c,
                kind: kind.clone(),
            })
        })
        .collect();
    parent_child_edges.sort();
    parent_child_edges.dedup();

    let mut partnership_edges: Vec<Partnership> = partnership
        .iter()
        .filter(|(_, info)| score(info, &attests) >= policy.relationship_threshold)
        .filter_map(|((pair, role), _)| {
            let (a, b) = (canon_of(&pair[0])?, canon_of(&pair[1])?);
            (a != b).then(|| Partnership {
                pair: sorted_pair(&a, &b),
                role: role.clone(),
            })
        })
        .collect();
    partnership_edges.sort();
    partnership_edges.dedup();

    // Resolve a place for a given event year: most-corroborated point + parent, and the name whose
    // `validRange` covers the year (falling back to the most-corroborated name when none covers or
    // there is no year).
    let resolve_place = |pid: &str, year: Option<i32>| -> PlaceView {
        let point = place_point.get(pid).and_then(|m| {
            m.iter()
                .max_by(|a, b| a.1 .0.len().cmp(&b.1 .0.len()).then(b.0.cmp(a.0)))
                .map(|(_, (_, v))| v.clone())
        });
        let part_of = part_of.get(pid).and_then(most_corroborated);
        let name = place_name
            .get(pid)
            .and_then(|cands| pick_place_name(cands, year));
        PlaceView {
            id: pid.to_string(),
            name,
            point,
            part_of,
        }
    };

    // Events — assemble each Event anchor's targeting claims into a hyper-edge (type / date / place
    // most-corroborated; participants canonicalized to persons). Sorted by event id (BTreeSet order).
    let events: Vec<EventView> = event_anchors
        .iter()
        .map(|eid| {
            let event_type = event_type.get(eid).and_then(most_corroborated);
            let date_edtf = event_date.get(eid).and_then(most_corroborated);
            let (date_min_year, date_max_year) = date_edtf
                .as_deref()
                .and_then(|s| openom_edtf::parse(s).ok())
                .map(|e| (e.min.map(|d| d.year), e.max.map(|d| d.year)))
                .unwrap_or((None, None));
            let place_id = event_place.get(eid).and_then(most_corroborated);
            let mut parts: Vec<Participant> = participants
                .get(eid)
                .into_iter()
                .flatten()
                .filter_map(|(person, role)| {
                    canon_of(person).map(|p| Participant {
                        person: p,
                        role: role.clone(),
                    })
                })
                .collect();
            parts.sort();
            parts.dedup();
            let place = place_id
                .as_deref()
                .map(|pid| resolve_place(pid, date_min_year.or(date_max_year)));
            EventView {
                id: eid.clone(),
                event_type,
                date_edtf,
                date_min_year,
                date_max_year,
                place_id,
                participants: parts,
                place,
            }
        })
        .collect();

    // Family unions — group children by their canonical parent-set, add childless partnerships, and
    // attach a marriage/divorce event whose spouses match. The stable id gives the GUI an addressable
    // "family" and makes full-vs-half siblings fall out of the parent-set grouping.
    let mut parents_of_child: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pc in &parent_child_edges {
        parents_of_child
            .entry(pc.child.clone())
            .or_default()
            .insert(pc.parent.clone());
    }
    let mut union_children: BTreeMap<Vec<String>, BTreeSet<String>> = BTreeMap::new();
    for (child, parents) in &parents_of_child {
        union_children
            .entry(parents.iter().cloned().collect())
            .or_default()
            .insert(child.clone());
    }
    for pn in &partnership_edges {
        union_children.entry(pn.pair.to_vec()).or_default();
    }
    let unions: Vec<Union> = union_children
        .iter()
        .map(|(parents, children)| {
            let marriage_event = (parents.len() == 2)
                .then(|| {
                    let want: BTreeSet<&String> = parents.iter().collect();
                    events
                        .iter()
                        .find(|e| {
                            matches!(e.event_type.as_deref(), Some("marriage") | Some("divorce"))
                                && e.participants
                                    .iter()
                                    .map(|p| &p.person)
                                    .collect::<BTreeSet<_>>()
                                    == want
                        })
                        .map(|e| e.id.clone())
                })
                .flatten();
            Union {
                id: format!("union:{}", parents.join("+")),
                parents: parents.clone(),
                children: children.iter().cloned().collect(),
                marriage_event,
            }
        })
        .collect();

    let conflicts = skipped
        .into_iter()
        .map(|cut_pair| Conflict { cut_pair })
        .collect();
    Projection {
        people,
        parent_child: parent_child_edges,
        partnerships: partnership_edges,
        unions,
        events,
        conflicts,
    }
}

// --- the constraint-repair union-find (§11) -----------------------------------------------------

/// A positive `same_as` edge with its merge score.
struct Edge {
    a: String,
    b: String,
    score: i64,
}

/// The clustering result: `node id → canonical (min) id`, and the edges a cut skipped.
struct Clustering {
    rep: BTreeMap<String, String>,
    skipped: Vec<[String; 2]>,
}

/// Deterministic union-find with disequality constraints. Positive edges are admitted in a fixed
/// order — `(score desc, then the sorted pair asc)` — and any edge that would merge two nodes cut
/// (directly or transitively) by a negative constraint is skipped and surfaced. The output is a pure
/// function of `(nodes, edges, cuts)`, independent of how the records were delivered.
fn cluster(nodes: &BTreeSet<String>, mut edges: Vec<Edge>, cuts: &[[String; 2]]) -> Clustering {
    let mut uf = Uf::new(nodes);

    edges.sort_by(|x, y| {
        y.score
            .cmp(&x.score)
            .then_with(|| sorted_pair(&x.a, &x.b).cmp(&sorted_pair(&y.a, &y.b)))
    });

    let mut skipped = Vec::new();
    for e in &edges {
        let ra = uf.find(&e.a);
        let rb = uf.find(&e.b);
        if ra == rb {
            continue;
        }
        // Would merging clusters ra and rb place both ends of some `different_from` together?
        let violates = cuts.iter().any(|c| {
            let rp = uf.find(&c[0]);
            let rq = uf.find(&c[1]);
            (rp == ra && rq == rb) || (rp == rb && rq == ra)
        });
        if violates {
            skipped.push(sorted_pair(&e.a, &e.b));
        } else {
            uf.union(&ra, &rb);
        }
    }

    // Canonical representative = the minimum id in each cluster.
    let mut min_of: BTreeMap<String, String> = BTreeMap::new();
    for n in nodes {
        let root = uf.find(n);
        let entry = min_of.entry(root).or_insert_with(|| n.clone());
        if n < entry {
            *entry = n.clone();
        }
    }
    let rep = nodes
        .iter()
        .map(|n| (n.clone(), min_of[&uf.find(n)].clone()))
        .collect();

    skipped.sort();
    skipped.dedup();
    Clustering { rep, skipped }
}

struct Uf {
    parent: BTreeMap<String, String>,
}

impl Uf {
    fn new(nodes: &BTreeSet<String>) -> Self {
        Uf {
            parent: nodes.iter().map(|n| (n.clone(), n.clone())).collect(),
        }
    }

    fn find(&mut self, x: &str) -> String {
        let mut root = x.to_string();
        while let Some(p) = self.parent.get(&root) {
            if p == &root {
                break;
            }
            root = p.clone();
        }
        // Path compression.
        let mut cur = x.to_string();
        while cur != root {
            let next = self
                .parent
                .get(&cur)
                .cloned()
                .unwrap_or_else(|| root.clone());
            self.parent.insert(cur, root.clone());
            cur = next;
        }
        root
    }

    /// Union with a deterministic tie-break: the smaller id becomes the root, so the structure never
    /// depends on argument order.
    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        let (root, child) = if ra < rb { (ra, rb) } else { (rb, ra) };
        self.parent.insert(child, root);
    }
}

fn sorted_pair(a: &str, b: &str) -> [String; 2] {
    if a <= b {
        [a.to_string(), b.to_string()]
    } else {
        [b.to_string(), a.to_string()]
    }
}

// --- attestation-weighted scoring ---------------------------------------------------------------

/// Everything known about one identity pair: who asserted it, the asserting claim ids, and the fact
/// fingerprint (shared by every assertion of the pair) so attestations can be matched to it.
#[derive(Default)]
struct PairInfo {
    authors: BTreeSet<String>,
    claim_ids: BTreeSet<String>,
    fingerprint: Option<String>,
}

/// Support/reject attestation authors for one target (a claim id or a fingerprint).
#[derive(Default)]
struct Votes {
    support: BTreeSet<String>,
    reject: BTreeSet<String>,
}

fn collect_pair(map: &mut BTreeMap<[String; 2], PairInfo>, c: &Claim, id: &str) {
    if let (Some(p), Some(author)) = (pair(c), Some(c.created_by.as_str())) {
        let info = map.entry(p).or_default();
        info.authors.insert(author.to_string());
        info.claim_ids.insert(id.to_string());
        if info.fingerprint.is_none() {
            info.fingerprint = fingerprint_str(c);
        }
    }
}

/// The `"sha256:<hex>"` fingerprint of a claim — the target an attestation uses to vote on the fact.
/// Built from just the 3 fields the fingerprint covers (`targetId`, `predicate`, `value`), never the
/// whole claim, so this stays cheap even though the claim itself carries citation/signature baggage.
fn fingerprint_str(c: &Claim) -> Option<String> {
    let subset = serde_json::json!({
        "targetId": c.target_id,
        "predicate": c.predicate,
        "value": c.value,
    });
    openom_claim::fingerprint(&subset)
        .ok()
        .map(|h| format!("sha256:{}", openom_jcs::hex(&h)))
}

/// Attestation-weighted confidence for an identity pair: distinct-author corroboration, plus
/// independent support (a `support` by one of the pair's own asserters is self-grading and excluded,
/// §5.3), minus distinct rejects. Attestations may target the fact fingerprint or any asserting
/// claim id.
fn score(info: &PairInfo, attests: &BTreeMap<String, Votes>) -> i64 {
    let mut support: BTreeSet<&str> = BTreeSet::new();
    let mut reject: BTreeSet<&str> = BTreeSet::new();
    let targets = info
        .claim_ids
        .iter()
        .map(String::as_str)
        .chain(info.fingerprint.as_deref());
    for t in targets {
        if let Some(v) = attests.get(t) {
            support.extend(v.support.iter().map(String::as_str));
            reject.extend(v.reject.iter().map(String::as_str));
        }
    }
    let indep_support = support
        .into_iter()
        .filter(|a| !info.authors.contains(*a))
        .count() as i64;
    info.authors.len() as i64 + indep_support - reject.len() as i64
}

/// The content reference of a name's intrinsic form — parts + script + culture (§4.1) — the target a
/// `preferred` selection points at. Stable across a name's `type`/`derived_from` changing.
fn name_ref(name_value: &Value) -> Option<String> {
    let mut intrinsic = serde_json::Map::new();
    for k in ["parts", "script", "culture"] {
        if let Some(v) = name_value.get(k) {
            intrinsic.insert(k.to_string(), v.clone());
        }
    }
    openom_claim::content_ref(&Value::Object(intrinsic)).ok()
}

/// Group a person's names into equivalence classes over `equivalent_to` (§6). Each name's class label
/// is the minimum `claim_id` in its connected component — the same union-find routine as identity
/// clustering, parameterized here by name content-refs instead of anchors.
fn equiv_classes(names: &[NameView]) -> BTreeMap<String, String> {
    let mut ref_to_id: BTreeMap<String, String> = BTreeMap::new();
    for n in names {
        if let Some(r) = name_ref(&n.parts) {
            ref_to_id.insert(r, n.claim_id.clone());
        }
    }
    let nodes: BTreeSet<String> = ref_to_id.keys().cloned().collect();
    let mut uf = Uf::new(&nodes);
    for n in names {
        let Some(own) = name_ref(&n.parts) else {
            continue;
        };
        if let Some(eqs) = n.parts.get("equivalent_to").and_then(Value::as_array) {
            for e in eqs.iter().filter_map(Value::as_str) {
                if nodes.contains(e) {
                    uf.union(&own, e);
                }
            }
        }
    }
    let mut min_id: BTreeMap<String, String> = BTreeMap::new();
    for (r, cid) in &ref_to_id {
        let root = uf.find(r);
        let entry = min_id.entry(root).or_insert_with(|| cid.clone());
        if cid < entry {
            *entry = cid.clone();
        }
    }
    ref_to_id
        .iter()
        .map(|(r, cid)| (cid.clone(), min_id[&uf.find(r)].clone()))
        .collect()
}

/// Tally a string field of a claim's `value` by author into `map[targetId][value]`.
fn tally(map: &mut BTreeMap<String, BTreeMap<String, BTreeSet<String>>>, c: &Claim, field: &str) {
    if let (Some(target), Some(val), Some(a)) = (
        Some(c.target_id.as_str()),
        c.value.get(field).and_then(Value::as_str),
        Some(c.created_by.as_str()),
    ) {
        map.entry(target.to_string())
            .or_default()
            .entry(val.to_string())
            .or_default()
            .insert(a.to_string());
    }
}

/// The value with the most distinct authors (ties broken by the smaller value).
fn most_corroborated(votes: &BTreeMap<String, BTreeSet<String>>) -> Option<String> {
    votes
        .iter()
        .max_by(|x, y| x.1.len().cmp(&y.1.len()).then(y.0.cmp(x.0)))
        .map(|(v, _)| v.clone())
}

/// Does an EDTF `validRange` cover `year`? An empty range is always-valid; an open end is unbounded on
/// that side; an unparseable range covers nothing.
fn range_covers(valid_range: &str, year: i32) -> bool {
    if valid_range.is_empty() {
        return true;
    }
    match openom_edtf::parse(valid_range) {
        Ok(e) => e.min.is_none_or(|d| d.year <= year) && e.max.is_none_or(|d| d.year >= year),
        Err(_) => false,
    }
}

/// Pick a place name for an event year: among `(validRange, name) -> authors` candidates, the
/// most-corroborated name whose range covers the year (ties by smallest name); falling back to the
/// most-corroborated name overall when no range covers or the event has no year.
fn pick_place_name(
    cands: &BTreeMap<(String, String), BTreeSet<String>>,
    year: Option<i32>,
) -> Option<String> {
    let best = |covering: bool| {
        cands
            .iter()
            .filter(|((vr, _), _)| !covering || year.is_some_and(|y| range_covers(vr, y)))
            .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0 .1.cmp(&a.0 .1)))
            .map(|((_, name), _)| name.clone())
    };
    year.and_then(|_| best(true)).or_else(|| best(false))
}

// --- record field helpers -----------------------------------------------------------------------

/// The canonical sorted pair from a `same_as` / `different_from` claim's `value.pair`.
fn pair(c: &Claim) -> Option<[String; 2]> {
    let arr = c.value.get("pair")?.as_array()?;
    if arr.len() != 2 {
        return None;
    }
    let a = arr[0].as_str()?;
    let b = arr[1].as_str()?;
    if a == b {
        return None;
    }
    Some(sorted_pair(a, b))
}

#[cfg(test)]
mod tests;
