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
const P_EXISTENCE: &str = "openom.org/core/existence/v1"; // the root "this individual is real", value {}
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
        Self {
            same_as_threshold: 1,
            different_from_threshold: 1,
            reattribute_threshold: 1,
            preferred_threshold: 1,
            relationship_threshold: 1,
        }
    }
}

/// One rendering of a person's name, retargeted to the canonical person.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NameView {
    pub claim_id: String,
    pub parts: Value,
    /// Equivalence-class label — the minimum `claim_id` among names joined (directly or transitively)
    /// by `equivalent_to`. Names sharing it are the *same* name differently rendered (§6); a name with
    /// no equivalents is its own class.
    pub equiv_class: String,
}

/// A projected person: one real individual, possibly assembled from several merged anchors.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
    /// targeting the person, each carrying its claim's open value map (mediaHash + mime/size/role/
    /// caption/crop/coverage as they apply). Sorted by claim id; a link with `role == "portrait"` is
    /// the portrait (a disputable `preferred` portrait slot is a later refinement).
    pub media: Vec<MediaLink>,
    /// Claims about this person whose `predicate` this build doesn't recognize, surfaced verbatim so a
    /// newer data-model vocabulary is visible (and re-editable) with no projection change (OPE-212b).
    /// A generic front-end renders these as key/value until a bespoke view exists. Sorted by claim id.
    pub other: Vec<GenericClaimView>,
}

/// A live claim whose `predicate` this build doesn't recognize — the read-model counterpart of the
/// mechanism's opaque [`Record::Unknown`](openom_claim::envelope::Record::Unknown) (OPE-212a). Carried
/// verbatim (an unknown predicate has no known semantics to corroborate) so new vocabulary shows up in
/// the UI immediately; a generic renderer displays it as key/value. Attached to a [`Person`] when its
/// (effective) target resolves to one, else carried in [`Projection::unclassified`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GenericClaimView {
    /// The claim's id — the stable UI handle.
    pub claim_id: String,
    /// The claim's subject (its `targetId`; the effective target after `reattribute_to`).
    pub target_id: String,
    /// The unrecognized predicate URI.
    pub predicate: String,
    /// The claim's value, verbatim.
    pub value: Value,
    /// The claim's author (`createdBy`).
    pub created_by: String,
}

/// A content-addressed blob linked to an anchor via a `media_link/v1` claim (§10.2). The projection's
/// job for media is *attach the link to the canonical person*. It breaks out the one guaranteed field
/// — the blob's `media_hash` (the thing you fetch) — and carries the rest of the shape, which is open
/// and varies by kind (an image has `width`/`height`, a document has a `coverage` locator, a future
/// kind whatever it needs), as an open value map rather than a fixed set of typed fields.
/// `role == "portrait"` is the portrait selection (a disputable `preferred` portrait slot is later).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MediaLink {
    /// The `media_link` claim's id — the stable UI handle for this link.
    pub claim_id: String,
    /// The linked blob's content hash — always present, fetched out-of-band from object storage.
    pub media_hash: String,
    /// The rest of the claim's value as an open map: `mime`, `width`/`height`, `role`, `caption`,
    /// `crop`, `coverage`, … as they apply to this media's kind.
    pub value: serde_json::Map<String, Value>,
}

/// A source referenced by a citation, resolved from its `core/source/v1` claim. Every field is
/// `None` when the `source_id` does not resolve to a known source claim (dangling reference).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CustomField {
    pub field_id: String,
    pub label: String,
    pub field_type: String,
    pub value: Value,
}

/// A `same_as` edge that was not applied because a `different_from` cut it — surfaced, never merged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Conflict {
    pub cut_pair: [String; 2],
}

/// A directional parent→child edge (stored once, read from either end) between canonical persons.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct ParentChild {
    pub parent: String,
    pub child: String,
    /// A `core/relations/v1` term: `biological` | `adoptive` | `step` | `foster` | `guardian`.
    pub kind: String,
}

/// A symmetric partnership between two canonical persons.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Partnership {
    pub pair: [String; 2],
    /// A `core/roles/v1` term: `spouse` | `partner`.
    pub role: String,
}

/// One participant in an event: the canonical person and the role they played.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Participant {
    pub person: String,
    /// A `core/roles/v1` term: `child` | `parent` | `spouse` | `witness` | `officiant` | …
    pub role: String,
}

/// A projected event (birth, death, marriage, …) — a hyper-edge assembled from the claims targeting
/// one Event anchor.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Projection {
    pub people: Vec<Person>,
    pub parent_child: Vec<ParentChild>,
    pub partnerships: Vec<Partnership>,
    pub unions: Vec<Union>,
    pub events: Vec<EventView>,
    pub conflicts: Vec<Conflict>,
    /// Unknown-predicate claims whose (effective) target does not resolve to a person — a claim about
    /// a newer anchor kind, an event, or a not-yet-known subject (OPE-212b). Kept so no live data is
    /// invisible; sorted by (target, predicate, claim id).
    pub unclassified: Vec<GenericClaimView>,
}

/// The output of the projection's `collect` phase: the deduped record set folded into per-kind
/// accumulators, before identity resolution and assembly. Bundling them in one struct keeps `collect`
/// a single delimited phase and makes adding a leaf predicate a field here plus its match arm — not a
/// free variable threaded end-to-end through a 1000-line body.
#[allow(clippy::type_complexity)]
#[derive(Default)]
struct Collected {
    anchors: BTreeSet<String>,
    same_as: BTreeMap<[String; 2], PairInfo>,
    different_from: BTreeMap<[String; 2], PairInfo>,
    attests: BTreeMap<String, Votes>,
    name_claims: Vec<(String, String, Value)>,
    sex_claims: Vec<(String, String, String, String)>,
    biography_claims: Vec<(String, String, String, String)>,
    field_label: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    field_type: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    custom_values: Vec<(String, String, String, Value, String)>,
    reattribute: BTreeMap<String, BTreeMap<String, PairInfo>>,
    preferred: BTreeMap<(String, String, String), PairInfo>,
    parent_child: BTreeMap<(String, String, String), PairInfo>,
    partnership: BTreeMap<([String; 2], String), PairInfo>,
    event_anchors: BTreeSet<String>,
    event_type: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    event_date: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    event_place: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    participants: BTreeMap<String, BTreeSet<(String, String)>>,
    sources: BTreeMap<String, Value>,
    citations: Vec<(String, String, String, Value)>,
    place_point: BTreeMap<String, BTreeMap<String, (BTreeSet<String>, Value)>>,
    place_name: BTreeMap<String, BTreeMap<(String, String), BTreeSet<String>>>,
    part_of: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    media_links: Vec<(String, String, Value)>,
    other_claims: Vec<(String, String, String, Value, String)>,
}

fn collect(deduped: &[&Record]) -> Collected {
    // Anchors + person-scoped claims. Deletion and edit-supersession are operations applied upstream
    // (the ops->snapshot layer, §8.2); the projection consumes the already-live claim set.
    let mut acc = Collected::default();
    for &r in deduped {
        let c: &Claim = match r {
            Record::Anchor(a) => {
                match a.type_uri.as_str() {
                    TYPE_PERSON => {
                        acc.anchors.insert(a.id.clone());
                    }
                    TYPE_EVENT => {
                        acc.event_anchors.insert(a.id.clone());
                    }
                    _ => {}
                }
                continue;
            }
            // A record of a type this build doesn't recognize is not part of any structured view yet; it
            // still survives in the materialized set (a generic renderer reaches it — OPE-212b/c).
            Record::Unknown(_) => continue,
            Record::Claim(c) => c,
        };
        // Any claim (whatever its predicate) may carry an inline citation backing the fact it asserts.
        // Today only a single-object citation is captured; an array citation is a documented seam.
        if let Some(Citations::One(cit)) = &c.citation {
            if let Ok(cit_val) = serde_json::to_value(cit) {
                acc.citations.push((
                    c.target_id.clone(),
                    c.id.clone(),
                    c.predicate.clone(),
                    cit_val,
                ));
            }
        }
        parse_claim(&mut acc, c);
    }
    acc
}

/// Fold one claim's structured fact into the matching accumulator, dispatched on its predicate. An
/// unrecognized predicate is kept verbatim in `other_claims` (OPE-212b), never minting a person.
fn parse_claim(acc: &mut Collected, c: &Claim) {
    let id = c.id.as_str();
    match c.predicate.as_str() {
        P_SOURCE => {
            acc.sources.insert(id.to_string(), c.value.clone());
        }
        P_PLACE_POINT => parse_place_point(acc, c),
        P_PLACE_NAME => parse_place_name(acc, c),
        P_PART_OF => tally(&mut acc.part_of, c, "parentPlaceId"),
        P_MEDIA_LINK => parse_media_link(acc, c),
        P_SAME_AS => collect_pair(&mut acc.same_as, c, id),
        P_DIFFERENT_FROM => collect_pair(&mut acc.different_from, c, id),
        P_ATTEST => parse_attest(acc, c),
        P_PREFERRED => parse_preferred(acc, c),
        P_PARENT => parse_parent(acc, c),
        P_PARTNERSHIP => parse_partnership(acc, c),
        P_EVENT_TYPE => tally(&mut acc.event_type, c, "type"),
        P_DATE => tally(&mut acc.event_date, c, "edtf"),
        P_EVENT_PLACE => tally(&mut acc.event_place, c, "placeId"),
        P_PARTICIPANT => parse_participant(acc, c),
        P_NAME => acc
            .name_claims
            .push((c.target_id.clone(), id.to_string(), c.value.clone())),
        P_SEX => parse_sex(acc, c),
        P_BIOGRAPHY => parse_biography(acc, c),
        P_CUSTOM_FIELD => parse_custom_field(acc, c),
        P_CUSTOM_VALUE => parse_custom_value(acc, c),
        P_REATTRIBUTE => parse_reattribute(acc, c),
        // The root existence proposition, auto-minted with each anchor (value {}). Its citation is
        // harvested above; an attestation on it is collected under P_ATTEST; the claim asserts no
        // structured fact, so it is consumed here rather than surfaced as an "other" claim.
        P_EXISTENCE => {}
        _ => acc.other_claims.push((
            c.target_id.clone(),
            id.to_string(),
            c.predicate.clone(),
            c.value.clone(),
            c.created_by.clone(),
        )),
    }
}

/// Record a claim's author + id into a `PairInfo`, seeding its fingerprint once — the shared tail of the
/// pair-relation predicates (preferred / parent / partnership / reattribute).
fn bump_pair_info(info: &mut PairInfo, author: &str, id: &str, c: &Claim) {
    info.authors.insert(author.to_string());
    info.claim_ids.insert(id.to_string());
    if info.fingerprint.is_none() {
        info.fingerprint = fingerprint_str(c);
    }
}

fn parse_place_point(acc: &mut Collected, c: &Claim) {
    acc.place_point
        .entry(c.target_id.clone())
        .or_default()
        .entry(c.value.to_string())
        .or_insert_with(|| (BTreeSet::new(), c.value.clone()))
        .0
        .insert(c.created_by.clone());
}

fn parse_place_name(acc: &mut Collected, c: &Claim) {
    let Some(name) = c.value.get("name").and_then(Value::as_str) else {
        return;
    };
    let range = c
        .value
        .get("validRange")
        .and_then(Value::as_str)
        .unwrap_or_default();
    acc.place_name
        .entry(c.target_id.clone())
        .or_default()
        .entry((range.to_string(), name.to_string()))
        .or_default()
        .insert(c.created_by.clone());
}

fn parse_media_link(acc: &mut Collected, c: &Claim) {
    // Keep the whole value so the media view round-trips mime/width/height/role/order/caption/crop/kind
    // (§10.2); require only `mediaHash` (the blob this links).
    if c.value.get("mediaHash").and_then(Value::as_str).is_some() {
        acc.media_links
            .push((c.target_id.clone(), c.id.clone(), c.value.clone()));
    }
}

fn parse_attest(acc: &mut Collected, c: &Claim) {
    let Some(verdict) = c.value.get("verdict").and_then(Value::as_str) else {
        return;
    };
    let v = acc.attests.entry(c.target_id.clone()).or_default();
    match verdict {
        "support" => {
            v.support.insert(c.created_by.clone());
        }
        "reject" => {
            v.reject.insert(c.created_by.clone());
        }
        _ => {}
    }
}

fn parse_preferred(acc: &mut Collected, c: &Claim) {
    // The referent is a `contentRef` (a `sha256:` content-ref of the name it prefers), NOT a claim id —
    // stable across authors/merges, which is the point of `preferred` (§4.1).
    let (Some(for_pred), Some(content_ref)) = (
        c.value.get("for").and_then(Value::as_str),
        c.value.get("contentRef").and_then(Value::as_str),
    ) else {
        return;
    };
    let info = acc
        .preferred
        .entry((
            c.target_id.clone(),
            for_pred.to_string(),
            content_ref.to_string(),
        ))
        .or_default();
    bump_pair_info(info, c.created_by.as_str(), c.id.as_str(), c);
}

fn parse_parent(acc: &mut Collected, c: &Claim) {
    let Some(parent) = c.value.get("parentPersonId").and_then(Value::as_str) else {
        return;
    };
    let kind = c
        .value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_KIND);
    let info = acc
        .parent_child
        .entry((c.target_id.clone(), parent.to_string(), kind.to_string()))
        .or_default();
    bump_pair_info(info, c.created_by.as_str(), c.id.as_str(), c);
}

fn parse_partnership(acc: &mut Collected, c: &Claim) {
    let Some(p) = pair(c) else {
        return;
    };
    let role = c
        .value
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_ROLE);
    let info = acc.partnership.entry((p, role.to_string())).or_default();
    bump_pair_info(info, c.created_by.as_str(), c.id.as_str(), c);
}

fn parse_participant(acc: &mut Collected, c: &Claim) {
    let (Some(person), Some(role)) = (
        c.value.get("personId").and_then(Value::as_str),
        c.value.get("role").and_then(Value::as_str),
    ) else {
        return;
    };
    acc.participants
        .entry(c.target_id.clone())
        .or_default()
        .insert((person.to_string(), role.to_string()));
}

fn parse_sex(acc: &mut Collected, c: &Claim) {
    if let Some(sex) = c.value.get("sex").and_then(Value::as_str) {
        acc.sex_claims.push((
            c.target_id.clone(),
            c.id.clone(),
            sex.to_string(),
            c.created_by.clone(),
        ));
    }
}

fn parse_biography(acc: &mut Collected, c: &Claim) {
    if let Some(text) = c.value.get("text").and_then(Value::as_str) {
        acc.biography_claims.push((
            c.target_id.clone(),
            c.id.clone(),
            text.to_string(),
            c.created_by.clone(),
        ));
    }
}

fn parse_custom_field(acc: &mut Collected, c: &Claim) {
    let Some(fid) = c.value.get("fieldId").and_then(Value::as_str) else {
        return;
    };
    if let Some(label) = c.value.get("label").and_then(Value::as_str) {
        acc.field_label
            .entry(fid.to_string())
            .or_default()
            .entry(label.to_string())
            .or_default()
            .insert(c.created_by.clone());
    }
    if let Some(ty) = c.value.get("type").and_then(Value::as_str) {
        acc.field_type
            .entry(fid.to_string())
            .or_default()
            .entry(ty.to_string())
            .or_default()
            .insert(c.created_by.clone());
    }
}

fn parse_custom_value(acc: &mut Collected, c: &Claim) {
    let (Some(fid), Some(val)) = (
        c.value.get("fieldId").and_then(Value::as_str),
        c.value.get("value"),
    ) else {
        return;
    };
    acc.custom_values.push((
        c.target_id.clone(),
        c.id.clone(),
        fid.to_string(),
        val.clone(),
        c.created_by.clone(),
    ));
}

fn parse_reattribute(acc: &mut Collected, c: &Claim) {
    let Some(person) = c.value.get("personId").and_then(Value::as_str) else {
        return;
    };
    let info = acc
        .reattribute
        .entry(c.target_id.clone())
        .or_default()
        .entry(person.to_string())
        .or_default();
    bump_pair_info(info, c.created_by.as_str(), c.id.as_str(), c);
}

/// Canonical person id for `id`: its cluster's representative anchor (`None` if it maps to no person).
fn canon_of(
    rep: &BTreeMap<String, String>,
    canonical: &BTreeMap<String, String>,
    id: &str,
) -> Option<String> {
    rep.get(id).and_then(|key| canonical.get(key)).cloned()
}

/// The person a claim's subject re-homes to: its winning `reattribute_to`, else the original target.
fn eff_target(rehome: &BTreeMap<String, String>, claim_id: &str, orig: &str) -> String {
    rehome.get(claim_id).cloned().unwrap_or_else(|| orig.to_string())
}

/// The identity-resolution outputs (project phase 2): the cluster map (`rep`), each cluster's canonical
/// anchor, the cluster membership, the reattribution winners (`rehome`), and the `different_from` cuts
/// dropped by the constraint-repair union-find.
struct Resolved {
    rep: BTreeMap<String, String>,
    canonical: BTreeMap<String, String>,
    by_key: BTreeMap<String, BTreeSet<String>>,
    rehome: BTreeMap<String, String>,
    skipped: Vec<[String; 2]>,
}

/// Cluster the collected identity claims into canonical persons and resolve reattribution.
fn resolve(c: &Collected, policy: &Policy) -> Resolved {
    // nodes = every id that participates as a person.
    let mut nodes: BTreeSet<String> = c.anchors.clone();
    for p in c.same_as.keys().chain(c.different_from.keys()) {
        nodes.insert(p[0].clone());
        nodes.insert(p[1].clone());
    }
    for (t, _, _) in &c.name_claims {
        nodes.insert(t.clone());
    }
    for (t, _, _, _) in &c.sex_claims {
        nodes.insert(t.clone());
    }
    for (t, _, _, _) in &c.biography_claims {
        nodes.insert(t.clone());
    }
    for (t, _, _, _, _) in &c.custom_values {
        nodes.insert(t.clone());
    }
    for (t, _, _) in &c.media_links {
        nodes.insert(t.clone());
    }
    for options in c.reattribute.values() {
        for person in options.keys() {
            nodes.insert(person.clone());
        }
    }
    for (child, parent, _) in c.parent_child.keys() {
        nodes.insert(child.clone());
        nodes.insert(parent.clone());
    }
    for (pair, _) in c.partnership.keys() {
        nodes.insert(pair[0].clone());
        nodes.insert(pair[1].clone());
    }

    // edges + cuts, each gated by its attestation-weighted score.
    let edges: Vec<Edge> = c
        .same_as
        .iter()
        .filter_map(|(pair, info)| {
            let s = score(info, &c.attests);
            (s >= policy.same_as_threshold).then(|| Edge {
                a: pair[0].clone(),
                b: pair[1].clone(),
                score: s,
            })
        })
        .collect();
    let cuts: Vec<[String; 2]> = c
        .different_from
        .iter()
        .filter(|(_, info)| score(info, &c.attests) >= policy.different_from_threshold)
        .map(|(pair, _)| pair.clone())
        .collect();

    let Clustering { rep, skipped } = cluster(&nodes, edges, &cuts);

    // Group nodes by cluster key, then pick each cluster's canonical PERSON id = its minimum *anchor*
    // member. A cluster with no anchor is not a person and is dropped.
    let mut by_key: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (node, key) in &rep {
        by_key.entry(key.clone()).or_default().insert(node.clone());
    }
    let mut canonical: BTreeMap<String, String> = BTreeMap::new(); // cluster key -> min anchor
    for (key, members) in &by_key {
        if let Some(anchor) = members.iter().find(|m| c.anchors.contains(*m)) {
            canonical.insert(key.clone(), anchor.clone());
        }
    }

    // reattribution: per re-homed claim, the winning net-positive personId (highest score, ties by id).
    let rehome: BTreeMap<String, String> = c
        .reattribute
        .iter()
        .filter_map(|(claim, options)| {
            options
                .iter()
                .filter(|(_, info)| score(info, &c.attests) >= policy.reattribute_threshold)
                .max_by(|a, b| {
                    score(a.1, &c.attests)
                        .cmp(&score(b.1, &c.attests))
                        .then(b.0.cmp(a.0))
                })
                .map(|(person, _)| (claim.clone(), person.clone()))
        })
        .collect();

    Resolved { rep, canonical, by_key, rehome, skipped }
}

/// Project a record set into the read model. Pure: the result depends only on the set of records and the
/// policy, never on their order. Four phases: **collect** (fold records into [`Collected`]), **resolve**
/// identity (cluster `same_as`/`different_from`, reattribute, canonicalize), **`build_person_maps`**
/// (per-person aggregation), and **assemble** the people / relationships / unions / events.
#[must_use]
pub fn project(records: &[Record], policy: &Policy) -> Projection {
    // The store guarantees unique content-hash ids, but be robust to a duplicated slice: keep the
    // first record per id, so projecting `recs` and `recs ++ recs` give the same result (set input).
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    let deduped: Vec<&Record> = records
        .iter()
        .filter(|r| seen_ids.insert(r.id().to_string()))
        .collect();

    let collected = collect(&deduped);
    let resolved = resolve(&collected, policy);
    let mut maps = build_person_maps(&collected, &resolved, policy);

    let people = assemble_people(&collected, &resolved, &mut maps);
    let events = assemble_events(&collected, &resolved);

    // Relationships between canonical persons (attestation-weighted; endpoints canonicalized through the
    // same_as clusters; a dangling endpoint or self-loop is dropped; post-canonicalization dups merged).
    let mut parent_child_edges: Vec<ParentChild> = collected
        .parent_child
        .iter()
        .filter(|(_, info)| score(info, &collected.attests) >= policy.relationship_threshold)
        .filter_map(|((child, parent, kind), _)| {
            let cc = canon_of(&resolved.rep, &resolved.canonical, child)?;
            let pp = canon_of(&resolved.rep, &resolved.canonical, parent)?;
            (cc != pp).then(|| ParentChild {
                parent: pp,
                child: cc,
                kind: kind.clone(),
            })
        })
        .collect();
    parent_child_edges.sort();
    parent_child_edges.dedup();

    let mut partnership_edges: Vec<Partnership> = collected
        .partnership
        .iter()
        .filter(|(_, info)| score(info, &collected.attests) >= policy.relationship_threshold)
        .filter_map(|((pair, role), _)| {
            let a = canon_of(&resolved.rep, &resolved.canonical, &pair[0])?;
            let b = canon_of(&resolved.rep, &resolved.canonical, &pair[1])?;
            (a != b).then(|| Partnership {
                pair: sorted_pair(&a, &b),
                role: role.clone(),
            })
        })
        .collect();
    partnership_edges.sort();
    partnership_edges.dedup();

    let unions = assemble_unions(&parent_child_edges, &partnership_edges, &events);
    let conflicts = resolved
        .skipped
        .iter()
        .map(|cut_pair| Conflict {
            cut_pair: cut_pair.clone(),
        })
        .collect();
    Projection {
        people,
        parent_child: parent_child_edges,
        partnerships: partnership_edges,
        unions,
        events,
        conflicts,
        unclassified: maps.unclassified,
    }
}

/// The per-canonical-person aggregates (project phase 3), ready for final assembly.
struct PersonMaps {
    names_by_person: BTreeMap<String, Vec<NameView>>,
    sex_by_person: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    biography_by_person: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    customs_of: BTreeMap<String, Vec<CustomField>>,
    sources_by_person: BTreeMap<String, Vec<Citation>>,
    media_by_person: BTreeMap<String, Vec<MediaLink>>,
    other_by_person: BTreeMap<String, Vec<GenericClaimView>>,
    unclassified: Vec<GenericClaimView>,
    preferred_name_of: BTreeMap<String, String>,
}

/// Group every per-person claim onto its canonical person (project phase 3), one aggregation per kind.
fn build_person_maps(c: &Collected, r: &Resolved, policy: &Policy) -> PersonMaps {
    let names_by_person = names_map(c, r);
    let (other_by_person, unclassified) = other_map(c, r);
    let preferred_name_of = preferred_names_map(c, r, &names_by_person, policy);
    PersonMaps {
        sex_by_person: sex_map(c, r),
        biography_by_person: biography_map(c, r),
        customs_of: customs_map(c, r),
        sources_by_person: sources_map(c, r),
        media_by_person: media_map(c, r),
        names_by_person,
        other_by_person,
        unclassified,
        preferred_name_of,
    }
}

/// Names per canonical person, each tagged with its `equivalent_to` equivalence class.
fn names_map(c: &Collected, r: &Resolved) -> BTreeMap<String, Vec<NameView>> {
    let mut names_by_person: BTreeMap<String, Vec<NameView>> = BTreeMap::new();
    for (target, cid, parts) in &c.name_claims {
        if let Some(canon) = canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) {
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
    names_by_person
}

/// Sex claims tallied per person as value -> attesting authors (a majority pick is made at assembly).
fn sex_map(c: &Collected, r: &Resolved) -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let mut sex_by_person: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for (target, cid, val, author) in &c.sex_claims {
        if let Some(canon) = canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) {
            sex_by_person
                .entry(canon)
                .or_default()
                .entry(val.clone())
                .or_default()
                .insert(author.clone());
        }
    }
    sex_by_person
}

/// Biography claims tallied per person as text -> attesting authors (most-corroborated wins at assembly).
fn biography_map(
    c: &Collected,
    r: &Resolved,
) -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let mut biography_by_person: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> =
        BTreeMap::new();
    for (target, cid, text, author) in &c.biography_claims {
        if let Some(canon) = canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) {
            biography_by_person
                .entry(canon)
                .or_default()
                .entry(text.clone())
                .or_default()
                .insert(author.clone());
        }
    }
    biography_by_person
}

/// Custom fields per person: per (person, fieldId) the most-corroborated value, with label/type from the
/// field's most-corroborated definition (dangling fieldId -> label = fieldId, type = "text").
fn customs_map(c: &Collected, r: &Resolved) -> BTreeMap<String, Vec<CustomField>> {
    #[allow(clippy::type_complexity)]
    let mut custom_by_person: BTreeMap<
        String,
        BTreeMap<String, BTreeMap<String, (BTreeSet<String>, Value)>>,
    > = BTreeMap::new();
    for (target, cid, fid, val, author) in &c.custom_values {
        if let Some(canon) = canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) {
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
                        label: c
                            .field_label
                            .get(fid)
                            .and_then(most_corroborated)
                            .unwrap_or_else(|| fid.clone()),
                        field_type: c
                            .field_type
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
    customs_of
}

/// Source citations per person, the `sourceId` resolved to its source claim's description (an unresolved
/// id surfaces the reference with empty source fields rather than dropping it).
fn sources_map(c: &Collected, r: &Resolved) -> BTreeMap<String, Vec<Citation>> {
    let mut sources_by_person: BTreeMap<String, Vec<Citation>> = BTreeMap::new();
    for (target, cid, pred, cit) in &c.citations {
        let Some(canon) = canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) else {
            continue;
        };
        let source_id = cit
            .get("sourceId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let src = c.sources.get(&source_id);
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
    sources_by_person
}

/// Media links per person (links targeting events or sources don't resolve to a person and are dropped).
fn media_map(c: &Collected, r: &Resolved) -> BTreeMap<String, Vec<MediaLink>> {
    let mut media_by_person: BTreeMap<String, Vec<MediaLink>> = BTreeMap::new();
    for (target, cid, value) in &c.media_links {
        if let Some(canon) = canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) {
            let media_hash = value
                .get("mediaHash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let mut rest = value.as_object().cloned().unwrap_or_default();
            rest.remove("mediaHash");
            media_by_person.entry(canon).or_default().push(MediaLink {
                claim_id: cid.clone(),
                media_hash,
                value: rest,
            });
        }
    }
    for links in media_by_person.values_mut() {
        links.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
        links.dedup();
    }
    media_by_person
}

/// Unknown-predicate claims (OPE-212b): each attached verbatim to its canonical person, or to
/// `unclassified` when its target isn't a person. Returns `(by_person, unclassified)`.
fn other_map(
    c: &Collected,
    r: &Resolved,
) -> (BTreeMap<String, Vec<GenericClaimView>>, Vec<GenericClaimView>) {
    let mut other_by_person: BTreeMap<String, Vec<GenericClaimView>> = BTreeMap::new();
    let mut unclassified: Vec<GenericClaimView> = Vec::new();
    for (target, cid, pred, value, author) in &c.other_claims {
        let view = GenericClaimView {
            claim_id: cid.clone(),
            target_id: target.clone(),
            predicate: pred.clone(),
            value: value.clone(),
            created_by: author.clone(),
        };
        match canon_of(&r.rep, &r.canonical, &eff_target(&r.rehome, cid, target)) {
            Some(canon) => other_by_person.entry(canon).or_default().push(view),
            None => unclassified.push(view),
        }
    }
    for views in other_by_person.values_mut() {
        views.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
    }
    unclassified.sort_by(|a, b| {
        a.target_id
            .cmp(&b.target_id)
            .then_with(|| a.predicate.cmp(&b.predicate))
            .then_with(|| a.claim_id.cmp(&b.claim_id))
    });
    (other_by_person, unclassified)
}

/// The `preferred` name selection per person: the highest-scored net-positive `preferred` whose referent
/// resolves to one of the person's names (ties by content-ref).
fn preferred_names_map(
    c: &Collected,
    r: &Resolved,
    names_by_person: &BTreeMap<String, Vec<NameView>>,
    policy: &Policy,
) -> BTreeMap<String, String> {
    let mut name_ref_to_id: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (person, views) in names_by_person {
        let map = views
            .iter()
            .filter_map(|v| name_ref(&v.parts).map(|rf| (rf, v.claim_id.clone())))
            .collect();
        name_ref_to_id.insert(person.clone(), map);
    }
    let mut by_slot: BTreeMap<(String, String), Vec<(&String, &PairInfo)>> = BTreeMap::new();
    for ((person, for_pred, claim_ref), info) in &c.preferred {
        if let Some(canon) = canon_of(&r.rep, &r.canonical, person) {
            by_slot
                .entry((canon, for_pred.clone()))
                .or_default()
                .push((claim_ref, info));
        }
    }
    let mut preferred_name_of: BTreeMap<String, String> = BTreeMap::new();
    for ((person, for_pred), options) in &by_slot {
        if for_pred != P_NAME {
            continue; // other slots (birthdate, portrait...) use the same mechanism - a later increment
        }
        let refs = name_ref_to_id.get(person);
        let winner = options
            .iter()
            .filter(|(claim_ref, info)| {
                score(info, &c.attests) >= policy.preferred_threshold
                    && refs.is_some_and(|m| m.contains_key(*claim_ref))
            })
            .max_by(|a, b| {
                score(a.1, &c.attests)
                    .cmp(&score(b.1, &c.attests))
                    .then(b.0.cmp(a.0))
            });
        if let Some(name_id) = winner.and_then(|(rf, _)| refs.and_then(|m| m.get(*rf))) {
            preferred_name_of.insert(person.clone(), name_id.clone());
        }
    }
    preferred_name_of
}

/// Build the canonical `Person` records from the resolved clusters + per-person maps (project phase 4a).
/// Consumes the owned per-person aggregates out of `m` (each belongs to exactly one person).
fn assemble_people(c: &Collected, r: &Resolved, m: &mut PersonMaps) -> Vec<Person> {
    let mut people = Vec::new();
    for (key, members) in &r.by_key {
        let Some(canon) = r.canonical.get(key) else {
            continue;
        };
        let mut also: Vec<String> = Vec::new();
        for mem in members {
            if c.anchors.contains(mem) && mem != canon {
                also.push(mem.clone());
            }
        }
        let names = m.names_by_person.remove(canon).unwrap_or_default();
        let sex = m.sex_by_person.get(canon).and_then(|tally| {
            tally
                .iter()
                .max_by(|x, y| x.1.len().cmp(&y.1.len()).then(y.0.cmp(x.0)))
                .map(|(val, _)| val.clone())
        });
        let preferred_name = m.preferred_name_of.get(canon).cloned();
        let biography = m.biography_by_person.get(canon).and_then(most_corroborated);
        let custom_fields = m.customs_of.remove(canon).unwrap_or_default();
        let sources = m.sources_by_person.remove(canon).unwrap_or_default();
        let media = m.media_by_person.remove(canon).unwrap_or_default();
        let other = m.other_by_person.remove(canon).unwrap_or_default();
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
            other,
        });
    }
    people.sort_by(|a, b| a.id.cmp(&b.id));
    people
}

/// Assemble each Event anchor's targeting claims into a hyper-edge (project phase 4b): type / date /
/// place most-corroborated; participants canonicalized to persons. Sorted by event id (`BTreeSet` order).
fn assemble_events(c: &Collected, r: &Resolved) -> Vec<EventView> {
    // Most-corroborated point + parent for a place, and the name whose `validRange` covers the year
    // (falling back to the most-corroborated name when none covers or there is no year).
    let resolve_place = |pid: &str, year: Option<i32>| -> PlaceView {
        let point = c.place_point.get(pid).and_then(|m| {
            m.iter()
                .max_by(|a, b| a.1 .0.len().cmp(&b.1 .0.len()).then(b.0.cmp(a.0)))
                .map(|(_, (_, v))| v.clone())
        });
        let part_of = c.part_of.get(pid).and_then(most_corroborated);
        let name = c
            .place_name
            .get(pid)
            .and_then(|cands| pick_place_name(cands, year));
        PlaceView {
            id: pid.to_string(),
            name,
            point,
            part_of,
        }
    };

    c.event_anchors
        .iter()
        .map(|eid| {
            let event_type = c.event_type.get(eid).and_then(most_corroborated);
            let date_edtf = c.event_date.get(eid).and_then(most_corroborated);
            let (date_min_year, date_max_year) = date_edtf
                .as_deref()
                .and_then(|s| edtf::parse(s).ok())
                .map_or((None, None), |e| (e.min.map(|d| d.year), e.max.map(|d| d.year)));
            let place_id = c.event_place.get(eid).and_then(most_corroborated);
            let mut parts: Vec<Participant> = c
                .participants
                .get(eid)
                .into_iter()
                .flatten()
                .filter_map(|(person, role)| {
                    canon_of(&r.rep, &r.canonical, person).map(|p| Participant {
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
        .collect()
}

/// Group children by canonical parent-set into family unions, add childless partnerships, and attach a
/// marriage/divorce event whose spouse-set matches this union's parents (project phase 4c).
fn assemble_unions(
    parent_child_edges: &[ParentChild],
    partnership_edges: &[Partnership],
    events: &[EventView],
) -> Vec<Union> {
    let mut parents_of_child: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pc in parent_child_edges {
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
    for pn in partnership_edges {
        union_children.entry(pn.pair.to_vec()).or_default();
    }
    union_children
        .iter()
        .map(|(parents, children)| {
            // The union's marriage/divorce event is one whose participant-person set is exactly this
            // union's parents (not restricted to two — a single-parent family can carry one too).
            let want: BTreeSet<&String> = parents.iter().collect();
            let marriage_event = events
                .iter()
                .find(|e| {
                    matches!(e.event_type.as_deref(), Some("marriage" | "divorce"))
                        && e.participants
                            .iter()
                            .map(|p| &p.person)
                            .collect::<BTreeSet<_>>()
                            == want
                })
                .map(|e| e.id.clone());
            Union {
                id: format!("union:{}", parents.join("+")),
                parents: parents.clone(),
                children: children.iter().cloned().collect(),
                marriage_event,
            }
        })
        .collect()
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
            entry.clone_from(n);
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
        Self {
            parent: nodes.iter().map(|n| (n.clone(), n.clone())).collect(),
        }
    }

    fn find(&mut self, x: &str) -> String {
        let mut root = x.to_string();
        while let Some(p) = self.parent.get(&root) {
            if p == &root {
                break;
            }
            root.clone_from(p);
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
        .map(|h| format!("sha256:{}", jcs::hex(&h)))
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
    // Counts are memory-bounded, so they always fit i64; saturate on the impossible overflow.
    let indep_support = i64::try_from(
        support.into_iter().filter(|a| !info.authors.contains(*a)).count(),
    )
    .unwrap_or(i64::MAX);
    let authors = i64::try_from(info.authors.len()).unwrap_or(i64::MAX);
    let rejects = i64::try_from(reject.len()).unwrap_or(i64::MAX);
    authors + indep_support - rejects
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
            entry.clone_from(cid);
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
    match edtf::parse(valid_range) {
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
