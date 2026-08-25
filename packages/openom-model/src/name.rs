//! The name model — `Name` / `Part` types + composition & equivalence resolvers.
//!
//! Spec: `plan/design.data-name-mode.md`. A person has a list of [`Name`]s; a name is an ordered list
//! of tagged [`Part`]s. Two **orthogonal** relations link names, and a name may carry both:
//!
//! - **composition** (`borrows_from`): a partial name **borrows the parts it doesn't state** (in
//!   practice the `family`/surname) from another name, resolved **transitively** and **acyclically**.
//!   Directional; the sole input to [`effective_parts`]. It does not inherit `type`.
//! - **equivalence** (`equivalent_to`): this name and the ones it links to are the **same name,
//!   differently rendered** (script transliteration, spelling variant, translation used as a name, or
//!   co-equal parallel originals). **Symmetric** and class-forming — see [`equivalence_class`].
//!   `provenance` records, per name, whether it is an `Original` or a `Derived` rendering.
//!
//! The two are independent: a romanized composing-byname both *borrows* a surname and is *equivalent
//! to* its other-script form (see the `composition_and_equivalence_combine` test). A name that is
//! neither — a pseudonym, an acronym alias — simply sets no relation; its "belongs to this person"
//! grouping comes from the `Node` it hangs on, and being a pseudonym/stage/regnal/religious name is a
//! `type`, not a relation. Embedding a name list into a `Node` is a later task (OPE-98).

use crate::NameId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Common part tags. The vocabulary is **open** — any string is a valid `tag`; these are the ones
/// the resolver reasons about (`family` is borrowed; `given`/`byname` fill the personal slot).
pub const TAG_GIVEN: &str = "given";
pub const TAG_FAMILY: &str = "family";
pub const TAG_BYNAME: &str = "byname";
pub const TAG_PATRONYMIC: &str = "patronymic";
pub const TAG_MATRONYMIC: &str = "matronymic";
pub const TAG_TITLE: &str = "title";
pub const TAG_SUFFIX: &str = "suffix";

/// Which side of its part a `particle` renders on. Default is `Prefix`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Position {
    Prefix,
    Suffix,
}

/// Whether an equivalent name form is a co-equal original or a rendering derived from another form.
/// Only meaningful on a name that sets `equivalent_to`; validated by [`validate`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    /// A co-equal original — e.g. one of two parallel originals (Maimonides' Hebrew ∥ Arabic), neither
    /// derived from the other.
    Original,
    /// A rendering produced from another form — a transliteration, transcription, or translation.
    Derived,
}

/// One tagged component of a name. `particle` is a separable connector (van, de, ibn, al-) that
/// renders with the part but is ignored for sorting/matching; `position` says which side.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Part {
    pub tag: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub particle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
}

impl Part {
    /// A plain tagged part (no particle).
    pub fn new(tag: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            value: value.into(),
            particle: None,
            position: None,
        }
    }

    /// A part carrying a connector particle (default `Prefix` position).
    pub fn with_particle(
        tag: impl Into<String>,
        value: impl Into<String>,
        particle: impl Into<String>,
        position: Position,
    ) -> Self {
        Self {
            tag: tag.into(),
            value: value.into(),
            particle: Some(particle.into()),
            position: Some(position),
        }
    }

    fn rendered(&self) -> String {
        match (&self.particle, self.position.unwrap_or(Position::Prefix)) {
            (Some(p), Position::Prefix) => format!("{p} {}", self.value),
            (Some(p), Position::Suffix) => format!("{} {p}", self.value),
            (None, _) => self.value.clone(),
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A single name a person carries. `role` is the open `type` soft label; the two relations
/// (`borrows_from`, `equivalent_to`) are orthogonal — see the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Name {
    pub id: NameId,
    /// The open `type` soft label (birth / married / nickname / public / …). A UI hint only.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// COMPOSITION — this name is partial; borrow its unstated parts (the family) from that name,
    /// transitively and acyclically. Directional. The only input to [`effective_parts`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrows_from: Option<NameId>,
    /// EQUIVALENCE — the same name as each listed name, differently rendered. Semantically undirected:
    /// the group is the connected component over these edges (stored direction is an encoding
    /// artifact). Never borrows parts. Usually empty or one entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_to: Vec<NameId>,
    /// Whether this form is an `Original` or a `Derived` rendering. Only meaningful with `equivalent_to`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// The default known-by name — at most one per person.
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub culture: Option<String>,
    pub parts: Vec<Part>,
}

/// Errors from resolving or validating a name list.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NameError {
    #[error("name {0} borrows through a `borrows_from` cycle")]
    CyclicBorrow(NameId),
    #[error("a name reference points at {0}, which is not in the list")]
    UnknownName(NameId),
    #[error("name {0} lists itself in `equivalent_to`")]
    SelfEquivalent(NameId),
    #[error("name {0} sets `provenance` without `equivalent_to`")]
    ProvenanceWithoutEquivalence(NameId),
    #[error("more than one name is marked `primary`")]
    MultiplePrimary,
}

fn find(names: &[Name], id: NameId) -> Option<&Name> {
    names.iter().find(|n| n.id == id)
}

/// The effective parts of a name: its own parts, plus — if it states no `family` part but has a
/// `borrows_from` — the `family` part(s) borrowed from the nearest ancestor up the composition chain
/// that has them. Transitive (Bobby → Bob → Robert) and cycle-safe. Never follows `equivalent_to`
/// (borrowing across a rendering would splice scripts).
pub fn effective_parts(names: &[Name], id: NameId) -> Result<Vec<Part>, NameError> {
    let name = find(names, id).ok_or(NameError::UnknownName(id))?;
    let mut parts = name.parts.clone();

    let has_family = parts.iter().any(|p| p.tag == TAG_FAMILY);
    if !has_family {
        let mut visited = HashSet::new();
        visited.insert(id);
        let mut cursor = name.borrows_from;
        while let Some(rid) = cursor {
            if !visited.insert(rid) {
                return Err(NameError::CyclicBorrow(rid));
            }
            let referenced = find(names, rid).ok_or(NameError::UnknownName(rid))?;
            let family: Vec<Part> = referenced
                .parts
                .iter()
                .filter(|p| p.tag == TAG_FAMILY)
                .cloned()
                .collect();
            if !family.is_empty() {
                parts.extend(family);
                break;
            }
            cursor = referenced.borrows_from;
        }
    }
    Ok(parts)
}

/// Render a name to a display string: its effective parts joined in order, each part rendered with
/// its particle on the stated side. (Particles are for display only — ignored for sort/match.)
pub fn render(names: &[Name], id: NameId) -> Result<String, NameError> {
    let parts = effective_parts(names, id)?;
    Ok(parts
        .iter()
        .map(Part::rendered)
        .collect::<Vec<_>>()
        .join(" "))
}

/// The equivalence class of `id`: every name reachable through `equivalent_to` edges treated as
/// **undirected**, including `id` itself (a name with no edges is a class of one). Returned in
/// names-list order. Errors on an edge pointing outside the list.
pub fn equivalence_class(names: &[Name], id: NameId) -> Result<Vec<NameId>, NameError> {
    if find(names, id).is_none() {
        return Err(NameError::UnknownName(id));
    }
    let mut visited = HashSet::new();
    visited.insert(id);
    let mut stack = vec![id];
    while let Some(cur) = stack.pop() {
        let node = find(names, cur).ok_or(NameError::UnknownName(cur))?;
        // Outgoing edges.
        for &t in &node.equivalent_to {
            if find(names, t).is_none() {
                return Err(NameError::UnknownName(t));
            }
            if visited.insert(t) {
                stack.push(t);
            }
        }
        // Incoming edges — the relation is symmetric, so a name pointing at `cur` is in the class too.
        for other in names {
            if other.equivalent_to.contains(&cur) && visited.insert(other.id) {
                stack.push(other.id);
            }
        }
    }
    Ok(names
        .iter()
        .map(|n| n.id)
        .filter(|id| visited.contains(id))
        .collect())
}

/// The `primary` name, if exactly one is marked. Errors if more than one is; `None` if none is.
pub fn primary(names: &[Name]) -> Result<Option<&Name>, NameError> {
    let mut found: Option<&Name> = None;
    for n in names.iter().filter(|n| n.primary) {
        if found.is_some() {
            return Err(NameError::MultiplePrimary);
        }
        found = Some(n);
    }
    Ok(found)
}

/// Validate a person's whole name list against every invariant: at most one `primary`; every
/// `borrows_from` chain resolvable and acyclic; every `equivalent_to` edge resolvable and not a
/// self-loop; and `provenance` only where an `equivalent_to` edge exists. The two relations are
/// independent — a name may set both.
pub fn validate(names: &[Name]) -> Result<(), NameError> {
    primary(names)?;
    for n in names {
        // Composition: resolvable + acyclic, independent of whether it happens to be followed.
        check_borrow_chain(names, n.id)?;
        // Equivalence: resolvable + irreflexive.
        for &t in &n.equivalent_to {
            if t == n.id {
                return Err(NameError::SelfEquivalent(n.id));
            }
            if find(names, t).is_none() {
                return Err(NameError::UnknownName(t));
            }
        }
        // `provenance` is a qualifier of the equivalence relation — meaningless without an edge.
        if n.provenance.is_some() && n.equivalent_to.is_empty() {
            return Err(NameError::ProvenanceWithoutEquivalence(n.id));
        }
    }
    Ok(())
}

/// Walk a name's `borrows_from` chain, erroring on a cycle or an unresolvable target — regardless of
/// whether `effective_parts` would actually follow it (a name that states its own family still must
/// not carry a cyclic/dangling borrow edge).
fn check_borrow_chain(names: &[Name], start: NameId) -> Result<(), NameError> {
    let mut visited = HashSet::new();
    visited.insert(start);
    let mut cursor = find(names, start)
        .ok_or(NameError::UnknownName(start))?
        .borrows_from;
    while let Some(rid) = cursor {
        if !visited.insert(rid) {
            return Err(NameError::CyclicBorrow(rid));
        }
        cursor = find(names, rid)
            .ok_or(NameError::UnknownName(rid))?
            .borrows_from;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeededIdSource;

    // Small helpers so the fixtures read like the design doc's examples.
    fn given(v: &str) -> Part {
        Part::new(TAG_GIVEN, v)
    }
    fn family(v: &str) -> Part {
        Part::new(TAG_FAMILY, v)
    }
    /// A minimal name: no relations, no metadata — tweak fields at the call site as needed.
    fn bare(id: NameId, role: &str, parts: Vec<Part>) -> Name {
        Name {
            id,
            role: Some(role.into()),
            borrows_from: None,
            equivalent_to: Vec::new(),
            provenance: None,
            primary: false,
            script: None,
            culture: None,
            parts,
        }
    }
    fn nick(id: NameId, of: NameId, parts: Vec<Part>, primary: bool) -> Name {
        Name {
            borrows_from: Some(of),
            primary,
            ..bare(id, "nickname", parts)
        }
    }
    fn birth(id: NameId, parts: Vec<Part>, primary: bool) -> Name {
        Name {
            primary,
            ..bare(id, "birth", parts)
        }
    }

    #[test]
    fn bill_clinton_composition() {
        let mut s = SeededIdSource::new(1);
        let (n1, n2, n3, n4, n5) = (
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
        );
        let names = vec![
            birth(
                n1,
                vec![given("William"), given("Jefferson"), family("Clinton")],
                false,
            ),
            nick(n2, n1, vec![given("Bill")], true),
            nick(n3, n1, vec![given("Bill"), given("Jefferson")], false),
            nick(n4, n1, vec![given("William"), given("Jeff")], false),
            // A standalone epithet — borrows nothing, is a rendering of nothing.
            bare(
                n5,
                "nickname",
                vec![Part::new(TAG_BYNAME, "The Comeback Kid")],
            ),
        ];
        assert_eq!(render(&names, n2).unwrap(), "Bill Clinton");
        assert_eq!(render(&names, n3).unwrap(), "Bill Jefferson Clinton");
        assert_eq!(render(&names, n4).unwrap(), "William Jeff Clinton");
        assert_eq!(render(&names, n5).unwrap(), "The Comeback Kid");
        assert_eq!(primary(&names).unwrap().unwrap().id, n2);
        assert!(validate(&names).is_ok());
    }

    #[test]
    fn magic_johnson_byname_borrows_only_family() {
        let mut s = SeededIdSource::new(2);
        let (m1, m2) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let names = vec![
            birth(
                m1,
                vec![
                    given("Earvin"),
                    family("Johnson"),
                    Part::new(TAG_SUFFIX, "Jr."),
                ],
                false,
            ),
            nick(m2, m1, vec![Part::new(TAG_BYNAME, "Magic")], true),
        ];
        // Borrows the family (Johnson) — not the given (Earvin), not the suffix (Jr.).
        assert_eq!(render(&names, m2).unwrap(), "Magic Johnson");
        assert_eq!(render(&names, m1).unwrap(), "Earvin Johnson Jr.");
    }

    #[test]
    fn tchaikovsky_is_equivalence_not_composition() {
        let mut s = SeededIdSource::new(3);
        let (n1, n2) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let names = vec![
            Name {
                primary: true,
                script: Some("Cyrl".into()),
                culture: Some("ru-RU".into()),
                ..bare(
                    n1,
                    "birth",
                    vec![
                        given("Пётр"),
                        Part::new(TAG_PATRONYMIC, "Ильич"),
                        family("Чайковский"),
                    ],
                )
            },
            Name {
                // A rendering: same name in Latin script, derived from the Cyrillic original. It
                // states its OWN full parts and borrows nothing — so it is equivalence, not composition.
                role: None,
                equivalent_to: vec![n1],
                provenance: Some(Provenance::Derived),
                script: Some("Latn".into()),
                ..bare(
                    n2,
                    "",
                    vec![
                        given("Pyotr"),
                        Part::new(TAG_PATRONYMIC, "Ilyich"),
                        family("Tchaikovsky"),
                    ],
                )
            },
        ];
        assert_eq!(render(&names, n2).unwrap(), "Pyotr Ilyich Tchaikovsky");
        // Symmetric class from a single stored edge, resolvable from either end, in list order.
        assert_eq!(equivalence_class(&names, n1).unwrap(), vec![n1, n2]);
        assert_eq!(equivalence_class(&names, n2).unwrap(), vec![n1, n2]);
        assert!(validate(&names).is_ok());
    }

    #[test]
    fn maimonides_parallel_originals_are_one_class() {
        // Hebrew ∥ Arabic are co-equal originals (Original); the Latin form is Derived. Rambam is a
        // separate name — neither relation — grouped to the person only by the (future) node.
        let mut s = SeededIdSource::new(8);
        let (he, ar, la, rambam) = (
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
        );
        let names = vec![
            Name {
                primary: true,
                script: Some("Hebr".into()),
                provenance: None,
                ..bare(he, "birth", vec![given("משה"), family("מימון")])
            },
            Name {
                equivalent_to: vec![he],
                provenance: Some(Provenance::Original),
                script: Some("Arab".into()),
                ..bare(ar, "birth", vec![given("موسى"), family("ميمون")])
            },
            Name {
                equivalent_to: vec![he],
                provenance: Some(Provenance::Derived),
                script: Some("Latn".into()),
                ..bare(la, "birth", vec![given("Moshe"), family("Maimon")])
            },
            bare(rambam, "nickname", vec![Part::new(TAG_BYNAME, "רמב״ם")]),
        ];
        let mut class = equivalence_class(&names, ar).unwrap();
        class.sort();
        let mut expect = vec![he, ar, la];
        expect.sort();
        assert_eq!(class, expect, "the three renderings are one class");
        assert_eq!(equivalence_class(&names, rambam).unwrap(), vec![rambam]);
        assert!(validate(&names).is_ok());
    }

    #[test]
    fn composition_and_equivalence_combine() {
        // The case that proves the axes are orthogonal: a Cyrillic press rendering of "Magic Johnson"
        // that BORROWS the surname (Джонсон, via the Cyrillic birth name) AND is EQUIVALENT to the
        // Latin byname "Magic". Two edges, two targets, resolved independently.
        let mut s = SeededIdSource::new(9);
        let (lat_birth, lat_magic, cyr_birth, cyr_magic) = (
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
        );
        let names = vec![
            birth(lat_birth, vec![given("Earvin"), family("Johnson")], false),
            nick(
                lat_magic,
                lat_birth,
                vec![Part::new(TAG_BYNAME, "Magic")],
                true,
            ),
            Name {
                equivalent_to: vec![lat_birth],
                provenance: Some(Provenance::Derived),
                script: Some("Cyrl".into()),
                ..bare(cyr_birth, "birth", vec![given("Эрвин"), family("Джонсон")])
            },
            Name {
                borrows_from: Some(cyr_birth),
                equivalent_to: vec![lat_magic],
                provenance: Some(Provenance::Derived),
                script: Some("Cyrl".into()),
                ..bare(cyr_magic, "nickname", vec![Part::new(TAG_BYNAME, "Мэджик")])
            },
        ];
        // Composition resolves via its OWN rendering's chain (borrows Джонсон, not Johnson).
        assert_eq!(render(&names, cyr_magic).unwrap(), "Мэджик Джонсон");
        // Equivalence pairs the two bynames, independent of the birth-name class.
        assert_eq!(
            equivalence_class(&names, lat_magic).unwrap(),
            vec![lat_magic, cyr_magic]
        );
        assert_eq!(
            equivalence_class(&names, lat_birth).unwrap(),
            vec![lat_birth, cyr_birth]
        );
        assert!(validate(&names).is_ok());
    }

    #[test]
    fn particle_prefix_and_suffix() {
        let mut s = SeededIdSource::new(4);
        let (a, b) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let vangogh = Name {
            ..bare(
                a,
                "birth",
                vec![
                    given("Vincent"),
                    given("Willem"),
                    Part::with_particle(TAG_FAMILY, "Gogh", "van", Position::Prefix),
                ],
            )
        };
        let caesar = Name {
            ..bare(
                b,
                "birth",
                vec![
                    given("Gaius"),
                    family("Iulius"),
                    Part::with_particle(TAG_PATRONYMIC, "Gai", "filius", Position::Suffix),
                ],
            )
        };
        let names = vec![vangogh, caesar];
        assert_eq!(render(&names, a).unwrap(), "Vincent Willem van Gogh");
        assert_eq!(render(&names, b).unwrap(), "Gaius Iulius Gai filius");
    }

    #[test]
    fn transitive_borrow_and_cycle_and_primary() {
        let mut s = SeededIdSource::new(5);
        let (robert, bob, bobby) = (
            NameId::generate(&mut s),
            NameId::generate(&mut s),
            NameId::generate(&mut s),
        );
        // Bobby → Bob → Robert (family Kennedy) — transitive borrow.
        let names = vec![
            birth(robert, vec![given("Robert"), family("Kennedy")], true),
            nick(bob, robert, vec![given("Bob")], false),
            nick(bobby, bob, vec![given("Bobby")], false),
        ];
        assert_eq!(render(&names, bobby).unwrap(), "Bobby Kennedy");

        // Cycle: x → y → x, neither has family.
        let (x, y) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let cyclic = vec![
            nick(x, y, vec![given("X")], false),
            nick(y, x, vec![given("Y")], false),
        ];
        assert_eq!(effective_parts(&cyclic, x), Err(NameError::CyclicBorrow(x)));

        // Two primaries → error; zero primaries → Ok(None).
        let two = vec![
            birth(x, vec![given("A")], true),
            birth(y, vec![given("B")], true),
        ];
        assert_eq!(primary(&two), Err(NameError::MultiplePrimary));
        let none = vec![birth(x, vec![given("A")], false)];
        assert_eq!(primary(&none).unwrap(), None);
    }

    #[test]
    fn validate_rejects_bad_equivalence_and_provenance() {
        let mut s = SeededIdSource::new(10);
        let (a, b) = (NameId::generate(&mut s), NameId::generate(&mut s));

        // Self-loop in equivalent_to.
        let mut n = bare(a, "birth", vec![given("A")]);
        n.equivalent_to = vec![a];
        assert_eq!(validate(&[n]), Err(NameError::SelfEquivalent(a)));

        // provenance without an equivalence edge.
        let mut n = bare(a, "birth", vec![given("A")]);
        n.provenance = Some(Provenance::Original);
        assert_eq!(
            validate(&[n]),
            Err(NameError::ProvenanceWithoutEquivalence(a))
        );

        // equivalent_to pointing outside the list.
        let mut n = bare(a, "birth", vec![given("A")]);
        n.equivalent_to = vec![b];
        assert_eq!(validate(&[n]), Err(NameError::UnknownName(b)));

        // A cyclic borrow is caught even when the name states its own family (effective_parts would
        // short-circuit, but validate walks the chain regardless).
        let mut n1 = birth(a, vec![given("A"), family("Fam")], false);
        n1.borrows_from = Some(b);
        let mut n2 = birth(b, vec![given("B"), family("Fam")], false);
        n2.borrows_from = Some(a);
        assert!(matches!(
            validate(&[n1, n2]),
            Err(NameError::CyclicBorrow(_))
        ));
    }

    #[test]
    fn name_round_trips_through_json() {
        let mut s = SeededIdSource::new(6);
        let (a, b) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let n = Name {
            equivalent_to: vec![b],
            provenance: Some(Provenance::Derived),
            ..nick(a, b, vec![given("Bill")], true)
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"borrows_from\":"), "composition edge key");
        assert!(json.contains("\"equivalent_to\":"), "equivalence edge key");
        assert!(
            json.contains("\"provenance\":\"derived\""),
            "provenance value"
        );
        assert!(json.contains("\"type\":"), "role serializes as `type`");
        let back: Name = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }
}
