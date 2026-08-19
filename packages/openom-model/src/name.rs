//! The name model — `Name` / `Part` types + a composition resolver.
//!
//! Spec: `plan/design.data-name-mode.md`. A person has a list of [`Name`]s; a name is an ordered
//! list of tagged [`Part`]s. The load-bearing axes are the parts, `ref` (a form-of link), `primary`
//! (the default known-by name), and `script`/`culture` (metadata). `type` is an open soft label.
//!
//! `ref` = "a form of": a partial entry **borrows the parts it doesn't state** (in practice the
//! `family`/surname) from the referenced name, resolved **transitively** and **acyclically**. It
//! does not inherit `type`. This module wires up that composition; embedding names into the tree
//! model (attaching a name list to a `Node`) is a later task (OPE-98).

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
        Self { tag: tag.into(), value: value.into(), particle: None, position: None }
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

/// A single name a person carries. `role` is the open `type` soft label; `form_of` is `ref`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Name {
    pub id: NameId,
    /// The open `type` soft label (birth / married / nickname / public / …). A UI hint only.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `ref` — this name is a *form of* that one; borrow its unstated parts (the family).
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub form_of: Option<NameId>,
    /// The default known-by name — at most one per person.
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub culture: Option<String>,
    pub parts: Vec<Part>,
}

/// Errors from resolving a name list.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NameError {
    #[error("name {0} references itself through a `ref` cycle")]
    CyclicRef(NameId),
    #[error("`ref` points at name {0}, which is not in the list")]
    DanglingRef(NameId),
    #[error("more than one name is marked `primary`")]
    MultiplePrimary,
}

fn find(names: &[Name], id: NameId) -> Option<&Name> {
    names.iter().find(|n| n.id == id)
}

/// The effective parts of a name: its own parts, plus — if it states no `family` part but has a
/// `ref` — the `family` part(s) borrowed from the nearest ancestor up the `ref` chain that has
/// them. Transitive (Bobby → Bob → Robert) and cycle-safe.
pub fn effective_parts(names: &[Name], id: NameId) -> Result<Vec<Part>, NameError> {
    let name = find(names, id).ok_or(NameError::DanglingRef(id))?;
    let mut parts = name.parts.clone();

    let has_family = parts.iter().any(|p| p.tag == TAG_FAMILY);
    if !has_family {
        let mut visited = HashSet::new();
        visited.insert(id);
        let mut cursor = name.form_of;
        while let Some(rid) = cursor {
            if !visited.insert(rid) {
                return Err(NameError::CyclicRef(rid));
            }
            let referenced = find(names, rid).ok_or(NameError::DanglingRef(rid))?;
            let family: Vec<Part> =
                referenced.parts.iter().filter(|p| p.tag == TAG_FAMILY).cloned().collect();
            if !family.is_empty() {
                parts.extend(family);
                break;
            }
            cursor = referenced.form_of;
        }
    }
    Ok(parts)
}

/// Render a name to a display string: its effective parts joined in order, each part rendered with
/// its particle on the stated side. (Particles are for display only — ignored for sort/match.)
pub fn render(names: &[Name], id: NameId) -> Result<String, NameError> {
    let parts = effective_parts(names, id)?;
    Ok(parts.iter().map(Part::rendered).collect::<Vec<_>>().join(" "))
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
    fn nick(id: NameId, of: NameId, parts: Vec<Part>, primary: bool) -> Name {
        Name {
            id,
            role: Some("nickname".into()),
            form_of: Some(of),
            primary,
            script: None,
            culture: None,
            parts,
        }
    }
    fn birth(id: NameId, parts: Vec<Part>, primary: bool) -> Name {
        Name {
            id,
            role: Some("birth".into()),
            form_of: None,
            primary,
            script: None,
            culture: None,
            parts,
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
            birth(n1, vec![given("William"), given("Jefferson"), family("Clinton")], false),
            nick(n2, n1, vec![given("Bill")], true),
            nick(n3, n1, vec![given("Bill"), given("Jefferson")], false),
            nick(n4, n1, vec![given("William"), given("Jeff")], false),
            Name {
                id: n5,
                role: Some("nickname".into()),
                form_of: None, // a standalone epithet — borrows nothing
                primary: false,
                script: None,
                culture: None,
                parts: vec![Part::new(TAG_BYNAME, "The Comeback Kid")],
            },
        ];
        assert_eq!(render(&names, n2).unwrap(), "Bill Clinton");
        assert_eq!(render(&names, n3).unwrap(), "Bill Jefferson Clinton");
        assert_eq!(render(&names, n4).unwrap(), "William Jeff Clinton");
        assert_eq!(render(&names, n5).unwrap(), "The Comeback Kid");
        assert_eq!(primary(&names).unwrap().unwrap().id, n2);
    }

    #[test]
    fn magic_johnson_byname_borrows_only_family() {
        let mut s = SeededIdSource::new(2);
        let (m1, m2) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let names = vec![
            birth(m1, vec![given("Earvin"), family("Johnson"), Part::new(TAG_SUFFIX, "Jr.")], false),
            nick(m2, m1, vec![Part::new(TAG_BYNAME, "Magic")], true),
        ];
        // Borrows the family (Johnson) — not the given (Earvin), not the suffix (Jr.).
        assert_eq!(render(&names, m2).unwrap(), "Magic Johnson");
        assert_eq!(render(&names, m1).unwrap(), "Earvin Johnson Jr.");
    }

    #[test]
    fn tchaikovsky_romanization_states_own_parts() {
        let mut s = SeededIdSource::new(3);
        let (n1, n2) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let names = vec![
            Name {
                id: n1,
                role: Some("birth".into()),
                form_of: None,
                primary: true,
                script: Some("Cyrl".into()),
                culture: Some("ru-RU".into()),
                parts: vec![
                    given("Пётр"),
                    Part::new(TAG_PATRONYMIC, "Ильич"),
                    family("Чайковский"),
                ],
            },
            Name {
                id: n2,
                role: None, // a rendering doesn't inherit type
                form_of: Some(n1),
                primary: false,
                script: Some("Latn".into()),
                culture: None,
                parts: vec![given("Pyotr"), Part::new(TAG_PATRONYMIC, "Ilyich"), family("Tchaikovsky")],
            },
        ];
        // Has its own family → borrows nothing.
        assert_eq!(render(&names, n2).unwrap(), "Pyotr Ilyich Tchaikovsky");
    }

    #[test]
    fn particle_prefix_and_suffix() {
        let mut s = SeededIdSource::new(4);
        let (a, b) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let vangogh = Name {
            id: a,
            role: Some("birth".into()),
            form_of: None,
            primary: false,
            script: None,
            culture: None,
            parts: vec![
                given("Vincent"),
                given("Willem"),
                Part::with_particle(TAG_FAMILY, "Gogh", "van", Position::Prefix),
            ],
        };
        let caesar = Name {
            id: b,
            role: Some("birth".into()),
            form_of: None,
            primary: false,
            script: None,
            culture: None,
            parts: vec![
                given("Gaius"),
                family("Iulius"),
                Part::with_particle(TAG_PATRONYMIC, "Gai", "filius", Position::Suffix),
            ],
        };
        let names = vec![vangogh, caesar];
        assert_eq!(render(&names, a).unwrap(), "Vincent Willem van Gogh");
        assert_eq!(render(&names, b).unwrap(), "Gaius Iulius Gai filius");
    }

    #[test]
    fn transitive_borrow_and_cycle_and_primary() {
        let mut s = SeededIdSource::new(5);
        let (robert, bob, bobby) =
            (NameId::generate(&mut s), NameId::generate(&mut s), NameId::generate(&mut s));
        // Bobby → Bob → Robert (family Kennedy) — transitive borrow.
        let names = vec![
            birth(robert, vec![given("Robert"), family("Kennedy")], true),
            nick(bob, robert, vec![given("Bob")], false),
            nick(bobby, bob, vec![given("Bobby")], false),
        ];
        assert_eq!(render(&names, bobby).unwrap(), "Bobby Kennedy");

        // Cycle: x → y → x, neither has family.
        let (x, y) = (NameId::generate(&mut s), NameId::generate(&mut s));
        let cyclic = vec![nick(x, y, vec![given("X")], false), nick(y, x, vec![given("Y")], false)];
        assert_eq!(effective_parts(&cyclic, x), Err(NameError::CyclicRef(x)));

        // Two primaries → error; zero primaries → Ok(None).
        let two = vec![birth(x, vec![given("A")], true), birth(y, vec![given("B")], true)];
        assert_eq!(primary(&two), Err(NameError::MultiplePrimary));
        let none = vec![birth(x, vec![given("A")], false)];
        assert_eq!(primary(&none).unwrap(), None);
    }

    #[test]
    fn name_round_trips_through_json() {
        let mut s = SeededIdSource::new(6);
        let n = nick(NameId::generate(&mut s), NameId::generate(&mut s), vec![given("Bill")], true);
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"ref\":"), "field renamed to `ref`");
        assert!(json.contains("\"type\":"), "field renamed to `type`");
        let back: Name = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }
}
