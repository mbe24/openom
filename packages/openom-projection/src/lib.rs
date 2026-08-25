//! The read-time **projection** — increment 1.
//!
//! The claim store is a grow-only set of records that different authors append concurrently and that
//! sync in any order. It carries no resolved truth: two authors may say person A and person B are the
//! same while a third says they are different. The projection turns that set into a materialized read
//! model **deterministically**, so every replica computes the same answer from the same records
//! without a shared clock — write-time invariants that can't hold in a concurrent append-only store
//! become read-time guarantees (the same move keyeo's StrongRemove resolver makes).
//!
//! This increment builds the identity core: group `same_as` / `different_from` edges, cluster the
//! anchors with **constraint-repair union-find** (§11) — admit positive edges in a fixed order,
//! skipping any that would merge two anchors cut, directly or transitively, by a `different_from` —
//! canonicalize each cluster to its minimum anchor id, and assemble a [`Person`] view (names + sex)
//! with tombstoned records suppressed.
//!
//! Not yet here (documented seams): attestation-weighted confidence (edge scores are distinct-author
//! corroboration for now), `preferred`, `reattribute_to`, events/EDTF views, the *role-gated*
//! tombstone (this increment suppresses tombstoned records but does not yet check the tombstoner's
//! authority — that needs the role/membership feed), and SQLite materialization.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

const TYPE_PERSON: &str = "openom.org/core/person/v1";
const P_NAME: &str = "openom.org/core/name/v1";
const P_SEX: &str = "openom.org/core/sex/v1";
const P_SAME_AS: &str = "openom.org/core/same_as/v1";
const P_DIFFERENT_FROM: &str = "openom.org/core/different_from/v1";
const P_ATTEST: &str = "openom.org/core/attest/v1";
const P_TOMBSTONE: &str = "openom.org/core/tombstone/v1";

/// Read-time policy knobs.
pub struct Policy {
    /// Minimum score to merge a `same_as` pair.
    pub same_as_threshold: i64,
    /// Minimum score for a `different_from` to act as a hard cut; a weaker or refuted one does not
    /// block a merge.
    pub different_from_threshold: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            same_as_threshold: 1,
            different_from_threshold: 1,
        }
    }
}

/// One rendering of a person's name, retargeted to the canonical person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameView {
    pub claim_id: String,
    pub parts: Value,
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
    /// Resolved sex, if asserted (the value with the most distinct authors; ties broken lexically).
    pub sex: Option<String>,
}

/// A `same_as` edge that was not applied because a `different_from` cut it — surfaced, never merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub cut_pair: [String; 2],
}

/// The materialized read model (increment 1: people + identity conflicts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub people: Vec<Person>,
    pub conflicts: Vec<Conflict>,
}

/// Project a record set into the read model. Pure: the result depends only on the set of records and
/// the policy, never on their order.
pub fn project(records: &[Value], policy: &Policy) -> Projection {
    // The store guarantees unique content-hash ids, but be robust to a duplicated slice: keep the
    // first record per id, so projecting `recs` and `recs ++ recs` give the same result (set input).
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    let deduped: Vec<&Value> = records
        .iter()
        .filter(|r| match str_field(r, "id") {
            Some(id) => seen_ids.insert(id.to_string()),
            None => true,
        })
        .collect();

    // --- classify -------------------------------------------------------------------------------
    let mut tombstoned: BTreeSet<String> = BTreeSet::new();
    for &r in &deduped {
        if predicate(r) == Some(P_TOMBSTONE) {
            if let Some(t) = str_field(r, "targetId") {
                tombstoned.insert(t.to_string());
            }
        }
    }

    // Anchors, and person-scoped claims (skipping any tombstoned record).
    let mut anchors: BTreeSet<String> = BTreeSet::new();
    let mut same_as: BTreeMap<[String; 2], PairInfo> = BTreeMap::new();
    let mut different_from: BTreeMap<[String; 2], PairInfo> = BTreeMap::new();
    let mut attests: BTreeMap<String, Votes> = BTreeMap::new(); // target (claim id | fingerprint) -> votes
    let mut name_claims: Vec<(String, String, Value)> = Vec::new(); // (targetId, claimId, parts)
    let mut sex_claims: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new(); // target -> value -> authors

    for &r in &deduped {
        if type_of(r) == Some(TYPE_PERSON) {
            if let Some(id) = str_field(r, "id") {
                anchors.insert(id.to_string());
            }
            continue;
        }
        let Some(pred) = predicate(r) else { continue };
        let Some(id) = str_field(r, "id") else {
            continue;
        };
        if tombstoned.contains(id) {
            continue;
        }
        match pred {
            P_SAME_AS => collect_pair(&mut same_as, r, id),
            P_DIFFERENT_FROM => collect_pair(&mut different_from, r, id),
            P_ATTEST => {
                if let (Some(t), Some(verdict), Some(a)) = (
                    str_field(r, "targetId"),
                    r.get("value")
                        .and_then(|v| v.get("verdict"))
                        .and_then(Value::as_str),
                    str_field(r, "createdBy"),
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
            P_NAME => {
                if let (Some(t), Some(v)) = (str_field(r, "targetId"), r.get("value")) {
                    name_claims.push((t.to_string(), id.to_string(), v.clone()));
                }
            }
            P_SEX => {
                if let (Some(t), Some(sex), Some(a)) = (
                    str_field(r, "targetId"),
                    r.get("value")
                        .and_then(|v| v.get("sex"))
                        .and_then(Value::as_str),
                    str_field(r, "createdBy"),
                ) {
                    sex_claims
                        .entry(t.to_string())
                        .or_default()
                        .entry(sex.to_string())
                        .or_default()
                        .insert(a.to_string());
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
    for t in sex_claims.keys() {
        nodes.insert(t.clone());
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

        let mut names: Vec<NameView> = name_claims
            .iter()
            .filter(|(t, _, _)| canon_of(t).as_deref() == Some(canon.as_str()))
            .map(|(_, cid, parts)| NameView {
                claim_id: cid.clone(),
                parts: parts.clone(),
            })
            .collect();
        names.sort_by(|x, y| x.claim_id.cmp(&y.claim_id));

        // Resolve sex: the value with the most distinct authors across all member anchors.
        let mut tally: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for m in members {
            if let Some(by_value) = sex_claims.get(m) {
                for (val, authors) in by_value {
                    tally
                        .entry(val.clone())
                        .or_default()
                        .extend(authors.iter().cloned());
                }
            }
        }
        let sex = tally
            .iter()
            .max_by(|x, y| x.1.len().cmp(&y.1.len()).then(y.0.cmp(x.0)))
            .map(|(val, _)| val.clone());

        people.push(Person {
            id: canon.clone(),
            also,
            names,
            sex,
        });
    }
    people.sort_by(|a, b| a.id.cmp(&b.id));

    let conflicts = skipped
        .into_iter()
        .map(|cut_pair| Conflict { cut_pair })
        .collect();
    Projection { people, conflicts }
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

fn collect_pair(map: &mut BTreeMap<[String; 2], PairInfo>, r: &Value, id: &str) {
    if let (Some(p), Some(author)) = (pair(r), str_field(r, "createdBy")) {
        let info = map.entry(p).or_default();
        info.authors.insert(author.to_string());
        info.claim_ids.insert(id.to_string());
        if info.fingerprint.is_none() {
            info.fingerprint = fingerprint_str(r);
        }
    }
}

/// The `"sha256:<hex>"` fingerprint of a claim — the target an attestation uses to vote on the fact.
fn fingerprint_str(r: &Value) -> Option<String> {
    openom_claim::fingerprint(r)
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

// --- record field helpers -----------------------------------------------------------------------

fn type_of(r: &Value) -> Option<&str> {
    str_field(r, "type")
}

fn predicate(r: &Value) -> Option<&str> {
    str_field(r, "predicate")
}

fn str_field<'a>(r: &'a Value, key: &str) -> Option<&'a str> {
    r.get(key).and_then(Value::as_str)
}

/// The canonical sorted pair from a `same_as` / `different_from` claim's `value.pair`.
fn pair(r: &Value) -> Option<[String; 2]> {
    let arr = r.get("value")?.get("pair")?.as_array()?;
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
