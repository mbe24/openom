//! The **web binding** for the family tree — a `wasm-bindgen` veneer over the pure [`Tree`]. Only
//! compiled with `--features wasm --target wasm32-*`; native (Tauri) callers use [`Tree`] directly,
//! so the merge logic stays identical across web and native (one implementation, two bindings — the
//! same discipline as `openom-sealer`).
//!
//! Marshalling: ids and op payloads cross as `Uint8Array` (`&[u8]` in, `Vec<u8>` out); an edit
//! returns the encoded `commute` ops for the caller to seal + append; the nested read model crosses
//! as JSON strings (non-secret display data, so `serde_json` — never the DEK or any key material —
//! which the app's views parse).

use wasm_bindgen::prelude::*;

use crate::{Pedigree, Tree, TreeOp};
use commute::codec::encode_ops;

/// A family tree exported to JS. Wraps the pure [`Tree`]; edits return the sealable delta bytes, the
/// caller (the JS sync shim) seals them with the wasm sealer and appends to the store.
#[wasm_bindgen]
pub struct WasmTree {
    inner: Tree,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn parse_pedi(s: &str) -> Pedigree {
    match s {
        "adopted" => Pedigree::Adopted,
        "foster" => Pedigree::Foster,
        "step" => Pedigree::Step,
        "unknown" => Pedigree::Unknown,
        _ => Pedigree::Birth,
    }
}

fn pedi_str(p: Pedigree) -> &'static str {
    match p {
        Pedigree::Birth => "birth",
        Pedigree::Adopted => "adopted",
        Pedigree::Foster => "foster",
        Pedigree::Step => "step",
        Pedigree::Unknown => "unknown",
    }
}

#[derive(serde::Serialize)]
struct ClaimView {
    id: String,
    value: String,
    source: Option<String>,
}
#[derive(serde::Serialize)]
struct FactView {
    claims: Vec<ClaimView>,
    preferred: Option<ClaimView>,
}
#[derive(serde::Serialize)]
struct ChildView {
    person: String,
    pedi: String,
}
#[derive(serde::Serialize)]
struct MediaLinkView {
    link: String,
    media: String,
}
#[derive(serde::Serialize)]
struct CiteView {
    source: String,
    claim: Option<String>,
}

fn claim_view(c: &crate::Claim) -> ClaimView {
    ClaimView { id: hex(&c.id), value: c.value.clone(), source: c.source.clone() }
}

#[wasm_bindgen]
impl WasmTree {
    /// A fresh tree for a 16-byte replica id (the caller mints it, e.g. `crypto.getRandomValues`).
    #[wasm_bindgen(constructor)]
    pub fn new(replica: &[u8]) -> Result<WasmTree, JsError> {
        let r: [u8; 16] = replica.try_into().map_err(|_| JsError::new("replica id must be 16 bytes"))?;
        Ok(WasmTree { inner: Tree::new(r) })
    }

    /// Rebuild a tree from a `commute` snapshot (log-derived recovery / first load).
    #[wasm_bindgen(js_name = fromSnapshot)]
    pub fn from_snapshot(replica: &[u8], bytes: &[u8]) -> Result<WasmTree, JsError> {
        let r: [u8; 16] = replica.try_into().map_err(|_| JsError::new("replica id must be 16 bytes"))?;
        let inner = Tree::from_snapshot(r, bytes).map_err(|e| JsError::new(&format!("bad snapshot: {e:?}")))?;
        Ok(WasmTree { inner })
    }

    // ---- edits (each returns the encoded commute ops to seal + append) ----

    #[wasm_bindgen(js_name = addPerson)]
    pub fn add_person(&mut self, id: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddPerson { id: id.to_vec() }))
    }
    #[wasm_bindgen(js_name = removePerson)]
    pub fn remove_person(&mut self, id: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemovePerson { id: id.to_vec() }))
    }
    #[wasm_bindgen(js_name = addClaim)]
    pub fn add_claim(&mut self, subject: &[u8], field: &str, claim: &[u8], value: &str, source: Option<String>) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddClaim {
            subject: subject.to_vec(),
            field: field.to_string(),
            claim: claim.to_vec(),
            value: value.to_string(),
            source,
        }))
    }
    #[wasm_bindgen(js_name = setPreferredClaim)]
    pub fn set_preferred_claim(&mut self, subject: &[u8], field: &str, claim: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::SetPreferredClaim { subject: subject.to_vec(), field: field.to_string(), claim: claim.to_vec() }))
    }
    #[wasm_bindgen(js_name = retractClaim)]
    pub fn retract_claim(&mut self, subject: &[u8], field: &str, claim: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RetractClaim { subject: subject.to_vec(), field: field.to_string(), claim: claim.to_vec() }))
    }
    #[wasm_bindgen(js_name = addFamily)]
    pub fn add_family(&mut self, id: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddFamily { id: id.to_vec() }))
    }
    #[wasm_bindgen(js_name = removeFamily)]
    pub fn remove_family(&mut self, id: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemoveFamily { id: id.to_vec() }))
    }
    #[wasm_bindgen(js_name = linkChild)]
    pub fn link_child(&mut self, family: &[u8], person: &[u8], pedi: &str) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::LinkChild { family: family.to_vec(), person: person.to_vec(), pedi: parse_pedi(pedi) }))
    }
    #[wasm_bindgen(js_name = unlinkChild)]
    pub fn unlink_child(&mut self, family: &[u8], person: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::UnlinkChild { family: family.to_vec(), person: person.to_vec() }))
    }
    #[wasm_bindgen(js_name = moveChild)]
    pub fn move_child(&mut self, person: &[u8], from: &[u8], to: &[u8], pedi: &str) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::MoveChild { person: person.to_vec(), from: from.to_vec(), to: to.to_vec(), pedi: parse_pedi(pedi) }))
    }
    #[wasm_bindgen(js_name = linkSpouse)]
    pub fn link_spouse(&mut self, family: &[u8], person: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::LinkSpouse { family: family.to_vec(), person: person.to_vec() }))
    }
    #[wasm_bindgen(js_name = unlinkSpouse)]
    pub fn unlink_spouse(&mut self, family: &[u8], person: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::UnlinkSpouse { family: family.to_vec(), person: person.to_vec() }))
    }
    #[wasm_bindgen(js_name = addName)]
    pub fn add_name(&mut self, subject: &[u8], name: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddName { subject: subject.to_vec(), name: name.to_vec() }))
    }
    #[wasm_bindgen(js_name = removeName)]
    pub fn remove_name(&mut self, subject: &[u8], name: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemoveName { subject: subject.to_vec(), name: name.to_vec() }))
    }
    #[wasm_bindgen(js_name = setPrimaryName)]
    pub fn set_primary_name(&mut self, subject: &[u8], name: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::SetPrimaryName { subject: subject.to_vec(), name: name.to_vec() }))
    }
    #[wasm_bindgen(js_name = addEvent)]
    pub fn add_event(&mut self, subject: &[u8], event: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddEvent { subject: subject.to_vec(), event: event.to_vec() }))
    }
    #[wasm_bindgen(js_name = removeEvent)]
    pub fn remove_event(&mut self, subject: &[u8], event: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemoveEvent { subject: subject.to_vec(), event: event.to_vec() }))
    }
    #[wasm_bindgen(js_name = addSource)]
    pub fn add_source(&mut self, source: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddSource { source: source.to_vec() }))
    }
    #[wasm_bindgen(js_name = removeSource)]
    pub fn remove_source(&mut self, source: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemoveSource { source: source.to_vec() }))
    }
    #[wasm_bindgen(js_name = cite)]
    pub fn cite(&mut self, subject: &[u8], field: &str, source: &[u8], claim: Option<Vec<u8>>) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::Cite { subject: subject.to_vec(), field: field.to_string(), source: source.to_vec(), claim }))
    }
    #[wasm_bindgen(js_name = uncite)]
    pub fn uncite(&mut self, subject: &[u8], field: &str, source: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::Uncite { subject: subject.to_vec(), field: field.to_string(), source: source.to_vec() }))
    }
    #[wasm_bindgen(js_name = addMediaRecord)]
    pub fn add_media_record(&mut self, media: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddMediaRecord { media: media.to_vec() }))
    }
    #[wasm_bindgen(js_name = removeMediaRecord)]
    pub fn remove_media_record(&mut self, media: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemoveMediaRecord { media: media.to_vec() }))
    }
    #[wasm_bindgen(js_name = addMediaLink)]
    pub fn add_media_link(&mut self, subject: &[u8], link: &[u8], media: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::AddMediaLink { subject: subject.to_vec(), link: link.to_vec(), media: media.to_vec() }))
    }
    #[wasm_bindgen(js_name = removeMediaLink)]
    pub fn remove_media_link(&mut self, subject: &[u8], link: &[u8]) -> Vec<u8> {
        encode_ops(&self.inner.apply(TreeOp::RemoveMediaLink { subject: subject.to_vec(), link: link.to_vec() }))
    }

    // ---- sync ----

    /// Integrate a peer's delta (the decrypted bytes of a pulled log entry).
    #[wasm_bindgen(js_name = mergeBytes)]
    pub fn merge_bytes(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.inner.doc_mut().merge_bytes(bytes).map_err(|e| JsError::new(&format!("bad delta: {e:?}")))
    }

    /// The full state as canonical bytes (bootstrap / compaction).
    pub fn snapshot(&self) -> Vec<u8> {
        self.inner.doc().snapshot()
    }

    // ---- read model (JSON) ----

    /// Live person ids as a JSON array of hex strings.
    pub fn persons(&self) -> String {
        let ids: Vec<String> = self.inner.persons().iter().map(|p| hex(p)).collect();
        serde_json::to_string(&ids).expect("serialize ids")
    }
    #[wasm_bindgen(js_name = hasPerson)]
    pub fn has_person(&self, id: &[u8]) -> bool {
        self.inner.has_person(id)
    }
    /// A fact as JSON `{ claims: [{id,value,source}], preferred }`.
    pub fn fact(&self, subject: &[u8], field: &str) -> String {
        let f = self.inner.fact(subject, field);
        let view = FactView { claims: f.claims.iter().map(claim_view).collect(), preferred: f.preferred.as_ref().map(claim_view) };
        serde_json::to_string(&view).expect("serialize fact")
    }
    /// Live family ids as a JSON array of hex strings.
    pub fn families(&self) -> String {
        let ids: Vec<String> = self.inner.families().iter().map(|f| hex(f)).collect();
        serde_json::to_string(&ids).expect("serialize families")
    }
    /// A family's children as JSON `[{person, pedi}]`.
    pub fn children(&self, family: &[u8]) -> String {
        let kids: Vec<ChildView> = self.inner.children_of(family).into_iter().map(|(p, pe)| ChildView { person: hex(&p), pedi: pedi_str(pe).into() }).collect();
        serde_json::to_string(&kids).expect("serialize children")
    }
    /// A family's spouses as a JSON array of hex strings.
    pub fn spouses(&self, family: &[u8]) -> String {
        let ids: Vec<String> = self.inner.spouses_of(family).iter().map(|s| hex(s)).collect();
        serde_json::to_string(&ids).expect("serialize spouses")
    }
    /// A subject's media links as JSON `[{link, media}]` (link id + the media-record id it points at).
    pub fn media(&self, subject: &[u8]) -> String {
        let links: Vec<MediaLinkView> =
            self.inner.media_of(subject).into_iter().map(|(l, m)| MediaLinkView { link: hex(&l), media: hex(&m) }).collect();
        serde_json::to_string(&links).expect("serialize media")
    }
    /// The doc-level media-record ids as a JSON array of hex strings.
    #[wasm_bindgen(js_name = mediaRecords)]
    pub fn media_records(&self) -> String {
        let ids: Vec<String> = self.inner.media_records().iter().map(|m| hex(m)).collect();
        serde_json::to_string(&ids).expect("serialize media records")
    }
    /// A subject's name-entity ids as a JSON array of hex strings.
    pub fn names(&self, subject: &[u8]) -> String {
        let ids: Vec<String> = self.inner.names_of(subject).iter().map(|n| hex(n)).collect();
        serde_json::to_string(&ids).expect("serialize names")
    }
    /// A subject's preferred (display) name-entity id as a hex string, or `null`.
    #[wasm_bindgen(js_name = primaryName)]
    pub fn primary_name(&self, subject: &[u8]) -> Option<String> {
        self.inner.primary_name(subject).map(|n| hex(&n))
    }
    /// A subject's event-entity ids as a JSON array of hex strings.
    pub fn events(&self, subject: &[u8]) -> String {
        let ids: Vec<String> = self.inner.events_of(subject).iter().map(|e| hex(e)).collect();
        serde_json::to_string(&ids).expect("serialize events")
    }
    /// The doc-level source-record ids as a JSON array of hex strings.
    pub fn sources(&self) -> String {
        let ids: Vec<String> = self.inner.sources().iter().map(|s| hex(s)).collect();
        serde_json::to_string(&ids).expect("serialize sources")
    }
    /// The sources citing a fact as JSON `[{source, claim}]` (claim = the supported claim id or null).
    pub fn cites(&self, subject: &[u8], field: &str) -> String {
        let cites: Vec<CiteView> = self
            .inner
            .cites_of(subject, field)
            .into_iter()
            .map(|(s, c)| CiteView { source: hex(&s), claim: c.map(|c| hex(&c)) })
            .collect();
        serde_json::to_string(&cites).expect("serialize cites")
    }
}
