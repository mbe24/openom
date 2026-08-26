// The opened family tree, backed by the claim-based engine (packages/openom-tree, wasm) — the
// migration target that replaces the treelog-backed FamilyTree with the SAME public surface, so the
// views and read helpers (queries.js/detail.js/graph.js) are unchanged. State is a set of claim/anchor
// records; every edit mints a self-contained, convergent op (assert / supersede / remove), and the read
// model comes from the engine's epistemic projection rather than a hand-rolled fold.
//
// This file is being built in stages (OPE-201): stage 1 is the READ adapter (projection → the v2 view
// shapes the UI reads) + load/merge/snapshot; the write surface (create/update/delete/marriage/child/
// media/undo/redo/seed) lands in stage 2 and currently throws.
import { createClaimTree } from './tree/index.js';
import { compareSiblings } from './sort.js';
import { profile } from './profile.js';
import { makeName, definePersonViews, mergeFamilyFields, defineFamilyViews } from './model.js';

const SNAP_TAG = 0xcc; // marks a snapshot payload that carries a coverage-cursor header
const COMPACT_AT = 200; // replayed-tail length past which hydrate folds the log into a fresh snapshot

const splitGiven = (s) => (String(s ?? '').trim() ? String(s).trim().split(/\s+/) : []);
const toU8 = (b) => (b instanceof Uint8Array ? b : new Uint8Array(b));

// The core claim vocabulary the projection recognizes (packages/openom-projection). Kept here so the
// read mapping and the (stage-2) write mapping name the same predicates/anchor types in one place.
export const V = {
  TYPE_PERSON: 'openom.org/core/person/v1',
  TYPE_EVENT: 'openom.org/core/event/v1',
  P_NAME: 'openom.org/core/name/v1',
  P_SEX: 'openom.org/core/sex/v1',
  P_BIOGRAPHY: 'openom.org/core/biography/v1',
  P_EVENT_TYPE: 'openom.org/core/event_type/v1',
  P_DATE: 'openom.org/core/date/v1',
  P_EVENT_PLACE: 'openom.org/core/event_place/v1',
  P_PARTICIPANT: 'openom.org/core/participant/v1',
  P_PARENT: 'openom.org/core/parent/v1',
  P_PARTNERSHIP: 'openom.org/core/partnership/v1',
  P_PREFERRED: 'openom.org/core/preferred/v1',
  P_CUSTOM_VALUE: 'openom.org/core/custom/value/v1',
  P_MEDIA_LINK: 'openom.org/core/media_link/v1',
  P_PLACE_NAME: 'openom.org/core/place_name/v1',
  P_SOURCE: 'openom.org/core/source/v1',
};

// The participant role that marks a person as the SUBJECT of a person-owned event (birth/death) — the
// events the profile shows under `person.events`. Spouses in a marriage event carry a different role and
// are read as a family fact, not a person event.
const ROLE_PRINCIPAL = 'principal';

// Human labels for the `supports` line of a citation, keyed by the predicate the citation backs. A
// predicate with no entry degrades to its cleaned last path segment.
const PRED_LABEL = {
  [V.P_NAME]: 'name',
  [V.P_SEX]: 'sex',
  [V.P_BIOGRAPHY]: 'biography',
  [V.P_EVENT_TYPE]: 'event',
  [V.P_DATE]: 'date',
  [V.P_EVENT_PLACE]: 'place',
};
const predicateLabel = (pred) =>
  PRED_LABEL[pred] ?? String(pred ?? '').split('/').filter(Boolean).slice(-2, -1)[0] ?? String(pred ?? '');

const EXTRACT_MAX = 120;
const trimExtract = (s) => {
  const t = String(s ?? '').trim();
  return t.length > EXTRACT_MAX ? t.slice(0, EXTRACT_MAX - 1).trimEnd() + '…' : t;
};

const notImplemented = (what) => {
  throw new Error(`ClaimFamilyTree: ${what} is not implemented yet (OPE-201 stage 2)`);
};

export class ClaimFamilyTree {
  revision = 0;
  people = new Map();
  families = new Map();
  media = new Map();
  mediaLinks = new Map();
  tombstones = new Map(); // kept for API shape; the engine owns real removal/revocation
  readOnly = false;
  readOnlyReason = null;

  #store;
  #docId;
  #schema;
  #createdBy;
  #engine = null;
  #ready;
  #listeners = new Set();
  #deltaListeners = new Set();
  #cursor = 0;

  constructor(store, docId, schema = null, createdBy = null) {
    this.#store = store;
    this.#docId = docId;
    this.#schema = schema;
    this.#createdBy = createdBy;
    this.#ready = createClaimTree({ createdBy });
  }

  async #ensure() {
    if (!this.#engine) this.#engine = await this.#ready;
    return this.#engine;
  }

  onRevision(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  /** Subscribe to each locally-produced op batch (raw bytes) — the sync controller seals + pushes them.
   *  Remote batches merged via mergeRemote are NOT emitted (they must not be pushed back). */
  onDelta(fn) {
    this.#deltaListeners.add(fn);
    return () => this.#deltaListeners.delete(fn);
  }

  #bump() {
    this.revision += 1;
    for (const fn of this.#listeners) fn(this.revision);
  }

  // ------------------------------------------------------------------ projection → view model
  /** Coerce a custom-field value back to its declared type (bool/number), else a string. */
  #coerceCustom(id, raw) {
    const type = this.#schema?.field?.(id)?.type;
    if (type === 'boolean') return raw === true || raw === 'true';
    if (type === 'number') return raw === '' || raw == null ? '' : Number(raw);
    return raw == null ? '' : String(raw);
  }

  #buildPerson(P, eventsByPerson) {
    // Names: each projection NameView.parts IS the name claim's value ({parts, convention, type}); the
    // preferred name (if resolved) leads, the rest follow in claim-id order (the projection's order).
    const ordered = P.preferred_name
      ? [P.names.find((n) => n.claim_id === P.preferred_name), ...P.names.filter((n) => n.claim_id !== P.preferred_name)].filter(Boolean)
      : P.names;
    const names = ordered.map((n) => {
      const v = n.parts ?? {};
      const parts = v.parts ?? {};
      return {
        parts: {
          given: splitGiven(parts.given),
          family: parts.family ?? '',
          prefix: parts.prefix ?? '',
          suffix: parts.suffix ?? '',
        },
        convention: v.convention || 'western',
        type: v.type || 'birth',
      };
    });
    if (!names.length) names.push(makeName({}));

    // Person-owned events (birth/death …): the projection events where this person is the principal.
    const events = (eventsByPerson.get(P.id) ?? []).map((e) => ({
      type: e.event_type ?? '',
      date: e.date_edtf ?? '',
      place: e.place?.name ?? '',
    }));

    const custom = {};
    for (const f of P.custom_fields ?? []) custom[f.field_id] = this.#coerceCustom(f.field_id, f.value);

    const person = {
      id: P.id,
      names,
      events,
      custom,
      sex: P.sex || 'U',
      note: P.biography ?? '',
    };

    const portrait = (P.media ?? []).find((m) => (m.value?.role) === 'portrait');
    if (portrait) person.portraitId = portrait.claim_id;

    // "Sources" in the profile = the citations aggregated on this person's claims (the projection already
    // does the aggregation + resolves each sourceId). Map its Citation shape to the view's flat shape.
    if (P.sources?.length) person.sources = P.sources.map((c) => this.#citationView(c));

    return definePersonViews(person);
  }

  #citationView(c) {
    const src = c.source ?? {};
    const detail = [];
    if (c.extract) detail.push('"' + trimExtract(c.extract) + '"');
    if (c.locator != null) {
      const loc = typeof c.locator === 'string' ? c.locator : JSON.stringify(c.locator);
      if (loc && loc !== '{}' && loc !== 'null') detail.push(loc);
    }
    return { title: src.title ?? '', detail: detail.join(', '), supports: predicateLabel(c.predicate) };
  }

  #buildFamily(U, eventsById) {
    const facts = {};
    const marriage = U.marriage_event ? eventsById.get(U.marriage_event) : null;
    if (marriage) {
      if (marriage.date_edtf) facts.marriage = marriage.date_edtf;
      if (marriage.place?.name) facts.place = marriage.place.name;
    }
    const childLinks = (U.children ?? []).map((id) => ({ id, pedi: 'birth' }));
    return defineFamilyViews(
      mergeFamilyFields(null, { id: U.id, spouses: U.parents ?? [], childLinks, facts }),
    );
  }

  #buildMedia(projPeople) {
    this.media = new Map();
    this.mediaLinks = new Map();
    for (const P of projPeople) {
      for (const m of P.media ?? []) {
        const hash = m.media_hash;
        const v = m.value ?? {};
        if (!this.media.has(hash)) {
          this.media.set(hash, {
            id: hash,
            kind: v.kind || 'image',
            mime: v.mime,
            hash,
            w: Number(v.width) || undefined,
            h: Number(v.height) || undefined,
          });
        }
        this.mediaLinks.set(m.claim_id, {
          id: m.claim_id,
          mediaId: hash,
          subjectId: P.id,
          role: v.role || 'document',
          order: Number(v.order) || 0,
          caption: v.caption,
          crop: v.crop ?? null,
        });
      }
    }
  }

  /** Rebuild the whole view-facing model from the engine's projection (after a load / merge). */
  #materialize() {
    profile('materialize', () => {
      const proj = this.#engine.project();
      const eventsById = new Map(proj.events.map((e) => [e.id, e]));
      const eventsByPerson = new Map();
      for (const e of proj.events) {
        for (const part of e.participants) {
          if (part.role !== ROLE_PRINCIPAL) continue;
          if (!eventsByPerson.has(part.person)) eventsByPerson.set(part.person, []);
          eventsByPerson.get(part.person).push(e);
        }
      }
      this.people = new Map(proj.people.map((P) => [P.id, this.#buildPerson(P, eventsByPerson)]));
      this.families = new Map((proj.unions ?? []).map((U) => [U.id, this.#buildFamily(U, eventsById)]));
      this.#buildMedia(proj.people);
    });
  }

  // ------------------------------------------------------------------ reading (same surface as legacy)
  person(id) { return this.people.get(id); }
  family(id) { return this.families.get(id); }
  allPeople() { return [...this.people.values()]; }
  allFamilies() { return [...this.families.values()]; }

  familiesOf(id) { return this.allFamilies().filter((f) => f.spouses.includes(id)); }
  childFamilyOf(id) { return this.allFamilies().find((f) => f.children.includes(id)); }

  parentsOf(id) {
    const fam = this.childFamilyOf(id);
    if (!fam) return { family: null, father: null, mother: null };
    const spouses = fam.spouses.map((s) => this.person(s)).filter(Boolean);
    let father = spouses.find((p) => p.sex === 'M') ?? null;
    let mother = spouses.find((p) => p.sex === 'F') ?? null;
    for (const p of spouses) {
      if (p === father || p === mother) continue;
      if (!father) father = p; else if (!mother) mother = p;
    }
    return { family: fam, father, mother };
  }

  childrenOf(id, familyId = null) {
    const fams = familyId ? [this.family(familyId)].filter(Boolean) : this.familiesOf(id);
    const ids = fams.flatMap((f) => f.children);
    return ids.map((c) => this.person(c)).filter(Boolean).sort(compareSiblings);
  }

  siblingsOf(id) {
    const fam = this.childFamilyOf(id);
    if (!fam) return [];
    return fam.children.filter((c) => c !== id).map((c) => this.person(c)).filter(Boolean).sort(compareSiblings);
  }

  mediaOf(subjectId) {
    const links = [...this.mediaLinks.values()].filter((l) => l.subjectId === subjectId);
    const portraitId = this.people.get(subjectId)?.portraitId;
    return links
      .sort((a, b) => (a.id === portraitId ? -1 : b.id === portraitId ? 1 : (a.order ?? 0) - (b.order ?? 0)))
      .map((link) => ({ link, media: this.media.get(link.mediaId) }))
      .filter((m) => m.media);
  }

  portraitOf(subjectId) {
    const p = this.people.get(subjectId);
    if (!p) return null;
    const link = p.portraitId ? this.mediaLinks.get(p.portraitId) : null;
    const chosen = link ?? this.mediaOf(subjectId).find((m) => m.link.role === 'portrait')?.link;
    if (!chosen) return null;
    const media = this.media.get(chosen.mediaId);
    return media ? { link: chosen, media } : null;
  }

  ancestorIds(id, seen = new Set()) {
    const { father, mother } = this.parentsOf(id);
    for (const p of [father, mother]) {
      if (p && !seen.has(p.id)) { seen.add(p.id); this.ancestorIds(p.id, seen); }
    }
    return seen;
  }

  /** The canonical person id an anchor resolves to (stable UI handle across same_as merges). */
  resolveId(anchor) { return this.#engine?.resolveId(anchor) ?? null; }

  // ------------------------------------------------------------------ sync
  /** The full engine state as a snapshot batch — the sync controller seals it as the bootstrap baseline
   *  a fresh device restores from. */
  snapshotBytes() {
    return this.#engine.snapshot();
  }

  /** Integrate a peer's op batch (raw bytes the controller already unsealed): merge it, persist it
   *  locally for durability, and refresh the views. Does not re-emit (not local). */
  async mergeRemote(bytes) {
    await this.#ensure();
    const bin = toU8(bytes);
    this.#engine.merge(bin);
    await this.#store.append(this.#docId, [bin]);
    this.#cursor += 1;
    this.#materialize();
    this.#bump();
  }

  // ------------------------------------------------------------------ loading
  // Snapshot payload = [SNAP_TAG][u32 BE coverage cursor][engine snapshot bytes] — same envelope as the
  // treelog engine, so the DocStore stays an opaque-byte store.
  #unwrapSnapshot(b) {
    if (b.length >= 5 && b[0] === SNAP_TAG) {
      const cursor = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(1, false);
      return { snapshot: b.subarray(5), cursor };
    }
    return { snapshot: b, cursor: 0 }; // unwrapped/foreign — replay the whole log (idempotent)
  }

  async hydrate() {
    await this.#ensure();
    const snap = await this.#store.readSnapshot(this.#docId);
    if (snap) {
      const raw = toU8(snap.bytes);
      const { snapshot, cursor } = this.#unwrapSnapshot(raw);
      this.#engine = await createClaimTree({ createdBy: this.#createdBy, snapshot });
      this.#cursor = cursor;
    }
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, this.#cursor);
    profile('hydrate.replay', () => {
      for (const u of updates) this.#engine.merge(toU8(u));
    });
    this.#cursor = cursor ?? this.#cursor + updates.length;
    this.#materialize();
    this.#bump();
  }

  toJSON() {
    return {
      version: 2,
      people: this.allPeople().map((p) => JSON.parse(JSON.stringify(p))),
      families: this.allFamilies().map((f) => JSON.parse(JSON.stringify(f))),
      media: [...this.media.values()],
      mediaLinks: [...this.mediaLinks.values()],
      tombstones: [],
    };
  }

  // ------------------------------------------------------------------ writing (stage 2, OPE-201)
  get canUndo() { return false; }
  get canRedo() { return false; }
  async createPerson() { return notImplemented('createPerson'); }
  async updatePerson() { return notImplemented('updatePerson'); }
  async deletePerson() { return notImplemented('deletePerson'); }
  async addMarriage() { return notImplemented('addMarriage'); }
  async addChild() { return notImplemented('addChild'); }
  async addParents() { return notImplemented('addParents'); }
  async removeMarriage() { return notImplemented('removeMarriage'); }
  async unlinkChild() { return notImplemented('unlinkChild'); }
  async unlinkSpouse() { return notImplemented('unlinkSpouse'); }
  async linkSpouse() { return notImplemented('linkSpouse'); }
  async setFamilyFacts() { return notImplemented('setFamilyFacts'); }
  async attachMedia() { return notImplemented('attachMedia'); }
  async setPortrait() { return notImplemented('setPortrait'); }
  async detachMedia() { return notImplemented('detachMedia'); }
  async setCrop() { return notImplemented('setCrop'); }
  async undo() { return notImplemented('undo'); }
  async redo() { return notImplemented('redo'); }
  async seed() { return notImplemented('seed'); }
  async compact() { return notImplemented('compact'); }
  async reset() { return notImplemented('reset'); }
}
