// The opened family tree, backed by the treelog CRDT engine (packages/openom-treelog, wasm). Same
// public surface as the legacy JS-op FamilyTree, so the views and read helpers are unchanged — the
// difference is entirely underneath: state lives in a commute `Doc`, every edit is a self-contained,
// convergent op, and multi-device merge is real.
//
// Representation: a person owns name- and event-sub-entities (each an opaque id with leaf facts), plus
// simple person facts (sex, note, portrait) and a single JSON `custom` claim. Families own spouse and
// child OR-sets and marriage facts. Ids are hex strings app-facing (opaque), 16-byte in the engine.
// Persistence: each edit appends its treelog delta bytes to the DocStore (opaque to the store); hydrate
// merges them back. The engine owns the Lamport clock and tombstones, so there is no manual meta here.
import { createTree } from './treelog/index.js';
import { compareSiblings } from './sort.js';
import {
  makeName, makeEvent, givenOf, familyOf, definePersonViews, mergeFamilyFields, defineFamilyViews,
} from './model.js';

const NEW_PERSON = { given: '', surname: '', sex: 'U', custom: {} };
const MAX_HISTORY = 100; // undo/redo timeline depth
const enc = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const bytes = (h) => new Uint8Array(h.match(/../g)?.map((x) => parseInt(x, 16)) ?? []);

/**
 * The app-facing id a seeded entity gets. Ids are opaque hex of the engine's byte id; `seed()` uses a
 * symbolic id's UTF-8 bytes as the engine id, so a fixture reference like SEED_FOCUS resolves through
 * this. (Created entities get random ids; only fixtures carry symbolic references.)
 */
export const seedAppId = (symbolic) => hex(enc.encode(symbolic));
const splitGiven = (s) => (String(s ?? '').trim() ? String(s).trim().split(/\s+/) : []);

/** The person fields the editor patches, mapped to where they live in the engine. */
const EVENT_TYPES = ['birth', 'death'];

export class FamilyTree {
  revision = 0;
  people = new Map();
  families = new Map();
  media = new Map();
  mediaLinks = new Map();
  tombstones = new Map(); // kept for API shape; the engine owns real tombstones
  readOnly = false;
  readOnlyReason = null;

  #store;
  #docId;
  #engine = null;
  #ready;
  #replica;
  #listeners = new Set();
  #cursor = 0; // store log entries folded into the engine
  #history = []; // engine snapshots — the undo/redo timeline
  #hindex = -1; // cursor into #history

  constructor(store, docId) {
    this.#store = store;
    this.#docId = docId;
    // A per-instance replica id (per browsing context). Reused as the claim id for ordinary single-
    // value edits, so re-editing the same field updates in place instead of piling up claims.
    this.#replica = crypto.getRandomValues(new Uint8Array(16));
    this.#ready = createTree({ replica: this.#replica });
  }

  async #ensure() {
    if (!this.#engine) this.#engine = await this.#ready;
    return this.#engine;
  }

  onRevision(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  #bump() {
    this.revision += 1;
    for (const fn of this.#listeners) fn(this.revision);
  }

  // ------------------------------------------------------------------ engine read helpers
  #val(subjectHex, field) {
    const f = this.#engine.fact(bytes(subjectHex), field);
    return f.preferred ? f.preferred.value : '';
  }

  #buildPerson(pidHex) {
    const e = this.#engine;
    const b = bytes(pidHex);
    const primary = e.primaryName(b);
    const nameIds = e.names(b);
    const ordered = primary ? [primary, ...nameIds.filter((n) => n !== primary)] : nameIds;
    const names = ordered.map((nid) => ({
      parts: {
        given: splitGiven(this.#val(nid, 'given')),
        family: this.#val(nid, 'family'),
        prefix: this.#val(nid, 'prefix'),
        suffix: this.#val(nid, 'suffix'),
      },
      convention: this.#val(nid, 'convention') || 'western',
      type: this.#val(nid, 'type') || 'birth',
    }));
    if (!names.length) names.push(makeName({}));
    const events = e.events(b).map((eid) => {
      const type = this.#val(eid, 'type');
      return makeEvent(type, { date: this.#val(eid, 'date'), place: this.#val(eid, 'place') });
    });
    // Custom fields are per-field facts (`custom.<id>`), independently mergeable. Enumerate them from
    // the engine — no schema needed — so a value survives even if its field left the schema. (Values
    // are strings under claim-payload v1; boolean/option coercion on read is a schema-layer follow-up.)
    const custom = {};
    for (const f of e.fieldsOf(b)) {
      if (f.startsWith('custom.')) custom[f.slice('custom.'.length)] = this.#val(pidHex, f);
    }
    const person = { id: pidHex, names, events, custom, sex: this.#val(pidHex, 'sex') || 'U', note: this.#val(pidHex, 'note') };
    const portrait = this.#val(pidHex, 'portrait');
    if (portrait) person.portraitId = portrait;
    // Sources cited on the person in general (field ""): reconstructed as v2 source records.
    const srcs = e.cites(b, '').map((c) => c.source);
    if (srcs.length) {
      person.sources = srcs.map((sidHex) => ({
        title: this.#val(sidHex, 'title'),
        detail: this.#val(sidHex, 'detail'),
        supports: this.#val(sidHex, 'supports'),
      }));
    }
    return definePersonViews(person);
  }

  #buildFamily(fidHex) {
    const e = this.#engine;
    const b = bytes(fidHex);
    const spouses = e.spouses(b);
    const childLinks = e.children(b).map((c) => ({ id: c.person, pedi: c.pedi }));
    const facts = {};
    const marriage = this.#val(fidHex, 'marriage.date');
    const place = this.#val(fidHex, 'marriage.place');
    if (marriage) facts.marriage = marriage;
    if (place) facts.place = place;
    return defineFamilyViews(mergeFamilyFields(null, { id: fidHex, spouses, childLinks: childLinks.map((c) => ({ ...c })), facts }));
  }

  #buildMedia() {
    const e = this.#engine;
    this.media = new Map();
    this.mediaLinks = new Map();
    for (const recHex of e.mediaRecords()) {
      this.media.set(recHex, {
        id: recHex,
        kind: this.#val(recHex, 'kind') || 'image',
        mime: this.#val(recHex, 'mime'),
        hash: this.#val(recHex, 'hash'),
        w: Number(this.#val(recHex, 'w')) || undefined,
        h: Number(this.#val(recHex, 'h')) || undefined,
      });
    }
    // Links are per subject; gather over persons and families. `link` and `media` are hex ids.
    const subjects = [...this.people.keys(), ...this.families.keys()];
    for (const subjHex of subjects) {
      for (const { link, media } of e.media(bytes(subjHex))) {
        this.mediaLinks.set(link, {
          id: link,
          mediaId: media,
          subjectId: subjHex,
          role: this.#val(link, 'role') || 'document',
          order: Number(this.#val(link, 'order')) || 0,
          caption: this.#val(link, 'caption'),
          crop: this.#val(link, 'crop') ? JSON.parse(this.#val(link, 'crop')) : null,
        });
      }
    }
  }

  /** Rebuild the view-facing Maps from the engine. Called after every change. */
  #materialize() {
    const e = this.#engine;
    this.people = new Map(e.persons().map((pid) => [pid, this.#buildPerson(pid)]));
    this.families = new Map(e.families().map((fid) => [fid, this.#buildFamily(fid)]));
    this.#buildMedia();
  }

  // ------------------------------------------------------------------ reading (same as legacy)
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

  // ------------------------------------------------------------------ writing
  /** Apply a batch of engine deltas (each Uint8Array) as one atomic store append, then rematerialize. */
  async #commit(deltas, { silent = false, undoable = true } = {}) {
    if (deltas.length) await this.#store.append(this.#docId, deltas);
    this.#cursor += deltas.length;
    this.#materialize();
    // A settled edit (non-silent) is one undo step; per-keystroke silent writes update state without a
    // frame, so undo reverts the whole edit rather than one character.
    if (undoable && !silent) this.#pushHistory();
    if (!silent) this.#bump();
  }

  // ------------------------------------------------------------------ undo/redo timeline
  /** Anchor the timeline at the current state (after hydrate/seed/reset — nothing to undo behind it). */
  #baseline() {
    this.#history = [this.#engine.snapshot()];
    this.#hindex = 0;
  }
  #pushHistory() {
    this.#history.length = this.#hindex + 1; // drop any redo tail
    this.#history.push(this.#engine.snapshot());
    if (this.#history.length > MAX_HISTORY) this.#history.shift();
    this.#hindex = this.#history.length - 1;
  }
  async #restoreTo(snap) {
    // Rebuild the engine from the target snapshot and rewrite the local log to match. (Log-rewrite is
    // fine offline; collaborative-undo semantics are deferred to the sync work.)
    this.#engine = await createTree({ replica: this.#replica, snapshot: snap });
    await this.#store.delete(this.#docId);
    await this.#store.append(this.#docId, [snap]);
    this.#cursor = 1;
    this.#materialize();
    this.#bump();
  }

  /** Set a single-value leaf claim (replica-stable claim id + preferred). Empty value → retract. */
  #setLeaf(subject, field, value, out) {
    const e = this.#engine;
    if (value === '' || value == null) {
      out.push(e.retractClaim(subject, field, this.#replica));
    } else {
      out.push(e.addClaim(subject, field, this.#replica, String(value), null));
      out.push(e.setPreferredClaim(subject, field, this.#replica));
    }
  }

  /** The subject's primary name-entity id (bytes), minting one if absent (recording deltas in `out`). */
  #primaryName(pid, out) {
    const e = this.#engine;
    const existing = e.primaryName(pid);
    if (existing) return bytes(existing);
    const nid = e.newId();
    out.push(e.addName(pid, nid));
    out.push(e.setPrimaryName(pid, nid));
    return nid;
  }

  /** The subject's event-entity of `type` (bytes), minting one if absent. */
  #eventOfType(pid, type, out) {
    const e = this.#engine;
    for (const eid of e.events(pid)) {
      // `eid` is a hex string from the shim; return the bytes callers pass back into the engine.
      if (this.#val(eid, 'type') === type) return bytes(eid);
    }
    const eid = e.newId();
    out.push(e.addEvent(pid, eid));
    this.#setLeaf(eid, 'type', type, out);
    return eid;
  }

  /** Translate an editor patch on person `pid` (bytes) into engine deltas, appended to `out`. */
  #applyPatch(pid, patch, out) {
    const e = this.#engine;
    if ('given' in patch || 'surname' in patch) {
      const nid = this.#primaryName(pid, out);
      if ('given' in patch) this.#setLeaf(nid, 'given', patch.given, out);
      if ('surname' in patch) this.#setLeaf(nid, 'family', patch.surname, out);
    }
    for (const [key, type] of [['birth', 'birth'], ['death', 'death']]) {
      const placeKey = key + 'Place';
      if (!(key in patch) && !(placeKey in patch)) continue;
      const eid = this.#eventOfType(pid, type, out);
      if (key in patch) this.#setLeaf(eid, 'date', patch[key], out);
      if (placeKey in patch) this.#setLeaf(eid, 'place', patch[placeKey], out);
    }
    if ('sex' in patch) this.#setLeaf(pid, 'sex', patch.sex, out);
    if ('note' in patch) this.#setLeaf(pid, 'note', patch.note, out);
    if ('portraitId' in patch) this.#setLeaf(pid, 'portrait', patch.portraitId, out);
    if ('custom' in patch) {
      // One fact per custom field. A falsy value (unset text, unchecked boolean) retracts the field,
      // matching the app's "empty/false = not set" convention (SchemaRegistry.usage).
      for (const [k, v] of Object.entries(patch.custom)) {
        const s = v === false || v === '' || v == null ? '' : String(v);
        this.#setLeaf(pid, 'custom.' + k, s, out);
      }
    }
    void e;
  }

  async createPerson(fields = {}) {
    const e = await this.#ensure();
    const pid = e.newId();
    const out = [e.addPerson(pid)];
    const merged = { ...NEW_PERSON, ...fields };
    this.#applyPatch(pid, merged, out);
    await this.#commit(out);
    return this.person(hex(pid));
  }

  async updatePerson(id, patch, opts = {}) {
    await this.#ensure();
    const out = [];
    this.#applyPatch(bytes(id), patch, out);
    await this.#commit(out, opts);
    return this.person(id);
  }

  async deletePerson(id) {
    const e = await this.#ensure();
    const pid = bytes(id);
    const out = [e.removePerson(pid)];
    // Self-contained ops don't cascade — unlink the person from every family explicitly.
    for (const f of this.families.values()) {
      if (f.spouses.includes(id)) out.push(e.unlinkSpouse(bytes(f.id), pid));
      if (f.children.includes(id)) out.push(e.unlinkChild(bytes(f.id), pid));
    }
    await this.#commit(out);
  }

  async addMarriage(aId, bFieldsOrId, facts = {}) {
    const e = await this.#ensure();
    const out = [];
    let bId;
    if (typeof bFieldsOrId === 'string') {
      bId = bFieldsOrId;
    } else {
      const nb = e.newId();
      out.push(e.addPerson(nb));
      this.#applyPatch(nb, { ...NEW_PERSON, ...bFieldsOrId }, out);
      bId = hex(nb);
    }
    const fid = e.newId();
    out.push(e.addFamily(fid));
    out.push(e.linkSpouse(fid, bytes(aId)));
    out.push(e.linkSpouse(fid, bytes(bId)));
    this.#setFamilyFacts(fid, facts, out);
    await this.#commit(out);
    return this.family(hex(fid));
  }

  async addChild(familyId, fieldsOrId) {
    const e = await this.#ensure();
    const out = [];
    let pid;
    if (typeof fieldsOrId === 'string') {
      pid = bytes(fieldsOrId);
    } else {
      pid = e.newId();
      out.push(e.addPerson(pid));
      this.#applyPatch(pid, { ...NEW_PERSON, ...fieldsOrId }, out);
    }
    out.push(e.linkChild(bytes(familyId), pid, 'birth'));
    await this.#commit(out);
    return this.person(hex(pid));
  }

  async addParents(childId, father = null, mother = null) {
    const e = await this.#ensure();
    const existing = this.childFamilyOf(childId);
    const out = [];
    const fid = existing ? bytes(existing.id) : e.newId();
    if (!existing) {
      out.push(e.addFamily(fid));
      out.push(e.linkChild(fid, bytes(childId), 'birth'));
    }
    for (const [role, val] of [['M', father], ['F', mother]]) {
      if (!val) continue;
      let pid;
      if (typeof val === 'string') {
        pid = bytes(val);
      } else {
        pid = e.newId();
        out.push(e.addPerson(pid));
        this.#applyPatch(pid, { sex: role, ...NEW_PERSON, ...val }, out);
      }
      out.push(e.linkSpouse(fid, pid));
    }
    await this.#commit(out);
    return this.family(hex(fid));
  }

  async removeMarriage(familyId) {
    if (!this.families.has(familyId)) return;
    const e = await this.#ensure();
    await this.#commit([e.removeFamily(bytes(familyId))]);
  }

  async unlinkChild(familyId, personId) {
    const e = await this.#ensure();
    await this.#commit([e.unlinkChild(bytes(familyId), bytes(personId))]);
  }

  async unlinkSpouse(familyId, personId) {
    const e = await this.#ensure();
    await this.#commit([e.unlinkSpouse(bytes(familyId), bytes(personId))]);
  }

  async linkSpouse(familyId, personId) {
    const e = await this.#ensure();
    await this.#commit([e.linkSpouse(bytes(familyId), bytes(personId))]);
  }

  #setFamilyFacts(fid, facts, out) {
    if ('marriage' in facts) this.#setLeaf(fid, 'marriage.date', facts.marriage, out);
    if ('place' in facts) this.#setLeaf(fid, 'marriage.place', facts.place, out);
  }

  async setFamilyFacts(familyId, facts) {
    await this.#ensure();
    const out = [];
    this.#setFamilyFacts(bytes(familyId), facts, out);
    await this.#commit(out);
  }

  // ------------------------------------------------------------------ media
  async attachMedia(subjectId, { hash: h, mime, w, h: hh, caption = '', source = '', role = 'portrait', crop = null }) {
    const e = await this.#ensure();
    const rec = e.newId();
    const link = e.newId();
    const out = [e.addMediaRecord(rec)];
    this.#setLeaf(rec, 'mime', mime, out);
    this.#setLeaf(rec, 'hash', h, out);
    if (w) this.#setLeaf(rec, 'w', w, out);
    if (hh) this.#setLeaf(rec, 'h', hh, out);
    out.push(e.addMediaLink(bytes(subjectId), link, rec));
    this.#setLeaf(link, 'role', role, out);
    if (caption) this.#setLeaf(link, 'caption', caption, out);
    if (crop) this.#setLeaf(link, 'crop', JSON.stringify(crop), out);
    if (role === 'portrait') this.#setLeaf(bytes(subjectId), 'portrait', hex(link), out);
    await this.#commit(out);
    return { mediaId: hex(rec), linkId: hex(link) };
  }

  async setPortrait(subjectId, linkId) {
    await this.#ensure();
    const out = [];
    this.#setLeaf(bytes(subjectId), 'portrait', linkId, out);
    await this.#commit(out);
  }

  async detachMedia(linkId) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    const e = await this.#ensure();
    await this.#commit([e.removeMediaLink(bytes(link.subjectId), bytes(linkId))]);
  }

  async setCrop(linkId, crop) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    await this.#ensure();
    const out = [];
    this.#setLeaf(bytes(linkId), 'crop', JSON.stringify(crop), out);
    await this.#commit(out);
  }

  // ------------------------------------------------------------------ undo / redo
  get canUndo() { return this.#hindex > 0; }
  get canRedo() { return this.#hindex < this.#history.length - 1; }
  async undo() {
    if (!this.canUndo) return;
    this.#hindex -= 1;
    await this.#restoreTo(this.#history[this.#hindex]);
  }
  async redo() {
    if (!this.canRedo) return;
    this.#hindex += 1;
    await this.#restoreTo(this.#history[this.#hindex]);
  }

  // ------------------------------------------------------------------ loading
  async hydrate() {
    const e = await this.#ensure();
    const snap = await this.#store.readSnapshot(this.#docId);
    if (snap) {
      const b = snap.bytes instanceof Uint8Array ? snap.bytes : new Uint8Array(snap.bytes);
      // Rebuild the engine from the snapshot, then fold the tail.
      this.#engine = await createTree({ replica: this.#replica, snapshot: b });
      this.#cursor = snap.logCursor ?? 0;
    }
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, this.#cursor);
    for (const u of updates) {
      const bin = u instanceof Uint8Array ? u : new Uint8Array(u);
      this.#engine.mergeBytes(bin);
    }
    this.#cursor = cursor ?? this.#cursor + updates.length;
    this.#materialize();
    this.#baseline();
    this.#bump();
    void e;
  }

  async seed(ops) {
    const e = await this.#ensure();
    // `ops` are legacy v2 upsert ops (from seed.js). Translate them into engine deltas with a stable
    // string-id → engine-id map so cross-references resolve.
    const out = [];
    const idOf = new Map();
    const idFor = (s) => {
      let b = idOf.get(s);
      if (!b) { b = enc.encode(s); idOf.set(s, b); }
      return b;
    };
    for (const o of ops) {
      if (o.type === 'upsertPerson') {
        const pid = idFor(o.id);
        out.push(e.addPerson(pid));
        this.#applyPatch(pid, { ...NEW_PERSON, ...o.fields }, out);
        (o.fields.sources ?? []).forEach((s) => {
          const sid = e.newId();
          out.push(e.addSource(sid));
          this.#setLeaf(sid, 'title', s.title ?? '', out);
          this.#setLeaf(sid, 'detail', s.detail ?? '', out);
          this.#setLeaf(sid, 'supports', s.supports ?? '', out);
          out.push(e.cite(pid, '', sid, null));
        });
      } else if (o.type === 'upsertFamily') {
        const fid = idFor(o.id);
        out.push(e.addFamily(fid));
        for (const s of o.fields.spouses ?? []) out.push(e.linkSpouse(fid, idFor(s)));
        for (const c of o.fields.children ?? []) out.push(e.linkChild(fid, idFor(c), 'birth'));
        this.#setFamilyFacts(fid, o.fields.facts ?? {}, out);
      }
    }
    // Seeding is not an undoable action; anchor the timeline at the seeded state.
    await this.#commit(out, { undoable: false });
    this.#baseline();
  }

  async reset() {
    await this.#store.delete(this.#docId);
    this.#engine = await createTree({ replica: this.#replica });
    this.#cursor = 0;
    this.#materialize();
    this.#baseline();
    this.#bump();
  }

  async compact() {
    const e = await this.#ensure();
    const prev = await this.#store.readSnapshot(this.#docId);
    const payload = e.snapshot();
    try {
      await this.#store.putSnapshot(this.#docId, payload, prev?.version ?? null, { logCursor: this.#cursor });
    } catch (err) {
      if (err?.name !== 'ConflictError') throw err;
    }
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
}
