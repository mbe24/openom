// The opened family tree, backed by the claim-based engine (packages/openom-tree, wasm) — the
// migration target that replaces the treelog-backed FamilyTree with the SAME public surface, so the
// views and read helpers (queries.js/detail.js/graph.js) are unchanged. State is a set of claim/anchor
// records; every edit mints a self-contained, convergent op (assert / supersede / remove), and the read
// model comes from the engine's epistemic projection rather than a hand-rolled fold.
//
// This file is being built in stages (OPE-201): stage 1 is the READ adapter (projection → the v2 view
// shapes the UI reads) + load/merge/snapshot; the write surface (create/update/delete/marriage/child/
// media/undo/redo/seed) lands in stage 2 and currently throws.
import { createTree } from './tree/index.js';
import { compareSiblings } from './sort.js';
import { profile } from './profile.js';
import { makeName, definePersonViews, mergeFamilyFields, defineFamilyViews } from './model.js';

const SNAP_TAG = 0xcc; // marks a snapshot payload that carries a coverage-cursor header
const COMPACT_AT = 200; // replayed-tail length past which hydrate folds the log into a fresh snapshot

const splitGiven = (s) => (String(s ?? '').trim() ? String(s).trim().split(/\s+/) : []);
const toU8 = (b) => (b instanceof Uint8Array ? b : new Uint8Array(b));
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
/** A fresh opaque anchor id (person / event) — the engine does not mint anchor ids, the caller does. */
const uuid = () => 'x_' + hex(crypto.getRandomValues(new Uint8Array(16)));
// The author fallback must match the loader's, so a claim this replica authored reads back as "mine"
// (createdBy === this author) and an edit supersedes it in place instead of piling up a competitor.
const DEFAULT_AUTHOR = 'did:key:zLocalReplica';
const NEW_PERSON = { given: '', surname: '', sex: 'U', custom: {} };

// The core claim vocabulary the projection recognizes (packages/openom-projection). Kept here so the
// read mapping and the (stage-2) write mapping name the same predicates/anchor types in one place.
export const V = {
  TYPE_CLAIM: 'openom.org/core/claim/v1',
  TYPE_PERSON: 'openom.org/core/person/v1',
  TYPE_EVENT: 'openom.org/core/event/v1',
  TYPE_PLACE: 'openom.org/core/place/v1',
  P_EXISTENCE: 'openom.org/core/existence/v1',
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
  throw new Error(`FamilyTree: ${what} is not implemented yet (OPE-201 stage 2)`);
};

export class FamilyTree {
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
  #author;
  #engine = null;
  #ready;
  #listeners = new Set();
  #deltaListeners = new Set();
  #cursor = 0;
  #eventOf = new Map(); // `${personId}|${type}` -> event anchor id (rebuilt each materialize)
  #marriageEventOf = new Map(); // union id -> its marriage event anchor id (rebuilt each materialize)
  #undo = []; // frames of { added:[id], removed:[record] } (in-memory, session-local)
  #redo = [];
  #group = null; // the open silent-edit burst's frame (coalesces per-keystroke edits into one step)
  #removeOpId = new Map(); // removed record id -> the Remove op's id, so undo can revoke an anchor removal
  #overlay = new Map(); // pid -> pending display-only patch during a keystroke burst (mints at settle)

  constructor(store, docId, schema = null, createdBy = null) {
    this.#store = store;
    this.#docId = docId;
    this.#schema = schema;
    this.#author = createdBy ?? DEFAULT_AUTHOR;
    this.#ready = createTree({ createdBy: this.#author });
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

  /** Set the moderator did:keys (the members currently at Maintainer or above) whose
   *  remove/supersede/revoke ops the engine honors. Call on unlock and on every governing-keyring
   *  change; a solo tree can omit this — the engine defaults to its own author (the owner moderates
   *  their own tree). Re-projects immediately, so a role change resurfaces/hides claims at once. */
  async setModerators(dids) {
    const eng = await this.#ensure();
    eng.setModerators(dids);
    this.#materialize();
    this.#bump();
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
      this.#eventOf = new Map();
      for (const e of proj.events) {
        for (const part of e.participants) {
          if (part.role !== ROLE_PRINCIPAL) continue;
          if (!eventsByPerson.has(part.person)) eventsByPerson.set(part.person, []);
          eventsByPerson.get(part.person).push(e);
          // First event of a given (person, type) wins as the one an edit supersedes.
          const key = part.person + '|' + (e.event_type ?? '');
          if (!this.#eventOf.has(key)) this.#eventOf.set(key, e.id);
        }
      }
      this.people = new Map(proj.people.map((P) => [P.id, this.#buildPerson(P, eventsByPerson)]));
      this.families = new Map((proj.unions ?? []).map((U) => [U.id, this.#buildFamily(U, eventsById)]));
      this.#marriageEventOf = new Map((proj.unions ?? []).map((U) => [U.id, U.marriage_event]));
      this.#buildMedia(proj.people);
      // Re-apply any in-flight keystroke-burst overlay on top of the freshly projected people.
      for (const [pid, patch] of this.#overlay) {
        if (this.people.has(pid)) this.people.set(pid, this.#applyOverlay(this.people.get(pid), patch));
      }
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

  /** Merge store entries appended since our cursor — e.g. by another tab into the shared DocStore —
   *  into the engine WITHOUT re-appending (the store already holds them), then refresh the view. The
   *  cross-tab tick (tabSync.js) calls this on a BroadcastChannel ping; set-union makes the tail replay
   *  idempotent, so the loop is dumb. Returns whether anything was merged. */
  async syncTail() {
    await this.#ensure();
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, this.#cursor);
    if (!updates.length) return false;
    for (const u of updates) this.#engine.merge(toU8(u));
    this.#cursor = cursor ?? this.#cursor + updates.length;
    this.#materialize();
    this.#bump();
    return true;
  }

  // ------------------------------------------------------------------ loading
  // Snapshot payload = [SNAP_TAG][u32 BE coverage cursor][engine snapshot bytes] — same envelope as the
  // treelog engine, so the DocStore stays an opaque-byte store.
  #wrapSnapshot(snap, cursor) {
    const out = new Uint8Array(5 + snap.length);
    out[0] = SNAP_TAG;
    new DataView(out.buffer).setUint32(1, cursor >>> 0, false);
    out.set(snap, 5);
    return out;
  }
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
      this.#engine = await createTree({ createdBy: this.#author, snapshot });
      this.#cursor = cursor;
    }
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, this.#cursor);
    profile('hydrate.replay', () => {
      for (const u of updates) this.#engine.merge(toU8(u));
    });
    this.#cursor = cursor ?? this.#cursor + updates.length;
    this.#materialize();
    this.#bump();
    // Bound reload cost: once the replayed tail is long, fold it into a fresh snapshot.
    if (updates.length > COMPACT_AT) await this.compact().catch(() => {});
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
  // Each edit mints one or more ops (assert / supersede / remove) via the engine — which returns the
  // op-batch bytes AND applies the op to the local set — then persists the bytes and re-materializes.
  // A single-value field is one claim under (target, predicate): set = supersede this replica's prior
  // claim in place (or assert the first), clear = remove this replica's claim(s). Only *this replica's*
  // claims are touched, so a peer's competing claim survives (the projection resolves the contest).

  /** This replica's live claims under (target, predicate). */
  #liveMine(target, predicate) {
    return this.#engine.liveClaimsOf(target, predicate).filter((c) => c.createdBy === this.#author);
  }

  /** Set (value = object) or clear (value = null) a single-value claim with replace semantics. */
  #setSingle(target, predicate, value, out) {
    const mine = this.#liveMine(target, predicate);
    if (value == null) {
      for (const c of mine) this.#remove(c.id, out);
      return;
    }
    const prior = mine[0];
    out.push(prior
      ? this.#engine.supersedeClaim(prior.id, target, predicate, value)
      : this.#engine.assertClaim(target, predicate, value));
  }

  /** Merge a name patch (given/surname) into this replica's name claim, preserving its other parts. */
  #setName(pid, patch, out) {
    const prior = this.#liveMine(pid, V.P_NAME)[0];
    const cur = prior
      ? structuredClone(prior.value)
      : { parts: { given: '', family: '', prefix: '', suffix: '' }, convention: 'western', type: 'birth' };
    cur.parts = cur.parts ?? {};
    if ('given' in patch) cur.parts.given = String(patch.given ?? '');
    if ('surname' in patch) cur.parts.family = String(patch.surname ?? '');
    out.push(prior
      ? this.#engine.supersedeClaim(prior.id, pid, V.P_NAME, cur)
      : this.#engine.assertClaim(pid, V.P_NAME, cur));
  }

  /** The person's event anchor of `type` (birth/death), minting it (+ its type + principal participant)
   *  if absent. `cache` reuses an event minted earlier in the same commit (before re-materialize). */
  #eventFor(pid, type, out, cache) {
    const key = pid + '|' + type;
    if (cache.has(key)) return cache.get(key);
    const existing = this.#eventOf.get(key);
    if (existing) { cache.set(key, existing); return existing; }
    const eid = uuid();
    out.push(this.#engine.assertAnchor(eid, V.TYPE_EVENT));
    out.push(this.#engine.assertClaim(eid, V.P_EVENT_TYPE, { type }));
    out.push(this.#engine.assertClaim(eid, V.P_PARTICIPANT, { personId: pid, role: ROLE_PRINCIPAL }));
    cache.set(key, eid);
    return eid;
  }

  /** Set (or clear) an event's place: a Place is a claim-target id (deterministic per name, so equal
   *  place strings dedup) carrying a place_name claim; the event points at it via event_place. */
  #setEventPlace(eid, place, out) {
    if (!place) { this.#setSingle(eid, V.P_EVENT_PLACE, null, out); return; }
    const placeId = 'place:' + place;
    if (!this.#liveMine(placeId, V.P_PLACE_NAME).some((c) => c.value?.name === place)) {
      out.push(this.#engine.assertClaim(placeId, V.P_PLACE_NAME, { name: place }));
    }
    this.#setSingle(eid, V.P_EVENT_PLACE, { placeId }, out);
  }

  /** Set (or clear on empty) one custom field value. A boolean is written as an explicit 'true'/'false'
   *  (never cleared), matching the legacy semantics; text/number/option clear on empty. */
  #setCustom(pid, k, v, out) {
    const mine = this.#liveMine(pid, V.P_CUSTOM_VALUE).filter((c) => c.value?.fieldId === k);
    const isBool = typeof v === 'boolean' || this.#schema?.field?.(k)?.type === 'boolean';
    const clearing = !isBool && (v === '' || v == null);
    if (clearing) { for (const c of mine) this.#remove(c.id, out); return; }
    const value = { fieldId: k, value: isBool ? String(v === true || v === 'true') : String(v) };
    const prior = mine[0];
    out.push(prior
      ? this.#engine.supersedeClaim(prior.id, pid, V.P_CUSTOM_VALUE, value)
      : this.#engine.assertClaim(pid, V.P_CUSTOM_VALUE, value));
  }

  /** Translate an editor patch on person `pid` into engine ops. */
  #applyPatch(pid, patch, out, cache) {
    if ('given' in patch || 'surname' in patch) this.#setName(pid, patch, out);
    for (const [key, type] of [['birth', 'birth'], ['death', 'death']]) {
      const placeKey = key + 'Place';
      if (!(key in patch) && !(placeKey in patch)) continue;
      const eid = this.#eventFor(pid, type, out, cache);
      if (key in patch) this.#setSingle(eid, V.P_DATE, patch[key] ? { edtf: String(patch[key]) } : null, out);
      if (placeKey in patch) this.#setEventPlace(eid, patch[placeKey], out);
    }
    if ('sex' in patch) this.#setSingle(pid, V.P_SEX, patch.sex ? { sex: patch.sex } : null, out);
    if ('note' in patch) this.#setSingle(pid, V.P_BIOGRAPHY, patch.note ? { text: patch.note } : null, out);
    if ('custom' in patch) for (const [k, v] of Object.entries(patch.custom)) this.#setCustom(pid, k, v, out);
  }

  // --- undo/redo: a commit's inverse is computed generically by diffing this replica's live record set
  // before vs. after (keyed by content-hash id, so a supersede is exactly "one id gone, one id added").
  // Undo/redo apply that inverse as fresh forward ops (never a rewind), so the log stays convergent with
  // peers. The stacks are in-memory + session-local (reset on hydrate), matching the legacy engine.

  /** This replica's live records, id -> record. */
  #snapshotMine() {
    const m = new Map();
    for (const r of this.#engine.liveRecords()) if (r.createdBy === this.#author) m.set(r.id, r);
    return m;
  }

  /** Remove a record, remembering the Remove op's id (returned by the engine) so an anchor removal can
   *  later be revoked — a claim revives by re-assertion (fresh content-hash id), but an anchor's id is
   *  fixed, so its removal must be undone by revoke, not a re-assert the tombstone still suppresses. */
  #remove(recordId, _out) {
    const opId = this.#engine.remove(recordId);
    if (opId) this.#removeOpId.set(recordId, opId);
  }

  /** A commit's inverse frame: which of my records it added (to remove on undo) and removed (to
   *  re-assert on undo). Empty frames (no net change to my set) are dropped. */
  #frame(before, after) {
    const added = [...after.keys()].filter((id) => !before.has(id));
    const removed = [...before.values()].filter((r) => !after.has(r.id));
    return added.length || removed.length ? { added, removed } : null;
  }

  /** Apply an inverse frame as forward ops: remove what the commit added, and bring back what it
   *  removed. A record that left via a plain Remove (its op id is tracked in `#removeOpId`) is brought
   *  back by revoking that Remove — id-preserving, so citations/attestations bound to it survive, and
   *  with no re-mint churn. Only a claim that left via a Supersede (an edit — no Remove to revoke) is
   *  re-asserted; its fresh HLC timestamp guarantees a new, non-colliding id. Anchors always leave via
   *  Remove, so they always revoke. */
  #applyFrame(frame, out) {
    for (const id of frame.added) this.#remove(id, out);
    for (const r of frame.removed) {
      const opId = this.#removeOpId.get(r.id);
      if (opId) out.push(this.#engine.revoke(opId));
      else out.push(this.#engine.assertClaim(r.targetId, r.predicate, r.value));
    }
  }

  /** Record a commit's inverse frame on the undo stack, coalescing a run of silent (per-keystroke)
   *  edits into one step: the first silent commit opens the group; the settling non-silent commit
   *  closes it without adding a second frame; a standalone edit is its own frame. */
  #record(frame, silent) {
    if (!frame) { if (!silent) this.#group = null; return; }
    if (silent) {
      if (!this.#group) { this.#group = frame; this.#undo.push(frame); this.#redo.length = 0; }
      // Subsequent silent commits in the same burst extend the open group's added/removed sets.
      else { this.#group.added.push(...frame.added); this.#group.removed.push(...frame.removed); }
    } else if (this.#group) {
      this.#group.added.push(...frame.added); this.#group.removed.push(...frame.removed);
      this.#group = null;
    } else {
      this.#undo.push(frame); this.#redo.length = 0;
    }
  }

  /** Apply the collected op batches: persist, emit to the sync controller, re-materialize, notify, and
   *  (when `before` is given) record the inverse frame for undo. */
  async #commit(_out, before = null, { silent = false } = {}) {
    // One settled intention = one op-batch: the engine accumulated this edit's ops as they were minted;
    // flush() encodes them as a single entry (empty if nothing minted). `_out` is vestigial (the mint
    // calls now return empty) — the engine is the source of truth.
    const batch = this.#engine.flush();
    const batches = batch && batch.length ? [batch] : [];
    if (batches.length) await profile('store.append', () => this.#store.append(this.#docId, batches));
    this.#cursor += batches.length;
    if (this.#deltaListeners.size) for (const d of batches) for (const fn of this.#deltaListeners) fn(d);
    this.#materialize();
    if (before) this.#record(this.#frame(before, this.#snapshotMine()), silent);
    if (!silent) this.#bump();
  }

  get canUndo() { return this.#undo.length > 0; }
  get canRedo() { return this.#redo.length > 0; }

  async undo() {
    if (!this.#undo.length) return;
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    this.#applyFrame(this.#undo.pop(), out);
    await this.#commitReplay(out, before, this.#redo);
  }

  async redo() {
    if (!this.#redo.length) return;
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    this.#applyFrame(this.#redo.pop(), out);
    await this.#commitReplay(out, before, this.#undo);
  }

  /** Commit an undo/redo's ops, pushing the resulting inverse frame onto `target` (the opposite stack). */
  async #commitReplay(_out, before, target) {
    const batch = this.#engine.flush();
    const batches = batch && batch.length ? [batch] : [];
    if (batches.length) await this.#store.append(this.#docId, batches);
    this.#cursor += batches.length;
    if (this.#deltaListeners.size) for (const d of batches) for (const fn of this.#deltaListeners) fn(d);
    this.#materialize();
    const frame = this.#frame(before, this.#snapshotMine());
    if (frame) target.push(frame);
    this.#group = null;
    this.#bump();
  }

  async createPerson(fields = {}) {
    const e = await this.#ensure();
    const before = this.#snapshotMine();
    const pid = uuid();
    const out = [], cache = new Map();
    out.push(e.assertAnchor(pid, V.TYPE_PERSON));
    this.#applyPatch(pid, { ...NEW_PERSON, ...fields }, out, cache);
    await this.#commit(out, before);
    return this.person(pid);
  }

  /** Overlay a display-only patch onto a projected person view (given/surname/sex/note/birth/death/
   *  custom) — what the UI shows mid-burst before the settling commit mints anything. */
  #applyOverlay(person, patch) {
    if (!patch || !person) return person;
    const p = {
      ...person,
      names: (person.names ?? []).map((n) => ({ ...n, parts: { ...n.parts } })),
      events: (person.events ?? []).map((e) => ({ ...e })),
      custom: { ...person.custom },
    };
    if (!p.names.length) p.names.push(makeName({}));
    if ('given' in patch) p.names[0].parts.given = splitGiven(patch.given);
    if ('surname' in patch) p.names[0].parts.family = String(patch.surname ?? '');
    if ('sex' in patch) p.sex = patch.sex || 'U';
    if ('note' in patch) p.note = patch.note ?? '';
    for (const [key, type] of [['birth', 'birth'], ['death', 'death']]) {
      const placeKey = key + 'Place';
      if (!(key in patch) && !(placeKey in patch)) continue;
      let ev = p.events.find((e) => e.type === type);
      if (!ev) { ev = { type, date: '', place: '' }; p.events.push(ev); }
      if (key in patch) ev.date = String(patch[key] ?? '');
      if (placeKey in patch) ev.place = String(patch[placeKey] ?? '');
    }
    if ('custom' in patch) Object.assign(p.custom, patch.custom);
    return definePersonViews(p);
  }

  async updatePerson(id, patch, opts = {}) {
    await this.#ensure();
    // Silent (per-keystroke) edit: accumulate into the overlay and refresh the view WITHOUT minting —
    // a permanent claim per keystroke would be garbage. One claim (a supersede) mints at settle.
    if (opts.silent) {
      const merged = { ...(this.#overlay.get(id) ?? {}), ...patch };
      this.#overlay.set(id, merged);
      if (this.people.has(id)) this.people.set(id, this.#applyOverlay(this.people.get(id), merged));
      return this.person(id);
    }
    const pending = this.#overlay.get(id);
    this.#overlay.delete(id);
    const before = this.#snapshotMine();
    const out = [], cache = new Map();
    this.#applyPatch(id, { ...(pending ?? {}), ...patch }, out, cache);
    await this.#commit(out, before);
    return this.person(id);
  }
  /** Mint a fresh person anchor and apply an initial patch, into `out`. Returns the new id. */
  #newPerson(fields, out, cache) {
    const pid = uuid();
    out.push(this.#engine.assertAnchor(pid, V.TYPE_PERSON));
    this.#applyPatch(pid, { ...NEW_PERSON, ...fields }, out, cache);
    return pid;
  }

  /** The union's marriage event anchor (participants = its parents, type "marriage"), minting if absent. */
  #marriageEventFor(fam, out) {
    const existing = this.#marriageEventOf.get(fam.id);
    if (existing) return existing;
    const eid = uuid();
    out.push(this.#engine.assertAnchor(eid, V.TYPE_EVENT));
    out.push(this.#engine.assertClaim(eid, V.P_EVENT_TYPE, { type: 'marriage' }));
    for (const parent of fam.spouses) {
      out.push(this.#engine.assertClaim(eid, V.P_PARTICIPANT, { personId: parent, role: 'spouse' }));
    }
    return eid;
  }

  async deletePerson(id) {
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    // Remove this replica's claims about the person and the anchor itself; relationships others hold
    // that reference this person drop out of the projection on their own (dangling endpoint).
    for (const c of this.#engine.liveClaimsOfAny(id)) {
      if (c.createdBy === this.#author) this.#remove(c.id, out);
    }
    this.#remove(id, out);
    // The person's own events (birth/death) go with them.
    for (const [key, eid] of this.#eventOf) {
      if (!key.startsWith(id + '|')) continue;
      for (const c of this.#engine.liveClaimsOfAny(eid)) {
        if (c.createdBy === this.#author) this.#remove(c.id, out);
      }
      this.#remove(eid, out);
    }
    await this.#commit(out, before);
  }

  async addMarriage(aId, bFieldsOrId, facts = {}) {
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [], cache = new Map();
    const bId = typeof bFieldsOrId === 'string' ? bFieldsOrId : this.#newPerson(bFieldsOrId, out, cache);
    const pair = [aId, bId].sort();
    out.push(this.#engine.assertClaim(aId, V.P_PARTNERSHIP, { pair, role: 'spouse' }));
    if ('marriage' in facts || 'place' in facts) {
      const eid = uuid();
      out.push(this.#engine.assertAnchor(eid, V.TYPE_EVENT));
      out.push(this.#engine.assertClaim(eid, V.P_EVENT_TYPE, { type: 'marriage' }));
      for (const p of pair) out.push(this.#engine.assertClaim(eid, V.P_PARTICIPANT, { personId: p, role: 'spouse' }));
      if ('marriage' in facts) this.#setSingle(eid, V.P_DATE, facts.marriage ? { edtf: String(facts.marriage) } : null, out);
      if ('place' in facts) this.#setEventPlace(eid, facts.place, out);
    }
    await this.#commit(out, before);
    return this.family('union:' + pair.map((p) => this.resolveId(p) ?? p).sort().join('+'));
  }

  async addChild(familyId, fieldsOrId) {
    await this.#ensure();
    const before = this.#snapshotMine();
    const fam = this.family(familyId);
    const parents = fam ? fam.spouses : [];
    const out = [], cache = new Map();
    const pid = typeof fieldsOrId === 'string' ? fieldsOrId : this.#newPerson(fieldsOrId, out, cache);
    for (const parent of parents) {
      out.push(this.#engine.assertClaim(pid, V.P_PARENT, { parentPersonId: parent, kind: 'biological' }));
    }
    await this.#commit(out, before);
    return this.person(pid);
  }

  async addParents(childId, father = null, mother = null) {
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [], cache = new Map();
    const parentIds = [];
    for (const [role, val] of [['M', father], ['F', mother]]) {
      if (!val) continue;
      const pid = typeof val === 'string' ? val : this.#newPerson({ sex: role, ...val }, out, cache);
      parentIds.push(pid);
      out.push(this.#engine.assertClaim(childId, V.P_PARENT, { parentPersonId: pid, kind: 'biological' }));
    }
    await this.#commit(out, before);
    const canonical = parentIds.map((p) => this.resolveId(p) ?? p).sort();
    return this.family('union:' + canonical.join('+'));
  }

  async removeMarriage(familyId) {
    const fam = this.family(familyId);
    if (!fam) return;
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    const parents = fam.spouses;
    for (const p of parents) {
      for (const c of this.#liveMine(p, V.P_PARTNERSHIP)) {
        const pair = c.value?.pair ?? [];
        if (parents.length === pair.length && parents.every((x) => pair.includes(x))) this.#remove(c.id, out);
      }
    }
    for (const childId of fam.children) {
      for (const c of this.#liveMine(childId, V.P_PARENT)) {
        if (parents.includes(c.value?.parentPersonId)) this.#remove(c.id, out);
      }
    }
    const eid = this.#marriageEventOf.get(familyId);
    if (eid) {
      for (const c of this.#engine.liveClaimsOfAny(eid)) if (c.createdBy === this.#author) this.#remove(c.id, out);
      this.#remove(eid, out);
    }
    await this.#commit(out, before);
  }

  async unlinkChild(familyId, personId) {
    const fam = this.family(familyId);
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    const parents = fam ? fam.spouses : [];
    for (const c of this.#liveMine(personId, V.P_PARENT)) {
      if (parents.includes(c.value?.parentPersonId)) this.#remove(c.id, out);
    }
    await this.#commit(out, before);
  }

  async unlinkSpouse(familyId, personId) {
    const fam = this.family(familyId);
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    for (const c of this.#liveMine(personId, V.P_PARTNERSHIP)) {
      if ((c.value?.pair ?? []).includes(personId)) this.#remove(c.id, out);
    }
    for (const childId of fam?.children ?? []) {
      for (const c of this.#liveMine(childId, V.P_PARENT)) {
        if (c.value?.parentPersonId === personId) this.#remove(c.id, out);
      }
    }
    await this.#commit(out, before);
  }

  async linkSpouse(familyId, personId) {
    const fam = this.family(familyId);
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    const other = (fam?.spouses ?? [])[0];
    if (other) {
      const pair = [other, personId].sort();
      out.push(this.#engine.assertClaim(other, V.P_PARTNERSHIP, { pair, role: 'spouse' }));
      // Keep the union addressable by the same children: link the new spouse to its children too.
      for (const childId of fam.children) {
        out.push(this.#engine.assertClaim(childId, V.P_PARENT, { parentPersonId: personId, kind: 'biological' }));
      }
    }
    await this.#commit(out, before);
  }

  async setFamilyFacts(familyId, facts) {
    const fam = this.family(familyId);
    if (!fam) return;
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    const eid = this.#marriageEventFor(fam, out);
    if ('marriage' in facts) this.#setSingle(eid, V.P_DATE, facts.marriage ? { edtf: String(facts.marriage) } : null, out);
    if ('place' in facts) this.#setEventPlace(eid, facts.place, out);
    await this.#commit(out, before);
  }

  async attachMedia(subjectId, { hash, mime, w, h: hh, caption = '', role = 'portrait', crop = null }) {
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    const value = { mediaHash: hash, mime, role };
    if (w) value.width = Number(w);
    if (hh) value.height = Number(hh);
    if (caption) value.caption = caption;
    if (crop) value.crop = crop;
    out.push(this.#engine.assertClaim(subjectId, V.P_MEDIA_LINK, value));
    await this.#commit(out, before);
    const link = this.#liveMine(subjectId, V.P_MEDIA_LINK).find((c) => c.value?.mediaHash === hash);
    return { mediaId: hash, linkId: link?.id };
  }

  async setPortrait(subjectId, linkId) {
    await this.#ensure();
    const before = this.#snapshotMine();
    const out = [];
    for (const c of this.#liveMine(subjectId, V.P_MEDIA_LINK)) {
      const role = c.value?.role;
      if (c.id === linkId && role !== 'portrait') {
        out.push(this.#engine.supersedeClaim(c.id, subjectId, V.P_MEDIA_LINK, { ...c.value, role: 'portrait' }));
      } else if (c.id !== linkId && role === 'portrait') {
        out.push(this.#engine.supersedeClaim(c.id, subjectId, V.P_MEDIA_LINK, { ...c.value, role: 'document' }));
      }
    }
    await this.#commit(out, before);
  }

  async detachMedia(linkId) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    await this.#ensure();
    if (!this.#liveMine(link.subjectId, V.P_MEDIA_LINK).some((c) => c.id === linkId)) return;
    const before = this.#snapshotMine();
    const out = [];
    this.#remove(linkId, out);
    await this.#commit(out, before);
  }

  async setCrop(linkId, crop) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    await this.#ensure();
    const mine = this.#liveMine(link.subjectId, V.P_MEDIA_LINK).find((c) => c.id === linkId);
    if (mine) await this.#commit([this.#engine.supersedeClaim(linkId, link.subjectId, V.P_MEDIA_LINK, { ...mine.value, crop })]);
  }
  // ------------------------------------------------------------------ seed / compact / reset
  /** Translate legacy v2 seed ops (upsertPerson / upsertFamily, from seed.js) into claim/anchor ops.
   *  The symbolic seed id (e.g. "p_jsb") is used directly as the anchor id, so cross-references resolve
   *  and `seedAppId` is the identity. Not undoable (seeding clears the stacks). Fact-less person-general
   *  sources are skipped (they need a host claim — OPE-216). */
  async seed(ops) {
    await this.#ensure();
    const out = [], cache = new Map();
    for (const o of ops) {
      if (o.type === 'upsertPerson') {
        out.push(this.#engine.assertAnchor(o.id, V.TYPE_PERSON));
        this.#applyPatch(o.id, { ...NEW_PERSON, ...o.fields }, out, cache);
      } else if (o.type === 'upsertFamily') {
        const spouses = o.fields.spouses ?? [];
        const children = o.fields.children ?? [];
        if (spouses.length >= 2) {
          const pair = [spouses[0], spouses[1]].sort();
          out.push(this.#engine.assertClaim(spouses[0], V.P_PARTNERSHIP, { pair, role: 'spouse' }));
        }
        for (const c of children) {
          for (const s of spouses) {
            out.push(this.#engine.assertClaim(c, V.P_PARENT, { parentPersonId: s, kind: 'biological' }));
          }
        }
        const facts = o.fields.facts ?? {};
        if (facts.marriage || facts.place) {
          const eid = uuid();
          out.push(this.#engine.assertAnchor(eid, V.TYPE_EVENT));
          out.push(this.#engine.assertClaim(eid, V.P_EVENT_TYPE, { type: 'marriage' }));
          for (const s of spouses) out.push(this.#engine.assertClaim(eid, V.P_PARTICIPANT, { personId: s, role: 'spouse' }));
          if (facts.marriage) out.push(this.#engine.assertClaim(eid, V.P_DATE, { edtf: String(facts.marriage) }));
          if (facts.place) this.#setEventPlace(eid, facts.place, out);
        }
      }
    }
    await this.#commit(out); // no `before` → not undoable
    this.#undo.length = 0; this.#redo.length = 0; this.#group = null; this.#overlay.clear();
  }

  /** Fold the whole live set into one snapshot covering log entries 0..#cursor, so the next load
   *  restores it and replays only the tail. */
  async compact() {
    await this.#ensure();
    const prev = await this.#store.readSnapshot(this.#docId);
    const payload = this.#wrapSnapshot(this.#engine.snapshot(), this.#cursor);
    try {
      await this.#store.putSnapshot(this.#docId, payload, prev?.version ?? null);
    } catch (err) {
      if (err?.name !== 'ConflictError') throw err;
    }
  }

  async reset() {
    await this.#store.delete(this.#docId);
    this.#engine = await createTree({ createdBy: this.#author });
    this.#cursor = 0;
    this.#undo.length = 0; this.#redo.length = 0; this.#group = null; this.#overlay.clear();
    this.#materialize();
    this.#bump();
  }
}

/** The app-facing id a seeded entity gets — for the claim engine the anchor id IS the symbolic seed
 *  string, so this is the identity (unlike the treelog engine, which hex-encoded the byte id). */
export const seedAppId = (symbolic) => symbolic;
