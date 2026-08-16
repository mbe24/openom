// The opened family tree, backed by the treelog CRDT engine (packages/openom-treelog, wasm). Same
// public surface as the legacy JS-op FamilyTree, so the views and read helpers are unchanged — the
// difference is entirely underneath: state lives in a commute `Doc`, every edit is a self-contained,
// convergent op, and multi-device merge is real.
//
// Representation: a person owns name- and event-sub-entities (each an opaque id with leaf facts), plus
// simple person facts (sex, note, portrait) and per-field `custom.*` claims. Families own spouse and
// child OR-sets and marriage facts. Ids are hex strings app-facing (opaque), bytes in the engine.
// Persistence: each edit appends its treelog delta bytes to the DocStore (opaque to the store); hydrate
// merges them back. The engine owns the Lamport clock and tombstones, so there is no manual meta here.
//
// Undo/redo is FORWARD-only: an action records the compensating ops that reverse it, and undo applies
// them as new, freshly-stamped ops appended to the log — never a Lamport rewind or a log truncation, so
// it stays convergent when other replicas (e.g. another tab) share the same log.
import { createTree } from './treelog/index.js';
import { compareSiblings } from './sort.js';
import { profile } from './profile.js';
import {
  makeName, makeEvent, definePersonViews, mergeFamilyFields, defineFamilyViews,
} from './model.js';

const NEW_PERSON = { given: '', surname: '', sex: 'U', custom: {} };
const COMPACT_AT = 200; // replayed-tail length past which hydrate folds the log into a fresh snapshot
const SNAP_TAG = 0xcc; // marks a snapshot payload that carries a coverage-cursor header
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

// A stable per-device replica id, persisted so re-edits across reloads/tabs reuse the same claim id
// (update-in-place, not pile-up) and the version vector doesn't grow one entry per session. Falls back
// to a fresh id where no storage exists (e.g. a headless test) — correctness holds either way because
// a set/clear reconciles against whatever claims are currently live, not just this replica's.
const REPLICA_KEY = 'openom.replica.v1';
function loadReplica() {
  try {
    const s = globalThis.localStorage?.getItem(REPLICA_KEY);
    if (s && /^[0-9a-f]{32}$/.test(s)) return bytes(s);
  } catch { /* no storage — fall through */ }
  const r = crypto.getRandomValues(new Uint8Array(16));
  try { globalThis.localStorage?.setItem(REPLICA_KEY, hex(r)); } catch { /* ignore */ }
  return r;
}

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
  #deltaListeners = new Set(); // notified of each locally-produced delta (for the sync controller)
  #cursor = 0; // store log entries folded into the engine
  #undo = []; // stacks of inverse-descriptor batches
  #redo = [];
  #group = null; // the open silent-edit burst's frame (coalesces per-keystroke edits into one undo step)
  #schema; // optional SchemaRegistry — lets custom fields read back as their declared type

  constructor(store, docId, schema = null) {
    this.#store = store;
    this.#docId = docId;
    this.#schema = schema;
    this.#replica = loadReplica();
    this.#ready = createTree({ replica: this.#replica });
  }

  /** Coerce a stored custom-field string back to its declared type (bool/number), else leave a string. */
  #coerceCustom(id, raw) {
    const type = this.#schema?.field?.(id)?.type;
    if (type === 'boolean') return raw === 'true';
    if (type === 'number') return raw === '' ? '' : Number(raw);
    return raw;
  }

  async #ensure() {
    if (!this.#engine) this.#engine = await this.#ready;
    return this.#engine;
  }

  onRevision(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  /** Subscribe to each locally-produced delta (raw treelog bytes) — the sync controller seals + pushes
   *  them. Remote deltas merged via mergeRemote are NOT emitted (they must not be pushed back). */
  onDelta(fn) {
    this.#deltaListeners.add(fn);
    return () => this.#deltaListeners.delete(fn);
  }

  #bump() {
    this.revision += 1;
    for (const fn of this.#listeners) fn(this.revision);
  }

  #emit(deltas) {
    if (!this.#deltaListeners.size) return;
    for (const d of deltas) for (const fn of this.#deltaListeners) fn(d);
  }

  /** The full engine state as raw commute bytes — the sync controller seals it as the bootstrap
   *  baseline a fresh device restores from. */
  snapshotBytes() {
    return this.#engine.snapshot();
  }

  /** Integrate a peer's delta (raw treelog bytes the controller already unsealed): fold it into the
   *  engine, persist it locally for durability, and refresh the views. Does not re-emit (not local). */
  async mergeRemote(bytes) {
    await this.#ensure();
    const bin = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.#engine.mergeBytes(bin);
    await this.#store.append(this.#docId, [bin]);
    this.#cursor += 1;
    this.#materialize();
    this.#bump();
  }

  // ------------------------------------------------------------------ engine read helpers
  #val(subjectHex, field) {
    const f = this.#engine.fact(bytes(subjectHex), field);
    return f.preferred ? f.preferred.value : '';
  }

  /** Parse a crop claim defensively — a malformed value (or a forward-version sentinel string) must
   *  never throw and brick the whole read model. */
  #parseCrop(raw) {
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
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
      if (!f.startsWith('custom.')) continue;
      const id = f.slice('custom.'.length);
      custom[id] = this.#coerceCustom(id, this.#val(pidHex, f));
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
    // Filter out members whose person no longer exists (a dangling link left by a concurrent
    // delete-vs-link on another replica). people is materialized before families, so this is the one
    // place that keeps every consumer — raw counts + the query/graph layer included — free of ghosts.
    const spouses = e.spouses(b).filter((s) => this.people.has(s));
    const childLinks = e.children(b).filter((c) => this.people.has(c.person)).map((c) => ({ id: c.person, pedi: c.pedi }));
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
          crop: this.#parseCrop(this.#val(link, 'crop')),
        });
      }
    }
  }

  /** Rebuild the whole view-facing model from the engine (after a settled edit / load / undo). */
  #materialize() {
    profile('materialize', () => {
      const e = this.#engine;
      this.people = new Map(e.persons().map((pid) => [pid, this.#buildPerson(pid)]));
      this.families = new Map(e.families().map((fid) => [fid, this.#buildFamily(fid)]));
      this.#buildMedia();
    });
  }

  /** Refresh just one person in place — cheap enough to run on every silent keystroke. */
  #refreshPerson(id) {
    if (this.#engine.hasPerson(bytes(id))) this.people.set(id, this.#buildPerson(id));
    else this.people.delete(id);
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

  // ------------------------------------------------------------------ op primitives
  // Each applies through the shim AND records the inverse descriptor(s) into `inv` (a plain array of
  // [op, ...hexArgs]). `inv` is optional (seeding passes none). All ids in descriptors are hex.
  #opAddPerson(pid, out, inv) { out.push(this.#engine.addPerson(pid)); inv?.push(['removePerson', hex(pid)]); }
  #opRemovePerson(pid, out, inv) { out.push(this.#engine.removePerson(pid)); inv?.push(['addPerson', hex(pid)]); }
  #opAddFamily(fid, out, inv) { out.push(this.#engine.addFamily(fid)); inv?.push(['removeFamily', hex(fid)]); }
  #opRemoveFamily(fid, out, inv) { out.push(this.#engine.removeFamily(fid)); inv?.push(['addFamily', hex(fid)]); }
  #opLinkChild(fid, pid, pedi, out, inv) { out.push(this.#engine.linkChild(fid, pid, pedi)); inv?.push(['unlinkChild', hex(fid), hex(pid)]); }
  #opUnlinkChild(fid, pid, out, inv) {
    const cur = this.#engine.children(fid).find((k) => k.person === hex(pid));
    out.push(this.#engine.unlinkChild(fid, pid));
    inv?.push(['linkChild', hex(fid), hex(pid), cur ? cur.pedi : 'birth']);
  }
  #opLinkSpouse(fid, pid, out, inv) { out.push(this.#engine.linkSpouse(fid, pid)); inv?.push(['unlinkSpouse', hex(fid), hex(pid)]); }
  #opUnlinkSpouse(fid, pid, out, inv) { out.push(this.#engine.unlinkSpouse(fid, pid)); inv?.push(['linkSpouse', hex(fid), hex(pid)]); }
  #opAddName(pid, nid, out, inv) { out.push(this.#engine.addName(pid, nid)); inv?.push(['removeName', hex(pid), hex(nid)]); }
  #opRemoveName(pid, nid, out, inv) { out.push(this.#engine.removeName(pid, nid)); inv?.push(['addName', hex(pid), hex(nid)]); }
  #opSetPrimaryName(pid, nid, out, inv) {
    const prior = this.#engine.primaryName(pid); // hex | null
    out.push(this.#engine.setPrimaryName(pid, nid));
    inv?.push(['setPrimaryName', hex(pid), prior ?? hex(nid)]);
  }
  #opAddEvent(pid, eid, out, inv) { out.push(this.#engine.addEvent(pid, eid)); inv?.push(['removeEvent', hex(pid), hex(eid)]); }
  #opRemoveEvent(pid, eid, out, inv) { out.push(this.#engine.removeEvent(pid, eid)); inv?.push(['addEvent', hex(pid), hex(eid)]); }
  #opAddMediaRecord(mid, out, inv) { out.push(this.#engine.addMediaRecord(mid)); inv?.push(['removeMediaRecord', hex(mid)]); }
  #opRemoveMediaRecord(mid, out, inv) { out.push(this.#engine.removeMediaRecord(mid)); inv?.push(['addMediaRecord', hex(mid)]); }
  #opAddMediaLink(subj, link, media, out, inv) { out.push(this.#engine.addMediaLink(subj, link, media)); inv?.push(['removeMediaLink', hex(subj), hex(link)]); }
  #opRemoveMediaLink(subj, link, out, inv) {
    const cur = this.#engine.media(subj).find((m) => m.link === hex(link));
    out.push(this.#engine.removeMediaLink(subj, link));
    inv?.push(['addMediaLink', hex(subj), hex(link), cur ? cur.media : hex(link)]);
  }
  #opAddSource(sid, out, inv) { out.push(this.#engine.addSource(sid)); inv?.push(['removeSource', hex(sid)]); }
  #opCite(subj, field, sid, claim, out, inv) { out.push(this.#engine.cite(subj, field, sid, claim)); inv?.push(['uncite', hex(subj), field, hex(sid)]); }

  /**
   * Reconcile a fact's claim set to `targetClaims` with `targetPref` preferred (replace semantics), and
   * record the inverse = restore the fact to its current state. This is the one primitive behind every
   * single-value field set/clear. Retracts only currently-live claims, so a concurrent edit on another
   * replica (whose claim this replica hasn't merged) survives — the competing-claims guarantee.
   */
  #opRestoreFact(subject, field, targetClaims, targetPref, out, inv) {
    const cur = this.#engine.fact(subject, field);
    inv?.push(['restoreFact', hex(subject), field,
      cur.claims.map((c) => ({ id: c.id, value: c.value, source: c.source ?? null })),
      cur.preferred ? cur.preferred.id : null]);
    for (const c of cur.claims) out.push(this.#engine.retractClaim(subject, field, bytes(c.id)));
    for (const c of targetClaims) out.push(this.#engine.addClaim(subject, field, bytes(c.id), c.value, c.source ?? null));
    if (targetPref != null) out.push(this.#engine.setPreferredClaim(subject, field, bytes(targetPref)));
  }

  /** Apply one inverse/redo descriptor, recording its own inverse into `inv`. */
  #applyDesc(d, out, inv) {
    const [op, ...a] = d;
    switch (op) {
      case 'addPerson': return this.#opAddPerson(bytes(a[0]), out, inv);
      case 'removePerson': return this.#opRemovePerson(bytes(a[0]), out, inv);
      case 'addFamily': return this.#opAddFamily(bytes(a[0]), out, inv);
      case 'removeFamily': return this.#opRemoveFamily(bytes(a[0]), out, inv);
      case 'linkChild': return this.#opLinkChild(bytes(a[0]), bytes(a[1]), a[2], out, inv);
      case 'unlinkChild': return this.#opUnlinkChild(bytes(a[0]), bytes(a[1]), out, inv);
      case 'linkSpouse': return this.#opLinkSpouse(bytes(a[0]), bytes(a[1]), out, inv);
      case 'unlinkSpouse': return this.#opUnlinkSpouse(bytes(a[0]), bytes(a[1]), out, inv);
      case 'addName': return this.#opAddName(bytes(a[0]), bytes(a[1]), out, inv);
      case 'removeName': return this.#opRemoveName(bytes(a[0]), bytes(a[1]), out, inv);
      case 'setPrimaryName': return this.#opSetPrimaryName(bytes(a[0]), bytes(a[1]), out, inv);
      case 'addEvent': return this.#opAddEvent(bytes(a[0]), bytes(a[1]), out, inv);
      case 'removeEvent': return this.#opRemoveEvent(bytes(a[0]), bytes(a[1]), out, inv);
      case 'addMediaRecord': return this.#opAddMediaRecord(bytes(a[0]), out, inv);
      case 'removeMediaRecord': return this.#opRemoveMediaRecord(bytes(a[0]), out, inv);
      case 'addMediaLink': return this.#opAddMediaLink(bytes(a[0]), bytes(a[1]), bytes(a[2]), out, inv);
      case 'removeMediaLink': return this.#opRemoveMediaLink(bytes(a[0]), bytes(a[1]), out, inv);
      case 'restoreFact': return this.#opRestoreFact(bytes(a[0]), a[1], a[2], a[3], out, inv);
      default: return;
    }
  }

  // ------------------------------------------------------------------ writing
  /**
   * Apply `deltas` (each Uint8Array) as one atomic store append, refresh the view model, and record the
   * action's inverse for undo. `touched` lets a silent (per-keystroke) commit refresh only the edited
   * people instead of the whole tree.
   */
  async #commit(deltas, { silent = false, undoable = true, inverse = null, touched = null } = {}) {
    if (deltas.length) await profile('store.append', () => this.#store.append(this.#docId, deltas));
    this.#cursor += deltas.length;
    this.#emit(deltas);
    if (silent && touched) for (const id of touched) this.#refreshPerson(id);
    else this.#materialize();
    if (undoable) this.#record(inverse, silent);
    if (!silent) this.#bump();
  }

  /**
   * Record an undo frame. A run of silent (per-keystroke) writes coalesces into ONE frame whose inverse
   * is the pre-run state; the settling non-silent write closes the run without adding a second frame. A
   * standalone non-silent action is its own frame.
   */
  #record(inverse, silent) {
    if (!inverse || !inverse.length) { if (!silent) this.#group = null; return; }
    if (silent) {
      if (!this.#group) { this.#group = inverse; this.#undo.push(inverse); this.#redo.length = 0; }
    } else if (this.#group) {
      this.#group = null; // settling of a typing burst — frame already pushed
    } else {
      this.#undo.push(inverse); this.#redo.length = 0;
    }
  }

  /** Apply a recorded batch as a new forward action (reverse order), pushing its inverse to `target`. */
  async #applyBatch(batch, target) {
    await this.#ensure();
    const out = [], inv = [];
    for (const d of [...batch].reverse()) this.#applyDesc(d, out, inv);
    if (out.length) await this.#store.append(this.#docId, out);
    this.#cursor += out.length;
    this.#emit(out);
    this.#materialize();
    target.push(inv.reverse());
    this.#group = null;
    this.#bump();
  }

  /**
   * Set (or clear) a single-value leaf field with replace semantics, via the restore-fact primitive.
   * Clearing retracts every live claim (so a value written in a prior session or by another replica
   * really goes away); a set reconciles to this replica's single claim.
   */
  #setLeaf(subject, field, value, out, inv) {
    const clearing = value === '' || value == null;
    const myHex = hex(this.#replica);
    const target = clearing ? [] : [{ id: myHex, value: String(value), source: null }];
    this.#opRestoreFact(subject, field, target, clearing ? null : myHex, out, inv);
  }

  /** The subject's primary name-entity id (bytes), minting one if absent (recording ops in out/inv). */
  #primaryName(pid, out, inv) {
    const existing = this.#engine.primaryName(pid);
    if (existing) return bytes(existing);
    const nid = this.#engine.newId();
    this.#opAddName(pid, nid, out, inv);
    this.#opSetPrimaryName(pid, nid, out, inv);
    return nid;
  }

  /** The subject's event-entity of `type` (bytes), minting one if absent. */
  #eventOfType(pid, type, out, inv) {
    for (const eid of this.#engine.events(pid)) {
      if (this.#val(eid, 'type') === type) return bytes(eid);
    }
    const eid = this.#engine.newId();
    this.#opAddEvent(pid, eid, out, inv);
    this.#setLeaf(eid, 'type', type, out, inv);
    return eid;
  }

  /** Translate an editor patch on person `pid` (bytes) into engine deltas + inverse. */
  #applyPatch(pid, patch, out, inv) {
    if ('given' in patch || 'surname' in patch) {
      const nid = this.#primaryName(pid, out, inv);
      if ('given' in patch) this.#setLeaf(nid, 'given', patch.given, out, inv);
      if ('surname' in patch) this.#setLeaf(nid, 'family', patch.surname, out, inv);
    }
    for (const [key, type] of [['birth', 'birth'], ['death', 'death']]) {
      const placeKey = key + 'Place';
      if (!(key in patch) && !(placeKey in patch)) continue;
      const eid = this.#eventOfType(pid, type, out, inv);
      if (key in patch) this.#setLeaf(eid, 'date', patch[key], out, inv);
      if (placeKey in patch) this.#setLeaf(eid, 'place', patch[placeKey], out, inv);
    }
    if ('sex' in patch) this.#setLeaf(pid, 'sex', patch.sex, out, inv);
    if ('note' in patch) this.#setLeaf(pid, 'note', patch.note, out, inv);
    if ('portraitId' in patch) this.#setLeaf(pid, 'portrait', patch.portraitId, out, inv);
    if ('custom' in patch) {
      for (const [k, v] of Object.entries(patch.custom)) {
        const isBool = typeof v === 'boolean' || this.#schema?.field?.(k)?.type === 'boolean';
        // A boolean is stored as an explicit 'true'/'false' claim (never cleared), so unchecking is a
        // last-writer-wins write via the preferred pointer rather than a retract that goes sticky under
        // concurrency. Text/option/number clear on empty (empty = not set).
        const s = isBool ? String(v === true || v === 'true') : (v === '' || v == null ? '' : String(v));
        this.#setLeaf(pid, 'custom.' + k, s, out, inv);
      }
    }
  }

  #setFamilyFacts(fid, facts, out, inv) {
    if ('marriage' in facts) this.#setLeaf(fid, 'marriage.date', facts.marriage, out, inv);
    if ('place' in facts) this.#setLeaf(fid, 'marriage.place', facts.place, out, inv);
  }

  async createPerson(fields = {}) {
    const e = await this.#ensure();
    const pid = e.newId();
    const out = [], inv = [];
    this.#opAddPerson(pid, out, inv);
    this.#applyPatch(pid, { ...NEW_PERSON, ...fields }, out, inv);
    await this.#commit(out, { inverse: inv });
    return this.person(hex(pid));
  }

  async updatePerson(id, patch, opts = {}) {
    await this.#ensure();
    const out = [], inv = [];
    this.#applyPatch(bytes(id), patch, out, inv);
    await this.#commit(out, { ...opts, inverse: inv, touched: [id] });
    return this.person(id);
  }

  async deletePerson(id) {
    await this.#ensure();
    const pid = bytes(id);
    const out = [], inv = [];
    this.#opRemovePerson(pid, out, inv);
    // Self-contained ops don't cascade — unlink the person from every family explicitly.
    for (const f of this.families.values()) {
      if (f.spouses.includes(id)) this.#opUnlinkSpouse(bytes(f.id), pid, out, inv);
      if (f.children.includes(id)) this.#opUnlinkChild(bytes(f.id), pid, out, inv);
    }
    await this.#commit(out, { inverse: inv });
  }

  async addMarriage(aId, bFieldsOrId, facts = {}) {
    const e = await this.#ensure();
    const out = [], inv = [];
    let bId;
    if (typeof bFieldsOrId === 'string') {
      bId = bFieldsOrId;
    } else {
      const nb = e.newId();
      this.#opAddPerson(nb, out, inv);
      this.#applyPatch(nb, { ...NEW_PERSON, ...bFieldsOrId }, out, inv);
      bId = hex(nb);
    }
    const fid = e.newId();
    this.#opAddFamily(fid, out, inv);
    this.#opLinkSpouse(fid, bytes(aId), out, inv);
    this.#opLinkSpouse(fid, bytes(bId), out, inv);
    this.#setFamilyFacts(fid, facts, out, inv);
    await this.#commit(out, { inverse: inv });
    return this.family(hex(fid));
  }

  async addChild(familyId, fieldsOrId) {
    const e = await this.#ensure();
    const out = [], inv = [];
    let pid;
    if (typeof fieldsOrId === 'string') {
      pid = bytes(fieldsOrId);
    } else {
      pid = e.newId();
      this.#opAddPerson(pid, out, inv);
      this.#applyPatch(pid, { ...NEW_PERSON, ...fieldsOrId }, out, inv);
    }
    this.#opLinkChild(bytes(familyId), pid, 'birth', out, inv);
    await this.#commit(out, { inverse: inv });
    return this.person(hex(pid));
  }

  async addParents(childId, father = null, mother = null) {
    const e = await this.#ensure();
    const existing = this.childFamilyOf(childId);
    const out = [], inv = [];
    const fid = existing ? bytes(existing.id) : e.newId();
    if (!existing) {
      this.#opAddFamily(fid, out, inv);
      this.#opLinkChild(fid, bytes(childId), 'birth', out, inv);
    }
    for (const [role, val] of [['M', father], ['F', mother]]) {
      if (!val) continue;
      let pid;
      if (typeof val === 'string') {
        pid = bytes(val);
      } else {
        pid = e.newId();
        this.#opAddPerson(pid, out, inv);
        // NEW_PERSON first so `sex: role` isn't clobbered by its default 'U'.
        this.#applyPatch(pid, { ...NEW_PERSON, sex: role, ...val }, out, inv);
      }
      this.#opLinkSpouse(fid, pid, out, inv);
    }
    await this.#commit(out, { inverse: inv });
    return this.family(hex(fid));
  }

  async removeMarriage(familyId) {
    if (!this.families.has(familyId)) return;
    await this.#ensure();
    const out = [], inv = [];
    this.#opRemoveFamily(bytes(familyId), out, inv);
    await this.#commit(out, { inverse: inv });
  }

  async unlinkChild(familyId, personId) {
    await this.#ensure();
    const out = [], inv = [];
    this.#opUnlinkChild(bytes(familyId), bytes(personId), out, inv);
    await this.#commit(out, { inverse: inv });
  }

  async unlinkSpouse(familyId, personId) {
    await this.#ensure();
    const out = [], inv = [];
    this.#opUnlinkSpouse(bytes(familyId), bytes(personId), out, inv);
    await this.#commit(out, { inverse: inv });
  }

  async linkSpouse(familyId, personId) {
    await this.#ensure();
    const out = [], inv = [];
    this.#opLinkSpouse(bytes(familyId), bytes(personId), out, inv);
    await this.#commit(out, { inverse: inv });
  }

  async setFamilyFacts(familyId, facts) {
    await this.#ensure();
    const out = [], inv = [];
    this.#setFamilyFacts(bytes(familyId), facts, out, inv);
    await this.#commit(out, { inverse: inv });
  }

  // ------------------------------------------------------------------ media
  async attachMedia(subjectId, { hash: h, mime, w, h: hh, caption = '', source = '', role = 'portrait', crop = null }) {
    const e = await this.#ensure();
    const rec = e.newId();
    const link = e.newId();
    const out = [], inv = [];
    this.#opAddMediaRecord(rec, out, inv);
    this.#setLeaf(rec, 'mime', mime, out, inv);
    this.#setLeaf(rec, 'hash', h, out, inv);
    if (w) this.#setLeaf(rec, 'w', w, out, inv);
    if (hh) this.#setLeaf(rec, 'h', hh, out, inv);
    this.#opAddMediaLink(bytes(subjectId), link, rec, out, inv);
    this.#setLeaf(link, 'role', role, out, inv);
    if (caption) this.#setLeaf(link, 'caption', caption, out, inv);
    if (crop) this.#setLeaf(link, 'crop', JSON.stringify(crop), out, inv);
    if (role === 'portrait') this.#setLeaf(bytes(subjectId), 'portrait', hex(link), out, inv);
    await this.#commit(out, { inverse: inv });
    return { mediaId: hex(rec), linkId: hex(link) };
  }

  async setPortrait(subjectId, linkId) {
    await this.#ensure();
    const out = [], inv = [];
    this.#setLeaf(bytes(subjectId), 'portrait', linkId, out, inv);
    await this.#commit(out, { inverse: inv });
  }

  async detachMedia(linkId) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    await this.#ensure();
    const out = [], inv = [];
    this.#opRemoveMediaLink(bytes(link.subjectId), bytes(linkId), out, inv);
    // Drop the portrait pointer too if this link was it.
    if (this.people.get(link.subjectId)?.portraitId === linkId) this.#setLeaf(bytes(link.subjectId), 'portrait', '', out, inv);
    await this.#commit(out, { inverse: inv });
  }

  async setCrop(linkId, crop) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    await this.#ensure();
    const out = [], inv = [];
    this.#setLeaf(bytes(linkId), 'crop', JSON.stringify(crop), out, inv);
    await this.#commit(out, { inverse: inv });
  }

  // ------------------------------------------------------------------ undo / redo
  get canUndo() { return this.#undo.length > 0; }
  get canRedo() { return this.#redo.length > 0; }
  async undo() { if (this.#undo.length) await this.#applyBatch(this.#undo.pop(), this.#redo); }
  async redo() { if (this.#redo.length) await this.#applyBatch(this.#redo.pop(), this.#undo); }

  // ------------------------------------------------------------------ loading
  // A snapshot payload = [SNAP_TAG][u32 BE coverage cursor][commute snapshot bytes]. The coverage
  // cursor rides in the payload so no DocStore layer has to carry it — they stay opaque-byte stores.
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
      const raw = snap.bytes instanceof Uint8Array ? snap.bytes : new Uint8Array(snap.bytes);
      const { snapshot, cursor } = this.#unwrapSnapshot(raw);
      // Restore the folded state, then replay only the log tail after what the snapshot covers.
      this.#engine = await createTree({ replica: this.#replica, snapshot });
      this.#cursor = cursor;
    }
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, this.#cursor);
    profile('hydrate.replay', () => {
      for (const u of updates) {
        const bin = u instanceof Uint8Array ? u : new Uint8Array(u);
        this.#engine.mergeBytes(bin);
      }
    });
    this.#cursor = cursor ?? this.#cursor + updates.length;
    this.#materialize();
    this.#undo.length = 0; this.#redo.length = 0; this.#group = null;
    this.#bump();
    // Bound reload cost: once the replayed tail is long, fold it into a fresh snapshot so future loads
    // skip it (mirrors the legacy engine's COMPACT_AT, lost in the treelog rewrite).
    if (updates.length > COMPACT_AT) await this.compact().catch(() => {});
  }

  async seed(ops) {
    const e = await this.#ensure();
    // `ops` are legacy v2 upsert ops (from seed.js). Translate into engine deltas with a stable
    // string-id → engine-id map so cross-references resolve. Seeding is not undoable (no inverse).
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
        this.#opAddPerson(pid, out, null);
        this.#applyPatch(pid, { ...NEW_PERSON, ...o.fields }, out, null);
        (o.fields.sources ?? []).forEach((s) => {
          const sid = e.newId();
          this.#opAddSource(sid, out, null);
          this.#setLeaf(sid, 'title', s.title ?? '', out, null);
          this.#setLeaf(sid, 'detail', s.detail ?? '', out, null);
          this.#setLeaf(sid, 'supports', s.supports ?? '', out, null);
          this.#opCite(pid, '', sid, null, out, null);
        });
      } else if (o.type === 'upsertFamily') {
        const fid = idFor(o.id);
        this.#opAddFamily(fid, out, null);
        for (const s of o.fields.spouses ?? []) this.#opLinkSpouse(fid, idFor(s), out, null);
        for (const c of o.fields.children ?? []) this.#opLinkChild(fid, idFor(c), 'birth', out, null);
        this.#setFamilyFacts(fid, o.fields.facts ?? {}, out, null);
      }
    }
    await this.#commit(out, { undoable: false });
    this.#undo.length = 0; this.#redo.length = 0; this.#group = null;
  }

  async reset() {
    await this.#store.delete(this.#docId);
    this.#engine = await createTree({ replica: this.#replica });
    this.#cursor = 0;
    this.#materialize();
    this.#undo.length = 0; this.#redo.length = 0; this.#group = null;
    this.#bump();
  }

  async compact() {
    const e = await this.#ensure();
    const prev = await this.#store.readSnapshot(this.#docId);
    // Fold the whole log into one snapshot that COVERS log entries 0..#cursor; the next load restores
    // it and replays only the tail after #cursor instead of the entire history.
    const payload = this.#wrapSnapshot(e.snapshot(), this.#cursor);
    try {
      await this.#store.putSnapshot(this.#docId, payload, prev?.version ?? null);
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
