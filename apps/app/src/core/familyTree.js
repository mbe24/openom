import { encodeUpdate, decodeUpdate, KNOWN_OPS, DOC_VERSION, FutureVersionError } from './ops.js';
import { deviceId, loadClock, saveClock, makeIdFactory } from './identity.js';
import { compareSiblings } from './sort.js';
import { mergePersonFields, definePersonViews, mergeFamilyFields, defineFamilyViews,
  makeName, makeChildLink, makeTombstone, edgeKey } from './model.js';

/** Raw data without the derived views — getters don't survive cloning. */
const rawOf = (obj) => JSON.parse(JSON.stringify(obj));

// One factory for the whole process: device id plus a running counter.
const DEVICE = deviceId();
const nextId = makeIdFactory(DEVICE);

/** Default for a new person — in one place, not in every caller. */
const NEW_PERSON = { given: '', surname: '', sex: 'U', custom: {} };

/** Past this many log entries, a snapshot on the next load pays off. */
const COMPACT_AT = 200;

/**
 * The opened tree. Holds people and families in memory, writes every change as an
 * op to the DocStore, and bumps `revision` — rendering hangs off that; the UI
 * subscribes to nothing.
 */
export class FamilyTree {
  revision = 0;
  people = new Map();
  families = new Map();
  // Media live as metadata in the document; the bytes are in the BlobStore.
  media = new Map();       // mediaId -> { id, kind, mime, hash, w, h, caption, source }
  mediaLinks = new Map();  // linkId  -> { id, mediaId, subjectId, role, crop, order }
  // Tombstones: bookkeeping only today, the basis for merging later.
  tombstones = new Map();  // id -> { id, kind, device, at }
  #store;
  #docId;
  #deviceId = DEVICE;
  #lamport = loadClock();
  /** Set when the file comes from a newer version — then read-only. */
  readOnly = false;
  readOnlyReason = null;
  #undo = [];
  #logLength = 0;
  #covered = 0;   // log entries covered by the snapshot
  /**
   * The store position (log-entry count) through which this replica has folded
   * ops into memory. compact() must never cover beyond it without first applying
   * the tail: a snapshot that claims coverage of entries it never folded in would
   * drop a concurrent tab's interleaved ops on the next hydrate.
   */
  #appliedThrough = 0;
  #redo = [];
  #listeners = new Set();

  constructor(store, docId) {
    this.#store = store;
    this.#docId = docId;
  }

  onRevision(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  #bump() {
    this.revision += 1;
    for (const fn of this.#listeners) fn(this.revision);
  }

  // ---------------------------------------------------------------- reading
  person(id) { return this.people.get(id); }
  family(id) { return this.families.get(id); }
  allPeople() { return [...this.people.values()]; }
  allFamilies() { return [...this.families.values()]; }

  /** Families in which the person is a spouse. */
  familiesOf(id) {
    return this.allFamilies().filter((f) => f.spouses.includes(id));
  }

  /** The family in which the person is a child. */
  childFamilyOf(id) {
    return this.allFamilies().find((f) => f.children.includes(id));
  }

  parentsOf(id) {
    const fam = this.childFamilyOf(id);
    if (!fam) return { family: null, father: null, mother: null };
    const spouses = fam.spouses.map((s) => this.person(s)).filter(Boolean);
    // Sex leads, position is only the fallback: since a single parent can remain,
    // a positional fallback would push a lone mother into the father slot — and
    // thereby move her in the tree too.
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

  // ---------------------------------------------------------------- writing
  async #commit(ops, { undoable = true, silent = false } = {}) {
    // Loaded from the future: write nothing, or this version overwrites changes it
    // couldn't read.
    if (this.readOnly) { console.warn('read-only:', this.readOnlyReason); return; }
    const inverse = ops.map((o) => this.#invert(o)).reverse().filter(Boolean);
    this.#apply(ops);
    if (undoable && inverse.length) { this.#undo.push(inverse); this.#redo.length = 0; }
    this.#lamport += 1;
    saveClock(this.#lamport);
    const cursor = await this.#store.append(this.#docId, [encodeUpdate(ops, this.#deviceId, this.#lamport)]);
    // Advance the fold mark only when our single-entry append is contiguous with
    // what we've already folded (the common single-tab case). If another tab wrote
    // in between there is a gap, so leave it — compact() folds the gap first.
    if (cursor === this.#appliedThrough + 1) this.#appliedThrough = cursor;
    // Silent write: while typing, the view must not be rebuilt, or the field loses
    // the cursor.
    if (!silent) this.#bump();
  }

  /**
   * Applies ops. `at` is the change's timestamp; it decides against tombstones.
   * One's own writes are, by definition, the newest.
   */
  #apply(ops, at = Date.now()) {
    // A change older than the deletion must not resurrect anything.
    const buried = (key) => {
      const t = this.tombstones.get(key);
      return t ? t.at > at : false;
    };
    // Check first, then apply: a mixed list would otherwise half-land and leave a
    // half state. An unknown kind means a newer version — swallowing it would be
    // silent data loss.
    for (const o of ops) {
      if (!KNOWN_OPS.has(o.type)) throw new FutureVersionError('change', o.type, 'known ops');
    }
    for (const o of ops) {
      switch (o.type) {
        case 'upsertPerson': {
          if (buried(o.id)) break;
          this.tombstones.delete(o.id);
          const prev = this.people.get(o.id) ?? { id: o.id, custom: {}, names: [], events: [] };
          this.people.set(o.id, definePersonViews(mergePersonFields(prev, o.fields)));
          break;
        }
        case 'deletePerson': {
          this.tombstones.set(o.id, makeTombstone(o.id, 'person', this.#deviceId, at));
          this.people.delete(o.id);
          for (const f of this.families.values()) {
            f.parents = f.parents.filter((s) => s !== o.id);
            f.childLinks = f.childLinks.filter((c) => c.id !== o.id);
          }
          break;
        }
        case 'upsertFamily': {
          if (buried(o.id)) break;
          this.tombstones.delete(o.id);
          const prev = this.families.get(o.id) ?? { id: o.id, parents: [], childLinks: [], facts: {} };
          this.families.set(o.id, defineFamilyViews(mergeFamilyFields(prev, o.fields)));
          break;
        }
        case 'linkChild': {
          const key = edgeKey('child', o.familyId, o.personId);
          if (buried(key)) break;
          this.tombstones.delete(key);
          const f = this.families.get(o.familyId);
          // The kind of parentage travels along — the UI doesn't show it yet, but
          // an import must not lose it.
          if (f && !f.childLinks.some((c) => c.id === o.personId)) {
            f.childLinks.push(makeChildLink(o.personId, o.pedi ?? 'birth'));
          }
          break;
        }
        case 'unlinkChild': {
          // An unlinked edge needs a tombstone too: otherwise a merge brings it
          // back, because "absent" looks like "never existed".
          const key = edgeKey('child', o.familyId, o.personId);
          this.tombstones.set(key, makeTombstone(key, 'childLink', this.#deviceId, at));
          const f = this.families.get(o.familyId);
          if (f) f.childLinks = f.childLinks.filter((c) => c.id !== o.personId);
          break;
        }
        case 'linkSpouse': {
          const key = edgeKey('spouse', o.familyId, o.personId);
          if (buried(key)) break;
          this.tombstones.delete(key);
          const f = this.families.get(o.familyId);
          if (f && !f.parents.includes(o.personId)) f.parents.push(o.personId);
          break;
        }
        case 'unlinkSpouse': {
          const key = edgeKey('spouse', o.familyId, o.personId);
          this.tombstones.set(key, makeTombstone(key, 'spouseLink', this.#deviceId, at));
          const f = this.families.get(o.familyId);
          if (f) f.parents = f.parents.filter((s) => s !== o.personId);
          break;
        }
        case 'deleteFamily':
          this.tombstones.set(o.id, makeTombstone(o.id, 'family', this.#deviceId, at));
          this.families.delete(o.id);
          break;
        case 'upsertMedia': {
          const prev = this.media.get(o.id) ?? { id: o.id, kind: 'image' };
          this.media.set(o.id, { ...prev, ...o.fields });
          break;
        }
        case 'deleteMedia': {
          this.media.delete(o.id);
          for (const [lid, l] of [...this.mediaLinks]) if (l.mediaId === o.id) this.mediaLinks.delete(lid);
          for (const p of this.people.values()) if (p.portraitId && this.#linkGone(p.portraitId)) delete p.portraitId;
          break;
        }
        case 'upsertMediaLink': {
          const prev = this.mediaLinks.get(o.id) ?? { id: o.id, role: 'document', order: 0 };
          this.mediaLinks.set(o.id, { ...prev, ...o.fields });
          break;
        }
        case 'deleteMediaLink': {
          this.mediaLinks.delete(o.id);
          for (const p of this.people.values()) if (p.portraitId === o.id) delete p.portraitId;
          break;
        }
        default: break;   // already excluded by KNOWN_OPS
      }
    }
  }

  #invert(o) {
    switch (o.type) {
      case 'upsertPerson': {
        const prev = this.people.get(o.id);
        return prev
          ? { type: 'upsertPerson', id: o.id, fields: rawOf(prev) }
          : { type: 'deletePerson', id: o.id };
      }
      case 'upsertFamily': {
        const prev = this.families.get(o.id);
        return prev
          ? { type: 'upsertFamily', id: o.id, fields: rawOf(prev) }
          : { type: 'deleteFamily', id: o.id };
      }
      // Media follow the same pattern as people and families.
      case 'upsertMedia': case 'deleteMedia':
      case 'upsertMediaLink': case 'deleteMediaLink':
      case 'deletePerson': case 'deleteFamily':
        return this.#invertRecord(o);
      // Edges are their own inverse.
      case 'linkChild': return { type: 'unlinkChild', familyId: o.familyId, personId: o.personId };
      case 'unlinkChild': return { type: 'linkChild', familyId: o.familyId, personId: o.personId };
      case 'linkSpouse': return { type: 'unlinkSpouse', familyId: o.familyId, personId: o.personId };
      case 'unlinkSpouse': return { type: 'linkSpouse', familyId: o.familyId, personId: o.personId };
      default: return null;
    }
  }

  /**
   * Inverse for all record kinds: if something existed before, the inverse
   * restores it; if nothing did, it deletes. Six cases that differed only in
   * collection and op name now live in one place.
   */
  #invertRecord(o) {
    const kind = o.type.replace(/^(upsert|delete)/, '');
    const store = {
      Person: this.people, Family: this.families,
      Media: this.media, MediaLink: this.mediaLinks
    }[kind];
    const prev = store?.get(o.id);
    if (prev) return { type: 'upsert' + kind, id: o.id, fields: rawOf(prev) };
    return o.type.startsWith('upsert') ? { type: 'delete' + kind, id: o.id } : null;
  }

  /** A person op without a commit, so actions stay atomic. */
  #draftPerson(fields = {}) {
    const id = nextId('p');
    return { id, op: { type: 'upsertPerson', id, fields: { ...NEW_PERSON, ...fields } } };
  }

  async createPerson(fields = {}) {
    const { id, op } = this.#draftPerson(fields);
    await this.#commit([op]);
    return this.person(id);
  }

  // -------------------------------------------------------------- media
  #linkGone(linkId) { return !this.mediaLinks.has(linkId); }

  /** All of a person's media, portrait first. */
  mediaOf(subjectId) {
    const links = [...this.mediaLinks.values()].filter((l) => l.subjectId === subjectId);
    const portraitId = this.people.get(subjectId)?.portraitId;
    return links
      .sort((a, b) => (a.id === portraitId ? -1 : b.id === portraitId ? 1 : (a.order ?? 0) - (b.order ?? 0)))
      .map((link) => ({ link, media: this.media.get(link.mediaId) }))
      .filter((m) => m.media);
  }

  /** A person's preferred image — or null. */
  portraitOf(subjectId) {
    const p = this.people.get(subjectId);
    if (!p) return null;
    const link = p.portraitId ? this.mediaLinks.get(p.portraitId) : null;
    const chosen = link ?? this.mediaOf(subjectId).find((m) => m.link.role === 'portrait')?.link;
    if (!chosen) return null;
    const media = this.media.get(chosen.mediaId);
    return media ? { link: chosen, media } : null;
  }

  /**
   * Attaches a file already in the BlobStore to a person. The document gets only
   * the hash and dimensions — never the bytes.
   */
  async attachMedia(subjectId, { hash, mime, w, h, caption = '', source = '', role = 'portrait', crop = null }) {
    const mediaId = nextId('m_');
    const linkId = nextId('ml_');
    const ops = [
      { type: 'upsertMedia', id: mediaId, fields: { id: mediaId, kind: 'image', mime, hash, w, h, caption, source } },
      { type: 'upsertMediaLink', id: linkId, fields: { id: linkId, mediaId, subjectId, role, crop, order: this.mediaOf(subjectId).length } }
    ];
    if (role === 'portrait') ops.push({ type: 'upsertPerson', id: subjectId, fields: { portraitId: linkId } });
    await this.#commit(ops);
    return { mediaId, linkId };
  }

  async setPortrait(subjectId, linkId) {
    await this.#commit([{ type: 'upsertPerson', id: subjectId, fields: { portraitId: linkId } }]);
  }

  /** Detaches the link; the blob stays (other people may use it). */
  async detachMedia(linkId) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    const ops = [{ type: 'deleteMediaLink', id: linkId }];
    const stillUsed = [...this.mediaLinks.values()].some((l) => l.id !== linkId && l.mediaId === link.mediaId);
    if (!stillUsed) ops.push({ type: 'deleteMedia', id: link.mediaId });
    await this.#commit(ops);
  }

  /** The crop lives on the link, not in the file — non-destructive. */
  async setCrop(linkId, crop) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    await this.#commit([{ type: 'upsertMediaLink', id: linkId, fields: { crop } }]);
  }

  async updatePerson(id, patch, opts = {}) {
    await this.#commit([{ type: 'upsertPerson', id, fields: patch }], opts);
    return this.person(id);
  }

  async deletePerson(id) {
    await this.#commit([{ type: 'deletePerson', id }]);
  }

  async addMarriage(aId, bFieldsOrId, facts = {}) {
    const ops = [];
    let bId;
    if (typeof bFieldsOrId === 'string') {
      bId = bFieldsOrId;
    } else {
      const draft = this.#draftPerson(bFieldsOrId);
      bId = draft.id;
      ops.push(draft.op);
    }
    const id = nextId('f');
    ops.push({ type: 'upsertFamily', id, fields: { spouses: [aId, bId], children: [], facts } });
    await this.#commit(ops);
    return this.family(id);
  }

  async addChild(familyId, fieldsOrId) {
    const ops = [];
    let pid;
    if (typeof fieldsOrId === 'string') {
      pid = fieldsOrId;
    } else {
      const draft = this.#draftPerson(fieldsOrId);
      pid = draft.id;
      ops.push(draft.op);
    }
    ops.push({ type: 'linkChild', familyId, personId: pid });
    await this.#commit(ops);
    return this.person(pid);
  }

  /**
   * Create parents. Family, people, and links go into a single commit — one undo
   * takes the whole action back.
   */
  async addParents(childId, father = null, mother = null) {
    const existing = this.childFamilyOf(childId);
    const ops = [];
    const familyId = existing ? existing.id : nextId('f');
    if (!existing) {
      ops.push({ type: 'upsertFamily', id: familyId, fields: { spouses: [], children: [childId], facts: {} } });
    }
    for (const [role, val] of [['M', father], ['F', mother]]) {
      if (!val) continue;
      let pid;
      if (typeof val === 'string') {
        pid = val;
      } else {
        const draft = this.#draftPerson({ sex: role, ...val });
        pid = draft.id;
        ops.push(draft.op);
      }
      ops.push({ type: 'linkSpouse', familyId, personId: pid });
    }
    await this.#commit(ops);
    return this.family(familyId);
  }

  /**
   * Dissolves a marriage. The people stay, the family disappears — children of it
   * lose their parents and must be re-linked. One commit, so a single undo takes
   * it all back.
   */
  async removeMarriage(familyId) {
    if (!this.families.has(familyId)) return;
    await this.#commit([{ type: 'deleteFamily', id: familyId }]);
  }

  /** Removes a child from a family without deleting the person. */
  async unlinkChild(familyId, personId) {
    await this.#commit([{ type: 'unlinkChild', familyId, personId }]);
  }

  /** Removes a parent from the child's family; the person stays. */
  async unlinkSpouse(familyId, personId) {
    await this.#commit([{ type: 'unlinkSpouse', familyId, personId }]);
  }

  /** Add an existing person as a partner in an existing marriage. */
  async linkSpouse(familyId, personId) {
    await this.#commit([{ type: 'linkSpouse', familyId, personId }]);
  }

  /** All of a person's ancestors — for cycle protection when linking. */
  ancestorIds(id, seen = new Set()) {
    const { father, mother } = this.parentsOf(id);
    for (const p of [father, mother]) {
      if (p && !seen.has(p.id)) { seen.add(p.id); this.ancestorIds(p.id, seen); }
    }
    return seen;
  }

  async setFamilyFacts(familyId, facts) {
    await this.#commit([{ type: 'upsertFamily', id: familyId, fields: { facts } }]);
  }

  // ---------------------------------------------------------------- undo / redo
  get canUndo() { return this.#undo.length > 0; }
  get canRedo() { return this.#redo.length > 0; }

  async #replay(stack, counterStack) {
    const ops = stack.pop();
    if (!ops) return;
    const inverse = ops.map((o) => this.#invert(o)).reverse().filter(Boolean);
    this.#apply(ops);
    counterStack.push(inverse);
    this.#lamport += 1;
    saveClock(this.#lamport);
    const cursor = await this.#store.append(this.#docId, [encodeUpdate(ops, this.#deviceId, this.#lamport)]);
    if (cursor === this.#appliedThrough + 1) this.#appliedThrough = cursor;
    // An undo always redraws: there's no silent write here — that applies only
    // while typing in the editor.
    this.#bump();
  }

  async undo() { await this.#replay(this.#undo, this.#redo); }
  async redo() { await this.#replay(this.#redo, this.#undo); }

  // ---------------------------------------------------------------- loading
  async hydrate() {
    // How many log entries the snapshot already contains — everything before that
    // may be skipped on load.
    let covered = 0;
    const snap = await this.#store.readSnapshot(this.#docId);
    if (snap) {
      const bytes = snap.bytes instanceof Uint8Array ? snap.bytes : new Uint8Array(snap.bytes);
      const data = JSON.parse(new TextDecoder().decode(bytes));
      // If the field is missing, the file is from the first version; a higher one
      // we can't read and certainly must not overwrite.
      const dv = data.version ?? 1;
      covered = data.logCursor ?? 0;
      if (dv > DOC_VERSION) {
        this.readOnly = true;
        this.readOnlyReason = new FutureVersionError('tree', dv, DOC_VERSION).message;
        return;
      }
      this.people = new Map(data.people.map((p) => [p.id, definePersonViews(mergePersonFields(null, p))]));
      this.families = new Map(data.families.map((fam) => [fam.id, defineFamilyViews(mergeFamilyFields(null, fam))]));
      this.tombstones = new Map((data.tombstones ?? []).map((tt) => [tt.id, tt]));
    }
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, covered);
    try {
      for (const u of updates) {
        const { ops: list, meta } = decodeUpdate(u);
        this.#apply(list, meta.created_at ?? Date.now());
      }
    } catch (e) {
      if (e instanceof FutureVersionError) {
        this.readOnly = true;
        this.readOnlyReason = e.message;
      } else throw e;
    }
    // The counter must sit above everything already in the tree — otherwise a
    // fresh store hands out an id that already exists, and upsertPerson silently
    // writes onto the existing record.
    nextId.observe([...this.people.keys(), ...this.families.keys(),
      ...this.media.keys(), ...this.mediaLinks.keys()]);
    // Compact when the log has grown long: otherwise it grows forever and is fully
    // replayed on every start. Only the entries the snapshot doesn't yet cover count.
    this.#logLength = covered + updates.length;
    this.#covered = covered;
    // We have just folded every entry up to the store cursor into memory.
    this.#appliedThrough = cursor ?? this.#logLength;
    if (updates.length > COMPACT_AT) await this.compact().catch(() => {});
    this.#bump();
  }

  /**
   * Writes the current state as a snapshot, conditional on the version we read —
   * if another tab wrote in the meantime the CAS aborts, leaving its changes
   * rather than overwriting them.
   *
   * Fold-before-cover: a snapshot must contain every entry its coverage mark
   * claims. So we first apply any log tail we have not yet folded in (e.g. a
   * concurrent tab's ops); otherwise those entries would be marked "covered"
   * while missing from the snapshot, and the next hydrate would skip them —
   * silent loss. Re-applying our own already-folded ops is harmless: the ops are
   * idempotent (upserts merge, links check before pushing, deletes/unlinks are
   * no-ops the second time), and applying with the entry's own `created_at` keeps
   * tombstone ordering intact.
   */
  async compact() {
    if (this.readOnly) return;
    const { updates, cursor } = await this.#store.readUpdates(this.#docId, this.#appliedThrough);
    try {
      for (const u of updates) {
        const { ops: list, meta } = decodeUpdate(u);
        this.#apply(list, meta.created_at ?? Date.now());
      }
    } catch (e) {
      // A future-version entry from another tab: go read-only, don't snapshot.
      if (e instanceof FutureVersionError) {
        this.readOnly = true;
        this.readOnlyReason = e.message;
        return;
      }
      throw e;
    }
    this.#appliedThrough = cursor;
    // `cursor` is the absolute line count, not the increment.
    const covered = cursor;
    if (covered <= this.#covered) return;   // nothing new since the last snapshot
    const bytes = new TextEncoder().encode(
      JSON.stringify({ ...this.toJSON(), logCursor: covered }));
    const prev = await this.#store.readSnapshot(this.#docId);
    try {
      await this.#store.putSnapshot(this.#docId, bytes, prev?.version ?? null);
      this.#covered = covered;
      this.#logLength = covered;
    } catch (e) {
      // Another tab was faster: its snapshot stands, not ours. Our ops are still in
      // the log, so the next hydrate replays them onto it.
      if (e?.name !== 'ConflictError') throw e;
    }
  }

  /** Load fixture data without filling the undo stack. */
  async seed(ops) {
    await this.#commit(ops, { undoable: false });
    this.#undo.length = 0;
    this.#redo.length = 0;
  }

  async reset() {
    this.people.clear();
    this.families.clear();
    this.tombstones.clear();
    // The store loses snapshot and log — the counters for them must go too.
    this.#covered = 0;
    this.#logLength = 0;
    this.#appliedThrough = 0;
    this.#undo.length = 0;
    this.#redo.length = 0;
    await this.#store.delete(this.#docId);
    this.#bump();
  }

  toJSON() {
    // Media travel along as metadata; the recipient fetches the bytes by hash from
    // its BlobStore (or gets them in a package alongside). rawOf: the derived views
    // are getters and don't belong in the file — the model itself is written.
    return {
      version: DOC_VERSION,
      people: this.allPeople().map(rawOf),
      families: this.allFamilies().map(rawOf),
      media: [...this.media.values()],
      mediaLinks: [...this.mediaLinks.values()],
      tombstones: [...this.tombstones.values()]
    };
  }
}
