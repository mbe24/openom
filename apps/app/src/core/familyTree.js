import { encodeUpdate, decodeUpdate, KNOWN_OPS, DOC_VERSION, FutureVersionError } from './ops.js';
import { deviceId, loadClock, saveClock, makeIdFactory } from './identity.js';
import { compareSiblings } from './sort.js';
import { mergePersonFields, definePersonViews, mergeFamilyFields, defineFamilyViews,
  makeName, makeChildLink, makeTombstone, edgeKey } from './model.js';

/** Rohdaten ohne die abgeleiteten Sichten — Getter ueberleben kein Klonen. */
const rawOf = (obj) => JSON.parse(JSON.stringify(obj));

// Eine Fabrik fuer den ganzen Prozess: Geraete-ID plus laufender Zaehler.
const DEVICE = deviceId();
const nextId = makeIdFactory(DEVICE);

/** Vorgabe fuer eine neue Person — an einer Stelle, nicht in jedem Aufrufer. */
const NEW_PERSON = { given: '', surname: '', sex: 'U', custom: {} };

/** Ab so vielen Log-Eintraegen lohnt ein Snapshot beim naechsten Laden. */
const COMPACT_AT = 200;

/**
 * Der geoeffnete Baum. Haelt Personen und Familien im Speicher, schreibt jede
 * Aenderung als Op in den DocStore und zaehlt "revision" hoch — daran haengt
 * das Rendering, die UI abonniert nichts.
 */
export class FamilyTree {
  revision = 0;
  people = new Map();
  families = new Map();
  // Medien liegen als Metadaten im Dokument; die Bytes stehen im BlobStore.
  media = new Map();       // mediaId -> { id, kind, mime, hash, w, h, caption, source }
  mediaLinks = new Map();  // linkId  -> { id, mediaId, subjectId, role, crop, order }
  // Grabsteine: heute nur Buchhaltung, spaeter die Grundlage fuers Mergen.
  tombstones = new Map();  // id -> { id, kind, device, at }
  #store;
  #docId;
  #deviceId = DEVICE;
  #lamport = loadClock();
  /** Gesetzt, wenn die Datei aus einer neueren Fassung stammt — dann nur lesen. */
  readOnly = false;
  readOnlyReason = null;
  #undo = [];
  #logLength = 0;
  #covered = 0;   // vom Snapshot abgedeckte Log-Eintraege
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

  // ---------------------------------------------------------------- lesen
  person(id) { return this.people.get(id); }
  family(id) { return this.families.get(id); }
  allPeople() { return [...this.people.values()]; }
  allFamilies() { return [...this.families.values()]; }

  /** Familien, in denen die Person Ehepartner ist. */
  familiesOf(id) {
    return this.allFamilies().filter((f) => f.spouses.includes(id));
  }

  /** Die Familie, in der die Person Kind ist. */
  childFamilyOf(id) {
    return this.allFamilies().find((f) => f.children.includes(id));
  }

  parentsOf(id) {
    const fam = this.childFamilyOf(id);
    if (!fam) return { family: null, father: null, mother: null };
    const spouses = fam.spouses.map((s) => this.person(s)).filter(Boolean);
    // Geschlecht fuehrt, Position ist nur der Rest: seit ein einzelner Elternteil
    // uebrig bleiben kann, wuerde ein positionaler Rueckfall eine alleinstehende
    // Mutter in den Vaterslot schieben — und damit auch im Baum verschieben.
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

  // ---------------------------------------------------------------- schreiben
  async #commit(ops, { undoable = true, silent = false } = {}) {
    // Aus der Zukunft geladen: nichts schreiben, sonst ueberschreibt diese
    // Fassung Aenderungen, die sie nicht lesen konnte.
    if (this.readOnly) { console.warn('read-only:', this.readOnlyReason); return; }
    const inverse = ops.map((o) => this.#invert(o)).reverse().filter(Boolean);
    this.#apply(ops);
    if (undoable && inverse.length) { this.#undo.push(inverse); this.#redo.length = 0; }
    this.#lamport += 1;
    saveClock(this.#lamport);
    await this.#store.append(this.#docId, [encodeUpdate(ops, this.#deviceId, this.#lamport)]);
    // Still schreiben: waehrend des Tippens darf die Ansicht nicht neu gebaut
    // werden, sonst verliert das Feld den Cursor.
    if (!silent) this.#bump();
  }

  /**
   * Wendet Ops an. `at` ist der Zeitpunkt der Aenderung; er entscheidet gegen
   * Grabsteine. Eigene Schreibvorgaenge sind per Definition die juengsten.
   */
  #apply(ops, at = Date.now()) {
    // Eine Aenderung, die aelter ist als das Loeschen, darf nichts wiederbeleben.
    const buried = (key) => {
      const t = this.tombstones.get(key);
      return t ? t.at > at : false;
    };
    // Erst pruefen, dann anwenden: eine gemischte Liste wuerde sonst zur
    // Haelfte landen und einen halben Stand hinterlassen. Unbekannte Art heisst
    // neuere Fassung — verschlucken waere stiller Datenverlust.
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
          // Die Art der Kindschaft reist mit — die Oberflaeche zeigt sie noch
          // nicht, aber ein Import darf sie nicht verlieren.
          if (f && !f.childLinks.some((c) => c.id === o.personId)) {
            f.childLinks.push(makeChildLink(o.personId, o.pedi ?? 'birth'));
          }
          break;
        }
        case 'unlinkChild': {
          // Auch eine geloeste Kante braucht einen Grabstein: sonst bringt sie
          // ein Merge zurueck, weil "nicht vorhanden" wie "nie dagewesen" aussieht.
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
        default: break;   // von KNOWN_OPS bereits ausgeschlossen
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
      // Medien folgen demselben Muster wie Personen und Familien.
      case 'upsertMedia': case 'deleteMedia':
      case 'upsertMediaLink': case 'deleteMediaLink':
      case 'deletePerson': case 'deleteFamily':
        return this.#invertRecord(o);
      // Kanten sind ihr eigenes Gegenteil.
      case 'linkChild': return { type: 'unlinkChild', familyId: o.familyId, personId: o.personId };
      case 'unlinkChild': return { type: 'linkChild', familyId: o.familyId, personId: o.personId };
      case 'linkSpouse': return { type: 'unlinkSpouse', familyId: o.familyId, personId: o.personId };
      case 'unlinkSpouse': return { type: 'linkSpouse', familyId: o.familyId, personId: o.personId };
      default: return null;
    }
  }

  /**
   * Umkehrung fuer alle Datensatz-Arten: war vorher etwas da, stellt die
   * Umkehrung es wieder her; war nichts da, loescht sie. Sechs Faelle, die sich
   * nur in Sammlung und Op-Namen unterschieden, liegen jetzt an einer Stelle.
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

  /** Person-Op ohne Commit, damit Aktionen atomar bleiben. */
  #draftPerson(fields = {}) {
    const id = nextId('p');
    return { id, op: { type: 'upsertPerson', id, fields: { ...NEW_PERSON, ...fields } } };
  }

  async createPerson(fields = {}) {
    const { id, op } = this.#draftPerson(fields);
    await this.#commit([op]);
    return this.person(id);
  }

  // -------------------------------------------------------------- Medien
  #linkGone(linkId) { return !this.mediaLinks.has(linkId); }

  /** Alle Medien einer Person, Portraet zuerst. */
  mediaOf(subjectId) {
    const links = [...this.mediaLinks.values()].filter((l) => l.subjectId === subjectId);
    const portraitId = this.people.get(subjectId)?.portraitId;
    return links
      .sort((a, b) => (a.id === portraitId ? -1 : b.id === portraitId ? 1 : (a.order ?? 0) - (b.order ?? 0)))
      .map((link) => ({ link, media: this.media.get(link.mediaId) }))
      .filter((m) => m.media);
  }

  /** Das bevorzugte Bild einer Person — oder null. */
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
   * Haengt eine bereits im BlobStore liegende Datei an eine Person.
   * Das Dokument bekommt nur Hash und Masse — nie die Bytes.
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

  /** Loest die Verknuepfung; der Blob bleibt liegen (andere Personen koennen ihn nutzen). */
  async detachMedia(linkId) {
    const link = this.mediaLinks.get(linkId);
    if (!link) return;
    const ops = [{ type: 'deleteMediaLink', id: linkId }];
    const stillUsed = [...this.mediaLinks.values()].some((l) => l.id !== linkId && l.mediaId === link.mediaId);
    if (!stillUsed) ops.push({ type: 'deleteMedia', id: link.mediaId });
    await this.#commit(ops);
  }

  /** Zuschnitt liegt am Link, nicht in der Datei — nicht zerstoerend. */
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
   * Eltern anlegen. Familie, Personen und Verknuepfungen gehen in einen
   * einzigen Commit — ein Undo nimmt die ganze Aktion zurueck.
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
   * Loest eine Ehe. Die Personen bleiben, die Familie verschwindet — Kinder
   * daraus verlieren ihre Eltern und muessen neu verknuepft werden. Ein Commit,
   * also nimmt ein Undo alles zusammen zurueck.
   */
  async removeMarriage(familyId) {
    if (!this.families.has(familyId)) return;
    await this.#commit([{ type: 'deleteFamily', id: familyId }]);
  }

  /** Nimmt ein Kind aus einer Familie, ohne die Person zu loeschen. */
  async unlinkChild(familyId, personId) {
    await this.#commit([{ type: 'unlinkChild', familyId, personId }]);
  }

  /** Nimmt einen Elternteil aus der Familie des Kindes; die Person bleibt. */
  async unlinkSpouse(familyId, personId) {
    await this.#commit([{ type: 'unlinkSpouse', familyId, personId }]);
  }

  /** Vorhandene Person als Partner einer bestehenden Ehe eintragen. */
  async linkSpouse(familyId, personId) {
    await this.#commit([{ type: 'linkSpouse', familyId, personId }]);
  }

  /** Alle Vorfahren einer Person — fuer Zyklusschutz beim Verknuepfen. */
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
    await this.#store.append(this.#docId, [encodeUpdate(ops, this.#deviceId, this.#lamport)]);
    // Ein Undo zeichnet immer neu: hier gibt es kein stilles Schreiben, das
    // gilt nur beim Tippen im Editor.
    this.#bump();
  }

  async undo() { await this.#replay(this.#undo, this.#redo); }
  async redo() { await this.#replay(this.#redo, this.#undo); }

  // ---------------------------------------------------------------- laden
  async hydrate() {
    // Wie viele Log-Eintraege der Snapshot schon enthaelt — alles davor darf
    // beim Laden uebersprungen werden.
    let covered = 0;
    const snap = await this.#store.readSnapshot(this.#docId);
    if (snap) {
      const bytes = snap.bytes instanceof Uint8Array ? snap.bytes : new Uint8Array(snap.bytes);
      const data = JSON.parse(new TextDecoder().decode(bytes));
      // Fehlt die Angabe, stammt die Datei aus der ersten Fassung; eine hoehere
      // koennen wir nicht lesen und duerfen sie erst recht nicht ueberschreiben.
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
    const { updates } = await this.#store.readUpdates(this.#docId, covered);
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
    // Der Zaehler muss ueber allem liegen, was schon im Baum steht — sonst
    // vergibt ein frischer Speicher eine ID, die es bereits gibt, und
    // upsertPerson schreibt still auf den vorhandenen Datensatz.
    nextId.observe([...this.people.keys(), ...this.families.keys(),
      ...this.media.keys(), ...this.mediaLinks.keys()]);
    // Verdichten, wenn der Log lang geworden ist: sonst waechst er ewig und
    // wird bei jedem Start vollstaendig abgespielt.
    // Nur die Eintraege zaehlen, die der Snapshot noch nicht abdeckt.
    this.#logLength = covered + updates.length;
    this.#covered = covered;
    if (updates.length > COMPACT_AT) await this.compact().catch(() => {});
    this.#bump();
  }

  /**
   * Schreibt den aktuellen Stand als Snapshot und leert den Log. Bedingt auf
   * die Version, die wir gelesen haben — schreibt inzwischen ein anderer Tab,
   * bricht es ab, statt seine Aenderungen zu ueberschreiben.
   */
  async compact() {
    if (this.readOnly) return;
    // Erst den Stand festhalten, den der Snapshot abdecken wird — was danach
    // hereinkommt, bleibt im Log und wird beim naechsten Laden nachgespielt.
    // cursor ist bereits die absolute Zeilenzahl, nicht der Zuwachs: addiert
    // man #covered dazu, ueberspringt hydrate() spaeter echte Aenderungen.
    const { cursor: covered } = await this.#store.readUpdates(this.#docId, null);
    const bytes = new TextEncoder().encode(
      JSON.stringify({ ...this.toJSON(), logCursor: covered }));
    const prev = await this.#store.readSnapshot(this.#docId);
    try {
      await this.#store.putSnapshot(this.#docId, bytes, prev?.version ?? null);
      this.#covered = covered;
      this.#logLength = covered;
    } catch (e) {
      // Ein anderer Tab war schneller: dann gilt sein Snapshot, nicht unserer.
      if (e?.name !== 'ConflictError') throw e;
    }
  }

  /** Fixture-Daten einspielen, ohne den Undo-Stapel zu fuellen. */
  async seed(ops) {
    await this.#commit(ops, { undoable: false });
    this.#undo.length = 0;
    this.#redo.length = 0;
  }

  async reset() {
    this.people.clear();
    this.families.clear();
    this.tombstones.clear();
    // Der Store verliert Snapshot und Log — die Zaehler dazu muessen mit.
    this.#covered = 0;
    this.#logLength = 0;
    this.#undo.length = 0;
    this.#redo.length = 0;
    await this.#store.delete(this.#docId);
    this.#bump();
  }

  toJSON() {
    // Medien reisen als Metadaten mit; die Bytes holt der Empfaenger ueber den
    // Hash aus seinem BlobStore (oder bekommt sie in einem Paket daneben).
    // rawOf: die abgeleiteten Sichten sind Getter und gehoeren nicht in die
    // Datei — geschrieben wird das Modell selbst.
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
