// Datenmodell v2. Das Dokument traegt Listen — Namen, Ereignisse, Eltern,
// Kindverknuepfungen mit Art der Kindschaft. Die Oberflaeche liest weiterhin
// person.given / .surname / .birth und family.spouses / .children: das sind
// abgeleitete Sichten auf dieselben Daten, keine zweite Wahrheit.
//
// Warum jetzt und ohne neue Formulare: eine Modelaenderung kostet eine
// Migration, sobald Baeume existieren. Ein Formular kostet nichts. Also traegt
// das Modell heute schon, was der Import sonst wegwerfen muesste.

const GIVEN_SPLIT = /\s+/;

/** Ein Name in Teilen. Die Deutung der Teile haengt an `convention`. */
export function makeName({ given = '', surname = '', convention = 'western', type = 'birth' } = {}) {
  return {
    parts: {
      given: String(given).trim() ? String(given).trim().split(GIVEN_SPLIT) : [],
      family: String(surname ?? '').trim(),
      prefix: '',
      suffix: ''
    },
    convention,
    type
  };
}

export const givenOf = (name) => (name?.parts?.given ?? []).join(' ');
export const familyOf = (name) => name?.parts?.family ?? '';

/** Ereignis mit Datum, Ort und Quellen — Geburt und Tod sind zwei davon. */
export function makeEvent(type, { date = '', place = '', sources = [] } = {}) {
  return { type, date: String(date ?? ''), place: String(place ?? ''), sources };
}

const eventOf = (events, type) => (events ?? []).find((e) => e.type === type) ?? null;

/**
 * Nimmt ein Feld-Bruchstueck in alter oder neuer Form und schreibt es in die
 * v2-Struktur. So koennen Seed, Import und Editor unveraendert `given`,
 * `surname`, `birth`, `death`, `birthPlace`, `deathPlace` schicken.
 */
export function mergePersonFields(base, fields = {}) {
  const p = { ...base };
  // Zeitstempel sind die Weiche fuer spaeteres Zusammenfuehren: ohne sie kann
  // ein Merge bei zwei Fassungen derselben Person nicht entscheiden.
  p.createdAt = base?.createdAt ?? fields.createdAt ?? Date.now();
  p.updatedAt = fields.updatedAt ?? Date.now();
  p.names = fields.names ?? p.names ?? [];
  p.events = fields.events ?? p.events ?? [];
  p.custom = { ...(base?.custom ?? {}), ...(fields.custom ?? {}) };

  for (const [k, v] of Object.entries(fields)) {
    if (['names', 'events', 'custom', 'createdAt', 'updatedAt',
      'given', 'surname', 'birth', 'death', 'birthPlace', 'deathPlace'].includes(k)) continue;
    p[k] = v;
  }

  if (!p.names.length) p.names = [makeName({})];
  if ('given' in fields || 'surname' in fields) {
    const first = p.names[0];
    const next = makeName({
      given: 'given' in fields ? fields.given : givenOf(first),
      surname: 'surname' in fields ? fields.surname : familyOf(first),
      convention: first?.convention ?? 'western',
      type: first?.type ?? 'birth'
    });
    p.names = [next, ...p.names.slice(1)];
  }

  for (const [key, type] of [['birth', 'birth'], ['death', 'death']]) {
    const placeKey = key + 'Place';
    if (!(key in fields) && !(placeKey in fields)) continue;
    const prev = eventOf(p.events, type);
    const ev = makeEvent(type, {
      date: key in fields ? fields[key] : prev?.date ?? '',
      place: placeKey in fields ? fields[placeKey] : prev?.place ?? '',
      sources: prev?.sources ?? []
    });
    p.events = [...p.events.filter((e) => e.type !== type), ev];
  }
  return p;
}

/**
 * Legt die abgeleiteten Felder als Getter auf das Objekt. Getter statt Kopien,
 * damit es keine zweite Wahrheit gibt, die auseinanderlaufen kann.
 */
export function definePersonViews(p) {
  Object.defineProperties(p, {
    given: { get() { return givenOf(this.names?.[0]); }, enumerable: false, configurable: true },
    surname: { get() { return familyOf(this.names?.[0]); }, enumerable: false, configurable: true },
    convention: { get() { return this.names?.[0]?.convention ?? 'western'; }, enumerable: false, configurable: true },
    birth: { get() { return eventOf(this.events, 'birth')?.date ?? ''; }, enumerable: false, configurable: true },
    death: { get() { return eventOf(this.events, 'death')?.date ?? ''; }, enumerable: false, configurable: true },
    birthPlace: { get() { return eventOf(this.events, 'birth')?.place ?? ''; }, enumerable: false, configurable: true },
    deathPlace: { get() { return eventOf(this.events, 'death')?.place ?? ''; }, enumerable: false, configurable: true }
  });
  return p;
}

/** Kindverknuepfung: id plus Art der Kindschaft (GEDCOM `PEDI`). */
export const makeChildLink = (id, pedi = 'birth') => ({ id, pedi });

export function mergeFamilyFields(base, fields = {}) {
  const f = { ...base };
  f.createdAt = base?.createdAt ?? fields.createdAt ?? Date.now();
  f.updatedAt = fields.updatedAt ?? Date.now();
  for (const [k, v] of Object.entries(fields)) {
    if (['spouses', 'children', 'parents', 'childLinks', 'facts', 'createdAt', 'updatedAt'].includes(k)) continue;
    f[k] = v;
  }
  f.facts = { ...(base?.facts ?? {}), ...(fields.facts ?? {}) };
  f.parents = fields.parents ?? (fields.spouses ? [...fields.spouses] : base?.parents ?? []);
  const kids = fields.childLinks ?? fields.children ?? base?.childLinks ?? [];
  f.childLinks = kids.map((c) => (typeof c === 'string' ? makeChildLink(c) : { ...c }));
  return f;
}

export function defineFamilyViews(f) {
  Object.defineProperties(f, {
    // Namen der alten Sicht: die Oberflaeche fragt weiter nach spouses und
    // children, bekommt aber die Listen des neuen Modells.
    spouses: { get() { return this.parents; }, enumerable: false, configurable: true },
    children: { get() { return this.childLinks.map((c) => c.id); }, enumerable: false, configurable: true }
  });
  return f;
}

/**
 * Grabstein. Noch benutzt sie niemand zum Zusammenfuehren — sie werden aber ab
 * jetzt mitgeschrieben, damit ein spaeterer Sync weiss, dass etwas geloescht
 * *wurde*. Ohne Grabstein laesst eine Bearbeitung auf einem anderen Geraet die
 * geloeschte Person wieder auferstehen.
 */
export const makeTombstone = (id, kind, device, at = Date.now()) => ({ id, kind, device, at });

/** Schluessel fuer den Grabstein einer Kante — Kanten haben keine eigene ID. */
export const edgeKey = (kind, familyId, personId) => kind + ':' + familyId + ':' + personId;
