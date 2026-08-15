// Identitaet des Geraets und die logische Uhr. Beides muss den Neustart
// ueberleben: eine neue Geraete-ID bei jedem Laden macht Zusammenfuehren
// unmoeglich, und eine bei 0 beginnende Uhr laesst dieselbe "Uhrzeit" mehrfach
// vorkommen — der Merge kann Aenderungen dann nicht mehr ordnen.

const DEVICE_KEY = 'openom.deviceId';
const CLOCK_KEY = 'openom.lamport';
const SEQ_KEY = 'openom.idSeq';

const rand = () => Math.random().toString(36).slice(2, 10);

export function deviceId() {
  try {
    let id = localStorage.getItem(DEVICE_KEY);
    if (!id) { id = 'd' + rand() + rand().slice(0, 4); localStorage.setItem(DEVICE_KEY, id); }
    return id;
  } catch {
    // Ohne Speicher bleibt es bei einer Sitzungs-ID — besser als keine.
    return 'd' + rand();
  }
}

// Per-(JS-context, tree) replica id for the sync log's idempotency dot (§8). It is a
// >=128-bit CSPRNG value, minted fresh per context — NOT derived from `deviceId()`.
// deviceId is machine-stable, which would (a) let the server correlate every tree
// edited from one machine and (b) collide across two tabs of the same origin (which
// are independent writers). A fresh random id per session, paired with the replica
// counter from 0, keeps every dot unique without any persistence.
const replicaIds = new Map();

export function replicaId(treeId) {
  let id = replicaIds.get(treeId);
  if (!id) {
    id = new Uint8Array(16);
    crypto.getRandomValues(id); // WebCrypto CSPRNG (browser + Node 18+), never Math.random
    replicaIds.set(treeId, id);
  }
  return id;
}

export function loadClock() {
  try { return Number(localStorage.getItem(CLOCK_KEY)) || 0; } catch { return 0; }
}

export function saveClock(value) {
  try { localStorage.setItem(CLOCK_KEY, String(value)); } catch { /* fluechtig */ }
}

/**
 * IDs aus Geraet und Zaehler statt aus Zufall. Die Geraete-ID vorn macht sie
 * zwischen Geraeten eindeutig, der laufende Zaehler innerhalb eines Geraets;
 * nebenbei sind sie dadurch sortierbar.
 *
 * Der Zaehler ist eigenstaendig und wird bei jeder Ausgabe fortgeschrieben —
 * an die Lamport-Uhr gehaengt lief er falsch, weil ein Commit mehrere IDs
 * verbraucht, die Uhr aber nur um eins steigt. Nach einem Neustart lagen
 * vergebene Nummern dann wieder im Ausgabebereich.
 */
export function makeIdFactory(device) {
  // Eigene Kennung je JS-Kontext. Zwei Tabs derselben Herkunft teilen sich
  // seit dem IndexedDB-Store *ein* Dokument, lesen den Zaehler aber beide beim
  // Laden — ohne diesen Zusatz vergeben sie dieselben IDs, und upsertPerson
  // schreibt die zweite Person auf die erste.
  const ctx = device + rand().slice(0, 3);
  let n = 0;
  const factory = (prefix) => {
    // Bei jeder Ausgabe frisch lesen und schreiben: der Zaehler soll auch dann
    // steigen, wenn ein anderer Tab zwischendurch welche verbraucht hat.
    let stored = 0;
    try { stored = Number(localStorage.getItem(SEQ_KEY)) || 0; } catch { /* fluechtig */ }
    n = Math.max(n, stored) + 1;
    try { localStorage.setItem(SEQ_KEY, String(n)); } catch { /* fluechtig */ }
    return prefix + '_' + ctx + '_' + n.toString(36);
  };
  /**
   * Hebt den Zaehler ueber alles, was im geladenen Baum schon steht. Noetig,
   * wenn eine Datei auf einem Geraet geoeffnet wird, dessen Speicher den
   * Zaehler nicht kennt — etwa nach einem Import auf einem neu aufgesetzten
   * Geraet mit derselben Geraete-ID.
   */
  factory.observe = (ids) => {
    let max = n;
    for (const raw of ids) {
      const parts = String(raw).split('_');
      // Zaehler dieses Geraets, gleich aus welchem Tab sie stammen.
      if (parts.length < 3 || !parts[1].startsWith(device)) continue;
      const v = parseInt(parts[2], 36);
      if (Number.isFinite(v) && v > max) max = v;
    }
    if (max > n) {
      n = max;
      try { localStorage.setItem(SEQ_KEY, String(n)); } catch { /* fluechtig */ }
    }
  };
  return factory;
}
