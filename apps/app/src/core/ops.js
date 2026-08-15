// Ops sind die einzige Schreibform. Der Store sieht sie nur als Bytes —
// spaeter ersetzt ein Yrs-Update den Inhalt, ohne dass Aufrufer sich aendern.
//
// SCHEMA_VERSION zaehlt die Op-Sprache, DOC_VERSION die Form des Dokuments
// (siehe DATA-MODEL-V2.md). Beides steht in jeder geschriebenen Einheit, damit
// eine aeltere App eine neuere Datei erkennt statt sie still falsch zu lesen.
export const SCHEMA_VERSION = 2;
export const DOC_VERSION = 2;

/** Op-Arten, die diese App versteht. Alles andere ist eine neuere Datei. */
export const KNOWN_OPS = new Set([
  'upsertPerson', 'deletePerson',
  'upsertFamily', 'deleteFamily',
  'linkChild', 'unlinkChild', 'linkSpouse', 'unlinkSpouse',
  'upsertMedia', 'deleteMedia', 'upsertMediaLink', 'deleteMediaLink'
]);

export function op(type, payload) {
  return { type, ...payload };
}

// One update = one opaque byte blob. The store (and the sealer above it) treat it as
// bytes and nothing else — so ops AND provenance must live *inside* the bytes, not beside
// them in a structured record. An earlier version returned `{ bytes, meta }`, which a
// plaintext store happened to accept but the encryption layer could not: sealing a plain
// object as a byte slice yields empty ciphertext and silently drops `meta`. Everything is
// in the JSON payload now, so the whole update — ops and metadata alike — is encrypted.
export function encodeUpdate(ops, deviceId, lamport) {
  const payload = {
    ops,
    meta: {
      device_id: deviceId, lamport, created_at: Date.now(),
      schema_version: SCHEMA_VERSION, doc_version: DOC_VERSION
    }
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

/**
 * Gibt Ops **und** Herkunft zurueck. Ohne die Herkunft kann das Anwenden nicht
 * entscheiden, ob eine Aenderung aelter ist als ein Grabstein.
 */
export function decodeUpdate(update) {
  const bytes = update instanceof Uint8Array ? update : new Uint8Array(update);
  const { ops, meta = {} } = JSON.parse(new TextDecoder().decode(bytes));
  const v = meta.schema_version;
  // Fehlt die Angabe, stammt der Eintrag aus der ersten Fassung — die ist
  // lesbar. Ist sie hoeher als unsere, ist sie es nicht.
  if (v != null && v > SCHEMA_VERSION) {
    throw new FutureVersionError('update', v, SCHEMA_VERSION);
  }
  return { ops, meta };
}

/**
 * Eine Datei aus der Zukunft. Wird nicht verschluckt: der Baum oeffnet dann
 * schreibgeschuetzt, statt die unbekannten Aenderungen beim naechsten Speichern
 * zu ueberschreiben.
 */
export class FutureVersionError extends Error {
  constructor(what, found, supported) {
    super('This ' + what + ' was written by a newer version of openom (' +
      found + ' > ' + supported + ').');
    this.name = 'FutureVersionError';
    this.what = what;
    this.found = found;
    this.supported = supported;
  }
}
