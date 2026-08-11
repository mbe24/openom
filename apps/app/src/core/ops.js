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

export function encodeUpdate(ops, deviceId, lamport) {
  const bytes = new TextEncoder().encode(JSON.stringify(ops));
  return {
    bytes: Array.from(bytes),
    meta: {
      device_id: deviceId, lamport, created_at: Date.now(),
      schema_version: SCHEMA_VERSION, doc_version: DOC_VERSION
    }
  };
}

/**
 * Gibt Ops **und** Herkunft zurueck. Ohne die Herkunft kann das Anwenden nicht
 * entscheiden, ob eine Aenderung aelter ist als ein Grabstein.
 */
export function decodeUpdate(update) {
  const meta = update?.meta ?? {};
  const v = meta.schema_version;
  // Fehlt die Angabe, stammt der Eintrag aus der ersten Fassung — die ist
  // lesbar. Ist sie hoeher als unsere, ist sie es nicht.
  if (v != null && v > SCHEMA_VERSION) {
    throw new FutureVersionError('update', v, SCHEMA_VERSION);
  }
  const bytes = update.bytes instanceof Uint8Array ? update.bytes : new Uint8Array(update.bytes);
  return { ops: JSON.parse(new TextDecoder().decode(bytes)), meta };
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
