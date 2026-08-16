// Slice 1 of the engine swap: project the app's live v2 model (FamilyTree's in-memory people/families)
// into a treelog engine and check that treelog's read model reproduces exactly what the views read.
// This runs in SHADOW — it builds a throwaway engine, asserts parity, and persists nothing. It proves
// the projection on real data before any write path or view depends on it, and the same projector is
// the basis for the eventual migration.
//
// Representation note: this maps each view-read field to a single string-valued fact on the record's
// own id (person or family). That is enough for read-model parity — the getters the views call
// (person.given/.birth/…, family.spouses/.children/.facts) all reproduce. The richer sub-entity model
// (names/events/sources/media as first-class sub-entities with leaf facts) is a later slice; it changes
// the internal shape and merge granularity, not this parity contract. Ids are the record's string id as
// raw UTF-8 bytes — treelog ids are opaque and arbitrary-length, so no mapping table is needed.

const enc = new TextEncoder();

/** A v2 string id (`"p_jsb"`, `"f_veit"`) as treelog subject/entity id bytes. */
export const subjectId = (s) => enc.encode(s);
/** A stable claim id for the single claim a projected field carries (unique within its fact). */
const claimId = (field) => enc.encode('c:' + field);
/** Hex of id bytes, to compare against treelog's hex-string read model. */
const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// The person fields the views actually read, via the v2 derived getters. Field keys mirror the
// treelog conventions already used in tests ("name.given", "birth.date", …).
const PERSON_FIELDS = [
  ['name.given', (p) => p.given],
  ['name.surname', (p) => p.surname],
  ['sex', (p) => p.sex],
  ['birth.date', (p) => p.birth],
  ['birth.place', (p) => p.birthPlace],
  ['death.date', (p) => p.death],
  ['death.place', (p) => p.deathPlace],
  ['note', (p) => p.note ?? ''],
];

const nonEmpty = (v) => v !== '' && v != null;

/**
 * Project a v2 model into a treelog engine (the wrapped shim from `createTree`). Emits ops through the
 * shim; the caller owns the engine and discards it after the parity check.
 * @param {object} tree  wrapped treelog engine (has addPerson/addClaim/addFamily/linkSpouse/linkChild)
 * @param {{people: Map, families: Map}} v2  FamilyTree's read model (people/families with v2 getters)
 */
export function projectV2(tree, { people, families }) {
  for (const [id, p] of people) {
    const sid = subjectId(id);
    tree.addPerson(sid);
    for (const [field, get] of PERSON_FIELDS) {
      const v = get(p);
      if (nonEmpty(v)) tree.addClaim(sid, field, claimId(field), String(v), null);
    }
    for (const [k, v] of Object.entries(p.custom ?? {})) {
      if (nonEmpty(v)) tree.addClaim(sid, 'custom.' + k, claimId('custom.' + k), String(v), null);
    }
    // Person-level sources: flattened to one JSON claim each for now (the first-class source/citation
    // model rides with the sub-entity slice). Parity below checks they survive verbatim.
    (p.sources ?? []).forEach((s, i) => tree.addClaim(sid, 'source.' + i, claimId('source.' + i), JSON.stringify(s), null));
  }
  for (const [id, f] of families) {
    const fid = subjectId(id);
    tree.addFamily(fid);
    for (const s of f.spouses) tree.linkSpouse(fid, subjectId(s));
    for (const cl of f.childLinks) tree.linkChild(fid, subjectId(cl.id), cl.pedi ?? 'birth');
    // Family-level facts live on the family id (the subject-generalization from Slice 0a).
    if (nonEmpty(f.facts?.marriage)) tree.addClaim(fid, 'marriage.date', claimId('marriage.date'), String(f.facts.marriage), null);
    if (nonEmpty(f.facts?.place)) tree.addClaim(fid, 'marriage.place', claimId('marriage.place'), String(f.facts.place), null);
  }
}

/**
 * Dark shadow check for the engine swap: when `localStorage['openom.engine'] === 'shadow'`, project the
 * given (already-hydrated) FamilyTree into a throwaway treelog engine and log a read-model parity
 * report. Persists nothing, changes no view, and NEVER throws — a diagnostic must not break app load.
 * Off by default (flag unset) and a no-op on an empty tree.
 * @returns {Promise<null | {ok: boolean, mismatches: string[], counts: object}>}
 */
export async function shadowParity(familyTree) {
  let on = false;
  try {
    on = globalThis.localStorage?.getItem('openom.engine') === 'shadow';
  } catch {
    // no localStorage in this context — treat as off
  }
  if (!on || !familyTree || familyTree.people?.size === 0) return null;
  try {
    const { createTree } = await import('./index.js');
    const engine = await createTree({});
    const v2 = { people: familyTree.people, families: familyTree.families };
    projectV2(engine, v2);
    const report = checkParity(engine, v2);
    const tag = '[openom.engine=shadow]';
    if (report.ok) {
      console.log(`${tag} read-model parity OK — treelog reproduced ${report.counts.people} people and ${report.counts.families} families.`);
    } else {
      console.warn(`${tag} ${report.mismatches.length} parity mismatch(es); first few:`, report.mismatches.slice(0, 10));
    }
    return report;
  } catch (e) {
    console.warn('[openom.engine=shadow] parity check could not run:', e);
    return null;
  }
}

/**
 * Compare treelog's read model against the v2 model the views read. Returns every divergence rather
 * than throwing, so the caller can log a full report.
 * @returns {{ok: boolean, mismatches: string[], counts: {people: number, families: number}}}
 */
export function checkParity(tree, { people, families }) {
  const mismatches = [];
  const val = (sid, field) => {
    const f = tree.fact(sid, field);
    return f.preferred ? f.preferred.value : '';
  };
  for (const [id, p] of people) {
    const sid = subjectId(id);
    if (!tree.hasPerson(sid)) mismatches.push(`person ${id}: missing from engine`);
    for (const [field, get] of PERSON_FIELDS) {
      const expected = String(get(p) ?? '');
      const got = val(sid, field);
      if (got !== expected) mismatches.push(`${id}.${field}: '${expected}' != '${got}'`);
    }
    for (const [k, v] of Object.entries(p.custom ?? {})) {
      const got = val(sid, 'custom.' + k);
      if (got !== String(v)) mismatches.push(`${id}.custom.${k}: '${v}' != '${got}'`);
    }
    (p.sources ?? []).forEach((s, i) => {
      const got = val(sid, 'source.' + i);
      if (got !== JSON.stringify(s)) mismatches.push(`${id}.source.${i}: source record diverged`);
    });
  }
  for (const [id, f] of families) {
    const fid = subjectId(id);
    const spouseSet = new Set(tree.spouses(fid));
    for (const s of f.spouses) {
      if (!spouseSet.has(hexOf(subjectId(s)))) mismatches.push(`family ${id}: missing spouse ${s}`);
    }
    const kidMap = new Map(tree.children(fid).map((k) => [k.person, k.pedi]));
    for (const cl of f.childLinks) {
      const h = hexOf(subjectId(cl.id));
      const pedi = cl.pedi ?? 'birth';
      if (!kidMap.has(h)) mismatches.push(`family ${id}: missing child ${cl.id}`);
      else if (kidMap.get(h) !== pedi) mismatches.push(`family ${id}: child ${cl.id} pedigree '${pedi}' != '${kidMap.get(h)}'`);
    }
    if (nonEmpty(f.facts?.marriage) && val(fid, 'marriage.date') !== String(f.facts.marriage)) {
      mismatches.push(`family ${id}: marriage.date '${f.facts.marriage}' != '${val(fid, 'marriage.date')}'`);
    }
    if (nonEmpty(f.facts?.place) && val(fid, 'marriage.place') !== String(f.facts.place)) {
      mismatches.push(`family ${id}: marriage.place '${f.facts.place}' != '${val(fid, 'marriage.place')}'`);
    }
  }
  return { ok: mismatches.length === 0, mismatches, counts: { people: people.size, families: families.size } };
}
