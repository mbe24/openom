// Slice 1 verifier for the engine swap: project the real Bach seed (the app's own fixture, 59 people /
// 14 families) into the treelog wasm engine and assert its read model reproduces the v2 model the views
// read — every scalar field, custom field, source record, relationship, and family fact. This turns the
// one-shot projection experiment into a standing regression test. Needs the built wasm
// (node scripts/build-treelog.mjs); skips cleanly when absent.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { seedOps } from '../app/src/core/seed.js';
import { mergePersonFields, definePersonViews, mergeFamilyFields, defineFamilyViews } from '../app/src/core/model.js';
import { createTree } from '../app/src/core/treelog/index.js';
import { projectV2, checkParity } from '../app/src/core/treelog/project.js';

const wasmUrl = new URL('../app/src/vendor/treelog/openom_treelog_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;

// Build the exact view-facing v2 objects from the seed, the way FamilyTree.hydrate would.
function v2FromSeed() {
  const people = new Map();
  const families = new Map();
  for (const o of seedOps()) {
    if (o.type === 'upsertPerson') people.set(o.id, definePersonViews(mergePersonFields(null, o.fields)));
    if (o.type === 'upsertFamily') families.set(o.id, defineFamilyViews(mergeFamilyFields(null, o.fields)));
  }
  return { people, families };
}

describe.skipIf(!built)('engine swap — v2 → treelog read-model parity (Bach seed)', () => {
  it('reproduces every field, relationship, family fact, and source the views read', async () => {
    const v2 = v2FromSeed();
    const tree = await createTree({ initInput });
    projectV2(tree, v2);
    const report = checkParity(tree, v2);
    // A readable failure: surface the first divergences, not just "false".
    expect(report.mismatches.slice(0, 20)).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.counts).toEqual({ people: 59, families: 14 });
    // Spot-check the two cases the earlier experiment could not cover: a family fact and a rich source.
    expect(tree.families().length).toBe(14);
    expect(tree.persons().length).toBe(59);
  });

  it('survives a snapshot rebuild with an identical read model', async () => {
    const v2 = v2FromSeed();
    const a = await createTree({ initInput });
    projectV2(a, v2);
    const b = await createTree({ initInput, snapshot: a.snapshot() });
    // The projected tree round-trips through commute's snapshot bytes unchanged.
    expect(b.persons().sort()).toEqual(a.persons().sort());
    expect(b.families().sort()).toEqual(a.families().sort());
    expect(checkParity(b, v2).ok).toBe(true);
  });
});
