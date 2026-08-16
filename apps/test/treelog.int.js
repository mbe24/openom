// Integration smoke test: the treelog wasm engine driven through the JS shim. Needs the built wasm
// (node scripts/build-treelog.mjs); skips cleanly when absent so a fresh checkout stays green.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTree } from '../app/src/core/treelog/index.js';

const wasmUrl = new URL('../app/src/vendor/treelog/openom_treelog_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;

describe.skipIf(!built)('treelog wasm engine (via the JS shim)', () => {
  it('applies edits and surfaces the sourced-claim model to JS', async () => {
    const t = await createTree({ initInput });
    const p = t.newId();
    t.addPerson(p);
    const c1 = t.newId();
    const c2 = t.newId();
    t.addClaim(p, 'birth.date', c1, '1901', 'gravestone');
    t.addClaim(p, 'birth.date', c2, '1903', 'parish record');

    expect(t.hasPerson(p)).toBe(true);
    const fact = t.fact(p, 'birth.date');
    // Both competing claims are retained (the M2 guarantee), all the way through to JS.
    expect(fact.claims.map((c) => c.value).sort()).toEqual(['1901', '1903']);
    expect(fact.preferred).not.toBeNull();
  });

  it('rebuilds from a snapshot with an identical read model', async () => {
    const a = await createTree({ initInput });
    const p = a.newId();
    a.addPerson(p);
    const fam = a.newId();
    a.addFamily(fam);
    a.linkChild(fam, p, 'adopted');

    const b = await createTree({ initInput, snapshot: a.snapshot() });
    expect(b.persons()).toEqual(a.persons());
    expect(b.children(fam)).toEqual([{ person: a.persons()[0], pedi: 'adopted' }]);
  });
});
