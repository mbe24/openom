import { describe, it, expect, beforeAll } from 'vitest';
import fc from 'fast-check';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createClaimTree } from '../app/src/core/tree/index.js';
import { ClaimFamilyTree } from '../app/src/core/claimFamilyTree.js';
import { SealedStore } from '../app/src/core/sealedStore.js';
import { MemoryStore } from '../app/src/core/store.js';

// The claim engine written through an encrypting store must re-hydrate intact in a fresh instance (a
// reload) — this is the "make it real": a user's own sealed-at-rest tree, not just the in-memory demo.
// The sealer here faithfully models the WASM sealer's byte contract: seal takes a Uint8Array; ANYTHING
// ELSE coerces to empty bytes (exactly as wasm-bindgen's &[u8] does), so a caller that hands the store a
// non-byte payload fails here the same way it would in the browser. The engine's edit deltas and
// snapshots are Uint8Array, so they pass through cleanly — that's what this guards.

const wasmUrl = new URL('../app/src/vendor/tree/openom_tree_bg.wasm', import.meta.url);
const built = fs.existsSync(fileURLToPath(wasmUrl));
const initInput = built ? { module_or_path: fs.readFileSync(fileURLToPath(wasmUrl)) } : undefined;
beforeAll(async () => { if (built) await createClaimTree({ initInput }); });

function byteSealer() {
  const MARK = 0xe5; // proves the bytes actually passed through seal(), not a bypass
  return {
    async seal(pt: unknown) {
      const body = pt instanceof Uint8Array ? pt : new Uint8Array(0);
      const out = new Uint8Array(body.length + 1);
      out[0] = MARK;
      out.set(body, 1);
      return out;
    },
    async open(sealed: Uint8Array) {
      const b = sealed instanceof Uint8Array ? sealed : new Uint8Array(sealed);
      if (b[0] !== MARK) throw new Error('not sealed by this sealer');
      return b.slice(1);
    },
  };
}

const sealedStore = () => new SealedStore(new MemoryStore(), byteSealer());

async function reload(store: any, doc: string) {
  const t = new ClaimFamilyTree(store, doc, null, 'did:key:zLocal');
  await t.hydrate();
  return t;
}

describe.skipIf(!built)('persistence through an encrypting store (claim engine)', () => {
  it('re-hydrates deltas written through the sealer (the reload path)', async () => {
    const store = sealedStore();
    const a = new ClaimFamilyTree(store, 'tree-1', null, 'did:key:zLocal');
    await a.hydrate();
    const ada = await a.createPerson({ given: 'Ada', surname: 'Lovelace', birth: '1815' });
    const bea = await a.createPerson({ given: 'Bea' });

    const b = await reload(store, 'tree-1');
    expect(b.person(ada.id)?.given).toBe('Ada');
    expect(b.person(ada.id)?.birth).toBe('1815');
    expect(b.person(bea.id)?.given).toBe('Bea');
    expect(b.allPeople().length).toBe(2);
  });

  it('re-hydrates through a snapshot too (the compact path)', async () => {
    const store = sealedStore();
    const a = new ClaimFamilyTree(store, 'tree-2', null, 'did:key:zLocal');
    await a.hydrate();
    const solo = await a.createPerson({ given: 'Solo' });
    await a.compact();

    const b = await reload(store, 'tree-2');
    expect(b.person(solo.id)?.given).toBe('Solo');
    expect(b.allPeople().length).toBe(1);
  });

  it('survives arbitrary edit sequences and re-hydrates to the same state (fuzz)', async () => {
    // The model trims + whitespace-splits given names (model.js), so a name only round-trips unchanged
    // if it has no whitespace — generate letters-only names to compare cleanly.
    const nameArb = fc
      .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'.split('')), { minLength: 1, maxLength: 6 })
      .map((cs) => cs.join(''));
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.oneof(
            fc.record({ k: fc.constant('add'), given: nameArb }),
            fc.record({ k: fc.constant('rename'), i: fc.nat(), given: nameArb }),
            fc.record({ k: fc.constant('del'), i: fc.nat() }),
            fc.record({ k: fc.constant('compact') }),
          ),
          { minLength: 1, maxLength: 20 },
        ),
        async (steps) => {
          const store = sealedStore();
          const doc = 'fuzz';
          const a = new ClaimFamilyTree(store, doc, null, 'did:key:zLocal');
          await a.hydrate();
          const ids: string[] = [];
          const oracle = new Map<string, string>(); // id -> given, live people only

          for (const s of steps as any[]) {
            if (s.k === 'add') {
              const p = await a.createPerson({ given: s.given });
              ids.push(p.id);
              oracle.set(p.id, s.given);
            } else if (s.k === 'rename' && ids.length) {
              const id = ids[s.i % ids.length];
              if (oracle.has(id)) {
                await a.updatePerson(id, { given: s.given });
                oracle.set(id, s.given);
              }
            } else if (s.k === 'del' && ids.length) {
              const id = ids[s.i % ids.length];
              if (oracle.has(id)) {
                await a.deletePerson(id);
                oracle.delete(id);
              }
            } else if (s.k === 'compact') {
              await a.compact();
            }
          }

          const b = await reload(store, doc);
          expect(b.allPeople().length).toBe(oracle.size);
          for (const [id, given] of oracle) expect(b.person(id)?.given).toBe(given);
        },
      ),
      { numRuns: 100 },
    );
  });
});
