import { describe, it, expect, beforeEach } from 'vitest';
import { getSealer, forgetSealer, _resetSealerRegistry } from '../app/src/core/sealer/index.js';

// A minimal core satisfying the SealerSession contract; a fresh id per build lets us tell
// two distinct cores apart.
let built = 0;
const makeCore = () => {
  built += 1;
  const id = built;
  return Promise.resolve({
    id,
    treeId: new Uint8Array([id]),
    sealEntry: () => ({ envelope: new Uint8Array(), ciphertextHash: new Uint8Array() }),
    openEntry: () => new Uint8Array(),
  });
};

describe('sealer registry (§8a singleton per tree)', () => {
  beforeEach(() => {
    _resetSealerRegistry();
    built = 0;
  });

  it('returns the SAME session for one tree (no second replica/counter lineage)', async () => {
    const a = await getSealer('tree-1', makeCore);
    const b = await getSealer('tree-1', makeCore);
    expect(a).toBe(b);
    expect(built).toBe(1); // makeCore ran once — no second core built
  });

  it('builds a distinct session per tree', async () => {
    const a = await getSealer('tree-1', makeCore);
    const b = await getSealer('tree-2', makeCore);
    expect(a).not.toBe(b);
    expect(built).toBe(2);
  });

  it('forgetSealer forces a fresh session on the next open', async () => {
    const a = await getSealer('tree-1', makeCore);
    forgetSealer('tree-1');
    const b = await getSealer('tree-1', makeCore);
    expect(a).not.toBe(b);
    expect(built).toBe(2);
  });
});
