import { describe, it, expect } from 'vitest';
import { replicaId, deviceId } from '../app/src/core/identity.js';

// §8: replica_id must be a >=128-bit CSPRNG value, per-(tree, context), never derived
// from the machine-stable deviceId().
describe('replicaId (§8)', () => {
  it('is a 16-byte (128-bit) value', () => {
    expect(replicaId('tree-a')).toBeInstanceOf(Uint8Array);
    expect(replicaId('tree-a').length).toBe(16);
  });

  it('is stable per tree within a context', () => {
    expect(replicaId('tree-a')).toBe(replicaId('tree-a'));
  });

  it('differs across trees (independent random per tree)', () => {
    expect(Array.from(replicaId('tree-b'))).not.toEqual(Array.from(replicaId('tree-c')));
  });

  it('is not derived from deviceId()', () => {
    // deviceId is a short base36 string; replica_id is 16 random bytes — unrelated.
    const bytesHex = [...replicaId('tree-d')].map((b) => b.toString(16).padStart(2, '0')).join('');
    expect(bytesHex).not.toContain(deviceId());
    expect(bytesHex.length).toBe(32);
  });

  it('is not all-zero (RNG actually ran)', () => {
    expect([...replicaId('tree-e')].some((b) => b !== 0)).toBe(true);
  });
});
