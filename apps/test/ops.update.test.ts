import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { encodeUpdate, decodeUpdate, SCHEMA_VERSION, FutureVersionError } from '../app/src/core/ops.js';

// An update must be one opaque Uint8Array: the store — and the sealer layered above it —
// treat it as bytes and nothing else. An earlier version returned a `{ bytes, meta }`
// object, which a plaintext store accepted but the encryption layer could not (sealing a
// plain object as a byte slice yields empty ciphertext and drops `meta`). These pin the
// byte contract so that regression can't return silently.

// fullUnicode avoids lone surrogates, which UTF-8 encoding would replace — so the round
// trip is exact for every generated value.
const str = (max: number) => fc.fullUnicodeString({ maxLength: max });
const opsArb = fc.array(
  fc.record({
    type: fc.constantFrom('upsertPerson', 'deletePerson', 'upsertFamily'),
    id: str(12),
    fields: fc.dictionary(str(8), fc.oneof(str(12), fc.integer(), fc.boolean())),
  }),
  { maxLength: 8 },
);

describe('encodeUpdate / decodeUpdate — opaque byte update', () => {
  it('encodeUpdate returns a Uint8Array (the store + sealer byte contract)', () => {
    fc.assert(
      fc.property(opsArb, fc.hexaString({ maxLength: 12 }), fc.nat(), (ops, dev, lamport) => {
        expect(encodeUpdate(ops, dev, lamport)).toBeInstanceOf(Uint8Array);
      }),
    );
  });

  it('round-trips ops and provenance through encode → decode', () => {
    fc.assert(
      fc.property(opsArb, fc.hexaString({ maxLength: 12 }), fc.nat(), (ops, dev, lamport) => {
        const { ops: back, meta } = decodeUpdate(encodeUpdate(ops, dev, lamport));
        expect(back).toEqual(ops);
        expect(meta.device_id).toBe(dev);
        expect(meta.lamport).toBe(lamport);
        expect(meta.schema_version).toBe(SCHEMA_VERSION);
      }),
    );
  });

  it('decodes from a plain byte array too (what a store may hand back)', () => {
    const u = encodeUpdate([{ type: 'upsertPerson', id: 'p1', fields: { given: 'Ada' } }], 'd', 3);
    expect(decodeUpdate(Array.from(u)).ops[0].fields.given).toBe('Ada');
  });

  it('refuses an update from a newer schema', () => {
    const future = new TextEncoder().encode(
      JSON.stringify({ ops: [], meta: { schema_version: SCHEMA_VERSION + 1 } }),
    );
    expect(() => decodeUpdate(future)).toThrow(FutureVersionError);
  });
});
