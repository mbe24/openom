// The canonical-model JSON Schema (Draft 2020-12) validated from JS via ajv — the portable, single
// source of truth that the Rust side (openom-model, `jsonschema`) also checks. This locks that valid
// model / name instances pass and malformed ones fail, so the schema stays honest from both languages.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const loadSchema = (rel) => JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'));
const modelSchema = loadSchema('../../packages/openom-model/schema/model.schema.json');
const nameSchema = loadSchema('../../packages/openom-model/schema/name.schema.json');

// strict:false = spec behaviour (ignore unknown keywords like x-openom-bounds-version) rather than
// ajv's lint mode; ajv-formats supplies the `uuid` format assertion.
function compiler() {
  const a = new Ajv2020({ strict: false, allErrors: true });
  addFormats(a);
  return a;
}

const U = (n) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;

describe('canonical model JSON Schema (Draft 2020-12)', () => {
  it('accepts a valid model and rejects malformed ones', () => {
    const validate = compiler().compile(modelSchema);
    const model = {
      tree: U(1),
      nodes: { [U(2)]: { id: U(2), kind: 'Person' } },
      edges: {},
      events: {},
      sources: {},
      media: {},
      field_defs: {},
      field_values: {},
      cross_tree_links: {},
    };
    expect(validate(model)).toBe(true);

    expect(compiler().compile(modelSchema)({})).toBe(false); // missing required tables
    const bad = structuredClone(model);
    bad.nodes[U(2)].kind = 'Alien'; // illegal enum
    expect(compiler().compile(modelSchema)(bad)).toBe(false);
  });

  it('accepts a valid name and rejects a part without a tag', () => {
    const validate = compiler().compile(nameSchema);
    expect(
      validate({
        id: U(3),
        type: 'birth',
        parts: [
          { tag: 'given', value: 'Jane' },
          { tag: 'family', value: 'Austen' },
        ],
      }),
    ).toBe(true);
    expect(validate({ id: U(3), parts: [{ value: 'no tag' }] })).toBe(false);
  });
});
