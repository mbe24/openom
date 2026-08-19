// The canonical-model JSON Schema (Draft 2020-12) validated from JS via ajv — the portable, single
// source of truth that the Rust side (openom-model, `jsonschema`) also checks. The model schema
// $refs the name fragment by $id, so the name schema is registered before compiling the model.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const loadSchema = (rel) => JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'));
const modelSchema = loadSchema('../../packages/openom-model/schema/model.schema.json');
const nameSchema = loadSchema('../../packages/openom-model/schema/name.schema.json');

// strict:false = spec behaviour (ignore unknown keywords like x-openom-bounds-version); ajv-formats
// supplies the `uuid` format assertion.
function ajv() {
  const a = new Ajv2020({ strict: false, allErrors: true });
  addFormats(a);
  return a;
}
const modelValidator = () => {
  const a = ajv();
  a.addSchema(nameSchema); // register the fragment by its $id so the model's $ref resolves
  return a.compile(modelSchema);
};
const nameValidator = () => ajv().compile(nameSchema);

const U = (n) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;

describe('canonical model JSON Schema (Draft 2020-12)', () => {
  it('accepts a valid model with an embedded name and rejects malformed ones', () => {
    const validate = modelValidator();
    const model = {
      tree: U(1),
      nodes: {
        [U(2)]: {
          id: U(2),
          kind: 'Person',
          names: [
            {
              id: U(9),
              type: 'birth',
              parts: [
                { tag: 'given', value: 'Jane' },
                { tag: 'family', value: 'Austen' },
              ],
            },
          ],
        },
      },
      edges: {},
      events: {},
      sources: {},
      media: {},
      field_defs: {},
      field_values: {},
      cross_tree_links: {},
    };
    expect(validate(model)).toBe(true);

    expect(modelValidator()({})).toBe(false); // missing required tables
    const badKind = structuredClone(model);
    badKind.nodes[U(2)].kind = 'Alien';
    expect(modelValidator()(badKind)).toBe(false); // illegal enum
    const badName = structuredClone(model);
    badName.nodes[U(2)].names[0].parts[0] = { value: 'no tag' };
    expect(modelValidator()(badName)).toBe(false); // embedded name validated via the $ref
  });

  it('accepts a valid name and rejects a part without a tag', () => {
    const validate = nameValidator();
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
