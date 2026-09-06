// Slice-2 attributed writes (chain engine), driven directly against the REAL vendored wasm (no worker).
// Grows through Phase A; starts with the has_been_shared monotonic signal (A2).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, {
  provision as wasmProvision,
  provisionMember as wasmProvisionMember,
  addMember as wasmAddMember,
  removeMember as wasmRemoveMember,
  dagAddMember as wasmDagAddMember,
  keyringHasBeenShared as wasmKeyringHasBeenShared,
  entryAttribution as wasmEntryAttribution,
} from '../app/src/vendor/vault/openom_vault.js';

const enc = new TextEncoder();
const TREE = new Uint8Array(16).fill(7);
const OWNER = 'acct-owner';
const replica = (n: number) => new Uint8Array(16).fill(n);

// provision/addMember/removeMember return a VaultResult holding a sealer — read `.keyring`, then free.
function keyringOf(r: any): Uint8Array {
  const k = r.keyring;
  r.free();
  return k;
}

beforeAll(async () => {
  const wasmUrl = new URL('../app/src/vendor/vault/openom_vault_bg.wasm', import.meta.url);
  await init({ module_or_path: readFileSync(fileURLToPath(wasmUrl)) });
});

describe('keyringHasBeenShared — the monotonic shared signal (A2)', () => {
  it('is false for a never-shared solo tree, true once a member is admitted, and stays true after un-sharing', () => {
    const genesis = keyringOf(wasmProvision('chain', 'owner pass', TREE, OWNER, replica(1)));
    expect(wasmKeyringHasBeenShared('chain', genesis)).toBe(false); // solo → never shared

    // Admit an editor → the tree is now shared.
    const m = wasmProvisionMember('member pass');
    const shared = keyringOf(
      wasmAddMember(genesis, 'owner pass', TREE, OWNER, 1, 'acct-m', 'editor', m.authorPublic, m.hpkePublic),
    );
    m.free();
    expect(wasmKeyringHasBeenShared('chain', shared)).toBe(true);

    // Remove the only member → back to solo, but the signal is monotonic: still true.
    const solo = keyringOf(wasmRemoveMember(shared, 'owner pass', TREE, OWNER, 2, 'acct-m', replica(2)));
    expect(wasmKeyringHasBeenShared('chain', solo)).toBe(true); // un-shared, still requires attribution
  });

  // Phase C (OPE-351): the dag arm reads the resolved anchor's has_been_shared — a monotonic effective-Add scan.
  it('dag arm: false for a solo dag tree, true once a member is admitted', () => {
    const genesis = keyringOf(wasmProvision('dag', 'owner pass', TREE, OWNER, replica(1)));
    expect(wasmKeyringHasBeenShared('dag', genesis)).toBe(false); // solo → never shared

    // Admit an editor (dag Add op) → has_been_shared flips true. Note dag arg order: author key before hpke key.
    const m = wasmProvisionMember('member pass');
    const shared = keyringOf(
      wasmDagAddMember(genesis, 'owner pass', TREE, OWNER, replica(2), 'acct-m', 'editor', m.authorPublic, m.hpkePublic),
    );
    m.free();
    expect(wasmKeyringHasBeenShared('dag', shared)).toBe(true);
  });
});

describe('covers_through_seq round-trip (A4)', () => {
  it('a snapshot declares its coverage and it reads back through entryAttribution; a delta declares 0', () => {
    const p = wasmProvision('chain', 'owner pass', TREE, OWNER, replica(1));
    const sealer = p.takeSealer();
    p.free();

    // A snapshot sealed with covers_through_seq = 42 reads it back (AAD-bound).
    const snap = sealer.sealEntry('snapshot', 'openom-json', 'none', 0, new Uint8Array(), 42, new Uint8Array(), enc.encode('{}'));
    const sa = wasmEntryAttribution(snap.envelope);
    expect(sa.coversThroughSeq).toBe(42);
    sa.free();
    snap.free();

    // A delta subsumes nothing → 0.
    const delta = sealer.sealEntry('delta', 'openom-ops', 'none', 1, new Uint8Array(), 0, new Uint8Array(), enc.encode('[]'));
    const da = wasmEntryAttribution(delta.envelope);
    expect(da.coversThroughSeq).toBe(0);
    da.free();
    delta.free();
    sealer.free();
  });
});
