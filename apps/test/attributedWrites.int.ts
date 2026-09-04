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
  keyringHasBeenShared as wasmKeyringHasBeenShared,
} from '../app/src/vendor/vault/openom_vault.js';

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
    expect(wasmKeyringHasBeenShared(genesis)).toBe(false); // solo → never shared

    // Admit an editor → the tree is now shared.
    const m = wasmProvisionMember('member pass');
    const shared = keyringOf(
      wasmAddMember(genesis, 'owner pass', TREE, OWNER, 1, 'acct-m', 'editor', m.hpkePublic, m.authorPublic),
    );
    m.free();
    expect(wasmKeyringHasBeenShared(shared)).toBe(true);

    // Remove the only member → back to solo, but the signal is monotonic: still true.
    const solo = keyringOf(wasmRemoveMember(shared, 'owner pass', TREE, OWNER, 2, 'acct-m', replica(2)));
    expect(wasmKeyringHasBeenShared(solo)).toBe(true); // un-shared, still requires attribution
  });
});
