import { describe, it, expect } from 'vitest';
import { createInvokeVault } from '../app/src/core/sealer/invokeSealer.js';

// A fake Tauri `invoke`: an in-memory stand-in for the openom-vault-host commands, enough to
// exercise the adapter's marshalling and its SealerSession integration without a real webview.
// "Sealing" just tags the bytes so "opening" can recover them; the point is the boundary, not
// the crypto (the crypto is cargo-tested in openom-vault-host).
function fakeInvoke() {
  let seq = 0;
  const sealers = new Set<string>();
  const keyrings = new Set<string>();
  const calls: Array<{ cmd: string; args: any }> = [];
  const invoke = async (cmd: string, args: any = {}) => {
    calls.push({ cmd, args });
    switch (cmd) {
      case 'vault_has_keyring':
        return keyrings.has(args.treeKey);
      case 'vault_provision': {
        keyrings.add(args.treeKey);
        const id = 's' + ++seq;
        sealers.add(id);
        return { sealerId: id, revision: 1, recoveryCode: 'CODE-1' };
      }
      case 'vault_unlock': {
        if (!keyrings.has(args.treeKey)) throw { code: 'no_keyring', message: 'no keyring' };
        const id = 's' + ++seq;
        sealers.add(id);
        return { sealerId: id, revision: 1 };
      }
      case 'vault_recover': {
        const id = 's' + ++seq;
        sealers.add(id);
        return { sealerId: id, revision: 2, recoveryCode: 'CODE-2' };
      }
      case 'vault_change_passphrase':
        return { revision: 2, recoveryCode: 'CODE-3' };
      case 'sealer_seal_entry': {
        if (!sealers.has(args.sealerId)) throw { code: 'unknown_sealer', message: 'gone' };
        return { envelope: [0xee, ...args.plaintext], ciphertextHash: [1, 2, 3] };
      }
      case 'sealer_open_entry': {
        if (!sealers.has(args.sealerId)) throw { code: 'unknown_sealer', message: 'gone' };
        return (args.envelope as number[]).slice(1); // strip the 0xee tag
      }
      case 'sealer_lock':
        sealers.delete(args.sealerId);
        return undefined;
      default:
        throw { code: 'internal', message: 'unknown cmd ' + cmd };
    }
  };
  return { invoke, calls, sealers };
}

const TREE = new Uint8Array([1, 2, 3, 4]);

describe('invoke vault adapter', () => {
  it('provisions, then seals + opens through the returned SealerSession', async () => {
    const { invoke, calls } = fakeInvoke();
    const vault = createInvokeVault(invoke);

    expect(await vault.hasKeyring('my-tree')).toBe(false);
    const { session, recoveryCode } = await vault.provision('my-tree', TREE, 'passphrase', 'owner');
    expect(recoveryCode).toBe('CODE-1');
    expect(await vault.hasKeyring('my-tree')).toBe(true);

    const envelope = await session.seal(new Uint8Array([9, 8, 7]), 'my-tree', { kind: 'snapshot' });
    expect(envelope).toBeInstanceOf(Uint8Array);
    const opened = await session.open(envelope, 'my-tree', { kind: 'snapshot' });
    expect(Array.from(opened)).toEqual([9, 8, 7]);

    // treeId crosses as a JSON number array, never a Uint8Array (which serde can't decode).
    const provisionCall = calls.find((c) => c.cmd === 'vault_provision')!;
    expect(Array.isArray(provisionCall.args.treeId)).toBe(true);
    expect(provisionCall.args.treeId).toEqual([1, 2, 3, 4]);
  });

  it('unlock returns a session; changePassphrase returns only a fresh code', async () => {
    const { invoke } = fakeInvoke();
    const vault = createInvokeVault(invoke);
    await vault.provision('my-tree', TREE, 'pass', 'owner');

    const unlocked = await vault.unlock('my-tree', TREE, 'pass', 'owner');
    expect(unlocked.session).toBeTruthy();
    expect('recoveryCode' in unlocked).toBe(false);

    const changed = await vault.changePassphrase('my-tree', TREE, 'pass', 'new', 'owner');
    expect(changed.recoveryCode).toBe('CODE-3');
    expect('session' in changed).toBe(false);
  });

  it('propagates the structured error code from a rejected command', async () => {
    const { invoke } = fakeInvoke();
    const vault = createInvokeVault(invoke);
    await expect(vault.unlock('missing-tree', TREE, 'pass', 'owner')).rejects.toMatchObject({
      code: 'no_keyring',
    });
  });

  it('a host-evicted sealer rejects unknown_sealer and dispatches openom:sealer-locked', async () => {
    const { invoke, sealers } = fakeInvoke();
    const vault = createInvokeVault(invoke);
    const { session } = await vault.provision('my-tree', TREE, 'pass', 'owner');

    const events: string[] = [];
    const prevDispatch = (globalThis as any).dispatchEvent;
    const prevCE = (globalThis as any).CustomEvent;
    (globalThis as any).CustomEvent = class {
      type: string;
      detail: unknown;
      constructor(type: string, opts?: { detail?: unknown }) {
        this.type = type;
        this.detail = opts?.detail;
      }
    };
    (globalThis as any).dispatchEvent = (e: any) => events.push(e.type);
    try {
      // Simulate the Rust host clearing its registry underneath us (mobile background-lock /
      // window teardown) — the JS session still thinks it's live.
      sealers.clear();
      await expect(session.seal(new Uint8Array([1]), 'my-tree', { kind: 'snapshot' })).rejects.toMatchObject({
        code: 'unknown_sealer',
      });
      expect(events).toContain('openom:sealer-locked');
    } finally {
      (globalThis as any).dispatchEvent = prevDispatch;
      (globalThis as any).CustomEvent = prevCE;
    }
  });
});
