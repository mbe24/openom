import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, {
  provision as wasmProvision,
  unlock as wasmUnlock,
  recover as wasmRecover,
  changePassphrase as wasmChangePassphrase,
} from '../app/src/vendor/sealer/openom_sealer.js';

// The REAL wasm sealer, driven directly (no fake worker): loads the vendored openom_sealer_bg.wasm and
// runs the passphrase lifecycle through it, selecting the engine by tag. This is the web host's half of
// OPE-278's "dag through both hosts" — the counterpart to the native VaultHost dag tests — proving the
// dag engine actually works end to end through the browser-facing wasm veneer, not just in native Rust.
//
// It runs under Node (vitest, like every *.int) because the wasm glue is engine-agnostic to the host: the
// only browser API it needs is globalThis.crypto.getRandomValues, which Node 22 provides. `--target web`
// glue's default init accepts the wasm bytes directly, so no fetch/URL loader is needed here.

const enc = new TextEncoder();
const dec = new TextDecoder();

const TREE = new Uint8Array(16).fill(7); // a fixed 16-byte tree id
const MEMBER = 'acct-1';
const replica = (n: number) => new Uint8Array(16).fill(n);

// Seal one snapshot entry with a live sealer, returning the envelope (and freeing the outcome).
function sealSnapshot(sealer: any, plaintext: string): Uint8Array {
  const out = sealer.sealEntry(
    'snapshot',
    'openom-json',
    'none',
    0,
    new Uint8Array(),
    0,
    new Uint8Array(),
    enc.encode(plaintext),
  );
  const envelope = out.envelope;
  out.free();
  return envelope;
}

beforeAll(async () => {
  const wasmUrl = new URL('../app/src/vendor/sealer/openom_sealer_bg.wasm', import.meta.url);
  let bytes: Buffer;
  try {
    bytes = readFileSync(fileURLToPath(wasmUrl));
  } catch (e) {
    // The vendored wasm is a gitignored build artifact — rebuild it whenever the sealer crate changes.
    throw new Error(
      'vendored sealer wasm not found — build it first: `pnpm build:sealer` (from apps/) or ' +
        `\`node scripts/build-sealer.mjs\` (from the repo root). (${(e as Error).message})`,
    );
  }
  await init({ module_or_path: bytes });
});

describe('the real wasm sealer runs the dag engine end to end (OPE-278)', () => {
  it('provisions, seals, unlocks on a fresh replica, and opens the same data', () => {
    const p = wasmProvision('dag', 'correct horse', TREE, MEMBER, replica(1));
    const anchor = p.keyring; // the opaque dag anchor to persist
    const didKey = p.didKey;
    expect(p.watermark.length).toBeGreaterThan(0); // an opaque frontier watermark, not a stub
    expect(p.needsReseal).toBe(false); // a fresh single-replica tree is not stale
    const sealerA = p.takeSealer();
    p.free();

    const envelope = sealSnapshot(sealerA, 'the family tree');
    sealerA.free(); // drop the DEK — as a lock would

    // A fresh replica unlocks from the anchor bytes alone and opens what device A sealed.
    const u = wasmUnlock('dag', anchor, 'correct horse', TREE, MEMBER, replica(2));
    expect(u.didKey).toBe(didKey); // same owner identity across provision + unlock
    const sealerB = u.takeSealer();
    u.free();
    expect(dec.decode(sealerB.openEntry('snapshot', envelope))).toBe('the family tree');
    sealerB.free();
  });

  it('changes the passphrase: the old is retired, the new opens pre-change data', () => {
    const p = wasmProvision('dag', 'old pass', TREE, MEMBER, replica(1));
    const anchor0 = p.keyring;
    const wm0 = p.watermark;
    const sealerA = p.takeSealer();
    p.free();
    const envelope = sealSnapshot(sealerA, 'keepsake');
    sealerA.free();

    // Retarget under a new passphrase, gated on the stored frontier as the floor.
    const re = wasmChangePassphrase('dag', anchor0, 'old pass', 'battery staple', TREE, MEMBER, replica(1), wm0);
    const anchor1 = re.keyring;
    re.free();

    // The NEW passphrase opens the rekeyed anchor (the DEK is unchanged); the OLD one no longer does.
    const u = wasmUnlock('dag', anchor1, 'battery staple', TREE, MEMBER, replica(2));
    const sealerB = u.takeSealer();
    u.free();
    expect(dec.decode(sealerB.openEntry('snapshot', envelope))).toBe('keepsake');
    sealerB.free();

    expect(() => wasmUnlock('dag', anchor1, 'old pass', TREE, MEMBER, replica(3))).toThrow();
  });

  it('recovers with the code under a new passphrase and opens pre-recovery data', () => {
    const p = wasmProvision('dag', 'old pass', TREE, MEMBER, replica(1));
    const anchor0 = p.keyring;
    const wm0 = p.watermark;
    const recoveryCode = p.recoveryCode;
    const didOld = p.didKey;
    const sealerA = p.takeSealer();
    p.free();
    const envelope = sealSnapshot(sealerA, 'heirloom');
    sealerA.free();

    const r = wasmRecover('dag', anchor0, recoveryCode, 'brand new pass', TREE, MEMBER, replica(2), wm0);
    expect(r.didKey).not.toBe(didOld); // recovery mints a fresh owner identity
    const sealerR = r.takeSealer();
    const anchor1 = r.keyring;
    r.free();
    // The recovered sealer opens pre-recovery data — the DEK was re-wrapped, not rotated.
    expect(dec.decode(sealerR.openEntry('snapshot', envelope))).toBe('heirloom');
    sealerR.free();

    // And a fresh unlock with the new passphrase works against the recovered anchor.
    const u = wasmUnlock('dag', anchor1, 'brand new pass', TREE, MEMBER, replica(3));
    const sealerU = u.takeSealer();
    u.free();
    expect(dec.decode(sealerU.openEntry('snapshot', envelope))).toBe('heirloom');
    sealerU.free();
  });

  it('a wrong passphrase fails closed on the dag engine', () => {
    const p = wasmProvision('dag', 'right pass', TREE, MEMBER, replica(1));
    const anchor = p.keyring;
    p.takeSealer().free();
    p.free();
    expect(() => wasmUnlock('dag', anchor, 'wrong pass', TREE, MEMBER, replica(2))).toThrow();
  });
});

describe('the engine tag selects the engine in one wasm binary (OPE-278)', () => {
  it('runs the chain engine through the same binary, proving the tag is what switches it', () => {
    const p = wasmProvision('chain', 'correct horse', TREE, MEMBER, replica(1));
    const anchor = p.keyring;
    const sealerA = p.takeSealer();
    p.free();
    const envelope = sealSnapshot(sealerA, 'chain data');
    sealerA.free();

    const u = wasmUnlock('chain', anchor, 'correct horse', TREE, MEMBER, replica(2));
    const sealerB = u.takeSealer();
    u.free();
    expect(dec.decode(sealerB.openEntry('snapshot', envelope))).toBe('chain data');
    sealerB.free();
  });

  it('an unknown engine tag is rejected (the seam FromStr, surfaced through wasm)', () => {
    expect(() => wasmProvision('mosaic', 'pass', TREE, MEMBER, replica(1))).toThrow(
      /unknown keyring engine: mosaic/,
    );
  });
});
