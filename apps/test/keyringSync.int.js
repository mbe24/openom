// The client keyring-sync foundation (B3): RemoteStore.readKeyring + vault.syncKeyring + hop framing.
// The trust decision (legitimate successor vs fork/rollback/withheld hop) lives in the sealer wasm's
// acceptRemoteKeyring (Rust, already reviewed + proptested in openom-crypto/chain.rs), so here we cover
// the WIRING adversarially: that a rejection leaves stored state untouched, that only worker-validated
// heads are persisted + watermarked (monotonic), and that hops are framed in the exact wire shape the
// wasm decodes.
import { describe, it, expect } from 'vitest';
import { createVault, frameHops } from '../app/src/core/sealer/vault.js';
import { memoryKeyringStore } from '../app/src/core/sealer/keyringStore.js';
import { Watermarks } from '../app/src/core/watermarks.js';
import { RemoteStore } from '../app/src/core/remoteStore.js';

const bytes = (...xs) => new Uint8Array(xs);
// The chain watermark is the 4-byte big-endian revision (what the neutral cursor carries now).
const be32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};
const revOf = (cursor) =>
  cursor && cursor.length >= 4 ? new DataView(cursor.buffer, cursor.byteOffset, 4).getUint32(0, false) : 0;

// A 52-byte pinned chain watermark: revision(4) ‖ write-epoch pin key_id(16)‖H(DEK)(32) (OPE-286 phase 2).
const pinnedWm = (rev, fill = 0xab) => {
  const b = new Uint8Array(4 + 48).fill(fill);
  b.set(be32(rev), 0);
  return b;
};

// Inverse of frameHops — [u32-BE len][bytes]… → parts. Used to assert the client framed correctly.
function unframe(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out = [];
  let off = 0;
  while (off < buf.length) {
    const n = dv.getUint32(off, false);
    off += 4;
    out.push(buf.slice(off, off + n));
    off += n;
  }
  return out;
}

describe('frameHops', () => {
  it('length-prefixes each revision big-endian and concatenates in order', () => {
    const framed = frameHops([bytes(1, 2, 3), bytes(9)]);
    expect(Array.from(framed)).toEqual([0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 1, 9]);
    expect(unframe(framed).map((u) => Array.from(u))).toEqual([[1, 2, 3], [9]]);
  });
  it('empty input → empty buffer', () => {
    expect(frameHops([]).length).toBe(0);
  });
});

// A fake crypto worker exposing only acceptRemoteKeyring. It un-frames the hops (so the test proves the
// client framed them correctly) and stands in for the Rust trust decision: on success returns the last
// hop as the validated head; when constructed to reject, throws like verify_walk on a fork/rollback.
function fakeWorker({ reject = false, headRevision = 3 } = {}) {
  const state = { calls: 0, seen: null };
  return {
    state,
    async acceptRemoteKeyring(_anchor, _treeId, hops) {
      state.calls++;
      if (reject) throw new Error('keyring chain refused (fork/rollback)');
      state.seen = unframe(hops);
      return { keyring: state.seen[state.seen.length - 1], watermark: be32(headRevision) };
    },
  };
}

describe('vault.syncKeyring', () => {
  const treeKey = 'k1';
  const treeId = new Uint8Array(16);

  async function setup(worker) {
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    await keyringStore.saveHead(treeKey, 'chain', bytes(7, 7)); // the unlock anchor (head record) …
    await keyringStore.save(treeKey, 1, bytes(7, 7)); // … retained at revision 1 (chain §B3) …
    watermarks.observe(treeKey, { keyringCursor: be32(1) }); // … cursor at revision 1
    const vault = createVault({ worker, keyringStore, watermarks });
    return { vault, keyringStore, watermarks };
  }

  it('adopts a verified successor: persists the validated head + advances the watermark, framing correctly', async () => {
    const worker = fakeWorker({ headRevision: 3 });
    const { vault, keyringStore, watermarks } = await setup(worker);
    const r = await vault.syncKeyring(treeKey, treeId, async (since) => {
      expect(since).toBe(1); // fetches successors AFTER our current revision
      return [
        { revision: 2, bytes: bytes(2, 2) },
        { revision: 3, bytes: bytes(3, 3) },
      ];
    });
    expect(r).toEqual({ revision: 3, changed: true });
    expect(Array.from(await keyringStore.load(treeKey))).toEqual([3, 3]); // head = the newest revision
    expect(revOf(watermarks.current(treeKey).keyringCursor)).toBe(3);
    expect(worker.state.seen.map((u) => Array.from(u))).toEqual([[2, 2], [3, 3]]); // framing round-tripped
    // Every validated revision is RETAINED (governs entries stamped at it) — not just the head.
    expect(Array.from(await keyringStore.at(treeKey, 2))).toEqual([2, 2]);
    expect(Array.from(await keyringStore.at(treeKey, 3))).toEqual([3, 3]);
    expect(Array.from(await keyringStore.at(treeKey, 1))).toEqual([7, 7]); // the original anchor stays
  });

  it('carries the recover pin forward across a sync (OPE-286 phase 2): the accept path advances the revision but keeps the write-epoch pin', async () => {
    const worker = fakeWorker({ headRevision: 3 }); // wasm returns a bare-revision watermark
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    await keyringStore.saveHead(treeKey, 'chain', bytes(7, 7));
    await keyringStore.save(treeKey, 1, bytes(7, 7));
    const pin = pinnedWm(1);
    watermarks.observe(treeKey, { keyringCursor: pin }); // a pinned cursor from the last unlock/recover
    const vault = createVault({ worker, keyringStore, watermarks });
    await vault.syncKeyring(treeKey, treeId, async () => [{ revision: 3, bytes: bytes(3, 3) }]);
    const cursor = watermarks.current(treeKey).keyringCursor;
    expect(cursor.length).toBe(4 + 48); // still pinned — NOT erased to a bare revision
    expect(revOf(cursor)).toBe(3); // advanced to the synced head
    expect(Array.from(cursor.subarray(4))).toEqual(Array.from(pin.subarray(4))); // same pin carried forward
  });

  it('nothing newer → no-op: no verify call, stored keyring + watermark unchanged', async () => {
    const worker = fakeWorker();
    const { vault, keyringStore, watermarks } = await setup(worker);
    const r = await vault.syncKeyring(treeKey, treeId, async () => []);
    expect(r).toEqual({ revision: 1, changed: false });
    expect(worker.state.calls).toBe(0);
    expect(Array.from(await keyringStore.load(treeKey))).toEqual([7, 7]);
    expect(revOf(watermarks.current(treeKey).keyringCursor)).toBe(1);
  });

  it('a refused chain (fork/rollback from a hostile server) leaves stored keyring + watermark UNTOUCHED', async () => {
    const worker = fakeWorker({ reject: true });
    const { vault, keyringStore, watermarks } = await setup(worker);
    await expect(vault.syncKeyring(treeKey, treeId, async () => [{ revision: 2, bytes: bytes(9) }])).rejects.toThrow(/refused/);
    expect(Array.from(await keyringStore.load(treeKey))).toEqual([7, 7]); // NOT overwritten
    expect(revOf(watermarks.current(treeKey).keyringCursor)).toBe(1); // NOT advanced
  });
});

describe('RemoteStore.readKeyring', () => {
  const b64 = (arr) => btoa(String.fromCharCode(...arr));

  it('parses the revision chain + head, base64-decoding payloads, and fetches from the given cursor', async () => {
    const rs = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async (url) => {
        expect(url).toBe('http://x/trees/t1/keyring?from=2');
        return { ok: true, status: 200, json: async () => ({ revisions: [{ revision: 2, payload: b64([5, 6]) }], head: 2 }) };
      },
    });
    const r = await rs.readKeyring('t1', 2);
    expect(r.head).toBe(2);
    expect(r.revisions.map((x) => ({ revision: x.revision, bytes: Array.from(x.bytes) }))).toEqual([{ revision: 2, bytes: [5, 6] }]);
  });

  it('404 (no keyring yet) → empty chain', async () => {
    const rs = new RemoteStore({ baseUrl: 'http://x', fetch: async () => ({ ok: false, status: 404 }) });
    expect(await rs.readKeyring('t1')).toEqual({ revisions: [], head: 0 });
  });
});

describe('vault.adoptReset (recovery/succession)', () => {
  const treeKey = 'k1';
  const treeId = new Uint8Array(16);

  async function setup(worker) {
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    await keyringStore.saveHead(treeKey, 'chain', bytes(7, 7)); // the unlock anchor (head record)
    await keyringStore.save(treeKey, 1, bytes(7, 7)); // retained at rev 1 (chain §B3)
    watermarks.observe(treeKey, { keyringCursor: be32(1) });
    const vault = createVault({ worker, keyringStore, watermarks });
    return { vault, keyringStore, watermarks };
  }

  it('adopts a validated reset after OOB confirm: stores it + advances the watermark', async () => {
    // The worker (Rust) has validated the reset chains onto the trusted head; this asserts the vault
    // persists + watermarks it. (The OOB signer re-verification is the caller's job, before this.)
    const worker = { acceptResetKeyring: async (_a, _t, candidate) => ({ keyring: candidate, watermark: be32(2) }) };
    const { vault, keyringStore, watermarks } = await setup(worker);
    const r = await vault.adoptReset(treeKey, treeId, bytes(2, 2));
    expect(r).toEqual({ revision: 2 });
    expect(Array.from(await keyringStore.at(treeKey, 2))).toEqual([2, 2]);
    expect(revOf(watermarks.current(treeKey).keyringCursor)).toBe(2);
  });

  it('carries the recover pin forward across a reset (OPE-286 phase 2)', async () => {
    const worker = { acceptResetKeyring: async (_a, _t, candidate) => ({ keyring: candidate, watermark: be32(2) }) };
    const keyringStore = memoryKeyringStore();
    const watermarks = new Watermarks();
    await keyringStore.saveHead(treeKey, 'chain', bytes(7, 7));
    await keyringStore.save(treeKey, 1, bytes(7, 7));
    const pin = pinnedWm(1);
    watermarks.observe(treeKey, { keyringCursor: pin });
    const vault = createVault({ worker, keyringStore, watermarks });
    await vault.adoptReset(treeKey, treeId, bytes(2, 2));
    const cursor = watermarks.current(treeKey).keyringCursor;
    expect(cursor.length).toBe(4 + 48);
    expect(revOf(cursor)).toBe(2);
    expect(Array.from(cursor.subarray(4))).toEqual(Array.from(pin.subarray(4)));
  });

  it('a candidate that is not a valid reset onto the head is refused; stored state untouched', async () => {
    const worker = {
      acceptResetKeyring: async () => {
        throw new Error('reset does not chain onto the trusted head');
      },
    };
    const { vault, keyringStore, watermarks } = await setup(worker);
    await expect(vault.adoptReset(treeKey, treeId, bytes(9))).rejects.toThrow(/does not chain/);
    expect(Array.from(await keyringStore.load(treeKey))).toEqual([7, 7]); // head unchanged
    expect(revOf(watermarks.current(treeKey).keyringCursor)).toBe(1); // not advanced
  });
});
