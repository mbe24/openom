// The launch-gate verify composer's decision logic (§B3), against a fake worker + keyring lookup. The
// crypto itself is Rust-tested (openom-crypto verify_entry / epoch_is_attributed); here we pin the
// composition: what's accepted vs rejected vs held, sourced from the (verified) keyring, not the entry.
import { describe, it, expect, vi } from 'vitest';
import { createEntryVerifier, RetryableVerifyError, SecurityVerifyError } from '../app/src/core/sealer/entryVerifier.js';

const KID = new Uint8Array([1, 2, 3]);

// A fake worker: entryAttribution returns canned header fields; epochIsAttributed + verifyEntry are
// configurable spies.
function fakeWorker({ keyringRevision = 3, attributed = true, verifyThrows = false } = {}) {
  return {
    entryAttribution: vi.fn(async () => ({ keyringRevision, keyId: KID })),
    epochIsAttributed: vi.fn(async () => attributed),
    verifyEntry: vi.fn(async () => {
      if (verifyThrows) throw new Error('author_signature does not verify');
    }),
  };
}

const KR = new Uint8Array([9]); // a stand-in governing keyring blob
const bytes = (...x) => new Uint8Array(x);

describe('createEntryVerifier', () => {
  it('accepts an unattributed V1 entry (keyring_revision 0) without touching the keyring or verifying', async () => {
    const worker = fakeWorker({ keyringRevision: 0 });
    const keyringAt = vi.fn(async () => null);
    const verify = createEntryVerifier({ version: 1, worker, keyringAt });
    await expect(verify(bytes(0xaa), bytes(1))).resolves.toBeUndefined();
    expect(keyringAt).not.toHaveBeenCalled();
    expect(worker.verifyEntry).not.toHaveBeenCalled();
  });

  it('accepts an entry under an UNattributed epoch (not shared) without verifying', async () => {
    const worker = fakeWorker({ attributed: false });
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => KR });
    await expect(verify(bytes(0xaa), bytes(1))).resolves.toBeUndefined();
    expect(worker.verifyEntry).not.toHaveBeenCalled();
  });

  it('verifies (and accepts) a valid entry under an attributed epoch, against the governing keyring', async () => {
    const worker = fakeWorker({ attributed: true, verifyThrows: false });
    const keyringAt = vi.fn(async (rev) => {
      expect(rev).toBe(3); // fetched the governing revision from the header
      return KR;
    });
    const verify = createEntryVerifier({ version: 1, worker, keyringAt });
    await expect(verify(bytes(0xaa), bytes(1))).resolves.toBeUndefined();
    expect(worker.verifyEntry).toHaveBeenCalledWith(1, expect.any(Uint8Array), expect.any(Uint8Array), KR);
  });

  it('REJECTS (throws) when verification fails under an attributed epoch', async () => {
    const worker = fakeWorker({ attributed: true, verifyThrows: true });
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => KR });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toThrow(/does not verify/);
  });

  it('HOLDS (retryable) when the governing keyring revision is not available yet', async () => {
    const worker = fakeWorker({ keyringRevision: 5 });
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => null });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toBeInstanceOf(RetryableVerifyError);
    expect(worker.verifyEntry).not.toHaveBeenCalled();
  });
});

describe('createEntryVerifier — shared tree (attributed-writes invariant)', () => {
  const shared = { hasBeenShared: async () => true, headRevision: async () => 5 };

  it('REJECTS an unattributed rev-0 entry HARD (not a retryable hold that would stall the tail)', async () => {
    const worker = fakeWorker({ keyringRevision: 0 });
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => null, ...shared });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toBeInstanceOf(SecurityVerifyError);
    expect(worker.verifyEntry).not.toHaveBeenCalled();
  });

  it('verifies EVERY entry — no accept-unsigned even when the epoch reads unattributed (closes H1)', async () => {
    const worker = fakeWorker({ keyringRevision: 3, attributed: false }); // epoch "unattributed", but the tree is shared
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => KR, ...shared });
    await expect(verify(bytes(0xaa), bytes(1))).resolves.toBeUndefined();
    expect(worker.epochIsAttributed).not.toHaveBeenCalled(); // the shared path never takes the accept-unsigned gate
    expect(worker.verifyEntry).toHaveBeenCalledWith(1, expect.any(Uint8Array), expect.any(Uint8Array), KR);
  });

  it('REJECTS (throws) when a signed entry fails verification', async () => {
    const worker = fakeWorker({ keyringRevision: 3, verifyThrows: true });
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => KR, ...shared });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toThrow(/does not verify/);
  });

  it('HOLDS (retryable) a missing governing revision at/below the verified head', async () => {
    const worker = fakeWorker({ keyringRevision: 4 }); // <= head (5)
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => null, ...shared });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toBeInstanceOf(RetryableVerifyError);
  });

  it('REJECTS a governing revision BEYOND the verified head (no unbounded tail-blocking hold)', async () => {
    const worker = fakeWorker({ keyringRevision: 99 }); // > head (5)
    const verify = createEntryVerifier({ version: 1, worker, keyringAt: async () => null, ...shared });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toBeInstanceOf(SecurityVerifyError);
  });

  it('is STICKY: once observed shared, a later keyring withhold cannot re-open the accept-unsigned path', async () => {
    const worker = fakeWorker({ keyringRevision: 0 });
    let isShared = true;
    const verify = createEntryVerifier({
      version: 1, worker, keyringAt: async () => null,
      hasBeenShared: async () => isShared, headRevision: async () => 5,
    });
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toBeInstanceOf(SecurityVerifyError); // shared → rev-0 rejected
    isShared = false; // the server withholds the share revision from this device
    await expect(verify(bytes(0xaa), bytes(1))).rejects.toBeInstanceOf(SecurityVerifyError); // still enforced
  });
});
