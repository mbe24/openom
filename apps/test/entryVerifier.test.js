// The launch-gate verify composer's decision logic (§B3), against a fake worker + keyring lookup. The
// crypto itself is Rust-tested (openom-crypto verify_entry / epoch_is_attributed); here we pin the
// composition: what's accepted vs rejected vs held, sourced from the (verified) keyring, not the entry.
import { describe, it, expect, vi } from 'vitest';
import { createEntryVerifier, RetryableVerifyError } from '../app/src/core/sealer/entryVerifier.js';

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
