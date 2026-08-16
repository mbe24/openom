import { describe, it, expect, vi } from 'vitest';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { ConflictError } from '../app/src/core/store.js';

// A minimal fetch Response stand-in.
function res({ status = 200, etag = null as string | null, body = new Uint8Array(), text = '' } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (n: string) => (n.toLowerCase() === 'etag' ? etag : null) },
    arrayBuffer: async () => body.buffer,
    text: async () => text,
  };
}

describe('RemoteStore', () => {
  it('readSnapshot returns bytes + unquoted version', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"abc-123"', body: new Uint8Array([1, 2, 3]) }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    const snap = await store.readSnapshot('tree-1');
    expect(Array.from(snap!.bytes)).toEqual([1, 2, 3]);
    expect(snap!.version).toBe('abc-123');
    expect(fetch).toHaveBeenCalledWith('http://x/trees/tree-1', expect.anything());
  });

  it('readSnapshot returns null on 404', async () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => res({ status: 404 }) });
    expect(await store.readSnapshot('t')).toBeNull();
  });

  it('putSnapshot returns the new version and omits If-Match on create', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"v-new"' }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    const v = await store.putSnapshot('t', new Uint8Array([9]), null);
    expect(v).toBe('v-new');
    const init = fetch.mock.calls[0][1] as any;
    expect(init.method).toBe('PUT');
    expect(init.headers['if-match']).toBeUndefined();
  });

  it('putSnapshot sends If-Match when expected is given', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"v2"' }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    await store.putSnapshot('t', new Uint8Array([9]), 'v1');
    const init = fetch.mock.calls[0][1] as any;
    expect(init.headers['if-match']).toBe('v1');
  });

  it('putSnapshot throws ConflictError on 409', async () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => res({ status: 409 }) });
    await expect(store.putSnapshot('t', new Uint8Array([1]), 'stale')).rejects.toBeInstanceOf(ConflictError);
  });

  it('attaches a bearer token when provided', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"v"' }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, token: 'jwt-abc' });
    await store.readSnapshot('t');
    const init = fetch.mock.calls[0][1] as any;
    expect(init.headers.authorization).toBe('Bearer jwt-abc');
  });

  it('caps reports remote + conditional + durable', () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => res() });
    expect(store.caps()).toEqual({ remote: true, conditionalWrites: true, durable: true });
  });

  it('readLog on a 404 (no log yet) returns an empty tail; list/delete stay unsupported', async () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => res({ status: 404 }) });
    expect(await store.readLog('t', -1)).toEqual({ entries: [], nextCursor: -1, oldestRetainedSeq: 0, headSeq: -1 });
    await expect(store.list()).rejects.toThrow();
    await expect(store.delete()).rejects.toThrow();
  });
});
