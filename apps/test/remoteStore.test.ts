import { describe, it, expect, vi } from 'vitest';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { ConflictError, AuthError } from '../app/src/core/store.js';

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

// A JSON Response stand-in (for endpoints the caller reads via res.json()).
function jsonRes({ status = 200, json = {} as any } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
    json: async () => json,
    text: async () => JSON.stringify(json),
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

  it('fetches the bearer PER REQUEST from the AuthSession seam (never captured at construction)', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"v"' }));
    // A seam whose token rotates between calls — a construction-time token would strand the second.
    let n = 0;
    const auth = { getAccessToken: vi.fn(async () => `jwt-${++n}`) };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    await store.readSnapshot('t');
    await store.readSnapshot('t');
    expect((fetch.mock.calls[0][1] as any).headers.authorization).toBe('Bearer jwt-1');
    expect((fetch.mock.calls[1][1] as any).headers.authorization).toBe('Bearer jwt-2');
    expect(auth.getAccessToken).toHaveBeenCalledTimes(2);
  });

  it('accepts a bare getAccessToken function as the seam', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"v"' }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth: async () => 'jwt-fn' });
    await store.readSnapshot('t');
    expect((fetch.mock.calls[0][1] as any).headers.authorization).toBe('Bearer jwt-fn');
  });

  it('omits Authorization when no auth seam is given', async () => {
    const fetch = vi.fn(async () => res({ status: 200, etag: '"v"' }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    await store.readSnapshot('t');
    expect((fetch.mock.calls[0][1] as any).headers.authorization).toBeUndefined();
  });

  it('on a 401 does EXACTLY ONE forced-refresh retry, then succeeds', async () => {
    const fetch = vi.fn(async () => (fetch.mock.calls.length === 1 ? res({ status: 401 }) : res({ status: 200, etag: '"ok"' })));
    const auth = { getAccessToken: vi.fn(async ({ forceRefresh } = {}) => (forceRefresh ? 'fresh' : 'stale')) };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    const snap = await store.readSnapshot('t');
    expect(snap!.version).toBe('ok');
    // First attempt stale, retry forced-refresh.
    expect(auth.getAccessToken).toHaveBeenNthCalledWith(1, { forceRefresh: false });
    expect(auth.getAccessToken).toHaveBeenNthCalledWith(2, { forceRefresh: true });
    expect((fetch.mock.calls[1][1] as any).headers.authorization).toBe('Bearer fresh');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('a persistent 401 surfaces AuthError after one retry — never loops', async () => {
    const fetch = vi.fn(async () => res({ status: 401, text: 'nope' }));
    const auth = { getAccessToken: vi.fn(async () => 'tok') };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    await expect(store.readSnapshot('t')).rejects.toBeInstanceOf(AuthError);
    expect(fetch).toHaveBeenCalledTimes(2); // initial + one forced-refresh retry, no more
  });

  it('a 401 with no auth seam surfaces AuthError without a retry', async () => {
    const fetch = vi.fn(async () => res({ status: 401 }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    await expect(store.readSnapshot('t')).rejects.toBeInstanceOf(AuthError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('the 401 retry also protects a PUT (keyring publish path)', async () => {
    const queue = [res({ status: 401 }), jsonRes({ json: { revision: 2 } })];
    const fetch = vi.fn(async () => queue.shift());
    const auth = { getAccessToken: vi.fn(async ({ forceRefresh } = {}) => (forceRefresh ? 'fresh' : 'stale')) };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    const out = await store.putKeyring('t', new Uint8Array([1, 2]));
    expect(out).toEqual({ revision: 2 });
    expect(fetch).toHaveBeenCalledTimes(2);
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

describe('RemoteStore membership summary (/access)', () => {
  // A JSON Response stand-in (the base `res` helper is bytes-only).
  const jres = ({ status = 200, json = {}, text = '' } = {}) => ({
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
    json: async () => json,
    text: async () => text,
  });

  it('getAccess maps the server shape and returns null on 404', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ json: { members: [{ member_id: 'owner', role: 1 }], generation: 3, basis: ['op:a'] } }),
    });
    expect(await store.getAccess('t')).toEqual({
      members: [{ memberId: 'owner', role: 1 }],
      generation: 3,
      basis: ['op:a'],
    });
    const s404 = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ status: 404 }) });
    expect(await s404.getAccess('t')).toBeNull();
  });

  it('getAccess defaults generation to null and basis to [] when absent (chain, never summary-pushed)', async () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ json: { members: [] } }) });
    expect(await store.getAccess('t')).toEqual({ members: [], generation: null, basis: [] });
  });

  it('putAccess sends the snake_case body + CAS generation and returns {generation, unchanged}', async () => {
    const fetch = vi.fn(async () => jres({ json: { generation: 4 } }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    const out = await store.putAccess('t', {
      basis: ['op:b'],
      expectedGeneration: 3,
      members: [
        { memberId: 'owner', role: 1 },
        { memberId: 'bob', role: 4 },
      ],
    });
    expect(out).toEqual({ generation: 4, unchanged: false });
    const init = fetch.mock.calls[0][1] as any;
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual({
      basis: ['op:b'],
      expected_generation: 3,
      members: [
        { member_id: 'owner', role: 1 },
        { member_id: 'bob', role: 4 },
      ],
    });
  });

  it('putAccess surfaces `unchanged`, and throws ConflictError on 409', async () => {
    const ok = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ json: { generation: 5, unchanged: true } }) });
    expect(await ok.putAccess('t', { basis: [], expectedGeneration: 5, members: [] })).toEqual({
      generation: 5,
      unchanged: true,
    });
    const conflict = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ status: 409 }) });
    await expect(conflict.putAccess('t', { basis: [], expectedGeneration: 1, members: [] })).rejects.toBeInstanceOf(
      ConflictError,
    );
  });
});
