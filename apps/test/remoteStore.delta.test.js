// RemoteStore's delta-log surface (appendLog / readLog / activity) — request shaping + response
// parsing, with an injected fetch. The server contract itself is covered by openom/tests/api.rs.
import { describe, it, expect } from 'vitest';
import { RemoteStore, BootstrapRequiredError } from '../app/src/core/remoteStore.js';

const res = (status, body) => ({
  ok: status < 400,
  status,
  json: async () => body,
  text: async () => JSON.stringify(body),
});
const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

describe('RemoteStore delta-log surface', () => {
  it('appendLog POSTs the delta bytes and returns the assigned seq', async () => {
    let seen;
    const rs = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async (url, opts) => {
        seen = { url, method: opts.method, body: opts.body };
        return res(200, { seq: 7 });
      },
    });
    const seq = await rs.appendLog('t1', new Uint8Array([1, 2, 3]));
    expect(seq).toBe(7);
    expect(seen.method).toBe('POST');
    expect(seen.url).toBe('http://x/trees/t1/log');
    expect(seen.body).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('readLog parses entries, base64 payloads, and the cursor', async () => {
    const rs = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async (url) => {
        expect(url).toBe('http://x/trees/t1/log?since=-1');
        return res(200, {
          entries: [{ seq: 0, member: 'm', replica: 'cmVw', counter: 0, time: '2026-01-01', payload: b64([9, 8, 7]) }],
          next_cursor: 0,
          oldest_retained_seq: 0,
          head_seq: 0,
        });
      },
    });
    const tail = await rs.readLog('t1', -1);
    expect(tail.entries).toHaveLength(1);
    expect(tail.entries[0].payload).toEqual(new Uint8Array([9, 8, 7]));
    expect(tail.entries[0].time).toBe('2026-01-01');
    expect(tail.nextCursor).toBe(0);
  });

  it('readLog throws BootstrapRequiredError on a 410 (cursor below the retained window)', async () => {
    const rs = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => res(410, { oldest_retained_seq: 5, head_seq: 9 }),
    });
    await expect(rs.readLog('t1', 0)).rejects.toBeInstanceOf(BootstrapRequiredError);
  });

  it('activity returns log metadata without the payloads', async () => {
    const rs = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => res(200, {
        entries: [{ seq: 3, member: 'm', replica: 'r', counter: 2, time: 't', payload: b64([1]) }],
        next_cursor: 3,
        head_seq: 3,
      }),
    });
    const a = await rs.activity('t1', -1);
    expect(a.changes[0]).toEqual({ seq: 3, member: 'm', replica: 'r', counter: 2, time: 't' });
    expect('payload' in a.changes[0]).toBe(false);
    expect(a.headSeq).toBe(3);
  });
});
