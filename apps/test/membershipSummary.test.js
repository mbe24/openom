import { describe, it, expect, vi } from 'vitest';
import { pushMembershipSummary } from '../app/src/core/membershipSummary.js';
import { ConflictError } from '../app/src/core/store.js';

const VIEW = [
  { memberId: 'owner', role: 1 },
  { memberId: 'bob', role: 4 },
];

// A fake RemoteStore: `stored` is the getAccess sequence (a single value or an array consumed per call);
// `putResults` the putAccess sequence (a value returned, or an Error thrown, per call).
function fakeRemote({ stored = null, putResults = [{ generation: 1, unchanged: false }] } = {}) {
  const puts = [];
  const gets = Array.isArray(stored) ? stored : [stored];
  let getCall = 0;
  return {
    puts,
    getAccess: vi.fn(async () => gets[Math.min(getCall++, gets.length - 1)]),
    putAccess: vi.fn(async (_id, args) => {
      puts.push(args);
      const r = putResults[Math.min(puts.length - 1, putResults.length - 1)];
      if (r instanceof Error) throw r;
      return r;
    }),
  };
}

describe('pushMembershipSummary', () => {
  it('first push (no stored summary) sends expectedGeneration null and skips the coverage check', async () => {
    const covers = vi.fn();
    const remote = fakeRemote({ stored: null });
    const out = await pushMembershipSummary(
      remote,
      't',
      { view: VIEW, basis: ['op:1'] },
      { coversBasis: covers, refresh: vi.fn() },
    );
    expect(out).toEqual({ generation: 1, unchanged: false });
    expect(remote.puts[0].expectedGeneration).toBeNull();
    expect(remote.puts[0].basis).toEqual(['op:1']);
    expect(remote.puts[0].members).toBe(VIEW);
    expect(covers).not.toHaveBeenCalled(); // nothing to be behind
  });

  it('covered: pushes with the stored generation and does not refresh', async () => {
    const remote = fakeRemote({
      stored: { generation: 5, basis: ['op:old'], members: [] },
      putResults: [{ generation: 6, unchanged: false }],
    });
    const refresh = vi.fn();
    const out = await pushMembershipSummary(
      remote,
      't',
      { view: VIEW, basis: ['op:new'] },
      { coversBasis: async () => true, refresh },
    );
    expect(out.generation).toBe(6);
    expect(remote.puts[0].expectedGeneration).toBe(5);
    expect(refresh).not.toHaveBeenCalled();
  });

  it('uncovered: refreshes once, then asserts the recomputed view', async () => {
    const remote = fakeRemote({
      stored: { generation: 5, basis: ['op:ahead'], members: [] },
      putResults: [{ generation: 6, unchanged: false }],
    });
    const refresh = vi.fn(async () => ({ view: [{ memberId: 'owner', role: 1 }], basis: ['op:merged'] }));
    const out = await pushMembershipSummary(
      remote,
      't',
      { view: VIEW, basis: ['op:stale'] },
      { coversBasis: async () => false, refresh },
    );
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(remote.puts[0].basis).toEqual(['op:merged']);
    expect(remote.puts[0].members).toEqual([{ memberId: 'owner', role: 1 }]);
    expect(out.generation).toBe(6);
  });

  it('on a 409 it re-GETs the fresh generation and retries once', async () => {
    const remote = fakeRemote({
      stored: [
        { generation: 5, basis: ['op:a'], members: [] },
        { generation: 7, basis: ['op:b'], members: [] },
      ],
      putResults: [new ConflictError(5, null), { generation: 8, unchanged: false }],
    });
    const out = await pushMembershipSummary(remote, 't', { view: VIEW, basis: ['op:x'] }, { coversBasis: async () => true });
    expect(remote.getAccess).toHaveBeenCalledTimes(2);
    expect(remote.puts[1].expectedGeneration).toBe(7); // retried against the advanced generation
    expect(out.generation).toBe(8);
  });

  it('a persistent 409 propagates as ConflictError', async () => {
    const remote = fakeRemote({
      stored: { generation: 5, basis: ['op:a'], members: [] },
      putResults: [new ConflictError(5, null), new ConflictError(7, null), new ConflictError(9, null)],
    });
    await expect(
      pushMembershipSummary(remote, 't', { view: VIEW, basis: ['op:x'] }, { coversBasis: async () => true }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('refreshes at most once, even across a 409 retry (anti-livelock)', async () => {
    const remote = fakeRemote({
      stored: [
        { generation: 5, basis: ['op:a'], members: [] },
        { generation: 7, basis: ['op:b'], members: [] },
      ],
      putResults: [new ConflictError(5, null), { generation: 8, unchanged: false }],
    });
    const refresh = vi.fn(async () => ({ view: VIEW, basis: ['op:merged'] }));
    await pushMembershipSummary(remote, 't', { view: VIEW, basis: ['op:stale'] }, { coversBasis: async () => false, refresh });
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
