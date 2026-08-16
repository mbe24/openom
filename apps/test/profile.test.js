// The opt-in profiler: a no-op passthrough when off (shipped default), recording timings when on.
// ENABLED is read once at module load, so each case reloads the module with the flag set/unset.
import { describe, it, expect, vi } from 'vitest';

async function load(enabled) {
  vi.resetModules();
  if (enabled) globalThis.__OPENOM_PROFILE__ = true;
  else delete globalThis.__OPENOM_PROFILE__;
  return import('../app/src/core/profile.js');
}

describe('profile', () => {
  it('is a no-op passthrough when disabled (the shipped default)', async () => {
    const { profile, profileSummary, profiling } = await load(false);
    expect(profiling()).toBe(false);
    expect(profile('x', () => 42)).toBe(42);
    expect(profileSummary()).toEqual([]); // records nothing when off
  });

  it('records timings and passes results/errors through when enabled', async () => {
    const { profile, profileSummary, profiling } = await load(true);
    expect(profiling()).toBe(true);
    expect(profile('sync', () => 7)).toBe(7);
    expect(await profile('async', async () => 8)).toBe(8);
    expect(() => profile('boom', () => { throw new Error('e'); })).toThrow('e');
    const labels = profileSummary().map((s) => s.label).sort();
    expect(labels).toEqual(['async', 'boom', 'sync']);
    expect(profileSummary().every((s) => s.calls === 1 && s.ms >= 0)).toBe(true);
    delete globalThis.__OPENOM_PROFILE__;
  });
});
