import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createLockPolicy } from '../app/src/core/lockPolicy.js';

// A fake window/document so the policy is testable in Node: activity + visibilitychange
// listeners land in one map, and `now` is a manual clock so we can simulate a timer that was
// frozen while the tab was hidden (advance the clock without advancing the timer).
function fakeEnv() {
  const listeners: Record<string, Function[]> = {};
  const addEventListener = (ev: string, fn: Function) => { (listeners[ev] ??= []).push(fn); };
  let visibility = 'visible';
  return {
    listeners,
    emit(ev: string) { (listeners[ev] || []).forEach((f) => f()); },
    setVisibility(v: string) { visibility = v; },
    target: { addEventListener },
    doc: { addEventListener, get visibilityState() { return visibility; } },
  };
}

describe('createLockPolicy', () => {
  let t = 0;
  const now = () => t;

  beforeEach(() => { t = 0; vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  // Advance both the manual clock and the fake timers together (the normal case).
  const advance = (ms: number) => { t += ms; vi.advanceTimersByTime(ms); };

  it('locks after the idle window with no activity', () => {
    const env = fakeEnv();
    const onLock = vi.fn();
    const p = createLockPolicy({ onLock, now, target: env.target, doc: env.doc });
    p.setIdleMinutes(5);
    p.arm();
    advance(5 * 60000);
    expect(onLock).toHaveBeenCalledWith('idle');
  });

  it('activity pushes the deadline out', () => {
    const env = fakeEnv();
    const onLock = vi.fn();
    const p = createLockPolicy({ onLock, now, target: env.target, doc: env.doc });
    p.setIdleMinutes(5);
    p.arm();
    advance(4 * 60000);
    env.emit('pointerdown'); // bump — deadline resets to now + 5min
    advance(4 * 60000);
    expect(onLock).not.toHaveBeenCalled();
    advance(1 * 60000);
    expect(onLock).toHaveBeenCalledWith('idle');
  });

  it('does not lock while disarmed (at the gate / demo)', () => {
    const env = fakeEnv();
    const onLock = vi.fn();
    const p = createLockPolicy({ onLock, now, target: env.target, doc: env.doc });
    p.setIdleMinutes(5);
    p.arm();
    p.disarm();
    advance(10 * 60000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it('idle window of 0 disables auto-lock', () => {
    const env = fakeEnv();
    const onLock = vi.fn();
    const p = createLockPolicy({ onLock, now, target: env.target, doc: env.doc });
    p.setIdleMinutes(0);
    p.arm();
    advance(60 * 60000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it('locks on return to visible when the deadline passed while hidden (frozen timer)', () => {
    const env = fakeEnv();
    const onLock = vi.fn();
    const p = createLockPolicy({ onLock, now, target: env.target, doc: env.doc });
    p.setIdleMinutes(5);
    p.arm();
    // Simulate a suspended tab: the wall clock moves past the deadline but the timer never fired.
    t += 6 * 60000;
    env.setVisibility('visible');
    env.emit('visibilitychange');
    expect(onLock).toHaveBeenCalledWith('idle');
  });
});
