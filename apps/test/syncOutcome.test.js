import { describe, it, expect } from 'vitest';
import {
  Ok, Offline, Conflict, Rejected, Deferred, Unauthorized,
  isOk, isRetryable, isTerminal, worst, classifyError,
  OK, OFFLINE, CONFLICT, REJECTED, DEFERRED, UNAUTHORIZED,
} from '../app/src/core/syncOutcome.js';
import { AuthError, ConflictError } from '../app/src/core/store.js';
import { BootstrapRequiredError } from '../app/src/core/remoteStore.js';

describe('syncOutcome', () => {
  it('constructors tag correctly and carry their payload', () => {
    expect(Ok(42)).toEqual({ tag: OK, value: 42 });
    expect(Conflict('r').remote).toBe('r');
    expect(Rejected({ status: 403 }).reason.status).toBe(403);
    expect(Deferred('x').reason).toBe('x');
    expect(Unauthorized()).toEqual({ tag: UNAUTHORIZED });
  });

  it('guards classify retryable vs terminal vs ok', () => {
    expect(isOk(Ok())).toBe(true);
    expect(isRetryable(Offline())).toBe(true);
    expect(isRetryable(Deferred())).toBe(true);
    expect(isRetryable(Conflict())).toBe(false);
    expect(isTerminal(Rejected())).toBe(true);
    expect(isTerminal(Unauthorized())).toBe(true);
    expect(isTerminal(Offline())).toBe(false);
  });

  it('worst() picks the most-severe channel outcome (unauthorized > rejected > conflict > offline > deferred > ok)', () => {
    expect(worst()).toEqual(Ok());
    expect(worst(Ok(), Deferred()).tag).toBe(DEFERRED);
    expect(worst(Deferred(), Offline()).tag).toBe(OFFLINE);
    expect(worst(Offline(), Conflict()).tag).toBe(CONFLICT);
    expect(worst(Conflict(), Rejected()).tag).toBe(REJECTED);
    expect(worst(Offline(), Unauthorized(), Ok()).tag).toBe(UNAUTHORIZED);
    // a single permanent refusal in any channel dominates transient noise in the others
    expect(worst(Offline(), Deferred(), Rejected(), Ok()).tag).toBe(REJECTED);
  });

  it('classifyError maps the real RemoteStore error shapes', () => {
    expect(classifyError(new AuthError('nope')).tag).toBe(UNAUTHORIZED);      // AuthError carries .status 401
    expect(classifyError(401).tag).toBe(UNAUTHORIZED);
    expect(classifyError(new ConflictError(1, 2)).tag).toBe(CONFLICT);        // ConflictError has no .status, by name
    expect(classifyError(new BootstrapRequiredError(0, 5)).tag).toBe(DEFERRED);
    expect(classifyError(410).tag).toBe(DEFERRED);
    // a status-carrying httpError (what RemoteStore now throws): 403/400 are PERMANENT
    const forbidden = Object.assign(new Error('putKeyring x: HTTP 403'), { status: 403 });
    expect(classifyError(forbidden).tag).toBe(REJECTED);
    expect(classifyError(forbidden).reason.status).toBe(403);
    expect(classifyError(400).tag).toBe(REJECTED);
    // 5xx / 429 / a bare network error are TRANSIENT
    expect(classifyError(Object.assign(new Error('HTTP 503'), { status: 503 })).tag).toBe(OFFLINE);
    expect(classifyError(429).tag).toBe(OFFLINE);
    expect(classifyError(new TypeError('Failed to fetch')).tag).toBe(OFFLINE);
  });
});
