// Opt-in profiling for the client hot paths (hydrate, materialize, engine merge/snapshot, sync
// push/pull). A no-op unless explicitly enabled — so it stays out of the shipped path and costs a single
// branch per call when off. Enable with localStorage['openom.profile'] = '1' or globalThis.__OPENOM_PROFILE__
// = true (a dev/debug switch, never on in a release build). Timings accumulate into a summary a dev
// overlay or the console can read (window.openomProfile()).
//
// Engine (wasm) cost is captured from here by wrapping the shim calls, rather than adding a timing
// dependency into the zero-dep commute/treelog crates.

let ENABLED = false;
try { ENABLED = globalThis.localStorage?.getItem('openom.profile') === '1'; } catch { /* no storage */ }
if (globalThis.__OPENOM_PROFILE__) ENABLED = true;

const now = () => globalThis.performance?.now?.() ?? Date.now();
const totals = new Map(); // label -> { calls, ms }

/** Whether profiling is on (so a caller can skip building a label it won't use). */
export const profiling = () => ENABLED;

function record(label, ms) {
  const t = totals.get(label) ?? { calls: 0, ms: 0 };
  t.calls += 1;
  t.ms += ms;
  totals.set(label, t);
}

/**
 * Time `fn` (sync or async) under `label` when profiling is on; otherwise just call it. Returns fn's
 * result (or promise). The off-path is a single boolean check, so it's safe to leave in hot code.
 */
export function profile(label, fn) {
  if (!ENABLED) return fn();
  const t0 = now();
  const done = () => record(label, now() - t0);
  let r;
  try {
    r = fn();
  } catch (e) {
    done();
    throw e;
  }
  if (r && typeof r.then === 'function') return r.finally(done);
  done();
  return r;
}

/** The accumulated timings, slowest total first — for a console dump or a dev overlay. */
export function profileSummary() {
  return [...totals.entries()]
    .map(([label, t]) => ({ label, calls: t.calls, ms: +t.ms.toFixed(2), avg: +(t.ms / t.calls).toFixed(3) }))
    .sort((a, b) => b.ms - a.ms);
}

export function resetProfile() {
  totals.clear();
}

// Convenience: reachable from the console when profiling is on.
if (ENABLED && typeof globalThis !== 'undefined') {
  globalThis.openomProfile = profileSummary;
  globalThis.openomProfileReset = resetProfile;
}
