// The unified AppError contract (plan/design.error-model.md). Every failure in the app — HTTP (9457),
// auth, vault, storage, or an unexpected crash — is normalized into one of these PLAIN, structured-clone-safe
// objects before it crosses a Comlink boundary, so the UI renders from `code` + `args` only and no backend
// internal / stack / live object ever leaks (decisions B1, B2, A4).
//
// AppError = { code, domain, retriable, retryAfter?, args?, action?, httpStatus?, requestId?, cause? }
//   code/domain/retriable/action  ← the registry (errorCodes.generated.js), never hand-set
//   args                          ← ONLY schema-declared keys with clone-safe primitive values
//   cause                         ← dev-log ONLY, string-coerced at construction; never rendered

import { ERROR_CODES } from './errorCodes.generated.js';

// Only these value types may cross the Comlink boundary inside an AppError (B2). A live object anywhere in
// the payload makes Comlink discard the WHOLE error, so we never let one in.
function safeArgValue(v) {
  const t = typeof v;
  return t === 'string' || t === 'number' || t === 'boolean' ? v : undefined;
}

/**
 * Build an AppError for a registry `code`. Domain/retriable/action come from the registry; `opts` supplies
 * the per-occurrence extras. Unknown args, non-primitive arg values, and a live `cause` are dropped/coerced —
 * so the result is always structured-clone-safe. Falls back to `internalError` if anything throws.
 * @param {string} code
 * @param {{ args?: object, retryAfter?: number, httpStatus?: number, requestId?: string|number, cause?: unknown }} [opts]
 */
export function makeError(code, opts = {}) {
  try {
    const meta = ERROR_CODES[code];
    if (!meta) return internalError(`unknown error code: ${code}`);
    const out = { code, domain: meta.domain, retriable: meta.retriable, action: meta.action };
    if (opts.args && meta.args.length) {
      const args = {};
      for (const { name } of meta.args) {
        const v = safeArgValue(opts.args[name]);
        if (v !== undefined) args[name] = v;
      }
      if (Object.keys(args).length) out.args = args;
    }
    if (typeof opts.retryAfter === 'number' && Number.isFinite(opts.retryAfter)) out.retryAfter = opts.retryAfter;
    if (typeof opts.httpStatus === 'number') out.httpStatus = opts.httpStatus;
    if (opts.requestId != null) out.requestId = String(opts.requestId);
    if (opts.cause != null) out.cause = String(opts.cause); // coerce NOW — never hold a live reference (B2)
    return out;
  } catch {
    return internalError('error while constructing an AppError');
  }
}

/**
 * The zero-dynamic-content literal fallback (B2): built from constants, so serializing it can never fail.
 * Used whenever construction/normalization itself throws.
 */
export function internalError(cause) {
  const out = { code: 'internal', domain: 'app', retriable: false, action: 'contact' };
  if (cause != null) {
    try { out.cause = String(cause); } catch { /* a hostile toString — leave cause unset */ }
  }
  return out;
}

/** True if `x` is a well-formed AppError carrying a known registry code. */
export function isAppError(x) {
  return (
    !!x && typeof x === 'object' &&
    typeof x.code === 'string' && Object.prototype.hasOwnProperty.call(ERROR_CODES, x.code) &&
    typeof x.domain === 'string' && typeof x.retriable === 'boolean'
  );
}

/**
 * Normalize ANY thrown/rejected value into an AppError — the catch-all every worker method and the global
 * error hooks funnel through (B1/C5). A raw Error's `.stack` is NEVER read or forwarded; only a string cause
 * is kept. An already-normalized AppError passes through unchanged.
 */
export function normalizeUnknown(e) {
  if (isAppError(e)) return e;
  let cause;
  try {
    cause = e && e.message != null ? String(e.message) : String(e);
  } catch {
    cause = 'non-stringable error';
  }
  return internalError(cause);
}
