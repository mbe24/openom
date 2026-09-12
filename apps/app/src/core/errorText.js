// The code→message seam between the error framework and the UI (plan/design.error-model.md). Given an
// AppError, produce a localized string via Fluent keyed by `${domain}-err-${code}`, interpolating the typed
// `args`. This is the MINIMAL renderer the framework provides so no call site ever falls back to a raw
// `.message`/`.stack` (decision A2); the full catalog + recovery affordances (retry/reauth/... buttons) are
// the UI partner's job (OPE-416). Until the partner adds the per-code Fluent keys, an unknown code degrades
// to a generic message — never a crash, never a leaked internal string.
//
// This module is MAIN-THREAD only (it imports the DOM-side i18n). The worker never imports it — the worker
// only ever produces AppErrors (errorModel.js), it never renders them.

import { t } from './i18n.js';
import { fluentKey } from './errorCodes.generated.js';
import { isAppError } from './errorModel.js';

const GENERIC_FALLBACK = 'Something went wrong. Please try again.';

/**
 * Localized, user-facing text for any caught value. A well-formed AppError renders via its per-code Fluent
 * key (with `args`); anything else, or a code the catalog doesn't cover yet, renders the generic message.
 * NEVER returns a raw `.message`/`.stack` — `cause` is dev-log-only and is not consulted here.
 */
export function errText(err) {
  if (isAppError(err)) {
    const key = fluentKey(err.code);
    const msg = t(key, err.args);
    if (msg !== key) return msg; // the partner's catalog covers this code
  }
  const generic = t('error-generic');
  return generic === 'error-generic' ? GENERIC_FALLBACK : generic;
}
